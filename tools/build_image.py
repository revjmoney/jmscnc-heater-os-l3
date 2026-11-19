"""Build a personalized candidate rootfs. Never talks to or flashes a miner."""
import argparse, hashlib, io, json, os, stat, struct, subprocess, tarfile
from pathlib import Path
from image_format import unpack_image, pack_image, put

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.1.3'
BASE_SHA='5b3fbe1132f050d770f25f91a97312b098496aba856f76e52c336c69c31953c1'
BACKUP_FILES={'cgminer.conf','network.conf','dropbear','shadow','lighttpd-htdigest.user','dropbear_rsa_host_key'}

DEFAULTS_SCRIPT='''#!/bin/sh
set -e
# Called after Bitmain mounts persistent /config and before networking/SSH.
grep -q ' /config ' /proc/mounts || { echo 'L3 Lab: config not mounted; defaults skipped'; exit 1; }
if [ ! -f /config/.l3lab-defaults-v1 ]; then
    umask 077
    for f in cgminer.conf network.conf dropbear shadow lighttpd-htdigest.user dropbear_rsa_host_key; do
        if [ -f /etc/l3lab/defaults/$f ]; then
            cp /etc/l3lab/defaults/$f /config/$f
            chmod 600 /config/$f
        fi
    done
    chmod 400 /config/shadow
    echo initialized > /config/.l3lab-defaults-v1
    sync
fi
'''
SCHEDULER_SCRIPT='''#!/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
case "$1" in
start) start-stop-daemon -S -b -m -p /tmp/l3lab-scheduler.pid -x /usr/bin/l3lab -- -scheduler ;;
stop) start-stop-daemon -K -p /tmp/l3lab-scheduler.pid ;;
restart) "$0" stop; "$0" start ;;
*) exit 1 ;;
esac
'''

def sha(b):return hashlib.sha256(b).hexdigest()
def read_backup(path):
    result={}
    if path.stat().st_size>1024*1024:raise ValueError('Backup too large')
    with tarfile.open(path,'r:') as archive:
        members=archive.getmembers()
        if len(members)>64:raise ValueError('Too many backup members')
        for m in members:
            if not m.isfile() or m.name not in BACKUP_FILES:continue
            if m.name in result or m.size>256*1024:raise ValueError('Invalid backup member')
            result[m.name]=archive.extractfile(m).read()
    for required in ('cgminer.conf','network.conf','shadow','lighttpd-htdigest.user'):
        if required not in result:raise ValueError('Missing required backup configuration: '+required)
    cfg=json.loads(result['cgminer.conf'])
    if not isinstance(cfg.get('pools'),list) or not cfg['pools']:raise ValueError('No pool defaults')
    # Local API access is required by the dashboard; do not expose privileged
    # CGMiner commands to every host as the original W:0/0 backup does.
    cfg.update({'api-listen':True,'api-network':True,'api-allow':'W:127.0.0.1'})
    result['cgminer.conf']=(json.dumps(cfg,indent=2)+'\n').encode()
    result['dropbear']=b'NO_START=0\n'
    return result

def archive_bytes(files,gz=False):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz' if gz else 'w',format=tarfile.USTAR_FORMAT) as t:
        for name,data,mode in files:
            h=tarfile.TarInfo(name);h.mode=mode;h.size=len(data);h.mtime=0;t.addfile(h,io.BytesIO(data))
    return out.getvalue()

def build(base,backup,binary,signer,keydir,destination):
    # Official stock archive downloaded from mirrors; published hashes match.
    # This is integrity verification, not proof of a manufacturer signature.
    basebytes=base.read_bytes()
    if sha(basebytes)!=BASE_SHA:raise ValueError('Unexpected stock base archive hash')
    with tarfile.open(fileobj=io.BytesIO(basebytes),mode='r:gz') as outer:
        fw=outer.extractfile('fw.tar.gz').read()
    with tarfile.open(fileobj=io.BytesIO(fw),mode='r:gz') as inner:
        stock=inner.extractfile('initramfs.bin.SD').read()
    header,entries=unpack_image(stock);original={e.name:(list(e.fields),e.data) for e in entries}
    binarybytes=binary.read_bytes()
    if binarybytes[:4]!=b'\x7fELF' or binarybytes[4:6]!=b'\x01\x01' or struct.unpack('<H',binarybytes[18:20])[0]!=40:raise ValueError('Backend is not a 32-bit little endian ARM ELF')
    # Verify statically linked ELF: no PT_INTERP or PT_DYNAMIC program header.
    phoff=struct.unpack('<I',binarybytes[28:32])[0];size,count=struct.unpack('<HH',binarybytes[42:46])
    if any(struct.unpack('<I',binarybytes[phoff+i*size:phoff+i*size+4])[0] in (2,3) for i in range(count)):raise ValueError('Backend has dynamic linker dependencies')
    defaults=read_backup(backup)
    keydir.mkdir(parents=True,exist_ok=True)
    private=keydir/'update-private.key';public=keydir/'update-public.key'
    if not private.exists() and not public.exists():subprocess.run([str(signer.resolve()),'-keygen',str(keydir.resolve())],check=True)
    if len(private.read_bytes())!=64 or len(public.read_bytes())!=32:raise ValueError('Invalid owner key files')
    for name,data in defaults.items():put(entries,'etc/l3lab/defaults/'+name,data,0o100600)
    put(entries,'etc/cgminer.conf.factory',defaults['cgminer.conf'],0o100600)
    put(entries,'etc/shadow.factory',defaults['shadow'],0o100400)
    put(entries,'etc/lighttpd-htdigest.user',defaults['lighttpd-htdigest.user'],0o100600)
    put(entries,'etc/init.d/l3lab-defaults',DEFAULTS_SCRIPT.encode(),0o100755)
    put(entries,'usr/bin/l3lab',binarybytes,0o100755)
    put(entries,'etc/l3lab/update-public.key',public.read_bytes(),0o100644)
    put(entries,'etc/init.d/l3lab-scheduler',SCHEDULER_SCRIPT.encode(),0o100755)
    put(entries,'etc/rcS.d/S75l3lab-scheduler',b'../init.d/l3lab-scheduler',0o120777)
    setup=original['etc/init.d/bitmainer_setup.sh'][1].decode()
    needle='echo NO_START=1 > /config/dropbear'
    if setup.count(needle)!=1:raise ValueError('Unexpected stock SSH startup script')
    setup=setup.replace(needle,'/etc/init.d/l3lab-defaults\nif [ ! -f /config/dropbear ]; then echo NO_START=0 > /config/dropbear; fi')
    put(entries,'etc/init.d/bitmainer_setup.sh',setup.encode(),0o100755)
    watchdog=original['sbin/monitorcg'][1].decode()
    if watchdog.count('sleep $check_inter')!=1:raise ValueError('Unexpected watchdog script')
    watchdog=watchdog.replace('sleep $check_inter','sleep $check_inter\n\t[ -e /tmp/l3lab/staged/install.lock ] && continue')
    put(entries,'sbin/monitorcg',watchdog.encode(),0o100755)
    put(entries,'www/pages/classic.html',original['www/pages/index.html'][1],0o100644)
    for name in ('index.html','style.css','app.js','monkey.png'):
        put(entries,'www/pages/'+name,(ROOT/'web'/name).read_bytes(),0o100644)
    put(entries,'www/pages/cgi-bin/l3lab.cgi',b'#!/bin/sh\nexec /usr/bin/l3lab\n',0o100755)
    # Remove the vendor's optional cloud monitoring binary and its web page.
    # Keep local hashboard protection, miner watchdog, DNS and NTP services.
    removed=[]
    for e in list(entries):
        if 'miner-monitor' in e.name and stat.S_ISREG(e.fields[1]) and not e.name.startswith('var/lib/opkg/'):
            entries.remove(e);removed.append(e.name)
    put(entries,'www/pages/monitor.html',b'<!doctype html><meta charset="utf-8"><title>Local monitoring</title><p>Cloud monitoring is removed in L3 Lab. <a href="index.html">Open local dashboard</a></p>')
    info=dict(name='JMSCNC Heater OS',edition='L3+ edition',release=VERSION,model='Antminer L3+',base='Bitmain 201907101440-384M',base_sha256=BASE_SHA,backup_sha256=sha(backup.read_bytes()),owner_key_sha256=sha(public.read_bytes()),cgminer_sha256=sha(original['usr/bin/cgminer'][1]),hardware_validation='pending',initial_web_install='Stock Bitmain 2019 signature gate: bootstrap/recovery required',dev_support='On at 1% by default, opt-out (0-5%). Runtime pool time-slice to the JMSCNC developer pool; saved pools never modified; no fallback pool. Stock miner binary retained byte-for-byte.',telemetry='Vendor miner-monitor removed; no dashboard telemetry',schedule='One daily Off/On window; CGMiner ASIC pause API, fan operation needs hardware validation',support='buymeacoffee.com/revjmoney, jmscnc.com')
    put(entries,'etc/l3lab/build.json',(json.dumps(info,indent=2)+'\n').encode())
    candidate=pack_image(header,entries);_,checked=unpack_image(candidate);new={e.name:(e.fields,e.data) for e in checked}
    if new['usr/bin/cgminer'][1]!=original['usr/bin/cgminer'][1]:raise AssertionError('Mining daemon unexpectedly changed')
    changed=[name for name,(fields,data) in original.items() if name not in new or new[name][0][:6]!=fields[:6] or new[name][1]!=data]
    added=[name for name in new if name not in original]
    destination.mkdir(parents=True,exist_ok=True)
    rawpath=destination/f'l3lab-{VERSION}-rootfs.bin';rawpath.write_bytes(candidate)
    manifest=dict(model='Antminer L3+',version=VERSION,payload='initramfs.bin.SD',sha256=sha(candidate),bytes=len(candidate),base_sha256=BASE_SHA,validation='Software-tested candidate; NAND flashing and fan-only pause require hardware validation')
    manifestpath=destination/'manifest.json';manifestbytes=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();manifestpath.write_bytes(manifestbytes)
    subprocess.run([str(signer.resolve()),'-sign',str(manifestpath.resolve()),'-private-key',str(private.resolve())],check=True)
    signature=Path(str(manifestpath)+'.sig').read_bytes()
    update=archive_bytes([('manifest.json',manifestbytes,0o600),('manifest.sig',signature,0o600),('initramfs.bin.SD',candidate,0o600)],True)
    updatepath=destination/f'l3lab-{VERSION}-update.tar.gz';updatepath.write_bytes(update)
    # A temporary overlay can bootstrap the signed updater when trusted SSH or
    # recovery root access is available. It never erases or writes NAND itself.
    overlayfiles=[]
    for e in checked:
        if e.name in added+changed and stat.S_ISREG(e.fields[1]):overlayfiles.append(('overlay/'+e.name,e.data,stat.S_IMODE(e.fields[1])))
    install='''#!/bin/sh
set -e
[ "$(id -u)" = 0 ] || { echo 'Root access required'; exit 1; }
grep -q '^Antminer L3+' /etc/issue 2>/dev/null || [ -f /usr/bin/compile_time ] || { echo 'Unsupported controller'; exit 1; }
[ "$(cat /usr/bin/compile_time)" = 'Wed Jul 10 14:34:16 CST 2019' ] || { echo 'Base build mismatch; stop'; exit 1; }
[ -e /dev/mtd8 ] || { echo 'Expected NAND rootfs not found'; exit 1; }
cd "$(dirname "$0")"
cp -p /www/pages/index.html /www/pages/classic.html
cp -Rp overlay/etc/. /etc/
cp -Rp overlay/usr/. /usr/
cp -Rp overlay/sbin/. /sbin/
cp -Rp overlay/www/. /www/
# Preserve symlink startup placement; this overlay is temporary until NAND installation.
ln -sf ../init.d/l3lab-scheduler /etc/rcS.d/S75l3lab-scheduler
mkdir -p /tmp/l3lab
/etc/init.d/l3lab-defaults
cp /config/dropbear /etc/default/dropbear
/etc/init.d/dropbear start
echo 'Temporary dashboard installed. Open the miner root page and use its signed firmware updater. Do not reboot before NAND installation.'
'''
    overlayfiles.append(('install-overlay.sh',install.encode(),0o755))
    (destination/f'l3lab-{VERSION}-bootstrap-overlay.tar.gz').write_bytes(archive_bytes(overlayfiles,True))
    # The same extraction-before-signature-check mechanism observed in the
    # published L3 unlock archive. This installs a temporary authenticated
    # dashboard; it does not remove signature checks from the stock updater,
    # start SSH, execute a script, or write a NAND partition automatically.
    # Compatibility is a candidate until tested against this exact device.
    boot=io.BytesIO()
    with tarfile.open(fileobj=boot,mode='w:gz',format=tarfile.USTAR_FORMAT) as t:
        link=tarfile.TarInfo('l3lab-root');link.type=tarfile.SYMTYPE;link.linkname='/';link.mode=0o755;t.addfile(link)
        for e in checked:
            if e.name in added+changed and stat.S_ISREG(e.fields[1]):
                h=tarfile.TarInfo('l3lab-root/'+e.name);h.mode=stat.S_IMODE(e.fields[1]);h.size=len(e.data);h.mtime=0;t.addfile(h,io.BytesIO(e.data))
    (destination/f'l3lab-{VERSION}-web-bootstrap-candidate.tar.gz').write_bytes(boot.getvalue())
    # Refresh an already running 0.1.0 bootstrap without replacing an active ELF.
    # Write the versioned executable first; switch its CGI entry point last.
    # This package neither touches NAND nor rewrites the owner's configuration.
    hotfix=io.BytesIO()
    with tarfile.open(fileobj=hotfix,mode='w:gz',format=tarfile.USTAR_FORMAT) as t:
        link=tarfile.TarInfo('l3lab-root');link.type=tarfile.SYMTYPE;link.linkname='/';link.mode=0o755;t.addfile(link)
        for name,data,mode in [(f'usr/bin/l3lab-v{VERSION}',binarybytes,0o755),('etc/l3lab/build.json',new['etc/l3lab/build.json'][1],0o644),('www/pages/index.html',(ROOT/'web/index.html').read_bytes(),0o644),('www/pages/style.css',(ROOT/'web/style.css').read_bytes(),0o644),('www/pages/app.js',(ROOT/'web/app.js').read_bytes(),0o644),('www/pages/monkey.png',(ROOT/'web/monkey.png').read_bytes(),0o644),('www/pages/cgi-bin/l3lab.cgi',f'#!/bin/sh\nexec /usr/bin/l3lab-v{VERSION}\n'.encode(),0o755)]:
            h=tarfile.TarInfo('l3lab-root/'+name);h.mode=mode;h.size=len(data);h.mtime=0;t.addfile(h,io.BytesIO(data))
    (destination/f'l3lab-{VERSION}-updater-hotfix.tar.gz').write_bytes(hotfix.getvalue())
    report=dict(info,rootfs_bytes=len(candidate),rootfs_sha256=sha(candidate),update_sha256=sha(update),web_bootstrap_sha256=sha(boot.getvalue()),web_bootstrap_status='Offline structure checked; extraction behavior on actual stock BusyBox remains untested',original_entries=len(original),candidate_entries=len(new),changed_paths=changed,added_paths=added,removed_paths=removed,checks=['uImage header/payload CRCs','bounded newc round-trip','ARM ELF identity and static linkage','stock CGMiner unchanged','private owner signing key excluded from rootfs'])
    if private.read_bytes() in candidate:raise AssertionError('Private signing key unexpectedly in image')
    (destination/'build-report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('rootfs_bytes','rootfs_sha256','candidate_entries','hardware_validation')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);p.add_argument('--backup',type=Path,required=True);p.add_argument('--binary',type=Path,default=ROOT/'build/l3lab-arm');p.add_argument('--signer',type=Path,default=ROOT/'build/l3lab-preview.exe');p.add_argument('--keys',type=Path,default=ROOT/'private');p.add_argument('--output',type=Path,default=ROOT/'firmware');a=p.parse_args();build(a.base,a.backup,a.binary,a.signer,a.keys,a.output)
