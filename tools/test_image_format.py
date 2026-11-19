import io, sys, tarfile, unittest
from pathlib import Path
from image_format import Entry, pack_image, put, read_cpio, unpack_image, write_cpio
from build_image import read_backup, VERSION

class ImageTests(unittest.TestCase):
    def test_metadata_roundtrip(self):
        fields=[1,0o100640,100,200,2,123456,0,8,1,0,0,0,0]
        entries=[Entry('file',fields,b'contents'),Entry('symlink',[2,0o120777,0,0,1,5,0,0,0,0,0,0,0],b'file')]
        after=read_cpio(write_cpio(entries))
        for before,after in zip(entries,after):
            self.assertEqual(before.name,after.name);self.assertEqual(before.data,after.data);self.assertEqual(before.fields[:6],after.fields[:6]);self.assertEqual(before.fields[7:11],after.fields[7:11])
    def test_reject_bad_paths_and_truncation(self):
        for name in ('/etc/shadow','../outside','path/../../outside','path\\evil'):
            with self.assertRaises(ValueError):put([],name,b'bad')
        with self.assertRaises(ValueError):read_cpio(b'070701'+b'0'*40)
    def test_duplicates(self):
        e=Entry('duplicate',[1,0o100644,0,0,1,0,0,0,0,0,0,0,0],b'')
        with self.assertRaises(ValueError):read_cpio(write_cpio([e,e]))
    def test_crc_and_boundaries(self):
        header=[0x27051956,0,0,0,0,0,0,5,2,3,1,b'test']
        image=pack_image(header,[Entry('file',[1,0o100644,0,0,1,0,0,0,0,0,0,0,0],b'hello')])
        self.assertEqual(unpack_image(image)[1][0].data,b'hello')
        for offset in (4,24,len(image)-1):
            bad=bytearray(image);bad[offset]^=1
            with self.assertRaises(ValueError):unpack_image(bytes(bad))
    def test_candidate_integrity(self):
        root=Path(__file__).resolve().parents[1];path=root/f'firmware/l3lab-{VERSION}-rootfs.bin'
        if not path.exists():self.skipTest('Build candidate first')
        _,entries=unpack_image(path.read_bytes());files={e.name:e for e in entries}
        self.assertNotIn('usr/bin/miner-monitor',files)
        self.assertEqual(files['etc/l3lab/defaults/dropbear'].data,b'NO_START=0\n')
        self.assertIn(b'/etc/init.d/l3lab-defaults',files['etc/init.d/bitmainer_setup.sh'].data)
        self.assertIn(b'install.lock',files['sbin/monitorcg'].data)
        self.assertEqual(files['usr/bin/l3lab'].data[:4],b'\x7fELF')
        self.assertFalse(any('update-private' in name for name in files))
        self.assertEqual(files['etc/rcS.d/S75l3lab-scheduler'].fields[1]&0o170000,0o120000)
    def test_updater_hotfix(self):
        root=Path(__file__).resolve().parents[1];path=root/f'firmware/l3lab-{VERSION}-updater-hotfix.tar.gz'
        if not path.exists():self.skipTest('Build hotfix first')
        with tarfile.open(path,'r:gz') as archive:
            members=archive.getmembers()
            self.assertEqual(len(members),7)
            self.assertTrue(members[0].issym())
            self.assertEqual(members[0].name,'l3lab-root')
            self.assertEqual(members[0].linkname,'/')
            self.assertEqual(members[1].name,f'l3lab-root/usr/bin/l3lab-v{VERSION}')
            self.assertEqual(archive.extractfile(members[1]).read(),(root/'build/l3lab-arm').read_bytes())
            self.assertEqual(members[-1].name,'l3lab-root/www/pages/cgi-bin/l3lab.cgi')
            self.assertEqual(archive.extractfile(members[-1]).read(),f'#!/bin/sh\nexec /usr/bin/l3lab-v{VERSION}\n'.encode())
            self.assertFalse(any('/config/' in m.name or '/dev/' in m.name or 'initramfs' in m.name for m in members))

if __name__=='__main__':unittest.main()
