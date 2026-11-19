# JMSCNC Heater OS (L3+ edition)

Open-source custom firmware for the **Bitmain Antminer L3+** (Scrypt / LTC+DOGE),
built to run the miner as a controllable winter space heater with a clean local
dashboard. It adds a browser console, live graphs, dark/light themes, searchable
settings, SSH control, a daily Off/On mining schedule, and an owner-signed web
updater, on top of your own Bitmain stock firmware.

By [Rev. J. Money](https://jmscnc.com) / **JMSCNC**. Version **0.1.3**.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://github.com/revjmoney/jmscnc-heater-os-l3/actions/workflows/go.yml/badge.svg)](https://github.com/revjmoney/jmscnc-heater-os-l3/actions/workflows/go.yml)
[![CodeQL](https://github.com/revjmoney/jmscnc-heater-os-l3/actions/workflows/codeql.yml/badge.svg)](https://github.com/revjmoney/jmscnc-heater-os-l3/actions/workflows/codeql.yml)
[![gitleaks](https://github.com/revjmoney/jmscnc-heater-os-l3/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/revjmoney/jmscnc-heater-os-l3/actions/workflows/gitleaks.yml)

> **Status: software-tested, not yet hardware-qualified on a second unit.** The
> original L3 Lab 0.1.3 was built and ran on the author's own L3+ (dashboard,
> SSH, mining and both fans came back after reboot). This public release has the
> same code plus the rebrand and the dev-support slice. Treat NAND flashing as
> brick-risk and keep a recovery method ready. See [Safety](#safety-and-recovery).

- No cloud account, no analytics, no dashboard telemetry.
- The stock `cgminer` mining binary is kept **byte-for-byte unchanged**.
- The only outbound mining connection this firmware adds is the optional,
  opt-out **developer-support slice** (1% by default, see below).

---

## Table of contents

1. [What you need](#what-you-need)
2. [Why you build it yourself (no image is shipped)](#why-you-build-it-yourself)
3. [Build from source](#build-from-source)
4. [Get a root shell on stock firmware (SSH unlock)](#get-a-root-shell-on-stock-firmware-ssh-unlock)
5. [Install on the miner](#install-on-the-miner)
6. [The dashboard](#the-dashboard)
7. [Developer support (the 1% slice)](#developer-support-the-1-slice)
8. [Daily heater schedule](#daily-heater-schedule)
9. [Helper tools reference](#helper-tools-reference)
10. [Safety and recovery](#safety-and-recovery)
11. [Licensing and credits](#licensing-and-credits)

---

## What you need

- An **Antminer L3+** you own, on the default July 10, 2019 Bitmain firmware
  (`compile_time` = `Wed Jul 10 14:34:16 CST 2019`). Other control boards / build
  dates are not supported by this builder.
- A Windows or Linux PC on the same LAN as the miner.
- **Go 1.23+** (for the backend), **Python 3.10+** (for the image builder and
  helper scripts), and OpenSSH `ssh` on PATH.
- `pip install requests cryptography` (only for the SSH-unlock helper).
- Your miner's **settings backup** (`.tar`) and a copy of the **Bitmain stock
  firmware archive** `Antminer-L3plus-201907101440-384M.tar.gz`
  (SHA-256 `5b3fbe1132f050d770f25f91a97312b098496aba856f76e52c336c69c31953c1`).
  You can dump the backup from the stock web UI (System → Backup) and download
  the stock archive from a firmware mirror; the builder verifies its hash.

---

## Why you build it yourself

This repository contains only JMSCNC's **own** code and scripts. It deliberately
does **not** include any Bitmain rootfs, kernel, `cgminer` binary, web files,
your pool configuration, login hashes, SSH host key, signing key, or any prebuilt
firmware image. Those are either Bitmain's (not redistributable) or private to
your specific miner.

So every owner builds a personalized image from their **own** stock firmware
backup, exactly like supplying a donor input. The builder reads your stock
archive and your settings backup, layers the JMSCNC dashboard and backend on top,
keeps the mining binary untouched, and signs the result with an **owner key it
generates locally and that never leaves your PC**.

---

## Build from source

The Go backend uses only the standard library (no external modules).

### Windows (PowerShell), one shot

```powershell
.\Build.ps1 -Base C:\path\to\Antminer-L3plus-201907101440-384M.tar.gz -Backup C:\path\to\your-miner-backup.tar
```

`Build.ps1` runs `go test`, `go vet`, builds the Windows preview binary and the
ARM firmware binary, builds the personalized image, and runs the image tests.

### Any platform, by hand

```powershell
$env:CGO_ENABLED='0'
go test ./...
go vet ./...

# Windows preview / signer binary (runs on your PC)
go build -trimpath -ldflags='-s -w' -o build/l3lab-preview.exe .

# ARM firmware binary (runs on the miner)
$env:GOOS='linux'; $env:GOARCH='arm'; $env:GOARM='7'
go build -trimpath -ldflags='-s -w' -o build/l3lab-arm .

# Build the personalized, owner-signed image + update package
python tools/build_image.py --base PATH_TO_STOCK_ARCHIVE --backup PATH_TO_YOUR_BACKUP
python -m unittest discover -s tools -p 'test_*.py' -v
```

Outputs land in `firmware/` (ignored by git): the rootfs image, the signed
`*-update.tar.gz`, a bootstrap overlay, a web-bootstrap candidate, and
`build-report.json` listing every changed/added path and hash. Your owner keys
land in `private/` (also git-ignored). **Back up `private/update-private.key`:**
it is the only key that can sign future updates for your miner. Keep it off the
miner.

### Preview the dashboard on your PC (read-only, safe)

```powershell
.\Preview.ps1 -Miner 192.168.1.50:4028
```

Opens `http://127.0.0.1:8787/`. It reads your miner's CGMiner API for live
numbers but refuses every write (no flashing, no SSH changes, no config writes).
Good for trying the UI before you install anything.

---

## Get a root shell on stock firmware (SSH unlock)

Stock L3+ firmware runs Dropbear but **rejects the root password over SSH**, so
there is no supported shell, and its web updater only accepts Bitmain-signed
packages. To install custom firmware the first time, you need a foothold.

**How the unlock works.** The stock web upgrade CGI **extracts** an uploaded
`.tar.gz` *before* it verifies the Bitmain signature. By putting a symlink to `/`
at the top of the archive, that extraction drops one file wherever we choose, so
we place a tiny, **token-guarded** CGI into `/www/pages/cgi-bin/`. The signature
check then fails (expected), but our CGI is already on disk. Called with a
one-time token, it appends a throwaway SSH public key to root's
`authorized_keys`. We SSH in, look around, then remove the key and the CGI. It
writes nothing to NAND, enables no service, and cleans up after itself.

`tools/recover_ssh.py` does the whole dance:

```powershell
pip install requests cryptography

# Default: install temp key, run a read-only inspection over SSH, then clean up
python tools\recover_ssh.py --host 192.168.1.50 --web-user root --web-pass root

# Or keep the key so you can SSH in manually to do the install, then clean up later
python tools\recover_ssh.py --host 192.168.1.50 --keep-key
ssh -i jmscnc-recovery-key root@192.168.1.50
python tools\recover_ssh.py --host 192.168.1.50 --cleanup-only
```

Replace the host and web credentials with your miner's. **Use this only on a
miner you own.** The script talks to the stock web UI with HTTP digest auth, so
you need the miner's current web login.

---

## Install on the miner

Do a dry run with `Preview.ps1` first, confirm your recovery method, and read
[Safety](#safety-and-recovery). The install is a browser flow after a one-time
bootstrap. Short version:

1. **Backup.** In the stock UI save a settings backup, and make sure you have a
   working L3+ recovery method (SD-card / control-board recovery). Confirm the
   live firmware is the July 10, 2019 base.
2. **Bootstrap the dashboard.** You have two routes:
   - **Web bootstrap:** in stock *System → Upgrade*, upload
     `firmware/l3lab-0.1.3-web-bootstrap-candidate.tar.gz` with "keep settings".
     A stock signature error is expected and does **not** prove success. Reload
     the miner's root page and check JMSCNC Heater OS loads and shows the correct
     model. If it does not, stop and use the SSH/recovery route instead; do not
     re-upload packages repeatedly.
   - **SSH overlay:** with root SSH (from the unlock above), review and run
     `firmware/l3lab-0.1.3-bootstrap-overlay.tar.gz`'s `install-overlay.sh`. This
     installs the temporary dashboard into RAM; a reboot loses it until the
     signed update is written.
3. **Stage the signed update.** In JMSCNC Heater OS → *Firmware updates*, upload
   the **owner-signed** `firmware/l3lab-0.1.3-update.tar.gz`. The backend checks
   the owner signature, model, payload hash, uImage CRCs, the real rootfs
   partition, good NAND blocks, spare capacity and RAM. Any failed check blocks
   installation.
4. **Save the recovery image.** Download the current-rootfs recovery image to
   your PC and tick the acknowledgement. Then confirm installation. The updater
   stops mining, writes **only** rootfs `mtd8`, reads it back through NAND-aware
   tooling, and compares the hash. Kernel, DTB, bootloader and the persistent
   config partition are not touched.
5. **Reboot only after a verified completion status.** Then check your pools,
   SSH, sensors and all hashboards. Test the schedule Off/On with nearby times
   while watching fans, temperature and wall power before leaving it unattended.

Rootfs updates on this board are **not atomic**: a failed NAND write or a power
cut needs your saved recovery image and a working recovery method.

---

## The dashboard

Open `http://<miner-ip>/` (press Ctrl+F5 if the browser cached old files).

- **Overview:** live hashrate, accepted/rejected, hottest chip, hardware errors,
  in-browser hashrate and temperature charts, board health, fans, active pool.
- **Hashboards:** per-chain ASIC map (72 per board), temps, hardware errors.
- **Pools & workers:** edit pool failover order; stored passwords are preserved
  unless replaced.
- **Mining settings:** all 142 discovered CGMiner options with readable names,
  descriptions and units; search and group filters. Dangerous/connection-critical
  options are shown but require SSH, not the web form.
- **System & SSH:** daily heater schedule, SSH on/off, settings backup/restore,
  network, system log, reboot.
- **Dev support:** the opt-out 1% slice (below).
- **Firmware updates:** the owner-signed updater.

Charts keep up to 24 h of samples in your browser only. No history daemon or
flash-write loop runs on the miner.

---

## Developer support (the 1% slice)

JMSCNC Heater OS is free and open source. To help fund the work, it can donate a
small, clearly shown slice of each hour's mining to the developer's pool, then
switch straight back to your own pools.

- **On at 1% by default (opt-out).** 1% is about **36 seconds of every hour**.
  The Dev support page shows it plainly, with a one-click **Turn off (0%)** and a
  **0%–5%** slider.
- **Your saved pools are never modified.** During the slice the donation pool is
  added to CGMiner's **runtime** pool list and switched to; when the slice ends it
  switches back and the pool is **removed**. Nothing is persisted, so a reboot or
  a mining restart always comes back to only your own pools.
- **No fallback pool.** If the donation pool is unreachable, CGMiner just keeps
  mining on your pools.
- **It stands down** when your saved config already mines to the donation worker,
  when a non-failover pool strategy (load-balance / round-robin) is set, and
  during a scheduled heater pause.

The slice supports the JMSCNC developer. No personal account details are shown in
the dashboard, and no on-chain address is involved.

If you would rather support the project another way, or on top of the slice:

- Buy Me a Coffee: https://buymeacoffee.com/revjmoney
- Website: https://jmscnc.com
- The track that started this, "Proof of Heat, Whitepaper Foreplay":
  https://soundcloud.com/revjmoney/proof-of-heat-whitepaper

No other donation links, to anyone, are in this firmware.

---

## Daily heater schedule

*System & SSH → Daily mining schedule* gives one **Off** time and one **On**
time per day, with a timezone and an enable checkbox. Off pauses ASIC work using
CGMiner's `ascdisable` API; On resumes only the devices this scheduler paused.
CGMiner stays running so its temperature and fan-control threads keep working.
Overnight windows and daylight saving time are handled. The default schedule is
**disabled**.

This is a software work-pause, **not** a power disconnect or a guaranteed
hashboard power-off. During commissioning, verify that share production stops,
wall power actually drops, fans keep running, and On resumes correctly before you
rely on it unattended.

---

## Helper tools reference

| File | What it does |
|------|--------------|
| `Build.ps1` | One-shot: test, vet, build Windows + ARM binaries, build image, run image tests. |
| `Preview.ps1` | Read-only dashboard preview on your PC against a live miner API. |
| `tools/build_image.py` | Builds the personalized, owner-signed rootfs + update package from your stock archive and backup. Never touches a miner. |
| `tools/image_format.py` | uImage/cpio pack/unpack used by the builder (`test_image_format.py` covers it). |
| `tools/catalog.py` | Extracts documented CGMiner options from Bitmain source into the settings catalog. |
| `tools/recover_ssh.py` | The SSH unlock: temporary root SSH on a stock miner via the pre-signature extraction trick, with automatic cleanup. |
| `mining-research/` | Offline scrypt benchmarking experiment. **Not** applied to the mining daemon; `cgminer` ships unchanged. |

The `l3lab`/`l3lab.cgi` names inside the firmware are kept as internal
identifiers so the backend code and tests stay stable; the user-facing branding
is JMSCNC Heater OS.

---

## Safety and recovery

- **Brick risk is real.** NAND writes are not atomic. Never start an install
  without a saved recovery image **and** a known-working L3+ recovery method.
- The updater writes only rootfs `mtd8` and verifies a NAND readback hash before
  it reports success. It never auto-reboots after a failure.
- Do not use these packages on a different miner model or firmware build.
- Keep `private/update-private.key` safe and off the miner. Keep your settings
  backup private: it contains pool and login secrets.
- The author's own second L3+ (powered off) is **not** flashed
  by this release; hardware qualification on it is still pending.

---

## Licensing and credits

- JMSCNC Heater OS original code (Go backend, dashboard, tooling, scripts, docs):
  **MIT** (see [`LICENSE`](LICENSE)).
- Third-party and GPL components, and what is deliberately **not** redistributed
  here (Bitmain stock firmware, the GPL-3.0 **CGMiner** binary and its source,
  base-system packages): see [`NOTICE.md`](NOTICE.md).
- CGMiner license text: `mining-research/CGMINER-COPYING`.

Built on research into the Bitmain L3+ platform and prior open-firmware work. The
firmware mirror provenance and the stock archive hashes are documented in
`NOTICE.md`.
