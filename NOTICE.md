# Third-party components and licenses

JMSCNC Heater OS (L3+ edition) is the original dashboard, backend, build tooling
and scripts in this repository. Those are MIT licensed (see `LICENSE`). It is
**not** a complete firmware image. To produce a flashable image you combine this
code with parts you supply from your **own** Antminer L3+, which carry their own
licenses and are **not redistributed here**.

## What is in this repository (MIT, redistributable)

- Go backend (`*.go`), dashboard (`web/`), build/recovery tooling (`tools/`),
  PowerShell build/preview scripts, and this documentation.

## What is NOT in this repository (you supply it)

- **Bitmain stock firmware** (`Antminer-L3plus-201907101440-384M.tar.gz`): the
  rootfs, kernel, `cgminer` mining binary, web CGIs and other vendor files.
  These are Bitmain's and are **not redistributable**. You download the stock
  image from a mirror (its SHA-256 is pinned by `tools/build_image.py`) or dump
  it from your own miner, and the builder reads your copy as a donor input.
- **Your miner's configuration and keys** (pool settings, login hashes, SSH host
  key): private to your hardware. Supply them as a settings backup `.tar`.

## GPL and other upstream components (shipped inside the stock image, not here)

- **CGMiner** (the `cgminer` binary and its scrypt driver): **GPL-3.0**. JMSCNC
  Heater OS keeps the stock `cgminer` byte-for-byte and does not modify or
  relink it; it only talks to its local API socket. The CGMiner license text is
  included at `mining-research/CGMINER-COPYING`. Corresponding source for the L3
  driver and the scrypt core is published by Bitmain:
  - https://github.com/bitmaintech/cgminer-ltc
  - https://github.com/bitmaintech/ltc_frimware
  The original scrypt file retains its BSD notice.
- **BusyBox, Dropbear, lighttpd, Linux kernel and other base-system packages**
  inside the stock rootfs each retain their own upstream licenses (GPL-2.0,
  MIT-style, etc.). They are part of the vendor image you supply, not of this
  repository.

## Research-only material (not installed in the firmware)

- `mining-research/scrypt-scratch.patch` and the harness files are a benchmarking
  experiment against the official scrypt source. They are **not** applied to the
  mining daemon in any build (the stock `cgminer` is retained unchanged).

If you redistribute a built image, you are responsible for complying with every
component's license, including providing CGMiner/GPL corresponding source.
