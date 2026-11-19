//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func replaceFile(from, to string) error { return os.Rename(from, to) }
func lockConfig(dir string) (func(), error) {
	os.MkdirAll(dir, 0700)
	f, e := os.OpenFile(filepath.Join(dir, "config.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func partitionSize() (int, error) {
	b, e := os.ReadFile("/proc/mtd")
	if e != nil {
		return 0, e
	}
	parts, e := parseMTD(b)
	if e != nil {
		return 0, e
	}
	root, e := validateL3Root(parts)
	if e != nil {
		return 0, e
	}
	return root.Size, nil
}

func hardwareLayout() (any, error) {
	b, e := os.ReadFile("/proc/mtd")
	if e != nil {
		return nil, e
	}
	parts, parseErr := parseMTD(b)
	var validationErr error
	if parseErr != nil {
		validationErr = parseErr
	} else {
		_, validationErr = validateL3Root(parts)
	}
	reason := ""
	if validationErr != nil {
		reason = validationErr.Error()
	}
	compile, _ := os.ReadFile("/usr/bin/compile_time")
	return map[string]any{"release": release, "compile_time": strings.TrimSpace(string(compile)), "proc_mtd": string(b), "partitions": parts, "layout_matches_verified_l3": validationErr == nil, "validation_error": reason, "expected_root_label": "root", "expected_root_bytes": 0x1400000, "writes_performed": false}, nil
}
func prepareFlash(dir string, imageSize int) error {
	size, e := partitionSize()
	if e != nil {
		return e
	}
	if imageSize > size-256*1024 {
		return errors.New("Image does not fit with a bad-block reserve")
	}
	if e = checkGoodBlocks(imageSize); e != nil {
		return e
	}
	for _, p := range []string{"/usr/sbin/nanddump", "/usr/sbin/nandwrite", "/usr/sbin/flash_eraseall"} {
		if _, e = os.Stat(p); e != nil {
			return fmt.Errorf("Required flash utility unavailable: %s", p)
		}
	}
	var memory syscall.Sysinfo_t
	if e = syscall.Sysinfo(&memory); e != nil {
		return e
	}
	if uint64(memory.Freeram)*uint64(memory.Unit) < uint64(size)*3 {
		return errors.New("Not enough free RAM for update and recovery backup")
	}
	dump := filepath.Join(dir, "partition-dump.bin")
	args := []string{"--omitoob", "-f", dump, "/dev/mtd8"}
	help, _ := run(3*time.Second, "/usr/sbin/nanddump", "--help")
	if bytes.Contains(help, []byte("--bb=")) {
		args = append([]string{"--bb=skipbad"}, args...)
	}
	if _, e = run(90*time.Second, "/usr/sbin/nanddump", args...); e != nil {
		return fmt.Errorf("Cannot create rootfs recovery backup: %w", e)
	}
	f, e := os.Open(dump)
	if e != nil {
		return e
	}
	defer f.Close()
	header := make([]byte, 64)
	if _, e = io.ReadFull(f, header); e != nil {
		return e
	}
	n := int(binary.BigEndian.Uint32(header[12:16]))
	if n < 1 || n > size-64 {
		return errors.New("Current rootfs header is not recoverable")
	}
	b := make([]byte, n+64)
	copy(b, header)
	if _, e = io.ReadFull(f, b[64:]); e != nil {
		return e
	}
	if e = validateImage(b); e != nil {
		return fmt.Errorf("Recovery backup failed CRC checks: %w", e)
	}
	if e = atomicFile(filepath.Join(dir, "recovery-rootfs.bin"), b, 0600); e != nil {
		return e
	}
	return os.Remove(dump)
}
func startFlashWorker(dir string, expectedSHA string) error {
	unlock, e := lockConfig(filepath.Dir(dir))
	if e != nil {
		return e
	}
	defer unlock()
	b, e := os.ReadFile(filepath.Join(dir, "state.json"))
	if e != nil {
		return e
	}
	var state map[string]any
	if json.Unmarshal(b, &state) != nil || state["state"] != "staged" {
		return errors.New("Update is not in the validated staged state")
	}
	if e = atomicFile(filepath.Join(dir, "state.json"), []byte(`{"state":"queued","message":"Starting verified update worker"}`), 0600); e != nil {
		return e
	}
	cmd := exec.Command(os.Args[0], "-flash-worker", dir, "-expected-sha", expectedSHA)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	log, e := os.OpenFile(filepath.Join(dir, "worker.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	cmd.Stdout = log
	cmd.Stderr = log
	return cmd.Start()
}
func deferredReboot() error {
	cmd := exec.Command("/bin/sh", "-c", "sleep 2; exec /sbin/reboot")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
func flashWorker(dir string, expectedSHA string) (err error) {
	unlock, e := lockConfig(filepath.Dir(dir))
	if e != nil {
		return e
	}
	defer unlock()
	lock, e := os.OpenFile(filepath.Join(dir, "install.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("An update worker already exists")
	}
	lock.Close()
	writeState := func(state, message string) {
		b, _ := json.Marshal(map[string]any{"state": state, "message": message, "time": time.Now().Unix()})
		atomicFile(filepath.Join(dir, "state.json"), b, 0600)
	}
	defer func() {
		if err != nil {
			writeState("failed", err.Error())
		}
		os.Remove(filepath.Join(dir, "install.lock"))
	}()
	public, e := os.ReadFile("/etc/l3lab/update-public.key")
	if e != nil {
		return e
	}
	manifest, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		return e
	}
	signature, e := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if e != nil {
		return e
	}
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, manifest, signature) {
		return errors.New("Staged update signature failed")
	}
	var m Manifest
	if e = json.Unmarshal(manifest, &m); e != nil {
		return e
	}
	image, e := os.ReadFile(filepath.Join(dir, "initramfs.bin.SD"))
	if e != nil {
		return e
	}
	if len(expectedSHA) != 64 || m.Model != "Antminer L3+" || m.Payload != "initramfs.bin.SD" || m.Bytes != len(image) || m.SHA256 != hash(image) || m.SHA256 != expectedSHA {
		return errors.New("Staged update differs from signed manifest")
	}
	if e = validateImage(image); e != nil {
		return e
	}
	size, e := partitionSize()
	if e != nil || len(image) > size-256*1024 {
		return errors.New("Rootfs partition capacity check failed")
	}
	if e = checkGoodBlocks(len(image)); e != nil {
		return e
	}
	backup, e := os.ReadFile(filepath.Join(dir, "recovery-rootfs.bin"))
	if e != nil {
		return e
	}
	if e = validateImage(backup); e != nil {
		return e
	}
	writeState("stopping", "Stopping the mining daemon before writing the root filesystem")
	// During a temporary bootstrap the already-running stock watchdog has
	// parsed its old loop. Restart it so init reloads the patched lock-aware
	// script. The new watchdog will see install.lock and leave CGMiner stopped.
	run(3*time.Second, "/usr/bin/killall", "monitorcg")
	if _, e = run(15*time.Second, "/etc/init.d/cgminer.sh", "stop"); e != nil {
		return e
	}
	// The firmware builder patches monitorcg to respect install.lock, so the
	// watchdog stays alive but does not restart CGMiner during this operation.
	writeState("flashing", "Writing the validated rootfs; keep power connected")
	if _, e = run(90*time.Second, "/usr/sbin/flash_eraseall", "/dev/mtd8"); e != nil {
		return fmt.Errorf("Rootfs erase failed; use recovery backup: %w", e)
	}
	if _, e = run(90*time.Second, "/usr/sbin/nandwrite", "-p", "/dev/mtd8", filepath.Join(dir, "initramfs.bin.SD")); e != nil {
		return fmt.Errorf("Rootfs write failed; use recovery backup: %w", e)
	}
	// Read back through NAND-aware tooling, not a raw MTD read.
	dump := filepath.Join(dir, "verify-dump.bin")
	args := []string{"--omitoob", "-f", dump, "/dev/mtd8"}
	help, _ := run(3*time.Second, "/usr/sbin/nanddump", "--help")
	if bytes.Contains(help, []byte("--bb=")) {
		args = append([]string{"--bb=skipbad"}, args...)
	}
	if _, e = run(90*time.Second, "/usr/sbin/nanddump", args...); e != nil {
		return e
	}
	f, e := os.Open(dump)
	if e != nil {
		return e
	}
	got := make([]byte, len(image))
	_, e = io.ReadFull(f, got)
	f.Close()
	if e != nil || hash(got) != hash(image) {
		return errors.New("Rootfs readback mismatch; use recovery backup")
	}
	os.Remove(dump)
	syscall.Sync()
	writeState("complete", "Rootfs readback verified. Reboot to start the new version.")
	return nil
}

// MEMGETBADBLOCK is the read-only Linux MTD ioctl _IOW('M', 11, loff_t).
// Count usable erase blocks instead of assuming every byte of mtd8 is usable.
func checkGoodBlocks(imageSize int) error {
	b, e := os.ReadFile("/proc/mtd")
	if e != nil {
		return e
	}
	size, erase := 0, 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "mtd8:" {
			n, err := strconv.ParseInt(f[1], 16, 32)
			if err != nil {
				return err
			}
			x, err := strconv.ParseInt(f[2], 16, 32)
			if err != nil {
				return err
			}
			size, erase = int(n), int(x)
		}
	}
	if size <= 0 || erase < 4096 || erase > 1024*1024 || size%erase != 0 {
		return errors.New("Invalid NAND erase block geometry")
	}
	fd, e := os.Open("/dev/mtd8")
	if e != nil {
		return e
	}
	defer fd.Close()
	good := 0
	const memGetBadBlock = uintptr((1 << 30) | (8 << 16) | ('M' << 8) | 11)
	for offset := int64(0); offset < int64(size); offset += int64(erase) {
		ret, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), memGetBadBlock, uintptr(unsafe.Pointer(&offset)))
		if errno != 0 {
			return fmt.Errorf("Cannot check NAND bad blocks: %v", errno)
		}
		if ret == 0 {
			good += erase
		}
	}
	if imageSize > good-2*erase {
		return errors.New("Image does not fit the usable NAND blocks with a two-block reserve")
	}
	return nil
}
