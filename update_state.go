package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Return the same reviewed manifest after navigation or a browser reload.
// A state flag alone must never make an unsigned package appear installable.
func readUpdateState(dir string, public []byte) (map[string]any, error) {
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if os.IsNotExist(err) {
		return map[string]any{"state": "idle"}, nil
	}
	if err != nil {
		return nil, err
	}
	var state map[string]any
	if err = json.Unmarshal(b, &state); err != nil {
		return nil, err
	}
	if state["state"] != "staged" {
		return state, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if err != nil {
		return nil, err
	}
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, raw, sig) {
		return nil, errors.New("Staged manifest signature failed; validate the update again")
	}
	var manifest Manifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(manifest.SHA256)
	if err != nil || len(digest) != 32 || manifest.Model != "Antminer L3+" || manifest.Payload != "initramfs.bin.SD" || manifest.Bytes < 64 || manifest.Bytes > maxRootfs {
		return nil, errors.New("Staged manifest is invalid")
	}
	backup, err := os.Stat(filepath.Join(dir, "recovery-rootfs.bin"))
	if err != nil {
		return nil, err
	}
	image, err := os.Stat(filepath.Join(dir, "initramfs.bin.SD"))
	if err != nil {
		return nil, err
	}
	if !backup.Mode().IsRegular() || backup.Size() < 64 || backup.Size() > maxRootfs || !image.Mode().IsRegular() || image.Size() != int64(manifest.Bytes) {
		return nil, errors.New("Staged image or recovery backup is incomplete")
	}
	state["staged"] = true
	state["manifest"] = manifest
	state["backup_ready"] = true
	return state, nil
}
