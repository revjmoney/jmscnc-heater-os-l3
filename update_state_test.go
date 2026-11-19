package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoverStagedReviewAfterRefresh(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Model: "Antminer L3+", Version: release, Payload: "initramfs.bin.SD", Bytes: 64, SHA256: strings.Repeat("a", 64)}
	raw, _ := json.Marshal(m)
	for name, data := range map[string][]byte{"state.json": []byte(`{"state":"staged","message":"Ready"}`), "manifest.json": raw, "manifest.sig": ed25519.Sign(priv, raw), "initramfs.bin.SD": make([]byte, 64), "recovery-rootfs.bin": make([]byte, 64)} {
		if e := os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	state, e := readUpdateState(dir, pub)
	if e != nil {
		t.Fatal(e)
	}
	if state["staged"] != true || state["backup_ready"] != true || state["manifest"].(Manifest).SHA256 != m.SHA256 {
		t.Fatal("Refresh lost the reviewed manifest or backup readiness")
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), append(raw, ' '), 0600)
	if _, e = readUpdateState(dir, pub); e == nil {
		t.Fatal("Tampered manifest exposed installation controls")
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600)
	os.Remove(filepath.Join(dir, "recovery-rootfs.bin"))
	if _, e = readUpdateState(dir, pub); e == nil {
		t.Fatal("Missing recovery backup exposed installation controls")
	}
}
func TestUpdateStateKeepsFailuresAndProgress(t *testing.T) {
	dir := t.TempDir()
	state, e := readUpdateState(dir, nil)
	if e != nil || state["state"] != "idle" {
		t.Fatal(state, e)
	}
	for _, s := range []string{"preparing", "failed", "queued", "flashing", "complete"} {
		raw, _ := json.Marshal(map[string]any{"state": s, "message": "Visible update status"})
		os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600)
		state, e = readUpdateState(dir, nil)
		if e != nil || state["state"] != s || state["message"] != "Visible update status" || state["staged"] == true {
			t.Fatal(state, e)
		}
	}
}
