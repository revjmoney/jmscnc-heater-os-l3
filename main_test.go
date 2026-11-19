package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	return &App{ConfigDir: dir, StateDir: dir, Preview: true}
}
func testConfig() map[string]any {
	return map[string]any{"pools": []any{map[string]any{"url": "stratum+tcp://pool.example:3333", "user": "worker", "pass": "private-value"}}, "bitmain-freq": "384", "api-listen": true}
}
func TestParseAPI(t *testing.T) {
	legacy, e := parseAPI([]byte("STATUS=S,Msg=OK|VERSION,CGMiner=4.9.0,Type=Antminer L3+|SUMMARY,Elapsed=10,GHS 5s=380|POOL=0,Status=Alive|"))
	if e != nil || text(first(legacy, "VERSION")["Type"]) != "Antminer L3+" || number(first(legacy, "SUMMARY")["Elapsed"]) != 10 || text(first(legacy, "POOLS")["Status"]) != "Alive" {
		t.Fatalf("Legacy section headers: %v %v", legacy, e)
	}
	data, e := parseAPI([]byte(`STATUS=S,When=1,Msg=OK|POOLS=0,URL=stratum+tcp://pool.example:3333,User=a\,b\|c\=d\\e|` + "\x00"))
	if e != nil {
		t.Fatal(e)
	}
	if got := text(first(data, "POOLS")["User"]); got != "a,b|c=d\\e" {
		t.Fatalf("Escaped API data: %q", got)
	}
	if _, e = parseAPI([]byte(`STATUS=E,Msg=Access denied|`)); e == nil {
		t.Fatal("API errors must propagate")
	}
	if _, e = parseAPI([]byte(`{"VERSION":[{"Type":"Antminer L3+"}]}`)); e != nil {
		t.Fatal(e)
	}
}
func TestSecretPreservation(t *testing.T) {
	a := testApp(t)
	current := testConfig()
	candidate := cloneRedacted(current)
	if text(obj(candidate["pools"].([]any)[0])["pass"]) != keepPassword {
		t.Fatal("Secret exposed")
	}
	if text(obj(current["pools"].([]any)[0])["pass"]) != "private-value" {
		t.Fatal("Redaction mutated original")
	}
	candidate["bitmain-freq"] = "400"
	if e := a.validateConfig(candidate, current); e != nil {
		t.Fatal(e)
	}
	if text(obj(candidate["pools"].([]any)[0])["pass"]) != "private-value" {
		t.Fatal("Saved secret lost")
	}
	bad := cloneRedacted(current)
	bad["monitor"] = "sh -c malicious"
	if e := a.validateConfig(bad, current); e == nil {
		t.Fatal("Shell command accepted")
	}
	bad = cloneRedacted(current)
	obj(bad["pools"].([]any)[0])["url"] = "file:///etc/shadow"
	if e := a.validateConfig(bad, current); e == nil {
		t.Fatal("Unsupported URL accepted")
	}
	bad = cloneRedacted(current)
	bad["bitmain-freq"] = "NaN"
	if e := a.validateConfig(bad, current); e == nil {
		t.Fatal("Nonfinite frequency accepted")
	}
}
func TestConfigRevisionAndBoolean(t *testing.T) {
	a := testApp(t)
	current := testConfig()
	current["verbose"] = true
	b, _ := json.Marshal(current)
	path := filepath.Join(a.ConfigDir, "cgminer.conf")
	os.WriteFile(path, b, 0600)
	candidate := cloneRedacted(current)
	candidate["verbose"] = false
	body, _ := json.Marshal(map[string]any{"revision": "stale", "config": candidate})
	r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if _, e := a.saveConfig(r); e == nil {
		t.Fatal("Stale revision accepted")
	}
	body, _ = json.Marshal(map[string]any{"revision": hash(b), "config": candidate})
	r = httptest.NewRequest("POST", "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if _, e := a.saveConfig(r); e != nil {
		t.Fatal(e)
	}
	saved, raw, e := a.config()
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := saved["verbose"]; ok {
		t.Fatal("False flag must be omitted")
	}
	if !bytes.Contains(raw, []byte("private-value")) {
		t.Fatal("Password lost")
	}
	prior, _ := os.ReadFile(path + ".l3lab.bak")
	if !bytes.Equal(prior, b) {
		t.Fatal("Previous configuration backup differs")
	}
}
func TestNetworkInjection(t *testing.T) {
	n := map[string]string{"hostname": "L3-3boards", "dhcp": "true"}
	if _, e := validateNetwork(n); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{"$(touch /tmp/pwned)", "x'; reboot; '", "x\nreboot"} {
		n["hostname"] = value
		if _, e := validateNetwork(n); e == nil {
			t.Fatal("Shell injection accepted")
		}
	}
	n = map[string]string{"hostname": "miner", "dhcp": "false", "ipaddress": "192.168.1.50", "gateway": "192.168.1.1", "netmask": "255.0.255.0"}
	if _, e := validateNetwork(n); e == nil {
		t.Fatal("Noncontiguous mask accepted")
	}
	n["netmask"] = "255.255.255.0"
	if _, e := validateNetwork(n); e != nil {
		t.Fatal(e)
	}
}
func TestWebGuards(t *testing.T) {
	a := testApp(t)
	r := httptest.NewRequest(http.MethodPost, "/?action=reboot", bytes.NewBufferString(`{"confirm":true}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("Preview allowed a write")
	}
	a.Preview = false
	w = httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/?action=settings", nil))
	if w.Code != 403 {
		t.Fatal("Unauthenticated firmware access allowed")
	}
	token, e := a.token()
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("X-L3-CSRF", token)
	r.Header.Set("Origin", "http://attacker.invalid")
	if e = a.writable(r); e == nil {
		t.Fatal("Cross-origin write allowed")
	}
}
func fixtureImage() []byte {
	archive := []byte("070701" + strings.Repeat("00000000", 11) + "0000000b00000000" + "TRAILER!!!\x00\x00\x00\x00")
	payload := gzipBytes(archive)
	h := make([]byte, 64)
	binary.BigEndian.PutUint32(h[:4], 0x27051956)
	binary.BigEndian.PutUint32(h[12:16], uint32(len(payload)))
	binary.BigEndian.PutUint32(h[24:28], crc32.ChecksumIEEE(payload))
	copy(h[28:32], []byte{5, 2, 3, 1})
	binary.BigEndian.PutUint32(h[4:8], crc32.ChecksumIEEE(h))
	return append(h, payload...)
}
func gzipBytes(b []byte) []byte {
	var out bytes.Buffer
	g := gzip.NewWriter(&out)
	g.Write(b)
	g.Close()
	return out.Bytes()
}
func updateFixture(t *testing.T, image []byte, model string, priv ed25519.PrivateKey, extra bool) []byte {
	t.Helper()
	m := Manifest{Model: model, Version: "test", Payload: "initramfs.bin.SD", SHA256: hash(image), Bytes: len(image)}
	manifest, _ := json.Marshal(m)
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, row := range []struct {
		Name string
		Data []byte
	}{{"manifest.json", manifest}, {"manifest.sig", ed25519.Sign(priv, manifest)}, {"initramfs.bin.SD", image}} {
		tw.WriteHeader(&tar.Header{Name: row.Name, Mode: 0600, Size: int64(len(row.Data))})
		tw.Write(row.Data)
	}
	if extra {
		tw.WriteHeader(&tar.Header{Name: "../outside", Mode: 0600, Size: 1})
		tw.Write([]byte("x"))
	}
	tw.Close()
	return gzipBytes(out.Bytes())
}
func TestSignedUpdate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	image := fixtureImage()
	data := updateFixture(t, image, "Antminer L3+", priv, false)
	if _, e := readUpdate(bytes.NewReader(data), pub); e != nil {
		t.Fatal(e)
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := readUpdate(bytes.NewReader(data), wrong); e == nil {
		t.Fatal("Wrong owner key accepted")
	}
	if _, e := readUpdate(bytes.NewReader(updateFixture(t, image, "Antminer S9", priv, false)), pub); e == nil {
		t.Fatal("Wrong model accepted")
	}
	if _, e := readUpdate(bytes.NewReader(updateFixture(t, image, "Antminer L3+", priv, true)), pub); e == nil {
		t.Fatal("Unexpected archive path accepted")
	}
	damaged := append([]byte(nil), image...)
	damaged[len(damaged)-1] ^= 1
	if e := validateImage(damaged); e == nil {
		t.Fatal("Corrupted rootfs accepted")
	}
	damaged = append([]byte(nil), image...)
	damaged[8] ^= 1
	if e := validateImage(damaged); e == nil {
		t.Fatal("Corrupted header accepted")
	}
}
func TestDailySchedule(t *testing.T) {
	s := Schedule{Enabled: true, Off: "16:00", On: "21:00", Timezone: "America/New_York"}
	for _, row := range []struct {
		UTC    string
		Paused bool
	}{{"2026-07-05T19:59:00Z", false}, {"2026-07-05T20:00:00Z", true}, {"2026-07-06T01:00:00Z", false}, {"2026-01-05T20:59:00Z", false}, {"2026-01-05T21:00:00Z", true}, {"2026-01-06T02:00:00Z", false}} {
		now, _ := time.Parse(time.RFC3339, row.UTC)
		p, e := shouldPause(s, now)
		if e != nil || p != row.Paused {
			t.Fatalf("%s: %v %v", row.UTC, p, e)
		}
	}
	s.Off = "22:00"
	s.On = "06:00"
	for _, row := range []struct {
		UTC    string
		Paused bool
	}{{"2026-07-06T02:00:00Z", true}, {"2026-07-06T09:59:00Z", true}, {"2026-07-06T10:00:00Z", false}} {
		now, _ := time.Parse(time.RFC3339, row.UTC)
		p, e := shouldPause(s, now)
		if e != nil || p != row.Paused {
			t.Fatalf("Overnight %s: %v %v", row.UTC, p, e)
		}
	}
	s.Off = s.On
	if e := validateSchedule(s); e == nil {
		t.Fatal("Equal times accepted")
	}
	s.Off = "25:00"
	if e := validateSchedule(s); e == nil {
		t.Fatal("Invalid time accepted")
	}
}

func TestActualBuiltFirmware(t *testing.T) {
	image, e := os.ReadFile("firmware/l3lab-" + release + "-rootfs.bin")
	if os.IsNotExist(e) {
		t.Skip("Build personalized firmware first")
	}
	if e != nil {
		t.Fatal(e)
	}
	if e = validateImage(image); e != nil {
		t.Fatal(e)
	}
	public, e := os.ReadFile("private/update-public.key")
	if e != nil {
		t.Fatal(e)
	}
	archive, e := os.ReadFile("firmware/l3lab-" + release + "-update.tar.gz")
	if e != nil {
		t.Fatal(e)
	}
	update, e := readUpdate(bytes.NewReader(archive), public)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(update.Image, image) {
		t.Fatal("Signed package differs from raw artifact")
	}
}
