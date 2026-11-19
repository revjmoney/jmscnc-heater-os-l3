package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/cgi"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var assets embed.FS

const release = "0.1.3"
const maxRootfs = 32 * 1024 * 1024
const keepPassword = "__KEEP_PASSWORD__"

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var helpPattern = regexp.MustCompile(`(?m)^\s+--([a-z0-9-]+)([^\r\n]*)`)
var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}$`)

type Option struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Kind        string   `json:"kind"`
	Description string   `json:"description"`
	Group       string   `json:"group"`
	Source      string   `json:"source"`
	ReadOnly    bool     `json:"read_only"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	Available   bool     `json:"available"`
}
type App struct {
	Host, ConfigDir, StateDir, CGMiner string
	Preview                            bool
	Demo                               bool
	mu                                 sync.Mutex
}
type Manifest struct {
	Model      string `json:"model"`
	Version    string `json:"version"`
	Payload    string `json:"payload"`
	SHA256     string `json:"sha256"`
	Bytes      int    `json:"bytes"`
	BaseSHA256 string `json:"base_sha256"`
	Validation string `json:"validation"`
}
type Update struct {
	Manifest                      Manifest
	RawManifest, Signature, Image []byte
}
type failure struct {
	Code    int
	Message string
}

func (e failure) Error() string           { return e.Message }
func fail(code int, message string) error { return failure{code, message} }
func hash(b []byte) string                { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func obj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func text(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func number(v any) float64 { n, _ := strconv.ParseFloat(strings.TrimSpace(text(v)), 64); return n }
func atomicFile(path string, b []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".l3lab-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return replaceFile(name, path)
}
func run(timeout time.Duration, command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	return cmd.CombinedOutput()
}
func (a *App) token() (string, error) {
	if err := os.MkdirAll(a.StateDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(a.StateDir, "csrf")
	if b, e := os.ReadFile(path); e == nil && len(b) == 64 {
		return string(b), nil
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	s := hex.EncodeToString(b)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(e) {
		v, e := os.ReadFile(path)
		return string(v), e
	}
	if e != nil {
		return "", e
	}
	_, e = f.WriteString(s)
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	return s, e
}
func splitAPI(s string, delimiter byte) []string {
	// Preserve escaped delimiters until the final value is decoded.
	var result []string
	start := 0
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == delimiter {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	return append(result, s[start:])
}
func unescapeAPI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
func parseAPI(raw []byte) (map[string][]map[string]any, error) {
	raw = bytes.TrimRight(raw, "\x00\r\n ")
	if len(raw) == 0 {
		return nil, errors.New("Empty mining API response")
	}
	out := map[string][]map[string]any{}
	if raw[0] == '{' {
		var jsonData map[string]json.RawMessage
		if e := json.Unmarshal(raw, &jsonData); e != nil {
			return nil, fmt.Errorf("Malformed mining API JSON: %w", e)
		}
		for k, v := range jsonData {
			var rows []map[string]any
			if json.Unmarshal(v, &rows) == nil {
				out[k] = rows
			}
		}
	} else {
		for _, record := range splitAPI(string(raw), '|') {
			if record == "" {
				continue
			}
			row := map[string]any{}
			kind := ""
			for _, field := range splitAPI(record, ',') {
				pair := splitAPI(field, '=')
				if len(pair) < 2 {
					if kind == "" {
						kind = unescapeAPI(field)
					}
					continue
				}
				k := unescapeAPI(pair[0])
				v := unescapeAPI(strings.Join(pair[1:], "="))
				if kind == "" {
					kind = k
				}
				row[k] = v
			}
			if kind != "" {
				// Legacy text replies name the version section CGMiner and the
				// pool section POOL; JSON replies use VERSION and POOLS.
				if kind == "CGMiner" {
					kind = "VERSION"
				}
				if kind == "POOL" {
					kind = "POOLS"
				}
				out[kind] = append(out[kind], row)
			}
		}
	}
	if rows := out["STATUS"]; len(rows) > 0 && text(rows[0]["STATUS"]) == "E" {
		return nil, errors.New(text(rows[0]["Msg"]))
	}
	return out, nil
}
func (a *App) api(command string) (map[string][]map[string]any, error) {
	allowed := map[string]bool{"version": true, "summary": true, "stats": true, "pools": true, "devs": true}
	if !allowed[command] {
		return nil, errors.New("API command is not read-only")
	}
	c, e := net.DialTimeout("tcp", a.Host, 2*time.Second)
	if e != nil {
		return nil, fmt.Errorf("Mining API unavailable: %w", e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = c.Write([]byte(command)); e != nil {
		return nil, e
	}
	var data []byte
	buf := make([]byte, 4096)
	for len(data) <= 1024*1024 {
		n, err := c.Read(buf)
		data = append(data, buf[:n]...)
		if i := bytes.IndexByte(data, 0); i >= 0 {
			data = data[:i]
			break
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("Mining API response exceeds limit")
	}
	return parseAPI(data)
}
func first(data map[string][]map[string]any, key string) map[string]any {
	if v := data[key]; len(v) > 0 {
		return v[0]
	}
	return map[string]any{}
}
func nullablePositive(v any) any {
	n := number(v)
	if n <= 0 {
		return nil
	}
	return n
}
func (a *App) status() (any, error) {
	commands := []string{"version", "summary", "stats", "pools"}
	results := make([]map[string][]map[string]any, 4)
	errs := make([]error, 4)
	var wg sync.WaitGroup
	for i, c := range commands {
		wg.Add(1)
		go func(i int, c string) { defer wg.Done(); results[i], errs[i] = a.api(c) }(i, c)
	}
	wg.Wait()
	if errs[0] != nil {
		return nil, errs[0]
	}
	version := first(results[0], "VERSION")
	if text(version["Type"]) != "Antminer L3+" {
		return nil, errors.New("This dashboard requires an Antminer L3+")
	}
	summary := first(results[1], "SUMMARY")
	stats := map[string]any{}
	for _, row := range results[2]["STATS"] {
		for k, v := range row {
			stats[k] = v
		}
	}
	boards := []map[string]any{}
	for i := 1; i <= 4; i++ {
		id := strconv.Itoa(i)
		chips := int(number(stats["chain_acn"+id]))
		temp := nullablePositive(stats["temp"+id])
		chipTemp := nullablePositive(stats["temp2_"+id])
		state := "healthy"
		if chips == 0 {
			state = "absent"
		} else if chips < 72 {
			state = "partial"
		} else if temp == nil && chipTemp == nil {
			state = "sensor unavailable"
		}
		boards = append(boards, map[string]any{"id": i, "chips": chips, "expected_chips": 72, "temperature": temp, "chip_temperature": chipTemp, "state": state, "hashrate": nullablePositive(stats["chain_rate"+id]), "hardware_errors": number(stats["chain_hw"+id]), "chip_status": text(stats["chain_acs"+id])})
	}
	pools := []map[string]any{}
	for _, p := range results[3]["POOLS"] {
		pools = append(pools, map[string]any{"id": number(p["POOL"]), "status": text(p["Status"]), "priority": number(p["Priority"]), "url": text(p["URL"]), "worker": text(p["User"]), "active": strings.EqualFold(text(p["Stratum Active"]), "true"), "accepted": number(p["Accepted"]), "rejected": number(p["Rejected"]), "last_share": number(p["Last Share Time"]), "difficulty": number(p["Stratum Difficulty"])})
	}
	warnings := []string{}
	for i, e := range errs {
		if e != nil {
			warnings = append(warnings, commands[i]+": "+e.Error())
		}
	}
	h := summary["GHS 5s"]
	if h == nil {
		h = summary["MHS 5s"]
	}
	av := summary["GHS av"]
	if av == nil {
		av = summary["MHS av"]
	}
	return map[string]any{"time": time.Now().Unix(), "version": version, "hashrate": nullablePositive(h), "average_hashrate": nullablePositive(av), "unit": "MH/s", "elapsed": number(summary["Elapsed"]), "accepted": number(summary["Accepted"]), "rejected": number(summary["Rejected"]), "stale": number(summary["Stale"]), "hardware_errors": number(summary["Hardware Errors"]), "rejected_percent": number(summary["Pool Rejected%"]), "frequency": nullablePositive(stats["frequency"]), "fans": []any{nullablePositive(stats["fan1"]), nullablePositive(stats["fan2"])}, "boards": boards, "pools": pools, "warnings": warnings, "raw": map[string]any{"summary": summary, "stats": stats}, "preview": a.Preview}, nil
}
func (a *App) config() (map[string]any, []byte, error) {
	path := filepath.Join(a.ConfigDir, "cgminer.conf")
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, e
	}
	if len(b) > 256*1024 {
		return nil, nil, errors.New("Config too large")
	}
	var v map[string]any
	if e = json.Unmarshal(b, &v); e != nil {
		return nil, nil, e
	}
	return v, b, nil
}
func cloneRedacted(config map[string]any) map[string]any {
	b, _ := json.Marshal(config)
	out := map[string]any{}
	json.Unmarshal(b, &out)
	if pools, ok := out["pools"].([]any); ok {
		for _, p := range pools {
			if m, ok := p.(map[string]any); ok {
				if _, has := m["pass"]; has {
					m["pass"] = keepPassword
				}
			}
		}
	}
	for _, k := range []string{"pass", "userpass"} {
		if _, ok := out[k]; ok {
			out[k] = keepPassword
		}
	}
	return out
}
func (a *App) options(config map[string]any) []Option {
	b, _ := assets.ReadFile("web/options.json")
	var options []Option
	json.Unmarshal(b, &options)
	byName := map[string]int{}
	for i, o := range options {
		byName[o.Name] = i
	}
	if !a.Preview {
		b, e := os.ReadFile(filepath.Join(a.StateDir, "cgminer-help"))
		if e != nil {
			b, e = run(3*time.Second, a.CGMiner, "--help")
			if e == nil {
				atomicFile(filepath.Join(a.StateDir, "cgminer-help"), b, 0600)
			}
		}
		if e == nil {
			for _, m := range helpPattern.FindAllStringSubmatch(string(b), -1) {
				name := m[1]
				if i, ok := byName[name]; ok {
					options[i].Available = true
					options[i].Source = "running binary"
				} else {
					kind := "boolean"
					if strings.Contains(m[2], "<arg>") {
						kind = "string"
					}
					options = append(options, Option{Name: name, Kind: kind, Description: strings.TrimSpace(m[2]), Group: optionGroup(name), Source: "running binary", Available: true})
					byName[name] = len(options) - 1
				}
			}
		}
	}
	for k, v := range config {
		if !keyPattern.MatchString(k) || k == "pools" {
			continue
		}
		if i, ok := byName[k]; ok {
			options[i].Available = true
			if a.Preview {
				options[i].Source = "backup configuration"
			}
		} else {
			kind := "string"
			if _, ok := v.(bool); ok {
				kind = "boolean"
			}
			options = append(options, Option{Name: k, Kind: kind, Description: "Present in the saved configuration. Exact semantics depend on this firmware build.", Group: optionGroup(k), Source: "existing configuration", Available: true})
		}
	}
	for i := range options {
		if options[i].Name == "monitor" || options[i].Name == "include" || options[i].Name == "config" || options[i].Name == "version-file" || options[i].Name == "default-config" {
			options[i].ReadOnly = true
		}
	}
	// Descriptions are presentation metadata only: raw keys, values, parser
	// bounds and write permissions still come from the existing option catalog.
	helpBytes, _ := assets.ReadFile("web/settings-help.json")
	help := map[string][2]string{}
	json.Unmarshal(helpBytes, &help)
	for i := range options {
		if entry, ok := help[options[i].Name]; ok {
			options[i].Label = entry[0]
			options[i].Description = entry[1]
		} else {
			options[i].Label = "Vendor setting: " + strings.ReplaceAll(options[i].Name, "-", " ")
		}
	}
	sort.Slice(options, func(i, j int) bool { return options[i].Name < options[j].Name })
	return options
}
func optionGroup(k string) string {
	if strings.HasPrefix(k, "bitmain-") {
		return "Hardware"
	}
	if strings.HasPrefix(k, "api-") {
		return "API"
	}
	if strings.HasPrefix(k, "log") || strings.Contains(k, "debug") || k == "verbose" || strings.Contains(k, "quiet") {
		return "Diagnostics"
	}
	if strings.HasPrefix(k, "sched-") {
		return "Schedule"
	}
	return "Mining"
}
func (a *App) settings() (any, error) {
	cfg, b, e := a.config()
	if e != nil {
		return nil, e
	}
	token, e := a.token()
	if e != nil {
		return nil, e
	}
	ssh, _ := os.ReadFile(filepath.Join(a.ConfigDir, "dropbear"))
	network, _ := os.ReadFile(filepath.Join(a.ConfigDir, "network.conf"))
	metadata, _ := os.ReadFile("/etc/l3lab/build.json")
	var build any
	json.Unmarshal(metadata, &build)
	return map[string]any{"config": cloneRedacted(cfg), "revision": hash(b), "options": a.options(cfg), "csrf": token, "preview": a.Preview, "ssh_enabled": strings.Contains(string(ssh), "NO_START=0"), "network": parseNetwork(network), "build": build, "release": release}, nil
}
func (a *App) writable(r *http.Request) error {
	if a.Preview {
		return fail(403, "Preview is read-only; changes belong on the miner after installation.")
	}
	if r.Method != "POST" {
		return fail(405, "Use POST")
	}
	token, e := a.token()
	if e != nil {
		return e
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-L3-CSRF")), []byte(token)) != 1 {
		return fail(403, "Invalid request token; reload the dashboard.")
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, e := url.Parse(origin)
		if e != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
			return fail(403, "Cross-origin request rejected")
		}
	}
	v, e := a.api("version")
	if e != nil {
		// A completed updater has stopped CGMiner. A reboot is allowed only
		// after the worker recorded successful NAND readback verification.
		if r.URL.Query().Get("action") == "reboot" {
			b, _ := os.ReadFile(filepath.Join(a.StateDir, "staged", "state.json"))
			var state map[string]any
			if json.Unmarshal(b, &state) == nil && state["state"] == "complete" {
				return nil
			}
		}
		return e
	}
	if text(first(v, "VERSION")["Type"]) != "Antminer L3+" {
		return fail(409, "Model mismatch")
	}
	return nil
}
func decodeJSON(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return fail(415, "Expected application/json")
	}
	d := json.NewDecoder(io.LimitReader(r.Body, 256*1024+1))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return fail(400, "Invalid JSON: "+e.Error())
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fail(400, "Trailing JSON data")
	}
	return nil
}
func (a *App) validateConfig(candidate, current map[string]any) error {
	if len(candidate) > 400 {
		return fail(400, "Too many settings")
	}
	known := map[string]Option{}
	for _, o := range a.options(current) {
		known[o.Name] = o
	}
	for k, o := range known {
		if o.ReadOnly {
			if old, exists := current[k]; exists {
				before, _ := json.Marshal(old)
				after, _ := json.Marshal(candidate[k])
				if !bytes.Equal(before, after) {
					return fail(400, "Setting requires SSH: "+k)
				}
			}
		}
	}
	for k, v := range candidate {
		if k == "pools" {
			continue
		}
		if !keyPattern.MatchString(k) {
			return fail(400, "Invalid setting name")
		}
		o, exists := known[k]
		if !exists || !o.Available {
			return fail(400, "Option not advertised by this binary or present in its config: "+k)
		}
		old, _ := json.Marshal(current[k])
		value, _ := json.Marshal(v)
		if bytes.Equal(old, value) {
			continue
		}
		if o.ReadOnly {
			return fail(400, "Setting requires SSH: "+k)
		}
		if o.Kind == "boolean" {
			if _, ok := v.(bool); !ok {
				return fail(400, k+" must be a boolean")
			}
			continue
		}
		s, ok := v.(string)
		if !ok {
			return fail(400, k+" must be a string (CGMiner config syntax)")
		}
		if len(s) > 8192 || strings.ContainsRune(s, 0) {
			return fail(400, "Invalid setting value: "+k)
		}
		if o.Kind == "integer" || o.Kind == "number" {
			n, e := strconv.ParseFloat(s, 64)
			if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || (o.Kind == "integer" && n != float64(int64(n))) || (o.Min != nil && n < *o.Min) || (o.Max != nil && n > *o.Max) {
				return fail(400, "Value outside source parser range: "+k)
			}
		}
	}
	oldPools, _ := current["pools"].([]any)
	pools, ok := candidate["pools"].([]any)
	if !ok || len(pools) == 0 || len(pools) > 16 {
		return fail(400, "Configure 1–16 pools")
	}
	for i, p := range pools {
		m, ok := p.(map[string]any)
		if !ok {
			return fail(400, "Invalid pool object")
		}
		for k, v := range m {
			if k != "url" && k != "user" && k != "pass" && k != "quota" {
				return fail(400, "Unknown pool field: "+k)
			}
			if _, ok := v.(string); !ok {
				return fail(400, "Pool values must be strings")
			}
			if len(text(v)) > 2048 || strings.ContainsAny(text(v), "\x00\r\n") {
				return fail(400, "Invalid pool value")
			}
		}
		u := text(m["url"])
		oldURL := ""
		if i < len(oldPools) {
			oldURL = text(obj(oldPools[i])["url"])
		}
		if u != oldURL {
			parsed, e := url.Parse(u)
			if e != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Scheme != "stratum+tcp" && parsed.Scheme != "stratum+ssl" && parsed.Scheme != "http" && parsed.Scheme != "https") {
				return fail(400, "Use a valid pool URL with a supported scheme")
			}
		}
		if text(m["pass"]) == keepPassword {
			if i >= len(oldPools) {
				return fail(400, "New pools need an explicit password")
			}
			m["pass"] = obj(oldPools[i])["pass"]
		}
	}
	for _, k := range []string{"pass", "userpass"} {
		if text(candidate[k]) == keepPassword {
			candidate[k] = current[k]
		}
	}
	return nil
}
func (a *App) saveConfig(r *http.Request) (any, error) {
	var in struct {
		Revision string         `json:"revision"`
		Config   map[string]any `json:"config"`
	}
	if e := decodeJSON(r, &in); e != nil {
		return nil, e
	}
	unlock, e := lockConfig(a.StateDir)
	if e != nil {
		return nil, e
	}
	defer unlock()
	current, b, e := a.config()
	if e != nil {
		return nil, e
	}
	if hash(b) != in.Revision {
		return nil, fail(409, "Configuration changed. Reload before saving.")
	}
	if e = a.validateConfig(in.Config, current); e != nil {
		return nil, e
	}
	// CGMiner's no-argument flags are disabled by omitting them, not JSON false.
	for _, o := range a.options(current) {
		if o.Kind == "boolean" && in.Config[o.Name] == false {
			delete(in.Config, o.Name)
		}
	}
	out, e := json.MarshalIndent(in.Config, "", "  ")
	if e != nil {
		return nil, e
	}
	out = append(out, '\n')
	if e = atomicFile(filepath.Join(a.ConfigDir, "cgminer.conf.l3lab.bak"), b, 0600); e != nil {
		return nil, e
	}
	if e = atomicFile(filepath.Join(a.ConfigDir, "cgminer.conf"), out, 0600); e != nil {
		return nil, e
	}
	return map[string]any{"saved": true, "revision": hash(out), "restart_required": true}, nil
}
func parseNetwork(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			switch k {
			case "dhcp", "hostname", "ipaddress", "netmask", "gateway", "dnsservers":
				out[k] = strings.Trim(v, "\"' ")
			}
		}
	}
	return out
}
func validateNetwork(n map[string]string) ([]byte, error) {
	allowed := map[string]bool{"dhcp": true, "hostname": true, "ipaddress": true, "netmask": true, "gateway": true, "dnsservers": true}
	for k := range n {
		if !allowed[k] {
			return nil, fail(400, "Unknown network setting")
		}
	}
	if n["dhcp"] != "true" && n["dhcp"] != "false" {
		return nil, fail(400, "DHCP must be true or false")
	}
	if !hostPattern.MatchString(n["hostname"]) {
		return nil, fail(400, "Invalid hostname")
	}
	if n["dhcp"] == "false" {
		for _, k := range []string{"ipaddress", "netmask", "gateway"} {
			if net.ParseIP(n[k]).To4() == nil {
				return nil, fail(400, "Invalid IPv4 "+k)
			}
		}
		mask := net.IPMask(net.ParseIP(n["netmask"]).To4())
		ones, bits := mask.Size()
		if bits != 32 || ones == 0 {
			return nil, fail(400, "Invalid contiguous netmask")
		}
	}
	for _, ip := range strings.Fields(n["dnsservers"]) {
		if net.ParseIP(ip).To4() == nil {
			return nil, fail(400, "Invalid DNS address")
		}
	}
	var out strings.Builder
	for _, k := range []string{"dhcp", "hostname", "ipaddress", "netmask", "gateway", "dnsservers"} {
		v := n[k]
		if strings.ContainsAny(v, "'\"`$;\r\n\x00") {
			return nil, fail(400, "Invalid network value")
		}
		if v != "" {
			fmt.Fprintf(&out, "%s='%s'\n", k, v)
		}
	}
	return []byte(out.String()), nil
}
func (a *App) backup(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", `attachment; filename="l3lab-settings.tar"`)
	t := tar.NewWriter(w)
	defer t.Close()
	for _, name := range []string{"cgminer.conf", "network.conf", "dropbear", "shadow", "lighttpd-htdigest.user", "dropbear_rsa_host_key"} {
		b, e := os.ReadFile(filepath.Join(a.ConfigDir, name))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if e = t.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(b))}); e != nil {
			return e
		}
		if _, e = t.Write(b); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) restore(r *http.Request) (any, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 1024*1024)
	if e := r.ParseMultipartForm(1024 * 1024); e != nil {
		return nil, fail(400, "Backup exceeds limit or is invalid")
	}
	defer r.MultipartForm.RemoveAll()
	f, _, e := r.FormFile("backup")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var cfg map[string]any
	for i := 0; ; i++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if i >= 64 {
			return nil, fail(400, "Too many backup members")
		}
		if e != nil {
			return nil, fail(400, "Invalid backup archive")
		}
		if h.Size < 0 || h.Size > 256*1024 {
			return nil, fail(400, "Backup member too large")
		}
		if h.Name == "cgminer.conf" {
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
				return nil, fail(400, "Config must be a regular file")
			}
			b, e := io.ReadAll(tr)
			if e != nil {
				return nil, e
			}
			if cfg != nil {
				return nil, fail(400, "Duplicate backup config")
			}
			if e = json.Unmarshal(b, &cfg); e != nil {
				return nil, fail(400, "Invalid backup configuration")
			}
		}
	}
	if cfg == nil {
		return nil, fail(400, "Backup contains no cgminer.conf")
	}
	unlock, e := lockConfig(a.StateDir)
	if e != nil {
		return nil, e
	}
	defer unlock()
	current, b, e := a.config()
	if e != nil {
		return nil, e
	}
	for _, k := range []string{"api-allow", "api-host", "api-port", "api-listen", "api-network", "api-groups"} {
		if v, ok := current[k]; ok {
			cfg[k] = v
		} else {
			delete(cfg, k)
		}
	}
	if e = a.validateConfig(cfg, current); e != nil {
		return nil, e
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	if e = atomicFile(filepath.Join(a.ConfigDir, "cgminer.conf.l3lab.bak"), b, 0600); e != nil {
		return nil, e
	}
	if e = atomicFile(filepath.Join(a.ConfigDir, "cgminer.conf"), append(out, '\n'), 0600); e != nil {
		return nil, e
	}
	return map[string]any{"saved": true, "restart_required": true, "message": "Miner and pool settings imported. Login credentials and SSH keys were preserved."}, nil
}
func validateImage(image []byte) error {
	if len(image) < 64 || len(image) > maxRootfs {
		return errors.New("Invalid rootfs size")
	}
	if binary.BigEndian.Uint32(image[:4]) != 0x27051956 || !bytes.Equal(image[28:32], []byte{5, 2, 3, 1}) {
		return errors.New("Expected Linux ARM gzip ramdisk")
	}
	head := append([]byte(nil), image[:64]...)
	expected := binary.BigEndian.Uint32(head[4:8])
	clear(head[4:8])
	if crc32.ChecksumIEEE(head) != expected {
		return errors.New("Rootfs header CRC mismatch")
	}
	size := int(binary.BigEndian.Uint32(image[12:16]))
	if size != len(image)-64 {
		return errors.New("Rootfs length mismatch")
	}
	if crc32.ChecksumIEEE(image[64:]) != binary.BigEndian.Uint32(image[24:28]) {
		return errors.New("Rootfs payload CRC mismatch")
	}
	g, e := gzip.NewReader(bytes.NewReader(image[64:]))
	if e != nil {
		return e
	}
	defer g.Close()
	return validateCPIO(g)
}

func validateCPIO(reader io.Reader) error {
	bounded := &io.LimitedReader{R: reader, N: 128*1024*1024 + 1}
	seen := map[string]bool{}
	for count := 0; count < 50000; count++ {
		h := make([]byte, 110)
		if _, e := io.ReadFull(bounded, h); e != nil {
			return errors.New("Truncated rootfs cpio header")
		}
		if string(h[:6]) != "070701" && string(h[:6]) != "070702" {
			return errors.New("Rootfs is not newc cpio")
		}
		fields := make([]uint64, 13)
		for i := range fields {
			v, e := strconv.ParseUint(string(h[6+i*8:14+i*8]), 16, 32)
			if e != nil {
				return errors.New("Invalid cpio header field")
			}
			fields[i] = v
		}
		namesize, size := int64(fields[11]), int64(fields[6])
		if namesize < 1 || namesize > 4096 || size > 128*1024*1024 {
			return errors.New("Cpio member exceeds limits")
		}
		namebytes := make([]byte, namesize)
		if _, e := io.ReadFull(bounded, namebytes); e != nil {
			return e
		}
		if namebytes[len(namebytes)-1] != 0 {
			return errors.New("Unterminated cpio filename")
		}
		name := strings.TrimPrefix(string(namebytes[:len(namebytes)-1]), "./")
		if strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") {
			return errors.New("Unsafe cpio filename")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return errors.New("Unsafe cpio path")
			}
		}
		if _, e := io.CopyN(io.Discard, bounded, (4-(110+namesize)%4)%4); e != nil {
			return e
		}
		if name == "TRAILER!!!" {
			if size != 0 {
				return errors.New("Invalid cpio trailer")
			}
			if _, e := io.Copy(io.Discard, bounded); e != nil {
				return e
			}
			if bounded.N <= 0 {
				return errors.New("Expanded rootfs exceeds limit")
			}
			return nil
		}
		if seen[name] {
			return errors.New("Duplicate cpio member")
		}
		seen[name] = true
		if string(h[:6]) == "070702" {
			buf := make([]byte, 4096)
			left := size
			var sum uint32
			for left > 0 {
				n := int64(len(buf))
				if left < n {
					n = left
				}
				if _, e := io.ReadFull(bounded, buf[:n]); e != nil {
					return e
				}
				for _, b := range buf[:n] {
					sum += uint32(b)
				}
				left -= n
			}
			if uint64(sum) != fields[12] {
				return errors.New("Cpio checksum mismatch")
			}
		} else {
			if _, e := io.CopyN(io.Discard, bounded, size); e != nil {
				return e
			}
		}
		if _, e := io.CopyN(io.Discard, bounded, (4-size%4)%4); e != nil {
			return e
		}
		if bounded.N <= 0 {
			return errors.New("Expanded rootfs exceeds limit")
		}
	}
	return errors.New("Too many rootfs members")
}
func readUpdate(reader io.Reader, public ed25519.PublicKey) (*Update, error) {
	g, e := gzip.NewReader(io.LimitReader(reader, maxRootfs+1024*1024))
	if e != nil {
		return nil, e
	}
	defer g.Close()
	t := tar.NewReader(g)
	u := &Update{}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return nil, errors.New("Update contains non-regular members")
		}
		if seen[h.Name] {
			return nil, errors.New("Duplicate update member")
		}
		seen[h.Name] = true
		max := int64(8192)
		if h.Name == "initramfs.bin.SD" {
			max = maxRootfs
		}
		if h.Size < 0 || h.Size > max {
			return nil, errors.New("Update member exceeds size limit")
		}
		b, e := io.ReadAll(t)
		if e != nil {
			return nil, e
		}
		switch h.Name {
		case "manifest.json":
			u.RawManifest = b
		case "manifest.sig":
			u.Signature = b
		case "initramfs.bin.SD":
			u.Image = b
		default:
			return nil, errors.New("Unexpected update member: " + h.Name)
		}
	}
	if len(seen) != 3 || !seen["manifest.json"] || !seen["manifest.sig"] || !seen["initramfs.bin.SD"] {
		return nil, errors.New("Incomplete update package")
	}
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, u.RawManifest, u.Signature) {
		return nil, errors.New("Update signature does not match this miner's owner key")
	}
	d := json.NewDecoder(bytes.NewReader(u.RawManifest))
	d.DisallowUnknownFields()
	if e = d.Decode(&u.Manifest); e != nil {
		return nil, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("Trailing manifest data")
	}
	if u.Manifest.Model != "Antminer L3+" || u.Manifest.Payload != "initramfs.bin.SD" || u.Manifest.Version == "" {
		return nil, errors.New("Update model or format mismatch")
	}
	if len(u.Image) != u.Manifest.Bytes || hash(u.Image) != u.Manifest.SHA256 {
		return nil, errors.New("Update payload hash mismatch")
	}
	if e = validateImage(u.Image); e != nil {
		return nil, e
	}
	return u, nil
}
func (a *App) stageUpdate(r *http.Request) (result any, stageErr error) {
	unlock, e := lockConfig(a.StateDir)
	if e != nil {
		return nil, e
	}
	defer unlock()
	dir := filepath.Join(a.StateDir, "staged")
	preparing := false
	defer func() {
		if preparing && stageErr != nil {
			b, _ := json.Marshal(map[string]any{"state": "failed", "message": stageErr.Error()})
			atomicFile(filepath.Join(dir, "state.json"), b, 0600)
		}
	}()
	r.Body = http.MaxBytesReader(nil, r.Body, maxRootfs+1024*1024)
	if e := r.ParseMultipartForm(1024 * 1024); e != nil {
		return nil, fail(400, "Invalid update upload")
	}
	defer r.MultipartForm.RemoveAll()
	f, _, e := r.FormFile("firmware")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	public, e := os.ReadFile("/etc/l3lab/update-public.key")
	if e != nil {
		return nil, e
	}
	update, e := readUpdate(f, public)
	if e != nil {
		return nil, fail(400, e.Error())
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if e = atomicFile(filepath.Join(dir, "state.json"), []byte(`{"state":"preparing","message":"Preparing recovery backup"}`), 0600); e != nil {
		return nil, e
	}
	preparing = true
	if e = atomicFile(filepath.Join(dir, "initramfs.bin.SD"), update.Image, 0600); e != nil {
		return nil, e
	}
	if e = atomicFile(filepath.Join(dir, "manifest.json"), update.RawManifest, 0600); e != nil {
		return nil, e
	}
	if e = atomicFile(filepath.Join(dir, "manifest.sig"), update.Signature, 0600); e != nil {
		return nil, e
	}
	if e = prepareFlash(dir, len(update.Image)); e != nil {
		return nil, fail(409, e.Error())
	}
	if e = atomicFile(filepath.Join(dir, "state.json"), []byte(`{"state":"staged","message":"Validated update is ready for review"}`), 0600); e != nil {
		return nil, e
	}
	return map[string]any{"staged": true, "manifest": update.Manifest, "backup_ready": true, "message": "Signature, model, CRCs, partition capacity and recovery backup checked. Download the recovery backup before installation."}, nil
}
func jsonResponse(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(value)
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if !a.Preview && r.Header.Get("X-L3-CGI-USER") == "" {
		jsonResponse(w, 403, map[string]any{"error": "Authenticated firmware web session required"})
		return
	}
	action := r.URL.Query().Get("action")
	if action == "" {
		action = "status"
	}
	reads := map[string]bool{"status": true, "settings": true, "logs": true, "update-state": true, "recovery-backup": true, "schedule": true, "hardware-layout": true, "dev-support": true}
	if reads[action] && r.Method != "GET" {
		jsonResponse(w, 405, map[string]any{"error": "Use GET"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var result any
	var e error
	if !reads[action] {
		if e = a.writable(r); e != nil {
			respondError(w, e)
			return
		}
	}
	switch action {
	case "status":
		result, e = a.status()
	case "settings":
		result, e = a.settings()
	case "hardware-layout":
		result, e = hardwareLayout()
	case "schedule":
		result = a.scheduleSettings()
	case "save-schedule":
		result, e = a.saveSchedule(r.Body)
	case "dev-support":
		result = a.devSupportSettings()
	case "save-dev-support":
		result, e = a.saveDevSupport(r.Body)
	case "save":
		result, e = a.saveConfig(r)
	case "restart":
		var in struct {
			Confirm bool `json:"confirm"`
		}
		e = decodeJSON(r, &in)
		if e == nil && !in.Confirm {
			e = fail(400, "Explicit restart confirmation required")
		}
		if e == nil {
			_, e = run(15*time.Second, "/etc/init.d/cgminer.sh", "restart")
			result = map[string]any{"restarted": e == nil}
		}
	case "ssh":
		var in struct {
			Enabled bool `json:"enabled"`
		}
		e = decodeJSON(r, &in)
		if e == nil {
			v := "NO_START=1\n"
			if in.Enabled {
				v = "NO_START=0\n"
			}
			e = atomicFile(filepath.Join(a.ConfigDir, "dropbear"), []byte(v), 0600)
			if e == nil {
				e = atomicFile("/etc/default/dropbear", []byte(v), 0600)
			}
			if e == nil {
				op := "stop"
				if in.Enabled {
					op = "start"
				}
				_, e = run(10*time.Second, "/etc/init.d/dropbear", op)
			}
			result = map[string]any{"ssh_enabled": in.Enabled}
		}
	case "network":
		var in struct {
			Network map[string]string `json:"network"`
		}
		e = decodeJSON(r, &in)
		if e == nil {
			var b []byte
			b, e = validateNetwork(in.Network)
			if e == nil {
				e = atomicFile(filepath.Join(a.ConfigDir, "network.conf"), b, 0600)
			}
			result = map[string]any{"saved": e == nil, "reboot_required": true}
		}
	case "backup":
		e = a.backup(w)
		if e != nil {
			respondError(w, e)
		}
		return
	case "restore":
		result, e = a.restore(r)
	case "logs":
		if a.Preview {
			result = map[string]any{"text": "Live logs require the dashboard to be installed on the miner. This preview reads only its mining API."}
		} else {
			var b []byte
			b, e = run(2*time.Second, "/sbin/logread")
			if len(b) > 64*1024 {
				b = b[len(b)-64*1024:]
			}
			cfg, _, _ := a.config()
			if p, ok := cfg["pools"].([]any); ok {
				for _, v := range p {
					s := text(obj(v)["pass"])
					if len(s) > 2 {
						b = bytes.ReplaceAll(b, []byte(s), []byte("[REDACTED]"))
					}
				}
			}
			result = map[string]any{"text": string(b)}
		}
	case "stage-update":
		result, e = a.stageUpdate(r)
	case "apply-update":
		var in struct {
			SHA256           string `json:"sha256"`
			BackupDownloaded bool   `json:"backup_downloaded"`
		}
		e = decodeJSON(r, &in)
		if e == nil && !in.BackupDownloaded {
			e = fail(400, "Download the recovery backup first")
		}
		if e == nil {
			var b []byte
			b, e = os.ReadFile(filepath.Join(a.StateDir, "staged", "initramfs.bin.SD"))
			if e == nil && hash(b) != in.SHA256 {
				e = fail(409, "Staged image changed")
			}
			if e == nil {
				e = startFlashWorker(filepath.Join(a.StateDir, "staged"), in.SHA256)
			}
			result = map[string]any{"installing": e == nil}
		}
	case "update-state":
		public, _ := os.ReadFile("/etc/l3lab/update-public.key")
		result, e = readUpdateState(filepath.Join(a.StateDir, "staged"), public)
	case "recovery-backup":
		if a.Preview {
			e = fail(403, "No recovery backup in preview")
			break
		}
		var f *os.File
		f, e = os.Open(filepath.Join(a.StateDir, "staged", "recovery-rootfs.bin"))
		if e == nil {
			defer f.Close()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="l3lab-recovery-rootfs.bin"`)
			io.Copy(w, f)
			return
		}
	case "reboot":
		var in struct {
			Confirm bool `json:"confirm"`
		}
		e = decodeJSON(r, &in)
		if e == nil && !in.Confirm {
			e = fail(400, "Explicit reboot confirmation required")
		}
		if e == nil {
			e = deferredReboot()
			result = map[string]any{"rebooting": e == nil}
		}
	default:
		e = fail(404, "Unknown dashboard action")
	}
	if e != nil {
		respondError(w, e)
		return
	}
	jsonResponse(w, 200, result)
}
func respondError(w http.ResponseWriter, e error) {
	code := 500
	var f failure
	if errors.As(e, &f) {
		code = f.Code
	}
	jsonResponse(w, code, map[string]any{"error": e.Error()})
}
func main() {
	preview := flag.Bool("preview", false, "Run a read-only dashboard on this computer")
	listen := flag.String("listen", "127.0.0.1:8787", "Preview listen address (loopback only)")
	host := flag.String("miner", "127.0.0.1:4028", "Mining API address")
	config := flag.String("config-dir", "/config", "Configuration directory")
	state := flag.String("state-dir", "/tmp/l3lab", "Temporary state directory")
	keygen := flag.String("keygen", "", "Create owner update keys in this directory")
	sign := flag.String("sign", "", "Sign this manifest with -private-key")
	private := flag.String("private-key", "", "Owner update private key file")
	worker := flag.String("flash-worker", "", "Run the validated rootfs flash worker")
	expectedSHA := flag.String("expected-sha", "", "Exact reviewed image SHA-256 required by the flash worker")
	scheduler := flag.Bool("scheduler", false, "Run the daily mining pause scheduler on the miner")
	flag.Parse()
	if *keygen != "" {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			panic(e)
		}
		if e = atomicFile(filepath.Join(*keygen, "update-private.key"), priv, 0600); e != nil {
			panic(e)
		}
		if e = atomicFile(filepath.Join(*keygen, "update-public.key"), pub, 0644); e != nil {
			panic(e)
		}
		fmt.Println("Owner key fingerprint:", hash(pub))
		return
	}
	if *sign != "" {
		b, e := os.ReadFile(*sign)
		if e != nil {
			panic(e)
		}
		p, e := os.ReadFile(*private)
		if e != nil || len(p) != ed25519.PrivateKeySize {
			panic("Invalid owner private key")
		}
		if e = atomicFile(*sign+".sig", ed25519.Sign(p, b), 0600); e != nil {
			panic(e)
		}
		return
	}
	if *worker != "" {
		if e := flashWorker(*worker, *expectedSHA); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	a := &App{Host: *host, ConfigDir: *config, StateDir: *state, CGMiner: "/usr/bin/cgminer", Preview: *preview}
	if *scheduler {
		if *preview {
			panic("Scheduler requires firmware mode")
		}
		a.schedulerLoop()
		return
	}
	if *preview {
		ip, _, e := net.SplitHostPort(*listen)
		if e != nil || net.ParseIP(ip) == nil || !net.ParseIP(ip).IsLoopback() {
			panic("Preview must bind to a loopback address")
		}
		mux := http.NewServeMux()
		mux.Handle("/cgi-bin/l3lab.cgi", a)
		web, _ := fs.Sub(assets, "web")
		mux.Handle("/", http.FileServer(http.FS(web)))
		fmt.Println("Read-only preview at http://" + *listen)
		srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second}
		if e := srv.ListenAndServe(); e != nil {
			panic(e)
		}
		return
	}
	if os.Getenv("GATEWAY_INTERFACE") == "" {
		fmt.Fprintln(os.Stderr, "Use as authenticated firmware CGI or pass -preview")
		os.Exit(2)
	}
	// Trust only the web server's CGI environment, never a client-supplied header.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-L3-CGI-USER")
		r.Header.Set("X-L3-CGI-USER", os.Getenv("REMOTE_USER"))
		a.ServeHTTP(w, r)
	})
	if e := cgi.Serve(handler); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

// Key encoding helpers used by the build package and tests.
func keyString(k []byte) string { return base64.StdEncoding.EncodeToString(k) }
