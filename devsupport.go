package main

// Dev support: an opt-out time slice that points the miner at the JMSCNC
// developer's pool for a small, disclosed share of each hour.
//
// How it works: the scheduler daemon checks once every few seconds. Inside the
// slice it adds the donation pool to CGMiner's RUNTIME pool list (addpool) and
// switches to it (switchpool). When the slice ends it switches back to the pool
// that was active before and removes the donation pool again (removepool).
// The saved cgminer.conf is never read for writing or rewritten; nothing is
// persisted with CGMiner's "save" command, so a reboot or CGMiner restart always
// comes back to the owner's own pools only. There is no fallback donation pool:
// if the donation pool is unreachable, CGMiner's normal failover simply keeps
// mining on the owner's pools.

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	donationURL               = "stratum+tcp://americas.mining-dutch.nl:3421"
	donationUser              = "revjmoney.l3heater"
	donationPass              = "x"
	devSupportDefaultPercent  = 1.0
	devSupportMaxPercent      = 5.0
	devSupportPeriod          = time.Hour
	devSupportConfigFile      = "l3lab-devsupport.json"
	devSupportStateFile       = "devsupport-state.json"
	devSupportTickInterval    = 3 * time.Second
	devSupportLinkCoffee      = "https://buymeacoffee.com/revjmoney"
	devSupportLinkSite        = "https://jmscnc.com"
	devSupportLinkProofOfHeat = "https://soundcloud.com/revjmoney/proof-of-heat-whitepaper"
)

type DevSupport struct {
	Enabled bool    `json:"enabled"`
	Percent float64 `json:"percent"`
}

type DevSupportState struct {
	State          string  `json:"state"`
	Message        string  `json:"message"`
	DonationPoolID int     `json:"donation_pool_id"`
	ReturnPoolID   int     `json:"return_pool_id"`
	SliceStarted   int64   `json:"slice_started,omitempty"`
	DonatedSeconds float64 `json:"donated_seconds"`
	Time           int64   `json:"time"`
}

// poolRow is the subset of a CGMiner POOLS row the dev-support logic needs.
type poolRow struct {
	ID       int
	URL      string
	User     string
	Priority int
	Status   string
}

// poolClient is the narrow CGMiner surface used by dev support (faked in tests).
type poolClient interface {
	Pools() ([]poolRow, error)
	AddPool(url, user, pass string) error
	SwitchPool(id int) error
	RemovePool(id int) error
}

func defaultDevSupport() DevSupport {
	return DevSupport{Enabled: true, Percent: devSupportDefaultPercent}
}

func validateDevSupport(d DevSupport) error {
	if math.IsNaN(d.Percent) || math.IsInf(d.Percent, 0) || d.Percent < 0 || d.Percent > devSupportMaxPercent {
		return fmt.Errorf("Dev support must be between 0%% and %g%%", devSupportMaxPercent)
	}
	// Tenths of a percent are plenty and keep the slice length readable.
	if math.Abs(d.Percent*10-math.Round(d.Percent*10)) > 1e-9 {
		return errors.New("Use at most one decimal place for dev support")
	}
	return nil
}

// devSupportSlice is the donated time per period; zero when off.
func devSupportSlice(d DevSupport) time.Duration {
	if !d.Enabled || d.Percent <= 0 || validateDevSupport(d) != nil {
		return 0
	}
	return time.Duration(d.Percent / 100 * float64(devSupportPeriod)).Round(time.Second)
}

// devSupportOffset spreads miners across the hour so a fleet does not switch at once.
func devSupportOffset(seed string) time.Duration {
	h := fnv.New32a()
	h.Write([]byte(seed))
	return time.Duration(h.Sum32()%uint32(devSupportPeriod/time.Second)) * time.Second
}

// devSupportWindow reports whether now falls inside this period's donation slice.
func devSupportWindow(d DevSupport, now time.Time, offset time.Duration) bool {
	slice := devSupportSlice(d)
	if slice <= 0 {
		return false
	}
	period := int64(devSupportPeriod / time.Second)
	pos := ((now.Unix()-int64(offset/time.Second))%period + period) % period
	return pos < int64(slice/time.Second)
}

func (a *App) devSupport() DevSupport {
	d := defaultDevSupport()
	b, e := os.ReadFile(filepath.Join(a.ConfigDir, devSupportConfigFile))
	if e == nil {
		var saved DevSupport
		if json.Unmarshal(b, &saved) == nil && validateDevSupport(saved) == nil {
			d = saved
		}
	}
	return d
}

func (a *App) devSupportSeed() string {
	network, _ := os.ReadFile(filepath.Join(a.ConfigDir, "network.conf"))
	return parseNetwork(network)["hostname"]
}

func (a *App) devSupportSettings() any {
	d := a.devSupport()
	b, _ := os.ReadFile(filepath.Join(a.StateDir, devSupportStateFile))
	var state any
	json.Unmarshal(b, &state)
	slice := devSupportSlice(d)
	return map[string]any{
		"dev_support":     d,
		"default":         defaultDevSupport(),
		"max_percent":     devSupportMaxPercent,
		"slice_seconds":   int(slice / time.Second),
		"period_seconds":  int(devSupportPeriod / time.Second),
		"active_now":      devSupportWindow(d, time.Now(), devSupportOffset(a.devSupportSeed())),
		"recipient":       "the JMSCNC developer",
		"saved_pools":     "Never modified. The donation pool exists only in CGMiner's runtime list during the slice.",
		"fallback":        "None. If the donation pool is down, CGMiner fails over to your own pools.",
		"state":           state,
		"links":           map[string]string{"buy_me_a_coffee": devSupportLinkCoffee, "website": devSupportLinkSite, "proof_of_heat": devSupportLinkProofOfHeat},
		"preview":         a.Preview,
		"hardware_tested": false,
	}
}

func (a *App) saveDevSupport(body io.Reader) (any, error) {
	var d DevSupport
	dec := json.NewDecoder(io.LimitReader(body, 4096))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&d); e != nil {
		return nil, fail(400, "Invalid dev support setting")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, fail(400, "Trailing dev support data")
	}
	if e := validateDevSupport(d); e != nil {
		return nil, fail(400, e.Error())
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	if e := atomicFile(filepath.Join(a.ConfigDir, devSupportConfigFile), append(b, '\n'), 0600); e != nil {
		return nil, e
	}
	return map[string]any{"saved": true, "dev_support": d, "slice_seconds": int(devSupportSlice(d) / time.Second)}, nil
}

func isDonationPool(url, user string) bool {
	return strings.EqualFold(strings.TrimSpace(url), donationURL) && strings.TrimSpace(user) == donationUser
}

// savedPoolsIncludeDonation is true when the owner deliberately mines to the
// donation worker in their own config; dev support then leaves everything alone.
func savedPoolsIncludeDonation(cfg map[string]any) bool {
	pools, _ := cfg["pools"].([]any)
	for _, p := range pools {
		m := obj(p)
		if isDonationPool(text(m["url"]), text(m["user"])) {
			return true
		}
	}
	return false
}

// nonFailoverStrategy names a CGMiner multipool strategy where switchpool does
// not route all work to one pool, so the slice could not be measured honestly.
func nonFailoverStrategy(cfg map[string]any) string {
	for _, k := range []string{"load-balance", "balance", "round-robin", "rotate"} {
		if v, ok := cfg[k]; ok && v != false && text(v) != "" {
			return k
		}
	}
	return ""
}

// devSupportStep moves CGMiner one step toward the wanted state. It only ever
// touches the pool whose URL and worker exactly match the donation pool.
func devSupportStep(c poolClient, want bool, prev DevSupportState, now time.Time) (DevSupportState, error) {
	state := prev
	state.Time = now.Unix()
	if prev.State == "donating" && prev.Time > 0 {
		if elapsed := now.Unix() - prev.Time; elapsed > 0 && elapsed < 120 {
			state.DonatedSeconds += float64(elapsed)
		}
	}
	rows, e := c.Pools()
	if e != nil {
		return state, e
	}
	var ours *poolRow
	current := -1
	currentPrio := math.MaxInt
	for i := range rows {
		r := rows[i]
		if isDonationPool(r.URL, r.User) {
			if ours == nil || r.ID > ours.ID {
				ours = &rows[i]
			}
			continue
		}
		if r.Priority < currentPrio {
			current, currentPrio = r.ID, r.Priority
		}
	}
	if want {
		if ours == nil {
			if e = c.AddPool(donationURL, donationUser, donationPass); e != nil {
				return state, e
			}
			if rows, e = c.Pools(); e != nil {
				return state, e
			}
			for i := range rows {
				if isDonationPool(rows[i].URL, rows[i].User) && (ours == nil || rows[i].ID > ours.ID) {
					ours = &rows[i]
				}
			}
			if ours == nil {
				return state, errors.New("CGMiner did not list the donation pool after adding it")
			}
		}
		if ours.Priority != 0 {
			if current < 0 {
				return state, errors.New("No owner pool to return to; dev support skipped")
			}
			state.ReturnPoolID = current
			if e = c.SwitchPool(ours.ID); e != nil {
				return state, e
			}
			state.SliceStarted = now.Unix()
		}
		state.State = "donating"
		state.DonationPoolID = ours.ID
		state.Message = "Dev support slice active: mining to the JMSCNC developer pool. Your saved pools are unchanged."
		return state, nil
	}
	if ours != nil {
		if ours.Priority == 0 {
			target := -1
			for _, r := range rows {
				if r.ID == prev.ReturnPoolID && !isDonationPool(r.URL, r.User) {
					target = r.ID
				}
			}
			if target < 0 {
				target = current
			}
			if target < 0 {
				return state, errors.New("No owner pool to switch back to")
			}
			if e = c.SwitchPool(target); e != nil {
				return state, e
			}
		}
		if e = c.RemovePool(ours.ID); e != nil {
			return state, e
		}
	}
	state.State = "mining"
	state.DonationPoolID = -1
	state.SliceStarted = 0
	state.Message = "Mining to your own pools."
	return state, nil
}

// cgminerPools adapts the local CGMiner API to poolClient.
type cgminerPools struct{ a *App }

func (p cgminerPools) Pools() ([]poolRow, error) {
	data, e := p.a.api("pools")
	if e != nil {
		return nil, e
	}
	var rows []poolRow
	for _, r := range data["POOLS"] {
		rows = append(rows, poolRow{ID: int(number(r["POOL"])), URL: text(r["URL"]), User: text(r["User"]), Priority: int(number(r["Priority"])), Status: text(r["Status"])})
	}
	return rows, nil
}
func (p cgminerPools) AddPool(url, user, pass string) error {
	return p.a.privileged("addpool", url+","+user+","+pass)
}
func (p cgminerPools) SwitchPool(id int) error { return p.a.privileged("switchpool", fmt.Sprint(id)) }
func (p cgminerPools) RemovePool(id int) error { return p.a.privileged("removepool", fmt.Sprint(id)) }

// privileged sends one of the few write commands dev support needs. CGMiner
// only accepts them from 127.0.0.1 (api-allow W:127.0.0.1).
func (a *App) privileged(command, param string) error {
	if a.Preview {
		return errors.New("No mining control in preview")
	}
	allowed := map[string]bool{"addpool": true, "switchpool": true, "removepool": true}
	if !allowed[command] || strings.ContainsAny(param, "|\\\r\n\x00") || len(param) > 512 {
		return errors.New("Invalid pool control")
	}
	c, e := net.DialTimeout("tcp", a.Host, 2*time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = fmt.Fprintf(c, "%s|%s", command, param); e != nil {
		return e
	}
	raw, e := io.ReadAll(io.LimitReader(c, 64*1024))
	if e != nil {
		return e
	}
	response, e := parseAPI(raw)
	if e != nil {
		return e
	}
	status := text(first(response, "STATUS")["STATUS"])
	if status != "S" && status != "I" {
		return fmt.Errorf("CGMiner refused %s: %s", command, text(first(response, "STATUS")["Msg"]))
	}
	return nil
}

func (a *App) devSupportTick(c poolClient, now time.Time) error {
	path := filepath.Join(a.StateDir, devSupportStateFile)
	b, _ := os.ReadFile(path)
	prev := DevSupportState{DonationPoolID: -1, ReturnPoolID: -1}
	json.Unmarshal(b, &prev)
	persist := func(s DevSupportState) {
		out, _ := json.Marshal(s)
		atomicFile(path, out, 0600)
	}
	if _, e := os.Stat(filepath.Join(a.StateDir, "staged", "install.lock")); e == nil {
		return nil // Firmware install in progress: never touch CGMiner.
	}
	d := a.devSupport()
	want := devSupportWindow(d, now, devSupportOffset(a.devSupportSeed()))
	reason := ""
	if cfg, _, e := a.config(); e == nil {
		if savedPoolsIncludeDonation(cfg) {
			want, reason = false, "Your saved pools already mine to the donation worker; dev support leaves them alone."
		} else if k := nonFailoverStrategy(cfg); k != "" {
			want, reason = false, "Dev support needs the failover pool strategy; it is skipped while "+k+" is set."
		}
	}
	if paused, _ := shouldPause(a.schedule(), now); paused {
		want = false
	}
	state, e := devSupportStep(c, want, prev, now)
	if e != nil {
		state.State = "error"
		state.Message = e.Error()
	} else if !d.Enabled || d.Percent == 0 {
		state.State, state.Message = "off", "Dev support is turned off. Thank you for trying JMSCNC Heater OS."
	} else if reason != "" {
		state.State, state.Message = "skipped", reason
	}
	persist(state)
	return e
}

func (a *App) devSupportLoop() {
	c := cgminerPools{a}
	for {
		a.devSupportTick(c, time.Now())
		time.Sleep(devSupportTickInterval)
	}
}
