package main

import (
	"testing"
	"time"
)

// fakePool is an in-memory CGMiner pool list for testing devSupportStep.
type fakePool struct {
	rows    []poolRow
	nextID  int
	added   int
	removed int
	switchd []int
	failAdd bool
}

func (f *fakePool) Pools() ([]poolRow, error) { return append([]poolRow(nil), f.rows...), nil }
func (f *fakePool) AddPool(url, user, pass string) error {
	if f.failAdd {
		return errMsg("addpool refused")
	}
	// New runtime pools land at the end with the lowest priority (highest number).
	f.rows = append(f.rows, poolRow{ID: f.nextID, URL: url, User: user, Priority: len(f.rows), Status: "Alive"})
	f.nextID++
	f.added++
	return nil
}
func (f *fakePool) SwitchPool(id int) error {
	f.switchd = append(f.switchd, id)
	for i := range f.rows {
		f.rows[i].Priority = 1
		if f.rows[i].ID == id {
			f.rows[i].Priority = 0
		}
	}
	return nil
}
func (f *fakePool) RemovePool(id int) error {
	for i := range f.rows {
		if f.rows[i].ID == id {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			f.removed++
			return nil
		}
	}
	return errMsg("removepool: not found")
}

type errMsg string

func (e errMsg) Error() string { return string(e) }

func ownerPools() *fakePool {
	return &fakePool{
		rows:   []poolRow{{ID: 0, URL: donationURL, User: "owner.worker1", Priority: 0, Status: "Alive"}, {ID: 1, URL: "stratum+tcp://other.pool:3333", User: "owner.worker2", Priority: 1, Status: "Alive"}},
		nextID: 2,
	}
}

func TestDevSupportSliceLength(t *testing.T) {
	got := devSupportSlice(DevSupport{Enabled: true, Percent: 1})
	if got != 36*time.Second {
		t.Fatalf("1%% of an hour should be 36s, got %v", got)
	}
	if devSupportSlice(DevSupport{Enabled: false, Percent: 1}) != 0 {
		t.Fatal("disabled slice must be zero")
	}
	if devSupportSlice(DevSupport{Enabled: true, Percent: 0}) != 0 {
		t.Fatal("0%% slice must be zero")
	}
	if devSupportSlice(DevSupport{Enabled: true, Percent: 5}) != 180*time.Second {
		t.Fatal("5%% of an hour should be 180s")
	}
}

func TestValidateDevSupport(t *testing.T) {
	ok := []DevSupport{{true, 0}, {true, 1}, {false, 0}, {true, 2.5}, {true, 5}}
	for _, d := range ok {
		if e := validateDevSupport(d); e != nil {
			t.Fatalf("%v should be valid: %v", d, e)
		}
	}
	bad := []DevSupport{{true, -1}, {true, 5.1}, {true, 100}, {true, 1.25}}
	for _, d := range bad {
		if validateDevSupport(d) == nil {
			t.Fatalf("%v should be invalid", d)
		}
	}
}

func TestDefaultIsOnePercentOptOut(t *testing.T) {
	d := defaultDevSupport()
	if !d.Enabled || d.Percent != 1 {
		t.Fatalf("default dev support must be enabled at 1%%, got %+v", d)
	}
}

func TestDevSupportWindowCoversSlice(t *testing.T) {
	d := DevSupport{Enabled: true, Percent: 1}
	base := time.Unix(0, 0).UTC()
	in := 0
	for s := 0; s < 3600; s++ {
		if devSupportWindow(d, base.Add(time.Duration(s)*time.Second), 0) {
			in++
		}
	}
	if in != 36 {
		t.Fatalf("expected 36 donation seconds per hour, counted %d", in)
	}
}

func TestDevSupportOffsetStable(t *testing.T) {
	if devSupportOffset("L3-3boards") != devSupportOffset("L3-3boards") {
		t.Fatal("offset must be deterministic for a host")
	}
	if devSupportOffset("a") == devSupportOffset("b") && devSupportOffset("a") == devSupportOffset("c") {
		t.Fatal("offset should vary by host")
	}
}

func TestDevSupportStepAddsSwitchesThenRestores(t *testing.T) {
	f := ownerPools()
	now := time.Unix(1000, 0)
	// Enter the slice: donation pool added and switched to; owner pool recorded.
	st, e := devSupportStep(f, true, DevSupportState{DonationPoolID: -1, ReturnPoolID: -1}, now)
	if e != nil {
		t.Fatal(e)
	}
	if f.added != 1 || len(f.switchd) != 1 {
		t.Fatalf("expected one add and one switch, got add=%d switch=%v", f.added, f.switchd)
	}
	if st.State != "donating" || st.DonationPoolID != 2 {
		t.Fatalf("unexpected state %+v", st)
	}
	if st.ReturnPoolID != 0 {
		t.Fatalf("should return to highest-priority owner pool 0, got %d", st.ReturnPoolID)
	}
	// Leave the slice: switch back to the owner pool and remove the donation pool.
	st2, e := devSupportStep(f, false, st, now.Add(36*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if f.removed != 1 {
		t.Fatalf("donation pool should be removed, removed=%d", f.removed)
	}
	last := f.switchd[len(f.switchd)-1]
	if last != 0 {
		t.Fatalf("final switch should target owner pool 0, got %d", last)
	}
	if st2.State != "mining" {
		t.Fatalf("should be back to mining, got %s", st2.State)
	}
	for _, r := range f.rows {
		if isDonationPool(r.URL, r.User) {
			t.Fatal("donation pool must not remain in the list")
		}
	}
}

func TestDevSupportNeverTouchesOwnerPoolCount(t *testing.T) {
	f := ownerPools()
	before := len(f.rows)
	st, _ := devSupportStep(f, true, DevSupportState{DonationPoolID: -1, ReturnPoolID: -1}, time.Unix(1, 0))
	devSupportStep(f, false, st, time.Unix(40, 0))
	if len(f.rows) != before {
		t.Fatalf("owner pool list changed: before=%d after=%d", before, len(f.rows))
	}
}

func TestDevSupportIdleWhenOff(t *testing.T) {
	f := ownerPools()
	st, e := devSupportStep(f, false, DevSupportState{DonationPoolID: -1, ReturnPoolID: -1}, time.Unix(1, 0))
	if e != nil {
		t.Fatal(e)
	}
	if f.added != 0 || f.removed != 0 || len(f.switchd) != 0 {
		t.Fatal("no pool commands should be sent when off and nothing staged")
	}
	if st.State != "mining" {
		t.Fatalf("state should be mining, got %s", st.State)
	}
}

func TestSavedPoolsIncludeDonation(t *testing.T) {
	cfg := map[string]any{"pools": []any{
		map[string]any{"url": donationURL, "user": donationUser, "pass": "x"},
	}}
	if !savedPoolsIncludeDonation(cfg) {
		t.Fatal("should detect owner already mining to the donation worker")
	}
	cfg2 := map[string]any{"pools": []any{map[string]any{"url": donationURL, "user": "owner.worker1"}}}
	if savedPoolsIncludeDonation(cfg2) {
		t.Fatal("different worker on the same host is not the donation pool")
	}
}

func TestNonFailoverStrategyDetected(t *testing.T) {
	if nonFailoverStrategy(map[string]any{"load-balance": true}) == "" {
		t.Fatal("load-balance should be flagged")
	}
	if nonFailoverStrategy(map[string]any{}) != "" {
		t.Fatal("plain failover config should not be flagged")
	}
	if nonFailoverStrategy(map[string]any{"load-balance": false}) != "" {
		t.Fatal("a false flag is not set")
	}
}

func TestIsDonationPoolTrimAndCase(t *testing.T) {
	if !isDonationPool(" "+donationURL+" ", donationUser) {
		t.Fatal("surrounding whitespace should be tolerated")
	}
	if isDonationPool("stratum+tcp://other.pool:3333", donationUser) {
		t.Fatal("a different pool is not the donation pool")
	}
}
