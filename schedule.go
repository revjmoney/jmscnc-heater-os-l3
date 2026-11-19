package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

type Schedule struct {
	Enabled  bool   `json:"enabled"`
	Off      string `json:"off"`
	On       string `json:"on"`
	Timezone string `json:"timezone"`
}

var clockPattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func validateSchedule(s Schedule) error {
	if !clockPattern.MatchString(s.Off) || !clockPattern.MatchString(s.On) {
		return errors.New("Use 24-hour HH:MM times")
	}
	if s.Off == s.On {
		return errors.New("Off and On must be different")
	}
	if len(s.Timezone) > 100 || strings.ContainsAny(s.Timezone, "\\\x00") {
		return errors.New("Invalid timezone")
	}
	if _, e := time.LoadLocation(s.Timezone); e != nil {
		return errors.New("Use an IANA timezone, such as America/New_York")
	}
	return nil
}
func clockMinute(s string) int {
	h, _ := strconv.Atoi(s[:2])
	m, _ := strconv.Atoi(s[3:])
	return h*60 + m
}
func shouldPause(s Schedule, now time.Time) (bool, error) {
	if e := validateSchedule(s); e != nil {
		return false, e
	}
	if !s.Enabled {
		return false, nil
	}
	zone, _ := time.LoadLocation(s.Timezone)
	now = now.In(zone)
	minute := now.Hour()*60 + now.Minute()
	off, on := clockMinute(s.Off), clockMinute(s.On)
	if off < on {
		return minute >= off && minute < on, nil
	}
	return minute >= off || minute < on, nil
}
func (a *App) schedule() Schedule {
	s := Schedule{Off: "16:00", On: "21:00", Timezone: "America/New_York"}
	b, e := os.ReadFile(filepath.Join(a.ConfigDir, "l3lab-schedule.json"))
	if e == nil {
		json.Unmarshal(b, &s)
	}
	return s
}
func (a *App) scheduleSettings() any {
	s := a.schedule()
	paused, _ := shouldPause(s, time.Now())
	b, _ := os.ReadFile(filepath.Join(a.StateDir, "schedule-state.json"))
	var state any
	json.Unmarshal(b, &state)
	return map[string]any{"schedule": s, "pause_window_now": paused, "state": state, "method": "ascdisable / ascenable; CGMiner stays running for temperature and fan control", "hardware_validation": "pending"}
}
func (a *App) saveSchedule(rbody io.Reader) (any, error) {
	var s Schedule
	d := json.NewDecoder(io.LimitReader(rbody, 4096))
	d.DisallowUnknownFields()
	if e := d.Decode(&s); e != nil {
		return nil, fail(400, "Invalid schedule")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, fail(400, "Trailing schedule data")
	}
	if e := validateSchedule(s); e != nil {
		return nil, fail(400, e.Error())
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	if e := atomicFile(filepath.Join(a.ConfigDir, "l3lab-schedule.json"), append(b, '\n'), 0600); e != nil {
		return nil, e
	}
	return map[string]any{"saved": true, "schedule": s}, nil
}
func (a *App) controlASC(command string, id int) error {
	if a.Preview {
		return errors.New("No mining control in preview")
	}
	if (command != "ascdisable" && command != "ascenable") || id < 0 || id > 15 {
		return errors.New("Invalid ASIC control")
	}
	c, e := net.DialTimeout("tcp", a.Host, 2*time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = fmt.Fprintf(c, "%s|%d", command, id); e != nil {
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
	status := first(response, "STATUS")
	if text(status["STATUS"]) != "S" {
		return fmt.Errorf("ASIC control refused: %s", text(status["Msg"]))
	}
	return nil
}

type ScheduleState struct {
	State     string `json:"state"`
	Message   string `json:"message"`
	PausedIDs []int  `json:"paused_ids"`
	Time      int64  `json:"time"`
}

func (a *App) schedulerTick() error {
	if a.Preview {
		return errors.New("No scheduler in preview")
	}
	if _, e := os.Stat(filepath.Join(a.StateDir, "staged", "install.lock")); e == nil {
		return nil
	}
	s := a.schedule()
	paused, e := shouldPause(s, time.Now())
	if e != nil {
		return e
	}
	b, _ := os.ReadFile(filepath.Join(a.StateDir, "schedule-state.json"))
	previous := ScheduleState{}
	json.Unmarshal(b, &previous)
	state := ScheduleState{State: "mining", Message: "Outside the daily pause window", PausedIDs: previous.PausedIDs, Time: time.Now().Unix()}
	persist := func() {
		out, _ := json.Marshal(state)
		atomicFile(filepath.Join(a.StateDir, "schedule-state.json"), out, 0600)
	}
	version, e := a.api("version")
	if e != nil {
		return e
	}
	if text(first(version, "VERSION")["Type"]) != "Antminer L3+" {
		return errors.New("Schedule model mismatch")
	}
	if paused {
		devs, e := a.api("devs")
		if e != nil {
			return e
		}
		rows := devs["ASC"]
		if len(rows) == 0 {
			return errors.New("CGMiner reports no ASIC device for scheduling")
		}
		for _, dev := range rows {
			id := int(number(dev["ASC"]))
			enabled := strings.EqualFold(text(dev["Enabled"]), "Y") || strings.EqualFold(text(dev["Enabled"]), "true")
			if !enabled {
				continue
			}
			if e = a.controlASC("ascdisable", id); e != nil {
				state.State = "error"
				state.Message = e.Error()
				persist()
				return e
			}
			exists := false
			for _, old := range state.PausedIDs {
				if old == id {
					exists = true
				}
			}
			if !exists {
				state.PausedIDs = append(state.PausedIDs, id)
			}
		}
		state.State = "paused"
		state.Message = "ASIC work paused; CGMiner remains running to control cooling. Confirm actual idle power and fan operation during commissioning."
		stats, e := a.api("stats")
		if e != nil {
			state.State = "error"
			state.Message = "Mining pause requested, but cooling telemetry is unavailable"
		} else {
			fans := false
			for _, row := range stats["STATS"] {
				if number(row["fan1"]) > 0 && number(row["fan2"]) > 0 {
					fans = true
				}
			}
			if !fans {
				state.State = "error"
				state.Message = "Cooling fan RPM is unavailable or zero; check the miner immediately"
			}
		}
	} else { // Resume only devices this scheduler previously disabled.
		for _, id := range state.PausedIDs {
			if e = a.controlASC("ascenable", id); e != nil {
				state.State = "error"
				state.Message = e.Error()
				persist()
				return e
			}
		}
		state.PausedIDs = nil
	}
	persist()
	return nil
}
func (a *App) schedulerLoop() {
	// Dev support runs in the same daemon on its own faster cadence.
	go a.devSupportLoop()
	for {
		if e := a.schedulerTick(); e != nil {
			b, _ := json.Marshal(map[string]any{"state": "error", "message": e.Error(), "time": time.Now().Unix()}) // Preserve device ownership for the next successful resume.
			path := filepath.Join(a.StateDir, "schedule-state.json")
			old, _ := os.ReadFile(path)
			var previous ScheduleState
			if json.Unmarshal(old, &previous) == nil {
				previous.State = "error"
				previous.Message = e.Error()
				previous.Time = time.Now().Unix()
				b, _ = json.Marshal(previous)
			}
			atomicFile(path, b, 0600)
		}
		time.Sleep(15 * time.Second)
	}
}
