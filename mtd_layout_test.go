package main

import (
	"strings"
	"testing"
)

const stockL3MTD = `dev:    size   erasesize  name
mtd0: 00020000 00020000 "spl"
mtd1: 00020000 00020000 "spl_backup1"
mtd2: 00020000 00020000 "spl_backup2"
mtd3: 00020000 00020000 "spl_backup3"
mtd4: 001c0000 00020000 "u-boot"
mtd5: 00020000 00020000 "bootenv"
mtd6: 00020000 00020000 "fdt"
mtd7: 00500000 00020000 "kernel"
mtd8: 01400000 00020000 "root"
mtd9: 01400000 00020000 "config"
`

func TestStockL3RootLabel(t *testing.T) {
	parts, e := parseMTD([]byte(stockL3MTD))
	if e != nil {
		t.Fatal(e)
	}
	p, e := validateL3Root(parts)
	if e != nil || p.Size != 20*1024*1024 || p.Label != "root" {
		t.Fatalf("Stock root must be accepted: %v %v", p, e)
	}
}
func TestRejectWrongNANDLayout(t *testing.T) {
	for _, mutate := range []struct{ From, To string }{{`"root"`, `"config"`}, {`"root"`, `"not-rootfs"`}, {`"kernel"`, `"bootloader"`}, {`"config"`, `"data"`}, {`mtd8: 01400000`, `mtd8: 01000000`}, {`mtd8: 01400000 00020000`, `mtd8: 01400000 00010000`}, {`mtd6:`, `mtd16:`}} {
		raw := strings.Replace(stockL3MTD, mutate.From, mutate.To, 1)
		p, e := parseMTD([]byte(raw))
		if e == nil {
			_, e = validateL3Root(p)
		}
		if e == nil {
			t.Fatalf("Unsafe layout accepted: %s -> %s", mutate.From, mutate.To)
		}
	}
}
func TestRejectMalformedMTD(t *testing.T) {
	for _, raw := range []string{"", stockL3MTD + `mtd8: 01400000 00020000 "root"`, strings.Replace(stockL3MTD, "01400000", "ffffffff", 1), strings.Replace(stockL3MTD, `"root"`, "root", 1)} {
		if _, e := parseMTD([]byte(raw)); e == nil {
			t.Fatal("Malformed partition table accepted")
		}
	}
}
