package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type MTDPartition struct {
	Index     int    `json:"index"`
	Size      int    `json:"size"`
	EraseSize int    `json:"erase_size"`
	Label     string `json:"label"`
}

var mtdLine = regexp.MustCompile(`^mtd([0-9]+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"([^"]+)"\s*$`)

func parseMTD(b []byte) (map[int]MTDPartition, error) {
	out := map[int]MTDPartition{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "mtd") {
			continue
		}
		m := mtdLine.FindStringSubmatch(line)
		if m == nil {
			return nil, errors.New("Malformed NAND partition table")
		}
		index, e := strconv.Atoi(m[1])
		if e != nil || index > 127 {
			return nil, errors.New("Invalid NAND partition index")
		}
		size, e := strconv.ParseInt(m[2], 16, 32)
		if e != nil {
			return nil, e
		}
		erase, e := strconv.ParseInt(m[3], 16, 32)
		if e != nil {
			return nil, e
		}
		if _, exists := out[index]; exists {
			return nil, errors.New("Duplicate NAND partition index")
		}
		if size <= 0 || erase < 4096 || erase > 1024*1024 || size%erase != 0 {
			return nil, errors.New("Invalid NAND partition geometry")
		}
		out[index] = MTDPartition{Index: index, Size: int(size), EraseSize: int(erase), Label: strings.ToLower(m[4])}
	}
	if len(out) == 0 {
		return nil, errors.New("NAND partition table is empty")
	}
	return out, nil
}
func validateL3Root(parts map[int]MTDPartition) (MTDPartition, error) {
	root, ok := parts[8]
	if !ok {
		return root, errors.New("Expected L3+ NAND rootfs partition mtd8 not found")
	}
	switch root.Label {
	case "root", "rootfs", "romfs", "file-system":
	default:
		return root, fmt.Errorf("mtd8 has unrecognized rootfs label %q", root.Label)
	}
	// Verified from the matching 2019 image's DTB, not inferred from mtd8 alone.
	for _, neighbor := range []struct {
		Index int
		Label string
		Size  int
	}{{6, "fdt", 0x20000}, {7, "kernel", 0x500000}, {9, "config", 0x1400000}} {
		p, exists := parts[neighbor.Index]
		if !exists || p.Label != neighbor.Label || p.Size != neighbor.Size {
			return root, fmt.Errorf("mtd%d does not match the verified L3+ %s partition", neighbor.Index, neighbor.Label)
		}
	}
	if root.Size != 0x1400000 || root.EraseSize != 0x20000 {
		return root, errors.New("Rootfs geometry differs from the verified L3+ 2019 layout")
	}
	return root, nil
}
