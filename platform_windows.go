//go:build windows

package main

import (
	"errors"
	"os"
	"sync"
)

var configLock sync.Mutex

func replaceFile(from, to string) error {
	// MoveFileEx through Go's os.Rename supports replacement on Windows.
	return os.Rename(from, to)
}
func lockConfig(dir string) (func(), error) { configLock.Lock(); return configLock.Unlock, nil }
func prepareFlash(dir string, size int) error {
	return errors.New("Flash preparation is available only on the L3+ Linux controller")
}
func hardwareLayout() (any, error) {
	return nil, errors.New("Controller partition diagnostics are available on the miner")
}
func startFlashWorker(dir string, expectedSHA string) error {
	return errors.New("Cannot flash from Windows preview")
}
func deferredReboot() error { return errors.New("Cannot reboot from Windows preview") }
func flashWorker(dir string, expectedSHA string) error {
	return errors.New("Cannot flash from Windows preview")
}
