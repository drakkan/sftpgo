// +build !windows

package vfs

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	defaultUID, defaultGID int
)

func init() {
	defaultUID = os.Getuid()
	defaultGID = os.Getuid()
	if defaultUID < 0 {
		defaultUID = 65534
	}
	if defaultGID < 0 {
		defaultGID = 65534
	}
}

func (fi FileInfo) getFileInfoSys() interface{} {
	return &syscall.Stat_t{
		Uid: uint32(defaultUID),
		Gid: uint32(defaultGID)}
}

func isCrossDeviceError(err error) bool {
	return errors.Is(err, unix.EXDEV)
}
