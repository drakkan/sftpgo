//go:build !windows
// +build !windows

package vfs

import (
	"os"
	"syscall"
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
