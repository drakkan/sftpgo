//go:build linux
// +build linux

package vfs

import (
	"runtime"
	"syscall"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

func (fs *OsFs) setuid() {
	if fs.uid <= 0 && fs.gid <= 0 {
		return
	}

	if syscall.Geteuid() > 0 {
		return
	}

	runtime.LockOSThread()

	if fs.gid != syscall.Getegid() && fs.gid > 0 {
		if err := syscall.Setegid(fs.gid); err != nil {
			fsLog(fs, logger.LevelError, "could not call setegid: %q", err)
		}
	}

	if fs.uid != syscall.Geteuid() && fs.uid > 0 {
		if err := syscall.Seteuid(fs.uid); err != nil {
			fsLog(fs, logger.LevelError, "could not call seteuid: %q", err)
		}
	}
}

func (fs *OsFs) unsetuid() {
	if fs.uid <= 0 && fs.gid <= 0 {
		return
	}

	if syscall.Getuid() != syscall.Geteuid() && fs.uid > 0 {
		if err := syscall.Seteuid(syscall.Getuid()); err != nil {
			fsLog(fs, logger.LevelError, "could not call seteuid: %q", err)
		}
	}

	if syscall.Getgid() != syscall.Getegid() && fs.gid > 0 {
		if err := syscall.Setegid(syscall.Getgid()); err != nil {
			fsLog(fs, logger.LevelError, "could not call setegid: %q", err)
		}
	}

	runtime.UnlockOSThread()
}
