//go:build linux
// +build linux

package vfs

import (
	"syscall"

	"github.com/peterverraedt/useros"
)

func osAsUser(uid, gid int) useros.OS {
	if syscall.Geteuid() > 0 {
		return useros.Default()
	}

	return useros.User{
		UID: uid,
		GID: gid,
	}.OS()
}
