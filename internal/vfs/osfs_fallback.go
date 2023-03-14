//go:build !linux
// +build !linux

package vfs

import "github.com/peterverraedt/useros"

func osAsUser(uid, gid int) useros.OS {
	return useros.Default()
}
