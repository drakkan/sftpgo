//go:build !linux
// +build !linux

package vfs

func (fs *OsFs) setuid() {
}

func (fs *OsFs) unsetuid() {
}
