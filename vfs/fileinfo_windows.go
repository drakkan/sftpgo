package vfs

import "syscall"

func (fi FileInfo) getFileInfoSys() interface{} {
	return syscall.Win32FileAttributeData{}
}
