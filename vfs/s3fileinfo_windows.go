package vfs

import "syscall"

func (fi S3FileInfo) getFileInfoSys() interface{} {
	return syscall.Win32FileAttributeData{}
}
