package vfs

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func (fi FileInfo) getFileInfoSys() interface{} {
	return syscall.Win32FileAttributeData{}
}

func isCrossDeviceError(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SAME_DEVICE)
}
