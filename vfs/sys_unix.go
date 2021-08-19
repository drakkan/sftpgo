//go:build !windows
// +build !windows

package vfs

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isCrossDeviceError(err error) bool {
	return errors.Is(err, unix.EXDEV)
}
