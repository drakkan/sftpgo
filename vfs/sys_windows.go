package vfs

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isCrossDeviceError(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SAME_DEVICE)
}

func isInvalidNameError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.ERROR_INVALID_NAME)
}
