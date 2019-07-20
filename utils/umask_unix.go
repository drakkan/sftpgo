// +build !windows

package utils

import (
	"syscall"

	"github.com/drakkan/sftpgo/logger"
)

// SetUmask set umask on unix systems
func SetUmask(umask int, configValue string) {
	logger.Debug(logSender, "set umask to %v (%v)", configValue, umask)
	syscall.Umask(umask)
}
