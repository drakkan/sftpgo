// +build !windows

package service

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/drakkan/sftpgo/logger"
)

func registerSigUSR1() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1)
	go func() {
		for range sig {
			logger.Debug(logSender, "", "Received log file rotation request")
			err := logger.RotateLogFile()
			if err != nil {
				logger.Warn(logSender, "", "error rotating log file: %v", err)
			}
		}
	}()
}
