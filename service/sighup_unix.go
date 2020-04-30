// +build !windows

package service

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
)

func registerSigHup() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		for range sig {
			logger.Debug(logSender, "", "Received reload request")
			err := dataprovider.ReloadConfig()
			if err != nil {
				logger.Warn(logSender, "", "error reloading dataprovider configuration: %v", err)
			}
			err = httpd.ReloadTLSCertificate()
			if err != nil {
				logger.Warn(logSender, "", "error reloading TLS certificate: %v", err)
			}
		}
	}()
}
