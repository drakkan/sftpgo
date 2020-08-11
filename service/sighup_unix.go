// +build !windows

package service

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/webdavd"
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
			err = ftpd.ReloadTLSCertificate()
			if err != nil {
				logger.Warn(logSender, "", "error reloading FTPD TLS certificate: %v", err)
			}
			err = webdavd.ReloadTLSCertificate()
			if err != nil {
				logger.Warn(logSender, "", "error reloading WebDav TLS certificate: %v", err)
			}
		}
	}()
}
