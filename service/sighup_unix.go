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
	"github.com/drakkan/sftpgo/telemetry"
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
			err = httpd.ReloadCertificateMgr()
			if err != nil {
				logger.Warn(logSender, "", "error reloading cert manager: %v", err)
			}
			err = ftpd.ReloadCertificateMgr()
			if err != nil {
				logger.Warn(logSender, "", "error reloading FTPD cert manager: %v", err)
			}
			err = webdavd.ReloadCertificateMgr()
			if err != nil {
				logger.Warn(logSender, "", "error reloading WebDAV cert manager: %v", err)
			}
			err = telemetry.ReloadCertificateMgr()
			if err != nil {
				logger.Warn(logSender, "", "error reloading telemetry cert manager: %v", err)
			}
		}
	}()
}
