//go:build !windows
// +build !windows

package service

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/telemetry"
	"github.com/drakkan/sftpgo/webdavd"
)

func registerSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)
	go func() {
		for sig := range c {
			switch sig {
			case syscall.SIGHUP:
				handleSIGHUP()
			case syscall.SIGUSR1:
				handleSIGUSR1()
			case syscall.SIGINT, syscall.SIGTERM:
				handleInterrupt()
			}
		}
	}()
}

func handleSIGHUP() {
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
	err = common.ReloadDefender()
	if err != nil {
		logger.Warn(logSender, "", "error reloading defender's lists: %v", err)
	}
}

func handleSIGUSR1() {
	logger.Debug(logSender, "", "Received log file rotation request")
	err := logger.RotateLogFile()
	if err != nil {
		logger.Warn(logSender, "", "error rotating log file: %v", err)
	}
}

func handleInterrupt() {
	logger.Debug(logSender, "", "Received interrupt request")
	os.Exit(0)
}
