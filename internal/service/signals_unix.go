// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build !windows
// +build !windows

package service

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/httpd"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/telemetry"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
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
	err = common.Reload()
	if err != nil {
		logger.Warn(logSender, "", "error reloading common configs: %v", err)
	}
	err = sftpd.Reload()
	if err != nil {
		logger.Warn(logSender, "", "error reloading sftpd revoked certificates: %v", err)
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
	plugin.Handler.Cleanup()
	common.WaitForTransfers(graceTime)
	os.Exit(0)
}
