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

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

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

const (
	serviceName     = "SFTPGo"
	serviceDesc     = "Fully featured and highly configurable SFTP server with optional FTP/S and WebDAV support"
	rotateLogCmd    = svc.Cmd(128)
	acceptRotateLog = svc.Accepted(rotateLogCmd)
)

// Status defines service status
type Status uint8

// Supported values for service status
const (
	StatusUnknown Status = iota
	StatusRunning
	StatusStopped
	StatusPaused
	StatusStartPending
	StatusPausePending
	StatusContinuePending
	StatusStopPending
)

type WindowsService struct {
	Service       Service
	isInteractive bool
}

func (s Status) String() string {
	switch s {
	case StatusRunning:
		return "running"
	case StatusStopped:
		return "stopped"
	case StatusStartPending:
		return "start pending"
	case StatusPausePending:
		return "pause pending"
	case StatusPaused:
		return "paused"
	case StatusContinuePending:
		return "continue pending"
	case StatusStopPending:
		return "stop pending"
	default:
		return "unknown"
	}
}

func (s *WindowsService) handleExit(wasStopped chan bool) {
	s.Service.Wait()

	select {
	case <-wasStopped:
		// the service was stopped nothing to do
		logger.Info(logSender, "", "Windows Service was stopped")
		return
	default:
		// the server failed while running, we must be sure to exit the process.
		// The defined recovery action will be executed.
		logger.Info(logSender, "", "Service wait ended, error: %v", s.Service.Error)
		if s.Service.Error == nil {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}
}

func (s *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	go func() {
		if err := s.Service.Start(false); err != nil {
			logger.Error(logSender, "", "Windows service failed to start, error: %v", err)
			s.Service.Error = err
			s.Service.Shutdown <- true
			return
		}
		logger.Info(logSender, "", "Windows service started")
		cmdsAccepted := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange | acceptRotateLog
		changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	}()

	wasStopped := make(chan bool, 1)

	go s.handleExit(wasStopped)

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			logger.Debug(logSender, "", "Received service interrogate request, current status: %v", c.CurrentStatus)
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			logger.Debug(logSender, "", "Received service stop request")
			changes <- svc.Status{State: svc.StopPending}
			wasStopped <- true
			s.Service.Stop()
			plugin.Handler.Cleanup()
			common.WaitForTransfers(graceTime)
			break loop
		case svc.ParamChange:
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
		case rotateLogCmd:
			logger.Debug(logSender, "", "Received log file rotation request")
			err := logger.RotateLogFile()
			if err != nil {
				logger.Warn(logSender, "", "error rotating log file: %v", err)
			}
		default:
			continue loop
		}
	}

	return false, 0
}

func (s *WindowsService) RunService() error {
	exePath, err := s.getExePath()
	if err != nil {
		return err
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	s.isInteractive = !isService
	dir := filepath.Dir(exePath)
	if err = os.Chdir(dir); err != nil {
		return err
	}
	if s.isInteractive {
		return s.Start()
	}
	return svc.Run(serviceName, s)
}

func (s *WindowsService) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer service.Close()
	err = service.Start()
	if err != nil {
		return fmt.Errorf("could not start service: %v", err)
	}
	return nil
}

func (s *WindowsService) Reload() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer service.Close()
	_, err = service.Control(svc.ParamChange)
	if err != nil {
		return fmt.Errorf("could not send control=%d: %v", svc.ParamChange, err)
	}
	return nil
}

func (s *WindowsService) RotateLogFile() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer service.Close()
	_, err = service.Control(rotateLogCmd)
	if err != nil {
		return fmt.Errorf("could not send control=%d: %v", rotateLogCmd, err)
	}
	return nil
}

func (s *WindowsService) Install(args ...string) error {
	exePath, err := s.getExePath()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err == nil {
		service.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}
	config := mgr.Config{
		DisplayName: serviceName,
		Description: serviceDesc,
		StartType:   mgr.StartAutomatic}
	service, err = m.CreateService(serviceName, exePath, config, args...)
	if err != nil {
		return err
	}
	defer service.Close()
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		if !strings.Contains(err.Error(), "exists") {
			service.Delete()
			return fmt.Errorf("SetupEventLogSource() failed: %s", err)
		}
	}
	recoveryActions := []mgr.RecoveryAction{
		{
			Type:  mgr.ServiceRestart,
			Delay: 5 * time.Second,
		},
		{
			Type:  mgr.ServiceRestart,
			Delay: 60 * time.Second,
		},
		{
			Type:  mgr.ServiceRestart,
			Delay: 90 * time.Second,
		},
	}
	err = service.SetRecoveryActions(recoveryActions, 300)
	if err != nil {
		service.Delete()
		return fmt.Errorf("unable to set recovery actions: %v", err)
	}
	return nil
}

func (s *WindowsService) Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer service.Close()
	err = service.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(serviceName)
	if err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}
	return nil
}

func (s *WindowsService) Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer service.Close()
	status, err := service.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("could not send control=%d: %v", svc.Stop, err)
	}
	timeout := time.Now().Add(10 * time.Second)
	for status.State != svc.Stopped {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to go to state=%d", svc.Stopped)
		}
		time.Sleep(300 * time.Millisecond)
		status, err = service.Query()
		if err != nil {
			return fmt.Errorf("could not retrieve service status: %v", err)
		}
	}
	return nil
}

func (s *WindowsService) Status() (Status, error) {
	m, err := mgr.Connect()
	if err != nil {
		return StatusUnknown, err
	}
	defer m.Disconnect()
	service, err := m.OpenService(serviceName)
	if err != nil {
		return StatusUnknown, fmt.Errorf("could not access service: %v", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return StatusUnknown, fmt.Errorf("could not query service status: %v", err)
	}
	switch status.State {
	case svc.StartPending:
		return StatusStartPending, nil
	case svc.Running:
		return StatusRunning, nil
	case svc.PausePending:
		return StatusPausePending, nil
	case svc.Paused:
		return StatusPaused, nil
	case svc.ContinuePending:
		return StatusContinuePending, nil
	case svc.StopPending:
		return StatusStopPending, nil
	case svc.Stopped:
		return StatusStopped, nil
	default:
		return StatusUnknown, fmt.Errorf("unknown status %v", status)
	}
}

func (s *WindowsService) getExePath() (string, error) {
	return os.Executable()
}
