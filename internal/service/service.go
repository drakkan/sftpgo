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

// Package service allows to start and stop the SFTPGo service
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpd"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	logSender = "service"
)

var (
	chars     = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	graceTime int
)

// Service defines the SFTPGo service
type Service struct {
	ConfigDir         string
	ConfigFile        string
	LogFilePath       string
	LogMaxSize        int
	LogMaxBackups     int
	LogMaxAge         int
	PortableMode      int
	PortableUser      dataprovider.User
	LogCompress       bool
	LogLevel          string
	LogUTCTime        bool
	LoadDataClean     bool
	LoadDataFrom      string
	LoadDataMode      int
	LoadDataQuotaScan int
	Shutdown          chan bool
	Error             error
}

func (s *Service) initLogger() {
	var logLevel zerolog.Level
	switch s.LogLevel {
	case "info":
		logLevel = zerolog.InfoLevel
	case "warn":
		logLevel = zerolog.WarnLevel
	case "error":
		logLevel = zerolog.ErrorLevel
	default:
		logLevel = zerolog.DebugLevel
	}
	if !filepath.IsAbs(s.LogFilePath) && util.IsFileInputValid(s.LogFilePath) {
		s.LogFilePath = filepath.Join(s.ConfigDir, s.LogFilePath)
	}
	logger.InitLogger(s.LogFilePath, s.LogMaxSize, s.LogMaxBackups, s.LogMaxAge, s.LogCompress, s.LogUTCTime, logLevel)
	if s.PortableMode == 1 {
		logger.EnableConsoleLogger(logLevel)
		if s.LogFilePath == "" {
			logger.DisableLogger()
		}
	}
}

// Start initializes and starts the service
func (s *Service) Start(disableAWSInstallationCode bool) error {
	s.initLogger()
	logger.Info(logSender, "", "starting SFTPGo %s, config dir: %s, config file: %s, log max size: %d log max backups: %d "+
		"log max age: %d log level: %s, log compress: %t, log utc time: %t, load data from: %q, grace time: %d secs",
		version.GetAsString(), s.ConfigDir, s.ConfigFile, s.LogMaxSize, s.LogMaxBackups, s.LogMaxAge, s.LogLevel,
		s.LogCompress, s.LogUTCTime, s.LoadDataFrom, graceTime)
	// in portable mode we don't read configuration from file
	if s.PortableMode != 1 {
		err := config.LoadConfig(s.ConfigDir, s.ConfigFile)
		if err != nil {
			logger.Error(logSender, "", "error loading configuration: %v", err)
			return err
		}
	}
	if !config.HasServicesToStart() {
		infoString := "no service configured, nothing to do"
		logger.Info(logSender, "", infoString)
		logger.InfoToConsole(infoString)
		return errors.New(infoString)
	}

	if err := s.initializeServices(disableAWSInstallationCode); err != nil {
		return err
	}

	s.startServices()
	go common.Config.ExecuteStartupHook() //nolint:errcheck

	return nil
}

func (s *Service) initializeServices(disableAWSInstallationCode bool) error {
	providerConf := config.GetProviderConf()
	kmsConfig := config.GetKMSConfig()
	err := kmsConfig.Initialize()
	if err != nil {
		logger.Error(logSender, "", "unable to initialize KMS: %v", err)
		logger.ErrorToConsole("unable to initialize KMS: %v", err)
		return err
	}
	mfaConfig := config.GetMFAConfig()
	err = mfaConfig.Initialize()
	if err != nil {
		logger.Error(logSender, "", "unable to initialize MFA: %v", err)
		logger.ErrorToConsole("unable to initialize MFA: %v", err)
		return err
	}
	err = dataprovider.Initialize(providerConf, s.ConfigDir, s.PortableMode == 0)
	if err != nil {
		logger.Error(logSender, "", "error initializing data provider: %v", err)
		logger.ErrorToConsole("error initializing data provider: %v", err)
		return err
	}
	if err := plugin.Initialize(config.GetPluginsConfig(), s.LogLevel); err != nil {
		logger.Error(logSender, "", "unable to initialize plugin system: %v", err)
		logger.ErrorToConsole("unable to initialize plugin system: %v", err)
		return err
	}
	smtpConfig := config.GetSMTPConfig()
	err = smtpConfig.Initialize(s.ConfigDir, s.PortableMode != 1)
	if err != nil {
		logger.Error(logSender, "", "unable to initialize SMTP configuration: %v", err)
		logger.ErrorToConsole("unable to initialize SMTP configuration: %v", err)
		return err
	}
	err = common.Initialize(config.GetCommonConfig(), providerConf.GetShared())
	if err != nil {
		logger.Error(logSender, "", "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	}

	if s.PortableMode == 1 {
		// create the user for portable mode
		err = dataprovider.AddUser(&s.PortableUser, dataprovider.ActionExecutorSystem, "", "")
		if err != nil {
			logger.ErrorToConsole("error adding portable user: %v", err)
			return err
		}
	} else {
		acmeConfig := config.GetACMEConfig()
		err = acme.Initialize(acmeConfig, s.ConfigDir, true)
		if err != nil {
			logger.Error(logSender, "", "error initializing ACME configuration: %v", err)
			logger.ErrorToConsole("error initializing ACME configuration: %v", err)
			return err
		}
	}

	if err := registerAWSContainer(disableAWSInstallationCode); err != nil {
		logger.Error(logSender, "", "error registering AWS container: %v", err)
		logger.ErrorToConsole("error registering AWS container: %v", err)
		return err
	}

	httpConfig := config.GetHTTPConfig()
	err = httpConfig.Initialize(s.ConfigDir)
	if err != nil {
		logger.Error(logSender, "", "error initializing http client: %v", err)
		logger.ErrorToConsole("error initializing http client: %v", err)
		return err
	}
	commandConfig := config.GetCommandConfig()
	if err := commandConfig.Initialize(); err != nil {
		logger.Error(logSender, "", "error initializing commands configuration: %v", err)
		logger.ErrorToConsole("error initializing commands configuration: %v", err)
		return err
	}

	return nil
}

func (s *Service) startServices() {
	err := s.LoadInitialData()
	if err != nil {
		logger.Error(logSender, "", "unable to load initial data: %v", err)
		logger.ErrorToConsole("unable to load initial data: %v", err)
	}

	sftpdConf := config.GetSFTPDConfig()
	ftpdConf := config.GetFTPDConfig()
	httpdConf := config.GetHTTPDConfig()
	webDavDConf := config.GetWebDAVDConfig()
	telemetryConf := config.GetTelemetryConfig()

	if sftpdConf.ShouldBind() {
		go func() {
			redactedConf := sftpdConf
			redactedConf.KeyboardInteractiveHook = util.GetRedactedURL(sftpdConf.KeyboardInteractiveHook)
			logger.Info(logSender, "", "initializing SFTP server with config %+v", redactedConf)
			if err := sftpdConf.Initialize(s.ConfigDir); err != nil {
				logger.Error(logSender, "", "could not start SFTP server: %v", err)
				logger.ErrorToConsole("could not start SFTP server: %v", err)
				s.Error = err
			}
			s.Shutdown <- true
		}()
	} else {
		logger.Info(logSender, "", "SFTP server not started, disabled in config file")
	}

	if httpdConf.ShouldBind() {
		go func() {
			providerConf := config.GetProviderConf()
			if err := httpdConf.Initialize(s.ConfigDir, providerConf.GetShared()); err != nil {
				logger.Error(logSender, "", "could not start HTTP server: %v", err)
				logger.ErrorToConsole("could not start HTTP server: %v", err)
				s.Error = err
			}
			s.Shutdown <- true
		}()
	} else {
		logger.Info(logSender, "", "HTTP server not started, disabled in config file")
		if s.PortableMode != 1 {
			logger.InfoToConsole("HTTP server not started, disabled in config file")
		}
	}
	if ftpdConf.ShouldBind() {
		go func() {
			if err := ftpdConf.Initialize(s.ConfigDir); err != nil {
				logger.Error(logSender, "", "could not start FTP server: %v", err)
				logger.ErrorToConsole("could not start FTP server: %v", err)
				s.Error = err
			}
			s.Shutdown <- true
		}()
	} else {
		logger.Info(logSender, "", "FTP server not started, disabled in config file")
	}
	if webDavDConf.ShouldBind() {
		go func() {
			if err := webDavDConf.Initialize(s.ConfigDir); err != nil {
				logger.Error(logSender, "", "could not start WebDAV server: %v", err)
				logger.ErrorToConsole("could not start WebDAV server: %v", err)
				s.Error = err
			}
			s.Shutdown <- true
		}()
	} else {
		logger.Info(logSender, "", "WebDAV server not started, disabled in config file")
	}
	if telemetryConf.ShouldBind() {
		go func() {
			if err := telemetryConf.Initialize(s.ConfigDir); err != nil {
				logger.Error(logSender, "", "could not start telemetry server: %v", err)
				logger.ErrorToConsole("could not start telemetry server: %v", err)
				s.Error = err
			}
			s.Shutdown <- true
		}()
	} else {
		logger.Info(logSender, "", "telemetry server not started, disabled in config file")
		if s.PortableMode != 1 {
			logger.InfoToConsole("telemetry server not started, disabled in config file")
		}
	}
}

// Wait blocks until the service exits
func (s *Service) Wait() {
	if s.PortableMode != 1 {
		registerSignals()
	}
	<-s.Shutdown
}

// Stop terminates the service unblocking the Wait method
func (s *Service) Stop() {
	close(s.Shutdown)
	logger.Debug(logSender, "", "Service stopped")
}

// LoadInitialData if a data file is set
func (s *Service) LoadInitialData() error {
	if s.LoadDataFrom == "" {
		return nil
	}
	if !filepath.IsAbs(s.LoadDataFrom) {
		return fmt.Errorf("invalid input_file %q, it must be an absolute path", s.LoadDataFrom)
	}
	if s.LoadDataMode < 0 || s.LoadDataMode > 1 {
		return fmt.Errorf("invalid loaddata-mode %v", s.LoadDataMode)
	}
	if s.LoadDataQuotaScan < 0 || s.LoadDataQuotaScan > 2 {
		return fmt.Errorf("invalid loaddata-scan %v", s.LoadDataQuotaScan)
	}
	info, err := os.Stat(s.LoadDataFrom)
	if err != nil {
		return fmt.Errorf("unable to stat file %q: %w", s.LoadDataFrom, err)
	}
	if info.Size() > httpd.MaxRestoreSize {
		return fmt.Errorf("unable to restore input file %q size too big: %d/%d bytes",
			s.LoadDataFrom, info.Size(), httpd.MaxRestoreSize)
	}
	content, err := os.ReadFile(s.LoadDataFrom)
	if err != nil {
		return fmt.Errorf("unable to read input file %q: %w", s.LoadDataFrom, err)
	}
	dump, err := dataprovider.ParseDumpData(content)
	if err != nil {
		return fmt.Errorf("unable to parse file to restore %q: %w", s.LoadDataFrom, err)
	}
	err = s.restoreDump(&dump)
	if err != nil {
		return err
	}
	logger.Info(logSender, "", "data loaded from file %q mode: %v", s.LoadDataFrom, s.LoadDataMode)
	logger.InfoToConsole("data loaded from file %q mode: %v", s.LoadDataFrom, s.LoadDataMode)
	if s.LoadDataClean {
		err = os.Remove(s.LoadDataFrom)
		if err == nil {
			logger.Info(logSender, "", "file %q deleted after successful load", s.LoadDataFrom)
			logger.InfoToConsole("file %q deleted after successful load", s.LoadDataFrom)
		} else {
			logger.Warn(logSender, "", "unable to delete file %q after successful load: %v", s.LoadDataFrom, err)
			logger.WarnToConsole("unable to delete file %q after successful load: %v", s.LoadDataFrom, err)
		}
	}
	return nil
}

func (s *Service) restoreDump(dump *dataprovider.BackupData) error {
	err := httpd.RestoreConfigs(dump.Configs, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore configs from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreIPListEntries(dump.IPLists, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore IP list entries from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreRoles(dump.Roles, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore roles from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreFolders(dump.Folders, s.LoadDataFrom, s.LoadDataMode, s.LoadDataQuotaScan, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore folders from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreGroups(dump.Groups, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore groups from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreUsers(dump.Users, s.LoadDataFrom, s.LoadDataMode, s.LoadDataQuotaScan, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore users from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreAdmins(dump.Admins, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore admins from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreAPIKeys(dump.APIKeys, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore API keys from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreShares(dump.Shares, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore API keys from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreEventActions(dump.EventActions, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "", "")
	if err != nil {
		return fmt.Errorf("unable to restore event actions from file %q: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreEventRules(dump.EventRules, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem,
		"", "", dump.Version)
	if err != nil {
		return fmt.Errorf("unable to restore event rules from file %q: %v", s.LoadDataFrom, err)
	}
	return nil
}

// SetGraceTime sets the grace time
func SetGraceTime(val int) {
	graceTime = val
}
