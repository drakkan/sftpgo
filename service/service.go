// Package service allows to start and stop the SFTPGo service
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpd"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
)

const (
	logSender = "service"
)

var (
	chars = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
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
	LogVerbose        bool
	LogUTCTime        bool
	LoadDataClean     bool
	LoadDataFrom      string
	LoadDataMode      int
	LoadDataQuotaScan int
	Shutdown          chan bool
	Error             error
}

func (s *Service) initLogger() {
	logLevel := zerolog.DebugLevel
	if !s.LogVerbose {
		logLevel = zerolog.InfoLevel
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

// Start initializes the service
func (s *Service) Start() error {
	s.initLogger()
	logger.Info(logSender, "", "starting SFTPGo %v, config dir: %v, config file: %v, log max size: %v log max backups: %v "+
		"log max age: %v log verbose: %v, log compress: %v, log utc time: %v, load data from: %#v", version.GetAsString(), s.ConfigDir, s.ConfigFile,
		s.LogMaxSize, s.LogMaxBackups, s.LogMaxAge, s.LogVerbose, s.LogCompress, s.LogUTCTime, s.LoadDataFrom)
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

	providerConf := config.GetProviderConf()
	err := common.Initialize(config.GetCommonConfig(), providerConf.GetShared())
	if err != nil {
		logger.Error(logSender, "", "%v", err)
		logger.ErrorToConsole("%v", err)
		os.Exit(1)
	}
	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		logger.Error(logSender, "", "unable to initialize KMS: %v", err)
		logger.ErrorToConsole("unable to initialize KMS: %v", err)
		os.Exit(1)
	}
	mfaConfig := config.GetMFAConfig()
	err = mfaConfig.Initialize()
	if err != nil {
		logger.Error(logSender, "", "unable to initialize MFA: %v", err)
		logger.ErrorToConsole("unable to initialize MFA: %v", err)
		os.Exit(1)
	}
	if err := plugin.Initialize(config.GetPluginsConfig(), s.LogVerbose); err != nil {
		logger.Error(logSender, "", "unable to initialize plugin system: %v", err)
		logger.ErrorToConsole("unable to initialize plugin system: %v", err)
		os.Exit(1)
	}
	smtpConfig := config.GetSMTPConfig()
	err = smtpConfig.Initialize(s.ConfigDir)
	if err != nil {
		logger.Error(logSender, "", "unable to initialize SMTP configuration: %v", err)
		logger.ErrorToConsole("unable to initialize SMTP configuration: %v", err)
		os.Exit(1)
	}
	err = dataprovider.Initialize(providerConf, s.ConfigDir, s.PortableMode == 0)
	if err != nil {
		logger.Error(logSender, "", "error initializing data provider: %v", err)
		logger.ErrorToConsole("error initializing data provider: %v", err)
		return err
	}

	if s.PortableMode == 1 {
		// create the user for portable mode
		err = dataprovider.AddUser(&s.PortableUser, dataprovider.ActionExecutorSystem, "")
		if err != nil {
			logger.ErrorToConsole("error adding portable user: %v", err)
			return err
		}
	}

	if err := registerAWSContainer(); err != nil {
		logger.Error(logSender, "", "error registering AWS container: %v", err)
		logger.ErrorToConsole("error registering AWS container: %v", err)
		return err
	}

	err = s.LoadInitialData()
	if err != nil {
		logger.Error(logSender, "", "unable to load initial data: %v", err)
		logger.ErrorToConsole("unable to load initial data: %v", err)
	}

	httpConfig := config.GetHTTPConfig()
	err = httpConfig.Initialize(s.ConfigDir)
	if err != nil {
		logger.Error(logSender, "", "error initializing http client: %v", err)
		logger.ErrorToConsole("error initializing http client: %v", err)
		return err
	}

	s.startServices()
	go common.Config.ExecuteStartupHook() //nolint:errcheck

	return nil
}

func (s *Service) startServices() {
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
			if err := httpdConf.Initialize(s.ConfigDir); err != nil {
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
		return fmt.Errorf("invalid input_file %#v, it must be an absolute path", s.LoadDataFrom)
	}
	if s.LoadDataMode < 0 || s.LoadDataMode > 1 {
		return fmt.Errorf("invalid loaddata-mode %v", s.LoadDataMode)
	}
	if s.LoadDataQuotaScan < 0 || s.LoadDataQuotaScan > 2 {
		return fmt.Errorf("invalid loaddata-scan %v", s.LoadDataQuotaScan)
	}
	info, err := os.Stat(s.LoadDataFrom)
	if err != nil {
		return fmt.Errorf("unable to stat file %#v: %w", s.LoadDataFrom, err)
	}
	if info.Size() > httpd.MaxRestoreSize {
		return fmt.Errorf("unable to restore input file %#v size too big: %v/%v bytes",
			s.LoadDataFrom, info.Size(), httpd.MaxRestoreSize)
	}
	content, err := os.ReadFile(s.LoadDataFrom)
	if err != nil {
		return fmt.Errorf("unable to read input file %#v: %w", s.LoadDataFrom, err)
	}
	dump, err := dataprovider.ParseDumpData(content)
	if err != nil {
		return fmt.Errorf("unable to parse file to restore %#v: %w", s.LoadDataFrom, err)
	}
	err = s.restoreDump(&dump)
	if err != nil {
		return err
	}
	logger.Info(logSender, "", "data loaded from file %#v mode: %v", s.LoadDataFrom, s.LoadDataMode)
	logger.InfoToConsole("data loaded from file %#v mode: %v", s.LoadDataFrom, s.LoadDataMode)
	if s.LoadDataClean {
		err = os.Remove(s.LoadDataFrom)
		if err == nil {
			logger.Info(logSender, "", "file %#v deleted after successful load", s.LoadDataFrom)
			logger.InfoToConsole("file %#v deleted after successful load", s.LoadDataFrom)
		} else {
			logger.Warn(logSender, "", "unable to delete file %#v after successful load: %v", s.LoadDataFrom, err)
			logger.WarnToConsole("unable to delete file %#v after successful load: %v", s.LoadDataFrom, err)
		}
	}
	return nil
}

func (s *Service) restoreDump(dump *dataprovider.BackupData) error {
	err := httpd.RestoreFolders(dump.Folders, s.LoadDataFrom, s.LoadDataMode, s.LoadDataQuotaScan, dataprovider.ActionExecutorSystem, "")
	if err != nil {
		return fmt.Errorf("unable to restore folders from file %#v: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreUsers(dump.Users, s.LoadDataFrom, s.LoadDataMode, s.LoadDataQuotaScan, dataprovider.ActionExecutorSystem, "")
	if err != nil {
		return fmt.Errorf("unable to restore users from file %#v: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreAdmins(dump.Admins, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "")
	if err != nil {
		return fmt.Errorf("unable to restore admins from file %#v: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreAPIKeys(dump.APIKeys, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "")
	if err != nil {
		return fmt.Errorf("unable to restore API keys from file %#v: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreShares(dump.Shares, s.LoadDataFrom, s.LoadDataMode, dataprovider.ActionExecutorSystem, "")
	if err != nil {
		return fmt.Errorf("unable to restore API keys from file %#v: %v", s.LoadDataFrom, err)
	}
	return nil
}
