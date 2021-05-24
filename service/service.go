// Package service allows to start and stop the SFTPGo service
package service

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/fsmeta"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
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
	if !filepath.IsAbs(s.LogFilePath) && utils.IsFileInputValid(s.LogFilePath) {
		s.LogFilePath = filepath.Join(s.ConfigDir, s.LogFilePath)
	}
	logger.InitLogger(s.LogFilePath, s.LogMaxSize, s.LogMaxBackups, s.LogMaxAge, s.LogCompress, logLevel)
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
		"log max age: %v log verbose: %v, log compress: %v, load data from: %#v", version.GetAsString(), s.ConfigDir, s.ConfigFile,
		s.LogMaxSize, s.LogMaxBackups, s.LogMaxAge, s.LogVerbose, s.LogCompress, s.LoadDataFrom)
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

	err := common.Initialize(config.GetCommonConfig())
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

	providerConf := config.GetProviderConf()

	err = dataprovider.Initialize(providerConf, s.ConfigDir, s.PortableMode == 0)
	if err != nil {
		logger.Error(logSender, "", "error initializing data provider: %v", err)
		logger.ErrorToConsole("error initializing data provider: %v", err)
		return err
	}

	fsMetaConfig := config.GetFSMetaConfig()
	if err := fsmeta.Initialize(fsMetaConfig); err != nil {
		logger.Error(logSender, "", "error initializing fsmeta provider: %v", err)
		logger.ErrorToConsole("error initializing fsmeta provider: %v", err)
		return err
	}

	if s.PortableMode == 1 {
		// create the user for portable mode
		err = dataprovider.AddUser(&s.PortableUser)
		if err != nil {
			logger.ErrorToConsole("error adding portable user: %v", err)
			return err
		}
	}

	err = s.loadInitialData()
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
			logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
			if err := sftpdConf.Initialize(s.ConfigDir); err != nil {
				logger.Error(logSender, "", "could not start SFTP server: %v", err)
				logger.ErrorToConsole("could not start SFTP server: %v", err)
				s.Error = err
			}
			s.Shutdown <- true
		}()
	} else {
		logger.Debug(logSender, "", "SFTP server not started, disabled in config file")
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
		logger.Debug(logSender, "", "HTTP server not started, disabled in config file")
		if s.PortableMode != 1 {
			logger.DebugToConsole("HTTP server not started, disabled in config file")
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
		logger.Debug(logSender, "", "FTP server not started, disabled in config file")
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
		logger.Debug(logSender, "", "WebDAV server not started, disabled in config file")
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
		logger.Debug(logSender, "", "telemetry server not started, disabled in config file")
		if s.PortableMode != 1 {
			logger.DebugToConsole("telemetry server not started, disabled in config file")
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

func (s *Service) loadInitialData() error {
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
		return err
	}
	if info.Size() > httpd.MaxRestoreSize {
		return fmt.Errorf("unable to restore input file %#v size too big: %v/%v bytes",
			s.LoadDataFrom, info.Size(), httpd.MaxRestoreSize)
	}
	content, err := ioutil.ReadFile(s.LoadDataFrom)
	if err != nil {
		return fmt.Errorf("unable to read input file %#v: %v", s.LoadDataFrom, err)
	}
	dump, err := dataprovider.ParseDumpData(content)
	if err != nil {
		return fmt.Errorf("unable to parse file to restore %#v: %v", s.LoadDataFrom, err)
	}
	err = s.restoreDump(dump)
	if err != nil {
		return err
	}
	logger.Info(logSender, "", "data loaded from file %#v mode: %v, quota scan %v", s.LoadDataFrom,
		s.LoadDataMode, s.LoadDataQuotaScan)
	logger.InfoToConsole("data loaded from file %#v mode: %v, quota scan %v", s.LoadDataFrom,
		s.LoadDataMode, s.LoadDataQuotaScan)
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

func (s *Service) restoreDump(dump dataprovider.BackupData) error {
	err := httpd.RestoreAdmins(dump.Admins, s.LoadDataFrom, s.LoadDataMode)
	if err != nil {
		return fmt.Errorf("unable to restore admins from file %#v: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreFolders(dump.Folders, s.LoadDataFrom, s.LoadDataMode, s.LoadDataQuotaScan)
	if err != nil {
		return fmt.Errorf("unable to restore folders from file %#v: %v", s.LoadDataFrom, err)
	}
	err = httpd.RestoreUsers(dump.Users, s.LoadDataFrom, s.LoadDataMode, s.LoadDataQuotaScan)
	if err != nil {
		return fmt.Errorf("unable to restore users from file %#v: %v", s.LoadDataFrom, err)
	}
	return nil
}
