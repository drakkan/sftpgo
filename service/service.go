// Package service allows to start and stop the SFTPGo service
package service

import (
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
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
	ConfigDir     string
	ConfigFile    string
	LogFilePath   string
	LogMaxSize    int
	LogMaxBackups int
	LogMaxAge     int
	PortableMode  int
	PortableUser  dataprovider.User
	LogCompress   bool
	LogVerbose    bool
	Profiler      bool
	Shutdown      chan bool
	Error         error
}

// Start initializes the service
func (s *Service) Start() error {
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
		if len(s.LogFilePath) == 0 {
			logger.DisableLogger()
		}
	}
	logger.Info(logSender, "", "starting SFTPGo %v, config dir: %v, config file: %v, log max size: %v log max backups: %v "+
		"log max age: %v log verbose: %v, log compress: %v, profile: %v", version.GetAsString(), s.ConfigDir, s.ConfigFile,
		s.LogMaxSize, s.LogMaxBackups, s.LogMaxAge, s.LogVerbose, s.LogCompress, s.Profiler)
	// in portable mode we don't read configuration from file
	if s.PortableMode != 1 {
		err := config.LoadConfig(s.ConfigDir, s.ConfigFile)
		if err != nil {
			logger.Error(logSender, "", "error loading configuration: %v", err)
		}
	}
	providerConf := config.GetProviderConf()

	err := dataprovider.Initialize(providerConf, s.ConfigDir)
	if err != nil {
		logger.Error(logSender, "", "error initializing data provider: %v", err)
		logger.ErrorToConsole("error initializing data provider: %v", err)
		return err
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(s.ConfigDir)

	sftpdConf := config.GetSFTPDConfig()
	httpdConf := config.GetHTTPDConfig()

	if s.PortableMode == 1 {
		// create the user for portable mode
		err = dataprovider.AddUser(s.PortableUser)
		if err != nil {
			logger.ErrorToConsole("error adding portable user: %v", err)
			return err
		}
	}

	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(s.ConfigDir); err != nil {
			logger.Error(logSender, "", "could not start SFTP server: %v", err)
			logger.ErrorToConsole("could not start SFTP server: %v", err)
			s.Error = err
		}
		s.Shutdown <- true
	}()

	if httpdConf.BindPort > 0 {
		go func() {
			if err := httpdConf.Initialize(s.ConfigDir, s.Profiler); err != nil {
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
	return nil
}

// Wait blocks until the service exits
func (s *Service) Wait() {
	if s.PortableMode != 1 {
		registerSigHup()
		registerSigUSR1()
	}
	<-s.Shutdown
}

// Stop terminates the service unblocking the Wait method
func (s *Service) Stop() {
	close(s.Shutdown)
	logger.Debug(logSender, "", "Service stopped")
}
