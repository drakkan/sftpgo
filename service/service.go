// Package service allows to start and stop the SFTPGo service
package service

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
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
	LogCompress   bool
	LogVerbose    bool
	PortableMode  int
	PortableUser  dataprovider.User
	Shutdown      chan bool
}

// Start initializes the service
func (s *Service) Start() error {
	logLevel := zerolog.DebugLevel
	if !s.LogVerbose {
		logLevel = zerolog.InfoLevel
	}
	logger.InitLogger(s.LogFilePath, s.LogMaxSize, s.LogMaxBackups, s.LogMaxAge, s.LogCompress, logLevel)
	version := utils.GetAppVersion()
	logger.Info(logSender, "", "starting SFTPGo %v, config dir: %v, config file: %v, log max size: %v log max backups: %v "+
		"log max age: %v log verbose: %v, log compress: %v", version.GetVersionAsString(), s.ConfigDir, s.ConfigFile, s.LogMaxSize,
		s.LogMaxBackups, s.LogMaxAge, s.LogVerbose, s.LogCompress)
	// in portable mode we don't read configuration from file
	if s.PortableMode != 1 {
		config.LoadConfig(s.ConfigDir, s.ConfigFile)
	}
	providerConf := config.GetProviderConf()

	err := dataprovider.Initialize(providerConf, s.ConfigDir)
	if err != nil {
		logger.Error(logSender, "", "error initializing data provider: %v", err)
		logger.ErrorToConsole("error initializing data provider: %v", err)
		return err
	}

	dataProvider := dataprovider.GetProvider()
	sftpdConf := config.GetSFTPDConfig()
	httpdConf := config.GetHTTPDConfig()

	if s.PortableMode == 1 {
		// create the user for portable mode
		err = dataprovider.AddUser(dataProvider, s.PortableUser)
		if err != nil {
			logger.ErrorToConsole("error adding portable user: %v", err)
			return err
		}
	}

	sftpd.SetDataProvider(dataProvider)

	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(s.ConfigDir); err != nil {
			logger.Error(logSender, "", "could not start SFTP server: %v", err)
			logger.ErrorToConsole("could not start SFTP server: %v", err)
		}
		s.Shutdown <- true
	}()

	if httpdConf.BindPort > 0 {
		httpd.SetDataProvider(dataProvider)

		go func() {
			if err := httpdConf.Initialize(s.ConfigDir); err != nil {
				logger.Error(logSender, "", "could not start HTTP server: %v", err)
				logger.ErrorToConsole("could not start HTTP server: %v", err)
			}
			s.Shutdown <- true
		}()
	} else {
		logger.Debug(logSender, "", "HTTP server not started, disabled in config file")
		if s.PortableMode != 1 {
			logger.DebugToConsole("HTTP server not started, disabled in config file")
		}
	}
	if s.PortableMode == 1 {
		logger.InfoToConsole("Portable mode ready, SFTP port: %v, user: %#v, password: %#v, public keys: %v, directory: %#v, permissions: %v,"+
			" SCP enabled: %v", sftpdConf.BindPort, s.PortableUser.Username, s.PortableUser.Password, s.PortableUser.PublicKeys,
			s.PortableUser.HomeDir, s.PortableUser.Permissions, sftpdConf.IsSCPEnabled)
	}
	return nil
}

// Wait blocks until the service exits
func (s *Service) Wait() {
	<-s.Shutdown
}

// Stop terminates the service unblocking the Wait method
func (s *Service) Stop() {
	close(s.Shutdown)
	logger.Debug(logSender, "", "Service stopped")
}

// StartPortableMode starts the service in portable mode
func (s *Service) StartPortableMode(sftpdPort int, enableSCP bool) error {
	rand.Seed(time.Now().UnixNano())
	if s.PortableMode != 1 {
		return fmt.Errorf("service is not configured for portable mode")
	}
	if len(s.PortableUser.Username) == 0 {
		s.PortableUser.Username = "user"
	}
	if len(s.PortableUser.PublicKeys) == 0 && len(s.PortableUser.Password) == 0 {
		var b strings.Builder
		for i := 0; i < 8; i++ {
			b.WriteRune(chars[rand.Intn(len(chars))])
		}
		s.PortableUser.Password = b.String()
	}
	tempDir := os.TempDir()
	instanceID := xid.New().String()
	databasePath := filepath.Join(tempDir, instanceID+".db")
	s.LogFilePath = filepath.Join(tempDir, instanceID+".log")
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Driver = dataprovider.BoltDataProviderName
	dataProviderConf.Name = databasePath
	config.SetProviderConf(dataProviderConf)
	httpdConf := config.GetHTTPDConfig()
	httpdConf.BindPort = 0
	config.SetHTTPDConfig(httpdConf)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.MaxAuthTries = 12
	if sftpdPort > 0 {
		sftpdConf.BindPort = sftpdPort
	} else {
		// dynamic ports starts from 49152
		sftpdConf.BindPort = 49152 + rand.Intn(15000)
	}
	sftpdConf.IsSCPEnabled = enableSCP
	config.SetSFTPDConfig(sftpdConf)

	return s.Start()
}
