//go:build !noportable
// +build !noportable

package service

import (
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/ftpd"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/sftpd"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/webdavd"
)

// StartPortableMode starts the service in portable mode
func (s *Service) StartPortableMode(sftpdPort, ftpPort, webdavPort int, enabledSSHCommands []string, advertiseService,
	advertiseCredentials bool, ftpsCert, ftpsKey, webDavCert, webDavKey string) error {
	if s.PortableMode != 1 {
		return fmt.Errorf("service is not configured for portable mode")
	}
	rand.Seed(time.Now().UnixNano())
	err := config.LoadConfig(s.ConfigDir, s.ConfigFile)
	if err != nil {
		fmt.Printf("error loading configuration file: %v using defaults\n", err)
	}
	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		return err
	}
	printablePassword := s.configurePortableUser()
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Driver = dataprovider.MemoryDataProviderName
	dataProviderConf.Name = ""
	dataProviderConf.PreferDatabaseCredentials = true
	config.SetProviderConf(dataProviderConf)
	httpdConf := config.GetHTTPDConfig()
	httpdConf.Bindings = nil
	config.SetHTTPDConfig(httpdConf)
	telemetryConf := config.GetTelemetryConfig()
	telemetryConf.BindPort = 0
	config.SetTelemetryConfig(telemetryConf)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.MaxAuthTries = 12
	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port: sftpdPort,
		},
	}
	if sftpdPort >= 0 {
		if sftpdPort > 0 {
			sftpdConf.Bindings[0].Port = sftpdPort
		} else {
			// dynamic ports starts from 49152
			sftpdConf.Bindings[0].Port = 49152 + rand.Intn(15000)
		}
		if util.IsStringInSlice("*", enabledSSHCommands) {
			sftpdConf.EnabledSSHCommands = sftpd.GetSupportedSSHCommands()
		} else {
			sftpdConf.EnabledSSHCommands = enabledSSHCommands
		}
	}
	config.SetSFTPDConfig(sftpdConf)

	if ftpPort >= 0 {
		ftpConf := config.GetFTPDConfig()
		binding := ftpd.Binding{}
		if ftpPort > 0 {
			binding.Port = ftpPort
		} else {
			binding.Port = 49152 + rand.Intn(15000)
		}
		ftpConf.Bindings = []ftpd.Binding{binding}
		ftpConf.Banner = fmt.Sprintf("SFTPGo portable %v ready", version.Get().Version)
		ftpConf.CertificateFile = ftpsCert
		ftpConf.CertificateKeyFile = ftpsKey
		config.SetFTPDConfig(ftpConf)
	}

	if webdavPort >= 0 {
		webDavConf := config.GetWebDAVDConfig()
		binding := webdavd.Binding{}
		if webdavPort > 0 {
			binding.Port = webdavPort
		} else {
			binding.Port = 49152 + rand.Intn(15000)
		}
		webDavConf.Bindings = []webdavd.Binding{binding}
		webDavConf.CertificateFile = webDavCert
		webDavConf.CertificateKeyFile = webDavKey
		config.SetWebDAVDConfig(webDavConf)
	}

	err = s.Start()
	if err != nil {
		return err
	}

	s.advertiseServices(advertiseService, advertiseCredentials)

	logger.InfoToConsole("Portable mode ready, user: %#v, password: %#v, public keys: %v, directory: %#v, "+
		"permissions: %+v, enabled ssh commands: %v file patterns filters: %+v %v", s.PortableUser.Username,
		printablePassword, s.PortableUser.PublicKeys, s.getPortableDirToServe(), s.PortableUser.Permissions,
		sftpdConf.EnabledSSHCommands, s.PortableUser.Filters.FilePatterns, s.getServiceOptionalInfoString())
	return nil
}

func (s *Service) getServiceOptionalInfoString() string {
	var info strings.Builder
	if config.GetSFTPDConfig().Bindings[0].IsValid() {
		info.WriteString(fmt.Sprintf("SFTP port: %v ", config.GetSFTPDConfig().Bindings[0].Port))
	}
	if config.GetFTPDConfig().Bindings[0].IsValid() {
		info.WriteString(fmt.Sprintf("FTP port: %v ", config.GetFTPDConfig().Bindings[0].Port))
	}
	if config.GetWebDAVDConfig().Bindings[0].IsValid() {
		scheme := "http"
		if config.GetWebDAVDConfig().CertificateFile != "" && config.GetWebDAVDConfig().CertificateKeyFile != "" {
			scheme = "https"
		}
		info.WriteString(fmt.Sprintf("WebDAV URL: %v://<your IP>:%v/", scheme, config.GetWebDAVDConfig().Bindings[0].Port))
	}
	return info.String()
}

func (s *Service) advertiseServices(advertiseService, advertiseCredentials bool) {
	var mDNSServiceSFTP *zeroconf.Server
	var mDNSServiceFTP *zeroconf.Server
	var mDNSServiceDAV *zeroconf.Server
	var err error

	if advertiseService {
		meta := []string{
			fmt.Sprintf("version=%v", version.Get().Version),
		}
		if advertiseCredentials {
			logger.InfoToConsole("Advertising credentials via multicast DNS")
			meta = append(meta, fmt.Sprintf("user=%v", s.PortableUser.Username))
			if len(s.PortableUser.Password) > 0 {
				meta = append(meta, fmt.Sprintf("password=%v", s.PortableUser.Password))
			} else {
				logger.InfoToConsole("Unable to advertise key based credentials via multicast DNS, we don't have the private key")
			}
		}
		sftpdConf := config.GetSFTPDConfig()
		if sftpdConf.Bindings[0].IsValid() {
			mDNSServiceSFTP, err = zeroconf.Register(
				fmt.Sprintf("SFTPGo portable %v", sftpdConf.Bindings[0].Port), // service instance name
				"_sftp-ssh._tcp",           // service type and protocol
				"local.",                   // service domain
				sftpdConf.Bindings[0].Port, // service port
				meta,                       // service metadata
				nil,                        // register on all network interfaces
			)
			if err != nil {
				mDNSServiceSFTP = nil
				logger.WarnToConsole("Unable to advertise SFTP service via multicast DNS: %v", err)
			} else {
				logger.InfoToConsole("SFTP service advertised via multicast DNS")
			}
		}
		ftpdConf := config.GetFTPDConfig()
		if ftpdConf.Bindings[0].IsValid() {
			port := ftpdConf.Bindings[0].Port
			mDNSServiceFTP, err = zeroconf.Register(
				fmt.Sprintf("SFTPGo portable %v", port),
				"_ftp._tcp",
				"local.",
				port,
				meta,
				nil,
			)
			if err != nil {
				mDNSServiceFTP = nil
				logger.WarnToConsole("Unable to advertise FTP service via multicast DNS: %v", err)
			} else {
				logger.InfoToConsole("FTP service advertised via multicast DNS")
			}
		}
		webdavConf := config.GetWebDAVDConfig()
		if webdavConf.Bindings[0].IsValid() {
			mDNSServiceDAV, err = zeroconf.Register(
				fmt.Sprintf("SFTPGo portable %v", webdavConf.Bindings[0].Port),
				"_http._tcp",
				"local.",
				webdavConf.Bindings[0].Port,
				meta,
				nil,
			)
			if err != nil {
				mDNSServiceDAV = nil
				logger.WarnToConsole("Unable to advertise WebDAV service via multicast DNS: %v", err)
			} else {
				logger.InfoToConsole("WebDAV service advertised via multicast DNS")
			}
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		if mDNSServiceSFTP != nil {
			logger.InfoToConsole("unregistering multicast DNS SFTP service")
			mDNSServiceSFTP.Shutdown()
		}
		if mDNSServiceFTP != nil {
			logger.InfoToConsole("unregistering multicast DNS FTP service")
			mDNSServiceFTP.Shutdown()
		}
		if mDNSServiceDAV != nil {
			logger.InfoToConsole("unregistering multicast DNS WebDAV service")
			mDNSServiceDAV.Shutdown()
		}
		s.Stop()
	}()
}

func (s *Service) getPortableDirToServe() string {
	var dirToServe string
	if s.PortableUser.FsConfig.Provider == sdk.S3FilesystemProvider {
		dirToServe = s.PortableUser.FsConfig.S3Config.KeyPrefix
	} else if s.PortableUser.FsConfig.Provider == sdk.GCSFilesystemProvider {
		dirToServe = s.PortableUser.FsConfig.GCSConfig.KeyPrefix
	} else {
		dirToServe = s.PortableUser.HomeDir
	}
	return dirToServe
}

// configures the portable user and return the printable password if any
func (s *Service) configurePortableUser() string {
	if s.PortableUser.Username == "" {
		s.PortableUser.Username = "user"
	}
	printablePassword := ""
	if s.PortableUser.Password != "" {
		printablePassword = "[redacted]"
	}
	if len(s.PortableUser.PublicKeys) == 0 && s.PortableUser.Password == "" {
		var b strings.Builder
		for i := 0; i < 8; i++ {
			b.WriteRune(chars[rand.Intn(len(chars))])
		}
		s.PortableUser.Password = b.String()
		printablePassword = s.PortableUser.Password
	}
	s.configurePortableSecrets()
	return printablePassword
}

func (s *Service) configurePortableSecrets() {
	// we created the user before to initialize the KMS so we need to create the secret here
	switch s.PortableUser.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		payload := s.PortableUser.FsConfig.S3Config.AccessSecret.GetPayload()
		s.PortableUser.FsConfig.S3Config.AccessSecret = kms.NewEmptySecret()
		if payload != "" {
			s.PortableUser.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret(payload)
		}
	case sdk.GCSFilesystemProvider:
		payload := s.PortableUser.FsConfig.GCSConfig.Credentials.GetPayload()
		s.PortableUser.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
		if payload != "" {
			s.PortableUser.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret(payload)
		}
	case sdk.AzureBlobFilesystemProvider:
		payload := s.PortableUser.FsConfig.AzBlobConfig.AccountKey.GetPayload()
		s.PortableUser.FsConfig.AzBlobConfig.AccountKey = kms.NewEmptySecret()
		if payload != "" {
			s.PortableUser.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret(payload)
		}
		payload = s.PortableUser.FsConfig.AzBlobConfig.SASURL.GetPayload()
		s.PortableUser.FsConfig.AzBlobConfig.SASURL = kms.NewEmptySecret()
		if payload != "" {
			s.PortableUser.FsConfig.AzBlobConfig.SASURL = kms.NewPlainSecret(payload)
		}
	case sdk.CryptedFilesystemProvider:
		payload := s.PortableUser.FsConfig.CryptConfig.Passphrase.GetPayload()
		s.PortableUser.FsConfig.CryptConfig.Passphrase = kms.NewEmptySecret()
		if payload != "" {
			s.PortableUser.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret(payload)
		}
	case sdk.SFTPFilesystemProvider:
		payload := s.PortableUser.FsConfig.SFTPConfig.Password.GetPayload()
		s.PortableUser.FsConfig.SFTPConfig.Password = kms.NewEmptySecret()
		if payload != "" {
			s.PortableUser.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(payload)
		}
		payload = s.PortableUser.FsConfig.SFTPConfig.PrivateKey.GetPayload()
		s.PortableUser.FsConfig.SFTPConfig.PrivateKey = kms.NewEmptySecret()
		if payload != "" {
			s.PortableUser.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(payload)
		}
	}
}
