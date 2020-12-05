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

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
)

// StartPortableMode starts the service in portable mode
func (s *Service) StartPortableMode(sftpdPort, ftpPort, webdavPort int, enabledSSHCommands []string, advertiseService, advertiseCredentials bool,
	ftpsCert, ftpsKey, webDavCert, webDavKey string) error {
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
	httpdConf.BindPort = 0
	config.SetHTTPDConfig(httpdConf)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.MaxAuthTries = 12
	sftpdConf.BindPort = sftpdPort
	if sftpdPort >= 0 {
		if sftpdPort > 0 {
			sftpdConf.BindPort = sftpdPort
		} else {
			// dynamic ports starts from 49152
			sftpdConf.BindPort = 49152 + rand.Intn(15000)
		}
		if utils.IsStringInSlice("*", enabledSSHCommands) {
			sftpdConf.EnabledSSHCommands = sftpd.GetSupportedSSHCommands()
		} else {
			sftpdConf.EnabledSSHCommands = enabledSSHCommands
		}
	}
	config.SetSFTPDConfig(sftpdConf)

	if ftpPort >= 0 {
		ftpConf := config.GetFTPDConfig()
		if ftpPort > 0 {
			ftpConf.BindPort = ftpPort
		} else {
			ftpConf.BindPort = 49152 + rand.Intn(15000)
		}
		ftpConf.Banner = fmt.Sprintf("SFTPGo portable %v ready", version.Get().Version)
		ftpConf.CertificateFile = ftpsCert
		ftpConf.CertificateKeyFile = ftpsKey
		config.SetFTPDConfig(ftpConf)
	}

	if webdavPort >= 0 {
		webDavConf := config.GetWebDAVDConfig()
		if webdavPort > 0 {
			webDavConf.BindPort = webdavPort
		} else {
			webDavConf.BindPort = 49152 + rand.Intn(15000)
		}
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
	if config.GetSFTPDConfig().BindPort > 0 {
		info.WriteString(fmt.Sprintf("SFTP port: %v ", config.GetSFTPDConfig().BindPort))
	}
	if config.GetFTPDConfig().BindPort > 0 {
		info.WriteString(fmt.Sprintf("FTP port: %v ", config.GetFTPDConfig().BindPort))
	}
	if config.GetWebDAVDConfig().BindPort > 0 {
		scheme := "http"
		if config.GetWebDAVDConfig().CertificateFile != "" && config.GetWebDAVDConfig().CertificateKeyFile != "" {
			scheme = "https"
		}
		info.WriteString(fmt.Sprintf("WebDAV URL: %v://<your IP>:%v/%v",
			scheme, config.GetWebDAVDConfig().BindPort, s.PortableUser.Username))
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
		if sftpdConf.BindPort > 0 {
			mDNSServiceSFTP, err = zeroconf.Register(
				fmt.Sprintf("SFTPGo portable %v", sftpdConf.BindPort), // service instance name
				"_sftp-ssh._tcp",   // service type and protocol
				"local.",           // service domain
				sftpdConf.BindPort, // service port
				meta,               // service metadata
				nil,                // register on all network interfaces
			)
			if err != nil {
				mDNSServiceSFTP = nil
				logger.WarnToConsole("Unable to advertise SFTP service via multicast DNS: %v", err)
			} else {
				logger.InfoToConsole("SFTP service advertised via multicast DNS")
			}
		}
		ftpdConf := config.GetFTPDConfig()
		if ftpdConf.BindPort > 0 {
			mDNSServiceFTP, err = zeroconf.Register(
				fmt.Sprintf("SFTPGo portable %v", ftpdConf.BindPort),
				"_ftp._tcp",
				"local.",
				ftpdConf.BindPort,
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
		if webdavConf.BindPort > 0 {
			mDNSServiceDAV, err = zeroconf.Register(
				fmt.Sprintf("SFTPGo portable %v", webdavConf.BindPort),
				"_http._tcp",
				"local.",
				webdavConf.BindPort,
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
	if s.PortableUser.FsConfig.Provider == dataprovider.S3FilesystemProvider {
		dirToServe = s.PortableUser.FsConfig.S3Config.KeyPrefix
	} else if s.PortableUser.FsConfig.Provider == dataprovider.GCSFilesystemProvider {
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
	if len(s.PortableUser.Password) > 0 {
		printablePassword = "[redacted]"
	}
	if len(s.PortableUser.PublicKeys) == 0 && len(s.PortableUser.Password) == 0 {
		var b strings.Builder
		for i := 0; i < 8; i++ {
			b.WriteRune(chars[rand.Intn(len(chars))])
		}
		s.PortableUser.Password = b.String()
		printablePassword = s.PortableUser.Password
	}
	// we created the user before to initialize the KMS so we need to create the secret here
	switch s.PortableUser.FsConfig.Provider {
	case dataprovider.S3FilesystemProvider:
		payload := s.PortableUser.FsConfig.S3Config.AccessSecret.GetPayload()
		if payload != "" {
			s.PortableUser.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret(payload)
		}
	case dataprovider.GCSFilesystemProvider:
		payload := s.PortableUser.FsConfig.GCSConfig.Credentials.GetPayload()
		if payload != "" {
			s.PortableUser.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret(payload)
		}
	case dataprovider.AzureBlobFilesystemProvider:
		payload := s.PortableUser.FsConfig.AzBlobConfig.AccountKey.GetPayload()
		if payload != "" {
			s.PortableUser.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret(payload)
		}
	case dataprovider.CryptedFilesystemProvider:
		payload := s.PortableUser.FsConfig.CryptConfig.Passphrase.GetPayload()
		if payload != "" {
			s.PortableUser.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret(payload)
		}
	}
	return printablePassword
}
