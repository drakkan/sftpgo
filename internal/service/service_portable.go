// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//go:build !noportable
// +build !noportable

package service

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

// StartPortableMode starts the service in portable mode
func (s *Service) StartPortableMode(sftpdPort, ftpPort, webdavPort int, enabledSSHCommands []string,
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
		if util.Contains(enabledSSHCommands, "*") {
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

	err = s.Start(true)
	if err != nil {
		return err
	}

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

func (s *Service) getPortableDirToServe() string {
	switch s.PortableUser.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		return s.PortableUser.FsConfig.S3Config.KeyPrefix
	case sdk.GCSFilesystemProvider:
		return s.PortableUser.FsConfig.GCSConfig.KeyPrefix
	case sdk.AzureBlobFilesystemProvider:
		return s.PortableUser.FsConfig.AzBlobConfig.KeyPrefix
	case sdk.SFTPFilesystemProvider:
		return s.PortableUser.FsConfig.SFTPConfig.Prefix
	case sdk.HTTPFilesystemProvider:
		return "/"
	default:
		return s.PortableUser.HomeDir
	}
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
		s.PortableUser.FsConfig.S3Config.AccessSecret = getSecretFromString(payload)
	case sdk.GCSFilesystemProvider:
		payload := s.PortableUser.FsConfig.GCSConfig.Credentials.GetPayload()
		s.PortableUser.FsConfig.GCSConfig.Credentials = getSecretFromString(payload)
	case sdk.AzureBlobFilesystemProvider:
		payload := s.PortableUser.FsConfig.AzBlobConfig.AccountKey.GetPayload()
		s.PortableUser.FsConfig.AzBlobConfig.AccountKey = getSecretFromString(payload)
		payload = s.PortableUser.FsConfig.AzBlobConfig.SASURL.GetPayload()
		s.PortableUser.FsConfig.AzBlobConfig.SASURL = getSecretFromString(payload)
	case sdk.CryptedFilesystemProvider:
		payload := s.PortableUser.FsConfig.CryptConfig.Passphrase.GetPayload()
		s.PortableUser.FsConfig.CryptConfig.Passphrase = getSecretFromString(payload)
	case sdk.SFTPFilesystemProvider:
		payload := s.PortableUser.FsConfig.SFTPConfig.Password.GetPayload()
		s.PortableUser.FsConfig.SFTPConfig.Password = getSecretFromString(payload)
		payload = s.PortableUser.FsConfig.SFTPConfig.PrivateKey.GetPayload()
		s.PortableUser.FsConfig.SFTPConfig.PrivateKey = getSecretFromString(payload)
		payload = s.PortableUser.FsConfig.SFTPConfig.KeyPassphrase.GetPayload()
		s.PortableUser.FsConfig.SFTPConfig.KeyPassphrase = getSecretFromString(payload)
	case sdk.HTTPFilesystemProvider:
		payload := s.PortableUser.FsConfig.HTTPConfig.Password.GetPayload()
		s.PortableUser.FsConfig.HTTPConfig.Password = getSecretFromString(payload)
		payload = s.PortableUser.FsConfig.HTTPConfig.APIKey.GetPayload()
		s.PortableUser.FsConfig.HTTPConfig.APIKey = getSecretFromString(payload)
	}
}

func getSecretFromString(payload string) *kms.Secret {
	if payload != "" {
		return kms.NewPlainSecret(payload)
	}
	return kms.NewEmptySecret()
}
