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

//go:build !noportable
// +build !noportable

package service

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/httpd"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

// StartPortableMode starts the service in portable mode
func (s *Service) StartPortableMode(sftpdPort, ftpPort, webdavPort, httpPort int, enabledSSHCommands []string,
	ftpsCert, ftpsKey, webDavCert, webDavKey, httpsCert, httpsKey string) error {
	if s.PortableMode != 1 {
		return fmt.Errorf("service is not configured for portable mode")
	}
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
	for idx := range httpdConf.Bindings {
		httpdConf.Bindings[idx].Port = 0
	}
	config.SetHTTPDConfig(httpdConf)
	telemetryConf := config.GetTelemetryConfig()
	telemetryConf.BindPort = 0
	config.SetTelemetryConfig(telemetryConf)

	configurePortableSFTPService(sftpdPort, enabledSSHCommands)
	configurePortableFTPService(ftpPort, ftpsCert, ftpsKey)
	configurePortableWebDAVService(webdavPort, webDavCert, webDavKey)
	configurePortableHTTPService(httpPort, httpsCert, httpsKey)

	err = s.Start(true)
	if err != nil {
		return err
	}
	if httpPort >= 0 {
		admin := &dataprovider.Admin{
			Username:    util.GenerateUniqueID(),
			Password:    util.GenerateUniqueID(),
			Status:      0,
			Permissions: []string{dataprovider.PermAdminAny},
		}
		if err := dataprovider.AddAdmin(admin, dataprovider.ActionExecutorSystem, "", ""); err != nil {
			return err
		}
	}

	logger.InfoToConsole("Portable mode ready, user: %q, password: %q, public keys: %v, directory: %q, "+
		"permissions: %+v, file patterns filters: %+v %v", s.PortableUser.Username,
		printablePassword, s.PortableUser.PublicKeys, s.getPortableDirToServe(), s.PortableUser.Permissions,
		s.PortableUser.Filters.FilePatterns, s.getServiceOptionalInfoString())
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
		info.WriteString(fmt.Sprintf("WebDAV URL: %v://<your IP>:%v/ ", scheme, config.GetWebDAVDConfig().Bindings[0].Port))
	}
	if config.GetHTTPDConfig().Bindings[0].IsValid() {
		scheme := "http"
		if config.GetHTTPDConfig().CertificateFile != "" && config.GetHTTPDConfig().CertificateKeyFile != "" {
			scheme = "https"
		}
		info.WriteString(fmt.Sprintf("WebClient URL: %v://<your IP>:%v/ ", scheme, config.GetHTTPDConfig().Bindings[0].Port))
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
		for i := 0; i < 16; i++ {
			b.WriteRune(chars[rand.Intn(len(chars))])
		}
		s.PortableUser.Password = b.String()
		printablePassword = s.PortableUser.Password
	}
	s.PortableUser.Filters.WebClient = []string{sdk.WebClientSharesDisabled, sdk.WebClientInfoChangeDisabled,
		sdk.WebClientPubKeyChangeDisabled, sdk.WebClientPasswordChangeDisabled, sdk.WebClientAPIKeyAuthChangeDisabled,
		sdk.WebClientMFADisabled,
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

func configurePortableSFTPService(port int, enabledSSHCommands []string) {
	sftpdConf := config.GetSFTPDConfig()
	if len(sftpdConf.Bindings) == 0 {
		sftpdConf.Bindings = append(sftpdConf.Bindings, sftpd.Binding{})
	}
	if port > 0 {
		sftpdConf.Bindings[0].Port = port
	} else if port == 0 {
		// dynamic ports starts from 49152
		sftpdConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		sftpdConf.Bindings[0].Port = 0
	}
	if util.Contains(enabledSSHCommands, "*") {
		sftpdConf.EnabledSSHCommands = sftpd.GetSupportedSSHCommands()
	} else {
		sftpdConf.EnabledSSHCommands = enabledSSHCommands
	}
	config.SetSFTPDConfig(sftpdConf)
}

func configurePortableFTPService(port int, cert, key string) {
	ftpConf := config.GetFTPDConfig()
	if len(ftpConf.Bindings) == 0 {
		ftpConf.Bindings = append(ftpConf.Bindings, ftpd.Binding{})
	}
	if port > 0 {
		ftpConf.Bindings[0].Port = port
	} else if port == 0 {
		ftpConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		ftpConf.Bindings[0].Port = 0
	}
	if ftpConf.Banner == "" {
		ftpConf.Banner = fmt.Sprintf("SFTPGo portable %v ready", version.Get().Version)
	}
	ftpConf.Bindings[0].CertificateFile = cert
	ftpConf.Bindings[0].CertificateKeyFile = key
	config.SetFTPDConfig(ftpConf)
}

func configurePortableWebDAVService(port int, cert, key string) {
	webDavConf := config.GetWebDAVDConfig()
	if len(webDavConf.Bindings) == 0 {
		webDavConf.Bindings = append(webDavConf.Bindings, webdavd.Binding{})
	}
	if port > 0 {
		webDavConf.Bindings[0].Port = port
	} else if port == 0 {
		webDavConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		webDavConf.Bindings[0].Port = 0
	}
	webDavConf.Bindings[0].CertificateFile = cert
	webDavConf.Bindings[0].CertificateKeyFile = key
	if cert != "" && key != "" {
		webDavConf.Bindings[0].EnableHTTPS = true
	}
	config.SetWebDAVDConfig(webDavConf)
}

func configurePortableHTTPService(port int, cert, key string) {
	httpdConf := config.GetHTTPDConfig()
	if len(httpdConf.Bindings) == 0 {
		httpdConf.Bindings = append(httpdConf.Bindings, httpd.Binding{})
	}
	if port > 0 {
		httpdConf.Bindings[0].Port = port
	} else if port == 0 {
		httpdConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		httpdConf.Bindings[0].Port = 0
	}
	httpdConf.Bindings[0].CertificateFile = cert
	httpdConf.Bindings[0].CertificateKeyFile = key
	if cert != "" && key != "" {
		httpdConf.Bindings[0].EnableHTTPS = true
	}
	httpdConf.Bindings[0].EnableWebAdmin = false
	httpdConf.Bindings[0].EnableWebClient = true
	httpdConf.Bindings[0].EnableRESTAPI = false
	httpdConf.Bindings[0].RenderOpenAPI = false
	config.SetHTTPDConfig(httpdConf)
}
