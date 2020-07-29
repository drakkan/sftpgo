// Package config manages the configuration
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
)

const (
	logSender = "config"
	// DefaultConfigName defines the name for the default config file.
	// This is the file name without extension, we use viper and so we
	// support all the config files format supported by viper
	DefaultConfigName = "sftpgo"
	// ConfigEnvPrefix defines a prefix that ENVIRONMENT variables will use
	configEnvPrefix = "sftpgo"
)

var (
	globalConf         globalConfig
	defaultSFTPDBanner = fmt.Sprintf("SFTPGo_%v", version.Get().Version)
	defaultFTPDBanner  = fmt.Sprintf("SFTPGo %v ready", version.Get().Version)
)

type globalConfig struct {
	Common       common.Configuration `json:"common" mapstructure:"common"`
	SFTPD        sftpd.Configuration  `json:"sftpd" mapstructure:"sftpd"`
	FTPD         ftpd.Configuration   `json:"ftpd" mapstructure:"ftpd"`
	ProviderConf dataprovider.Config  `json:"data_provider" mapstructure:"data_provider"`
	HTTPDConfig  httpd.Conf           `json:"httpd" mapstructure:"httpd"`
	HTTPConfig   httpclient.Config    `json:"http" mapstructure:"http"`
}

func init() {
	// create a default configuration to use if no config file is provided
	globalConf = globalConfig{
		Common: common.Configuration{
			IdleTimeout: 15,
			UploadMode:  0,
			Actions: common.ProtocolActions{
				ExecuteOn: []string{},
				Hook:      "",
			},
			SetstatMode:   0,
			ProxyProtocol: 0,
			ProxyAllowed:  []string{},
		},
		SFTPD: sftpd.Configuration{
			Banner:                  defaultSFTPDBanner,
			BindPort:                2022,
			BindAddress:             "",
			MaxAuthTries:            0,
			HostKeys:                []string{},
			KexAlgorithms:           []string{},
			Ciphers:                 []string{},
			MACs:                    []string{},
			TrustedUserCAKeys:       []string{},
			LoginBannerFile:         "",
			EnabledSSHCommands:      sftpd.GetDefaultSSHCommands(),
			KeyboardInteractiveHook: "",
		},
		FTPD: ftpd.Configuration{
			BindPort:                 0,
			BindAddress:              "",
			Banner:                   defaultFTPDBanner,
			BannerFile:               "",
			ActiveTransfersPortNon20: false,
			ForcePassiveIP:           "",
			PassivePortRange: ftpd.PortRange{
				Start: 50000,
				End:   50100,
			},
			CertificateFile:    "",
			CertificateKeyFile: "",
		},
		ProviderConf: dataprovider.Config{
			Driver:           "sqlite",
			Name:             "sftpgo.db",
			Host:             "",
			Port:             5432,
			Username:         "",
			Password:         "",
			ConnectionString: "",
			SQLTablesPrefix:  "",
			ManageUsers:      1,
			SSLMode:          0,
			TrackQuota:       1,
			PoolSize:         0,
			UsersBaseDir:     "",
			Actions: dataprovider.UserActions{
				ExecuteOn: []string{},
				Hook:      "",
			},
			ExternalAuthHook:  "",
			ExternalAuthScope: 0,
			CredentialsPath:   "credentials",
			PreLoginHook:      "",
		},
		HTTPDConfig: httpd.Conf{
			BindPort:           8080,
			BindAddress:        "127.0.0.1",
			TemplatesPath:      "templates",
			StaticFilesPath:    "static",
			BackupsPath:        "backups",
			AuthUserFile:       "",
			CertificateFile:    "",
			CertificateKeyFile: "",
		},
		HTTPConfig: httpclient.Config{
			Timeout:        20,
			CACertificates: nil,
			SkipTLSVerify:  false,
		},
	}

	viper.SetEnvPrefix(configEnvPrefix)
	replacer := strings.NewReplacer(".", "__")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName(DefaultConfigName)
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(true)
}

// GetCommonConfig returns the common protocols configuration
func GetCommonConfig() common.Configuration {
	return globalConf.Common
}

// SetCommonConfig sets the common protocols configuration
func SetCommonConfig(config common.Configuration) {
	globalConf.Common = config
}

// GetSFTPDConfig returns the configuration for the SFTP server
func GetSFTPDConfig() sftpd.Configuration {
	return globalConf.SFTPD
}

// SetSFTPDConfig sets the configuration for the SFTP server
func SetSFTPDConfig(config sftpd.Configuration) {
	globalConf.SFTPD = config
}

// GetFTPDConfig returns the configuration for the FTP server
func GetFTPDConfig() ftpd.Configuration {
	return globalConf.FTPD
}

// SetFTPDConfig sets the configuration for the FTP server
func SetFTPDConfig(config ftpd.Configuration) {
	globalConf.FTPD = config
}

// GetHTTPDConfig returns the configuration for the HTTP server
func GetHTTPDConfig() httpd.Conf {
	return globalConf.HTTPDConfig
}

// SetHTTPDConfig sets the configuration for the HTTP server
func SetHTTPDConfig(config httpd.Conf) {
	globalConf.HTTPDConfig = config
}

//GetProviderConf returns the configuration for the data provider
func GetProviderConf() dataprovider.Config {
	return globalConf.ProviderConf
}

//SetProviderConf sets the configuration for the data provider
func SetProviderConf(config dataprovider.Config) {
	globalConf.ProviderConf = config
}

// GetHTTPConfig returns the configuration for HTTP clients
func GetHTTPConfig() httpclient.Config {
	return globalConf.HTTPConfig
}

func getRedactedGlobalConf() globalConfig {
	conf := globalConf
	conf.ProviderConf.Password = "[redacted]"
	return conf
}

// LoadConfig loads the configuration
// configDir will be added to the configuration search paths.
// The search path contains by default the current directory and on linux it contains
// $HOME/.config/sftpgo and /etc/sftpgo too.
// configName is the name of the configuration to search without extension
func LoadConfig(configDir, configName string) error {
	var err error
	viper.AddConfigPath(configDir)
	setViperAdditionalConfigPaths()
	viper.AddConfigPath(".")
	viper.SetConfigName(configName)
	if err = viper.ReadInConfig(); err != nil {
		logger.Warn(logSender, "", "error loading configuration file: %v. Default configuration will be used: %+v",
			err, getRedactedGlobalConf())
		logger.WarnToConsole("error loading configuration file: %v. Default configuration will be used.", err)
		return err
	}
	err = viper.Unmarshal(&globalConf)
	if err != nil {
		logger.Warn(logSender, "", "error parsing configuration file: %v. Default configuration will be used: %+v",
			err, getRedactedGlobalConf())
		logger.WarnToConsole("error parsing configuration file: %v. Default configuration will be used.", err)
		return err
	}
	checkCommonParamsCompatibility()
	if strings.TrimSpace(globalConf.SFTPD.Banner) == "" {
		globalConf.SFTPD.Banner = defaultSFTPDBanner
	}
	if strings.TrimSpace(globalConf.FTPD.Banner) == "" {
		globalConf.FTPD.Banner = defaultFTPDBanner
	}
	if len(globalConf.ProviderConf.UsersBaseDir) > 0 && !utils.IsFileInputValid(globalConf.ProviderConf.UsersBaseDir) {
		err = fmt.Errorf("invalid users base dir %#v will be ignored", globalConf.ProviderConf.UsersBaseDir)
		globalConf.ProviderConf.UsersBaseDir = ""
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	if globalConf.Common.UploadMode < 0 || globalConf.Common.UploadMode > 2 {
		err = fmt.Errorf("invalid upload_mode 0, 1 and 2 are supported, configured: %v reset upload_mode to 0",
			globalConf.Common.UploadMode)
		globalConf.Common.UploadMode = 0
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	if globalConf.Common.ProxyProtocol < 0 || globalConf.Common.ProxyProtocol > 2 {
		err = fmt.Errorf("invalid proxy_protocol 0, 1 and 2 are supported, configured: %v reset proxy_protocol to 0",
			globalConf.Common.ProxyProtocol)
		globalConf.Common.ProxyProtocol = 0
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	if globalConf.ProviderConf.ExternalAuthScope < 0 || globalConf.ProviderConf.ExternalAuthScope > 7 {
		err = fmt.Errorf("invalid external_auth_scope: %v reset to 0", globalConf.ProviderConf.ExternalAuthScope)
		globalConf.ProviderConf.ExternalAuthScope = 0
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	if len(globalConf.ProviderConf.CredentialsPath) == 0 {
		err = fmt.Errorf("invalid credentials path, reset to \"credentials\"")
		globalConf.ProviderConf.CredentialsPath = "credentials"
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	checkHostKeyCompatibility()
	logger.Debug(logSender, "", "config file used: '%#v', config loaded: %+v", viper.ConfigFileUsed(), getRedactedGlobalConf())
	return err
}

func checkHostKeyCompatibility() {
	// we copy deprecated fields to new ones to keep backward compatibility so lint is disabled
	if len(globalConf.SFTPD.Keys) > 0 && len(globalConf.SFTPD.HostKeys) == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "keys is deprecated, please use host_keys")
		logger.WarnToConsole("keys is deprecated, please use host_keys")
		for _, k := range globalConf.SFTPD.Keys { //nolint:staticcheck
			globalConf.SFTPD.HostKeys = append(globalConf.SFTPD.HostKeys, k.PrivateKey)
		}
	}
}

func checkCommonParamsCompatibility() {
	// we copy deprecated fields to new ones to keep backward compatibility so lint is disabled
	if globalConf.SFTPD.IdleTimeout > 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "sftpd.idle_timeout is deprecated, please use common.idle_timeout")
		logger.WarnToConsole("sftpd.idle_timeout is deprecated, please use common.idle_timeout")
		globalConf.Common.IdleTimeout = globalConf.SFTPD.IdleTimeout //nolint:staticcheck
	}
	if len(globalConf.SFTPD.Actions.Hook) > 0 && len(globalConf.Common.Actions.Hook) == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "sftpd.actions is deprecated, please use common.actions")
		logger.WarnToConsole("sftpd.actions is deprecated, please use common.actions")
		globalConf.Common.Actions.ExecuteOn = globalConf.SFTPD.Actions.ExecuteOn //nolint:staticcheck
		globalConf.Common.Actions.Hook = globalConf.SFTPD.Actions.Hook           //nolint:staticcheck
	}
	if globalConf.SFTPD.SetstatMode > 0 && globalConf.Common.SetstatMode == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "sftpd.setstat_mode is deprecated, please use common.setstat_mode")
		logger.WarnToConsole("sftpd.setstat_mode is deprecated, please use common.setstat_mode")
		globalConf.Common.SetstatMode = globalConf.SFTPD.SetstatMode //nolint:staticcheck
	}
	if globalConf.SFTPD.UploadMode > 0 && globalConf.Common.UploadMode == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "sftpd.upload_mode is deprecated, please use common.upload_mode")
		logger.WarnToConsole("sftpd.upload_mode is deprecated, please use common.upload_mode")
		globalConf.Common.UploadMode = globalConf.SFTPD.UploadMode //nolint:staticcheck
	}
	if globalConf.SFTPD.ProxyProtocol > 0 && globalConf.Common.ProxyProtocol == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "sftpd.proxy_protocol is deprecated, please use common.proxy_protocol")
		logger.WarnToConsole("sftpd.proxy_protocol is deprecated, please use common.proxy_protocol")
		globalConf.Common.ProxyProtocol = globalConf.SFTPD.ProxyProtocol //nolint:staticcheck
		globalConf.Common.ProxyAllowed = globalConf.SFTPD.ProxyAllowed   //nolint:staticcheck
	}
}
