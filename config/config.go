// Package config manages the configuration.
// Configuration is loaded from sftpgo.conf file.
// If sftpgo.conf is not found or cannot be readed or decoded as json the default configuration is used.
// The default configuration an be found inside the source tree:
// https://github.com/drakkan/sftpgo/blob/master/sftpgo.conf
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
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
	globalConf    globalConfig
	defaultBanner = fmt.Sprintf("SFTPGo_%v", utils.GetAppVersion().Version)
)

type globalConfig struct {
	SFTPD        sftpd.Configuration `json:"sftpd" mapstructure:"sftpd"`
	ProviderConf dataprovider.Config `json:"data_provider" mapstructure:"data_provider"`
	HTTPDConfig  httpd.Conf          `json:"httpd" mapstructure:"httpd"`
	HTTPConfig   httpclient.Config   `json:"http" mapstructure:"http"`
}

func init() {
	// create a default configuration to use if no config file is provided
	globalConf = globalConfig{
		SFTPD: sftpd.Configuration{
			Banner:       defaultBanner,
			BindPort:     2022,
			BindAddress:  "",
			IdleTimeout:  15,
			MaxAuthTries: 0,
			Umask:        "0022",
			UploadMode:   0,
			Actions: sftpd.Actions{
				ExecuteOn:           []string{},
				Command:             "",
				HTTPNotificationURL: "",
			},
			Keys:                    []sftpd.Key{},
			KexAlgorithms:           []string{},
			Ciphers:                 []string{},
			MACs:                    []string{},
			TrustedUserCAKeys:       []string{},
			LoginBannerFile:         "",
			EnabledSSHCommands:      sftpd.GetDefaultSSHCommands(),
			KeyboardInteractiveHook: "",
			ProxyProtocol:           0,
			ProxyAllowed:            []string{},
		},
		ProviderConf: dataprovider.Config{
			Driver:           "sqlite",
			Name:             "sftpgo.db",
			Host:             "",
			Port:             5432,
			Username:         "",
			Password:         "",
			ConnectionString: "",
			UsersTable:       "users",
			ManageUsers:      1,
			SSLMode:          0,
			TrackQuota:       1,
			PoolSize:         0,
			UsersBaseDir:     "",
			Actions: dataprovider.Actions{
				ExecuteOn:           []string{},
				Command:             "",
				HTTPNotificationURL: "",
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

// GetSFTPDConfig returns the configuration for the SFTP server
func GetSFTPDConfig() sftpd.Configuration {
	return globalConf.SFTPD
}

// SetSFTPDConfig sets the configuration for the SFTP server
func SetSFTPDConfig(config sftpd.Configuration) {
	globalConf.SFTPD = config
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
	if strings.TrimSpace(globalConf.SFTPD.Banner) == "" {
		globalConf.SFTPD.Banner = defaultBanner
	}
	if len(globalConf.ProviderConf.UsersBaseDir) > 0 && !utils.IsFileInputValid(globalConf.ProviderConf.UsersBaseDir) {
		err = fmt.Errorf("invalid users base dir %#v will be ignored", globalConf.ProviderConf.UsersBaseDir)
		globalConf.ProviderConf.UsersBaseDir = ""
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	if globalConf.SFTPD.UploadMode < 0 || globalConf.SFTPD.UploadMode > 2 {
		err = fmt.Errorf("invalid upload_mode 0, 1 and 2 are supported, configured: %v reset upload_mode to 0",
			globalConf.SFTPD.UploadMode)
		globalConf.SFTPD.UploadMode = 0
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	if globalConf.SFTPD.ProxyProtocol < 0 || globalConf.SFTPD.ProxyProtocol > 2 {
		err = fmt.Errorf("invalid proxy_protocol 0, 1 and 2 are supported, configured: %v reset proxy_protocol to 0",
			globalConf.SFTPD.ProxyProtocol)
		globalConf.SFTPD.ProxyProtocol = 0
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
	checkHooksCompatibility()
	logger.Debug(logSender, "", "config file used: '%#v', config loaded: %+v", viper.ConfigFileUsed(), getRedactedGlobalConf())
	return err
}

func checkHooksCompatibility() {
	// we copy deprecated fields to new ones to keep backward compatibility so lint is disabled
	if len(globalConf.ProviderConf.ExternalAuthProgram) > 0 && len(globalConf.ProviderConf.ExternalAuthHook) == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "external_auth_program is deprecated, please use external_auth_hook")
		logger.WarnToConsole("external_auth_program is deprecated, please use external_auth_hook")
		globalConf.ProviderConf.ExternalAuthHook = globalConf.ProviderConf.ExternalAuthProgram //nolint:staticcheck
	}
	if len(globalConf.ProviderConf.PreLoginProgram) > 0 && len(globalConf.ProviderConf.PreLoginHook) == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "pre_login_program is deprecated, please use pre_login_hook")
		logger.WarnToConsole("pre_login_program is deprecated, please use pre_login_hook")
		globalConf.ProviderConf.PreLoginHook = globalConf.ProviderConf.PreLoginProgram //nolint:staticcheck
	}
	if len(globalConf.SFTPD.KeyboardInteractiveProgram) > 0 && len(globalConf.SFTPD.KeyboardInteractiveHook) == 0 { //nolint:staticcheck
		logger.Warn(logSender, "", "keyboard_interactive_auth_program is deprecated, please use keyboard_interactive_auth_hook")
		logger.WarnToConsole("keyboard_interactive_auth_program is deprecated, please use keyboard_interactive_auth_hook")
		globalConf.SFTPD.KeyboardInteractiveHook = globalConf.SFTPD.KeyboardInteractiveProgram //nolint:staticcheck
	}
}
