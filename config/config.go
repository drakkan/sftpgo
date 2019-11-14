// Package config manages the configuration.
// Configuration is loaded from sftpgo.conf file.
// If sftpgo.conf is not found or cannot be readed or decoded as json the default configuration is used.
// The default configuration an be found inside the source tree:
// https://github.com/drakkan/sftpgo/blob/master/sftpgo.conf
package config

import (
	"fmt"
	"strings"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/spf13/viper"
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
			Keys:            []sftpd.Key{},
			IsSCPEnabled:    false,
			KexAlgorithms:   []string{},
			Ciphers:         []string{},
			MACs:            []string{},
			LoginBannerFile: "",
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
		},
		HTTPDConfig: httpd.Conf{
			BindPort:        8080,
			BindAddress:     "127.0.0.1",
			TemplatesPath:   "templates",
			StaticFilesPath: "static",
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
	if globalConf.SFTPD.UploadMode < 0 || globalConf.SFTPD.UploadMode > 2 {
		err = fmt.Errorf("invalid upload_mode 0 and 1 are supported, configured: %v reset upload_mode to 0",
			globalConf.SFTPD.UploadMode)
		globalConf.SFTPD.UploadMode = 0
		logger.Warn(logSender, "", "Configuration error: %v", err)
		logger.WarnToConsole("Configuration error: %v", err)
	}
	logger.Debug(logSender, "", "config file used: '%v', config loaded: %+v", viper.ConfigFileUsed(), getRedactedGlobalConf())
	return err
}
