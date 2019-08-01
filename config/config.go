// Package config manages the configuration.
// Configuration is loaded from sftpgo.conf file.
// If sftpgo.conf is not found or cannot be readed or decoded as json the default configuration is used.
// The default configuration an be found inside the source tree:
// https://github.com/drakkan/sftpgo/blob/master/sftpgo.conf
package config

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
)

const (
	logSender     = "config"
	defaultBanner = "SFTPGo"
)

var (
	globalConf globalConfig
)

type globalConfig struct {
	SFTPD        sftpd.Configuration `json:"sftpd"`
	ProviderConf dataprovider.Config `json:"data_provider"`
	HTTPDConfig  api.HTTPDConf       `json:"httpd"`
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
			Actions: sftpd.Actions{
				ExecuteOn:           []string{},
				Command:             "",
				HTTPNotificationURL: "",
			},
			Keys: []sftpd.Key{},
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
		},
		HTTPDConfig: api.HTTPDConf{
			BindPort:    8080,
			BindAddress: "127.0.0.1",
		},
	}
}

// GetSFTPDConfig returns the configuration for the SFTP server
func GetSFTPDConfig() sftpd.Configuration {
	return globalConf.SFTPD
}

// GetHTTPDConfig returns the configuration for the HTTP server
func GetHTTPDConfig() api.HTTPDConf {
	return globalConf.HTTPDConfig
}

//GetProviderConf returns the configuration for the data provider
func GetProviderConf() dataprovider.Config {
	return globalConf.ProviderConf
}

// LoadConfig loads the configuration from sftpgo.conf or use the default configuration.
func LoadConfig(configPath string) error {
	logger.Debug(logSender, "load config from path: %v", configPath)
	file, err := os.Open(configPath)
	if err != nil {
		logger.Warn(logSender, "error loading configuration file: %v. Default configuration will be used: %+v", err, globalConf)
		logger.WarnToConsole("error loading configuration file: %v. Default configuration will be used.", err)
		return err
	}
	defer file.Close()
	err = json.NewDecoder(file).Decode(&globalConf)
	if err != nil {
		logger.Warn(logSender, "error parsing configuration file: %v. Default configuration will be used: %+v", err, globalConf)
		logger.WarnToConsole("error parsing configuration file: %v. Default configuration will be used.", err)
		return err
	}
	if strings.TrimSpace(globalConf.SFTPD.Banner) == "" {
		globalConf.SFTPD.Banner = defaultBanner
	}
	logger.Debug(logSender, "config loaded: %+v", globalConf)
	return err
}
