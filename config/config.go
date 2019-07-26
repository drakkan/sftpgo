package config

import (
	"encoding/json"
	"os"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
)

const (
	logSender = "config"
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
			Banner:       "SFTPServer",
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

// GetSFTPDConfig returns sftpd configuration
func GetSFTPDConfig() sftpd.Configuration {
	return globalConf.SFTPD
}

// GetHTTPDConfig returns httpd configuration
func GetHTTPDConfig() api.HTTPDConf {
	return globalConf.HTTPDConfig
}

//GetProviderConf returns data provider configuration
func GetProviderConf() dataprovider.Config {
	return globalConf.ProviderConf
}

// LoadConfig loads configuration from sftpgo.conf
func LoadConfig(configPath string) error {
	logger.Debug(logSender, "load config from path: %v", configPath)
	//globalConf.basePath = basePath
	file, err := os.Open(configPath)
	if err != nil {
		logger.Warn(logSender, "error loading configuration file: %v. Default configuration will be used: %+v", err, globalConf)
		return err
	}
	defer file.Close()
	err = json.NewDecoder(file).Decode(&globalConf)
	if err != nil {
		logger.Warn(logSender, "error parsing config file: %v. Default configuration will be used: %+v", err, globalConf)
		return err
	}
	logger.Debug(logSender, "config loaded: %+v", globalConf)
	return err
}
