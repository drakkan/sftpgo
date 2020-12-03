// Package config manages the configuration
package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/webdavd"
)

const (
	logSender = "config"
	// configName defines the name for config file.
	// This name does not include the extension, viper will search for files
	// with supported extensions such as "sftpgo.json", "sftpgo.yaml" and so on
	configName = "sftpgo"
	// ConfigEnvPrefix defines a prefix that environment variables will use
	configEnvPrefix = "sftpgo"
)

var (
	globalConf         globalConfig
	defaultSFTPDBanner = fmt.Sprintf("SFTPGo_%v", version.Get().Version)
	defaultFTPDBanner  = fmt.Sprintf("SFTPGo %v ready", version.Get().Version)
)

type globalConfig struct {
	Common       common.Configuration  `json:"common" mapstructure:"common"`
	SFTPD        sftpd.Configuration   `json:"sftpd" mapstructure:"sftpd"`
	FTPD         ftpd.Configuration    `json:"ftpd" mapstructure:"ftpd"`
	WebDAVD      webdavd.Configuration `json:"webdavd" mapstructure:"webdavd"`
	ProviderConf dataprovider.Config   `json:"data_provider" mapstructure:"data_provider"`
	HTTPDConfig  httpd.Conf            `json:"httpd" mapstructure:"httpd"`
	HTTPConfig   httpclient.Config     `json:"http" mapstructure:"http"`
	KMSConfig    kms.Configuration     `json:"kms" mapstructure:"kms"`
}

func init() {
	Init()
}

// Init initializes the global configuration.
// It is not supposed to be called outside of this package.
// It is exported to minimize refactoring efforts. Will eventually disappear.
func Init() {
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
			PasswordAuthentication:  true,
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
		WebDAVD: webdavd.Configuration{
			BindPort:           0,
			BindAddress:        "",
			CertificateFile:    "",
			CertificateKeyFile: "",
			Cors: webdavd.Cors{
				Enabled:          false,
				AllowedOrigins:   []string{},
				AllowedMethods:   []string{},
				AllowedHeaders:   []string{},
				ExposedHeaders:   []string{},
				AllowCredentials: false,
				MaxAge:           0,
			},
			Cache: webdavd.Cache{
				Users: webdavd.UsersCacheConfig{
					ExpirationTime: 0,
					MaxSize:        50,
				},
				MimeTypes: webdavd.MimeCacheConfig{
					Enabled: true,
					MaxSize: 1000,
				},
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
			ExternalAuthHook:   "",
			ExternalAuthScope:  0,
			CredentialsPath:    "credentials",
			PreLoginHook:       "",
			PostLoginHook:      "",
			PostLoginScope:     0,
			CheckPasswordHook:  "",
			CheckPasswordScope: 0,
			PasswordHashing: dataprovider.PasswordHashing{
				Argon2Options: dataprovider.Argon2Options{
					Memory:      65536,
					Iterations:  1,
					Parallelism: 2,
				},
			},
			UpdateMode:                0,
			PreferDatabaseCredentials: false,
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
		KMSConfig: kms.Configuration{
			Secrets: kms.Secrets{
				URL:           "",
				MasterKeyPath: "",
			},
		},
	}

	viper.SetEnvPrefix(configEnvPrefix)
	replacer := strings.NewReplacer(".", "__")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName(configName)
	setViperDefaults()
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

// GetWebDAVDConfig returns the configuration for the WebDAV server
func GetWebDAVDConfig() webdavd.Configuration {
	return globalConf.WebDAVD
}

// SetWebDAVDConfig sets the configuration for the WebDAV server
func SetWebDAVDConfig(config webdavd.Configuration) {
	globalConf.WebDAVD = config
}

// GetHTTPDConfig returns the configuration for the HTTP server
func GetHTTPDConfig() httpd.Conf {
	return globalConf.HTTPDConfig
}

// SetHTTPDConfig sets the configuration for the HTTP server
func SetHTTPDConfig(config httpd.Conf) {
	globalConf.HTTPDConfig = config
}

// GetProviderConf returns the configuration for the data provider
func GetProviderConf() dataprovider.Config {
	return globalConf.ProviderConf
}

// SetProviderConf sets the configuration for the data provider
func SetProviderConf(config dataprovider.Config) {
	globalConf.ProviderConf = config
}

// GetHTTPConfig returns the configuration for HTTP clients
func GetHTTPConfig() httpclient.Config {
	return globalConf.HTTPConfig
}

// GetKMSConfig returns the KMS configuration
func GetKMSConfig() kms.Configuration {
	return globalConf.KMSConfig
}

// SetKMSConfig sets the kms configuration
func SetKMSConfig(config kms.Configuration) {
	globalConf.KMSConfig = config
}

// HasServicesToStart returns true if the config defines at least a service to start.
// Supported services are SFTP, FTP and WebDAV
func HasServicesToStart() bool {
	if globalConf.SFTPD.BindPort > 0 {
		return true
	}
	if globalConf.FTPD.BindPort > 0 {
		return true
	}
	if globalConf.WebDAVD.BindPort > 0 {
		return true
	}
	return false
}

func getRedactedGlobalConf() globalConfig {
	conf := globalConf
	conf.ProviderConf.Password = "[redacted]"
	return conf
}

func setConfigFile(configDir, configFile string) {
	if configFile == "" {
		return
	}
	if !filepath.IsAbs(configFile) && utils.IsFileInputValid(configFile) {
		configFile = filepath.Join(configDir, configFile)
	}
	viper.SetConfigFile(configFile)
}

// LoadConfig loads the configuration
// configDir will be added to the configuration search paths.
// The search path contains by default the current directory and on linux it contains
// $HOME/.config/sftpgo and /etc/sftpgo too.
// configFile is an absolute or relative path (to the config dir) to the configuration file.
func LoadConfig(configDir, configFile string) error {
	var err error
	viper.AddConfigPath(configDir)
	setViperAdditionalConfigPaths()
	viper.AddConfigPath(".")
	setConfigFile(configDir, configFile)
	if err = viper.ReadInConfig(); err != nil {
		logger.Warn(logSender, "", "error loading configuration file: %v", err)
		logger.WarnToConsole("error loading configuration file: %v", err)
	}
	err = viper.Unmarshal(&globalConf)
	if err != nil {
		logger.Warn(logSender, "", "error parsing configuration file: %v", err)
		logger.WarnToConsole("error parsing configuration file: %v", err)
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
		warn := fmt.Sprintf("invalid upload_mode 0, 1 and 2 are supported, configured: %v reset upload_mode to 0",
			globalConf.Common.UploadMode)
		globalConf.Common.UploadMode = 0
		logger.Warn(logSender, "", "Configuration error: %v", warn)
		logger.WarnToConsole("Configuration error: %v", warn)
	}
	if globalConf.Common.ProxyProtocol < 0 || globalConf.Common.ProxyProtocol > 2 {
		warn := fmt.Sprintf("invalid proxy_protocol 0, 1 and 2 are supported, configured: %v reset proxy_protocol to 0",
			globalConf.Common.ProxyProtocol)
		globalConf.Common.ProxyProtocol = 0
		logger.Warn(logSender, "", "Configuration error: %v", warn)
		logger.WarnToConsole("Configuration error: %v", warn)
	}
	if globalConf.ProviderConf.ExternalAuthScope < 0 || globalConf.ProviderConf.ExternalAuthScope > 7 {
		warn := fmt.Sprintf("invalid external_auth_scope: %v reset to 0", globalConf.ProviderConf.ExternalAuthScope)
		globalConf.ProviderConf.ExternalAuthScope = 0
		logger.Warn(logSender, "", "Configuration error: %v", warn)
		logger.WarnToConsole("Configuration error: %v", warn)
	}
	if globalConf.ProviderConf.CredentialsPath == "" {
		warn := "invalid credentials path, reset to \"credentials\""
		globalConf.ProviderConf.CredentialsPath = "credentials"
		logger.Warn(logSender, "", "Configuration error: %v", warn)
		logger.WarnToConsole("Configuration error: %v", warn)
	}
	checkHostKeyCompatibility()
	logger.Debug(logSender, "", "config file used: '%#v', config loaded: %+v", viper.ConfigFileUsed(), getRedactedGlobalConf())
	return nil
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

func setViperDefaults() {
	viper.SetDefault("common.idle_timeout", globalConf.Common.IdleTimeout)
	viper.SetDefault("common.upload_mode", globalConf.Common.UploadMode)
	viper.SetDefault("common.actions.execute_on", globalConf.Common.Actions.ExecuteOn)
	viper.SetDefault("common.actions.hook", globalConf.Common.Actions.Hook)
	viper.SetDefault("common.setstat_mode", globalConf.Common.SetstatMode)
	viper.SetDefault("common.proxy_protocol", globalConf.Common.ProxyProtocol)
	viper.SetDefault("common.proxy_allowed", globalConf.Common.ProxyAllowed)
	viper.SetDefault("common.post_connect_hook", globalConf.Common.PostConnectHook)
	viper.SetDefault("sftpd.bind_port", globalConf.SFTPD.BindPort)
	viper.SetDefault("sftpd.bind_address", globalConf.SFTPD.BindAddress)
	viper.SetDefault("sftpd.max_auth_tries", globalConf.SFTPD.MaxAuthTries)
	viper.SetDefault("sftpd.banner", globalConf.SFTPD.Banner)
	viper.SetDefault("sftpd.host_keys", globalConf.SFTPD.HostKeys)
	viper.SetDefault("sftpd.kex_algorithms", globalConf.SFTPD.KexAlgorithms)
	viper.SetDefault("sftpd.ciphers", globalConf.SFTPD.Ciphers)
	viper.SetDefault("sftpd.macs", globalConf.SFTPD.MACs)
	viper.SetDefault("sftpd.trusted_user_ca_keys", globalConf.SFTPD.TrustedUserCAKeys)
	viper.SetDefault("sftpd.login_banner_file", globalConf.SFTPD.LoginBannerFile)
	viper.SetDefault("sftpd.enabled_ssh_commands", globalConf.SFTPD.EnabledSSHCommands)
	viper.SetDefault("sftpd.keyboard_interactive_auth_hook", globalConf.SFTPD.KeyboardInteractiveHook)
	viper.SetDefault("sftpd.password_authentication", globalConf.SFTPD.PasswordAuthentication)
	viper.SetDefault("ftpd.bind_port", globalConf.FTPD.BindPort)
	viper.SetDefault("ftpd.bind_address", globalConf.FTPD.BindAddress)
	viper.SetDefault("ftpd.banner", globalConf.FTPD.Banner)
	viper.SetDefault("ftpd.banner_file", globalConf.FTPD.BannerFile)
	viper.SetDefault("ftpd.active_transfers_port_non_20", globalConf.FTPD.ActiveTransfersPortNon20)
	viper.SetDefault("ftpd.force_passive_ip", globalConf.FTPD.ForcePassiveIP)
	viper.SetDefault("ftpd.passive_port_range.start", globalConf.FTPD.PassivePortRange.Start)
	viper.SetDefault("ftpd.passive_port_range.end", globalConf.FTPD.PassivePortRange.End)
	viper.SetDefault("ftpd.certificate_file", globalConf.FTPD.CertificateFile)
	viper.SetDefault("ftpd.certificate_key_file", globalConf.FTPD.CertificateKeyFile)
	viper.SetDefault("ftpd.tls_mode", globalConf.FTPD.TLSMode)
	viper.SetDefault("webdavd.bind_port", globalConf.WebDAVD.BindPort)
	viper.SetDefault("webdavd.bind_address", globalConf.WebDAVD.BindAddress)
	viper.SetDefault("webdavd.certificate_file", globalConf.WebDAVD.CertificateFile)
	viper.SetDefault("webdavd.certificate_key_file", globalConf.WebDAVD.CertificateKeyFile)
	viper.SetDefault("webdavd.cors.enabled", globalConf.WebDAVD.Cors.Enabled)
	viper.SetDefault("webdavd.cors.allowed_origins", globalConf.WebDAVD.Cors.AllowedOrigins)
	viper.SetDefault("webdavd.cors.allowed_methods", globalConf.WebDAVD.Cors.AllowedMethods)
	viper.SetDefault("webdavd.cors.allowed_headers", globalConf.WebDAVD.Cors.AllowedHeaders)
	viper.SetDefault("webdavd.cors.exposed_headers", globalConf.WebDAVD.Cors.ExposedHeaders)
	viper.SetDefault("webdavd.cors.allow_credentials", globalConf.WebDAVD.Cors.AllowCredentials)
	viper.SetDefault("webdavd.cors.max_age", globalConf.WebDAVD.Cors.MaxAge)
	viper.SetDefault("webdavd.cache.users.expiration_time", globalConf.WebDAVD.Cache.Users.ExpirationTime)
	viper.SetDefault("webdavd.cache.users.max_size", globalConf.WebDAVD.Cache.Users.MaxSize)
	viper.SetDefault("webdavd.cache.mime_types.enabled", globalConf.WebDAVD.Cache.MimeTypes.Enabled)
	viper.SetDefault("webdavd.cache.mime_types.max_size", globalConf.WebDAVD.Cache.MimeTypes.MaxSize)
	viper.SetDefault("data_provider.driver", globalConf.ProviderConf.Driver)
	viper.SetDefault("data_provider.name", globalConf.ProviderConf.Name)
	viper.SetDefault("data_provider.host", globalConf.ProviderConf.Host)
	viper.SetDefault("data_provider.port", globalConf.ProviderConf.Port)
	viper.SetDefault("data_provider.username", globalConf.ProviderConf.Username)
	viper.SetDefault("data_provider.password", globalConf.ProviderConf.Password)
	viper.SetDefault("data_provider.sslmode", globalConf.ProviderConf.SSLMode)
	viper.SetDefault("data_provider.connection_string", globalConf.ProviderConf.ConnectionString)
	viper.SetDefault("data_provider.sql_tables_prefix", globalConf.ProviderConf.SQLTablesPrefix)
	viper.SetDefault("data_provider.manage_users", globalConf.ProviderConf.ManageUsers)
	viper.SetDefault("data_provider.track_quota", globalConf.ProviderConf.TrackQuota)
	viper.SetDefault("data_provider.pool_size", globalConf.ProviderConf.PoolSize)
	viper.SetDefault("data_provider.users_base_dir", globalConf.ProviderConf.UsersBaseDir)
	viper.SetDefault("data_provider.actions.execute_on", globalConf.ProviderConf.Actions.ExecuteOn)
	viper.SetDefault("data_provider.actions.hook", globalConf.ProviderConf.Actions.Hook)
	viper.SetDefault("data_provider.external_auth_hook", globalConf.ProviderConf.ExternalAuthHook)
	viper.SetDefault("data_provider.external_auth_scope", globalConf.ProviderConf.ExternalAuthScope)
	viper.SetDefault("data_provider.credentials_path", globalConf.ProviderConf.CredentialsPath)
	viper.SetDefault("data_provider.prefer_database_credentials", globalConf.ProviderConf.PreferDatabaseCredentials)
	viper.SetDefault("data_provider.pre_login_hook", globalConf.ProviderConf.PreLoginHook)
	viper.SetDefault("data_provider.post_login_hook", globalConf.ProviderConf.PostLoginHook)
	viper.SetDefault("data_provider.post_login_scope", globalConf.ProviderConf.PostLoginScope)
	viper.SetDefault("data_provider.check_password_hook", globalConf.ProviderConf.CheckPasswordHook)
	viper.SetDefault("data_provider.check_password_scope", globalConf.ProviderConf.CheckPasswordScope)
	viper.SetDefault("data_provider.password_hashing.argon2_options.memory", globalConf.ProviderConf.PasswordHashing.Argon2Options.Memory)
	viper.SetDefault("data_provider.password_hashing.argon2_options.iterations", globalConf.ProviderConf.PasswordHashing.Argon2Options.Iterations)
	viper.SetDefault("data_provider.password_hashing.argon2_options.parallelism", globalConf.ProviderConf.PasswordHashing.Argon2Options.Parallelism)
	viper.SetDefault("data_provider.update_mode", globalConf.ProviderConf.UpdateMode)
	viper.SetDefault("httpd.bind_port", globalConf.HTTPDConfig.BindPort)
	viper.SetDefault("httpd.bind_address", globalConf.HTTPDConfig.BindAddress)
	viper.SetDefault("httpd.templates_path", globalConf.HTTPDConfig.TemplatesPath)
	viper.SetDefault("httpd.static_files_path", globalConf.HTTPDConfig.StaticFilesPath)
	viper.SetDefault("httpd.backups_path", globalConf.HTTPDConfig.BackupsPath)
	viper.SetDefault("httpd.auth_user_file", globalConf.HTTPDConfig.AuthUserFile)
	viper.SetDefault("httpd.certificate_file", globalConf.HTTPDConfig.CertificateFile)
	viper.SetDefault("httpd.certificate_key_file", globalConf.HTTPDConfig.CertificateKeyFile)
	viper.SetDefault("http.timeout", globalConf.HTTPConfig.Timeout)
	viper.SetDefault("http.ca_certificates", globalConf.HTTPConfig.CACertificates)
	viper.SetDefault("http.skip_tls_verify", globalConf.HTTPConfig.SkipTLSVerify)
	viper.SetDefault("kms.secrets.url", globalConf.KMSConfig.Secrets.URL)
	viper.SetDefault("kms.secrets.master_key_path", globalConf.KMSConfig.Secrets.MasterKeyPath)
}
