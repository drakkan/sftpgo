// Package config manages the configuration
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	"github.com/drakkan/sftpgo/telemetry"
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
	globalConf          globalConfig
	defaultSFTPDBanner  = fmt.Sprintf("SFTPGo_%v", version.Get().Version)
	defaultFTPDBanner   = fmt.Sprintf("SFTPGo %v ready", version.Get().Version)
	defaultSFTPDBinding = sftpd.Binding{
		Address:          "",
		Port:             2022,
		ApplyProxyConfig: true,
	}
	defaultFTPDBinding = ftpd.Binding{
		Address:          "",
		Port:             0,
		ApplyProxyConfig: true,
		TLSMode:          0,
		ForcePassiveIP:   "",
		ClientAuthType:   0,
		TLSCipherSuites:  nil,
	}
	defaultWebDAVDBinding = webdavd.Binding{
		Address:         "",
		Port:            0,
		EnableHTTPS:     false,
		ClientAuthType:  0,
		TLSCipherSuites: nil,
		Prefix:          "",
	}
	defaultHTTPDBinding = httpd.Binding{
		Address:         "127.0.0.1",
		Port:            8080,
		EnableWebAdmin:  true,
		EnableHTTPS:     false,
		ClientAuthType:  0,
		TLSCipherSuites: nil,
	}
)

type globalConfig struct {
	Common          common.Configuration  `json:"common" mapstructure:"common"`
	SFTPD           sftpd.Configuration   `json:"sftpd" mapstructure:"sftpd"`
	FTPD            ftpd.Configuration    `json:"ftpd" mapstructure:"ftpd"`
	WebDAVD         webdavd.Configuration `json:"webdavd" mapstructure:"webdavd"`
	ProviderConf    dataprovider.Config   `json:"data_provider" mapstructure:"data_provider"`
	HTTPDConfig     httpd.Conf            `json:"httpd" mapstructure:"httpd"`
	HTTPConfig      httpclient.Config     `json:"http" mapstructure:"http"`
	KMSConfig       kms.Configuration     `json:"kms" mapstructure:"kms"`
	TelemetryConfig telemetry.Conf        `json:"telemetry" mapstructure:"telemetry"`
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
			SetstatMode:         0,
			ProxyProtocol:       0,
			ProxyAllowed:        []string{},
			PostConnectHook:     "",
			MaxTotalConnections: 0,
			DefenderConfig: common.DefenderConfig{
				Enabled:          false,
				BanTime:          30,
				BanTimeIncrement: 50,
				Threshold:        15,
				ScoreInvalid:     2,
				ScoreValid:       1,
				ObservationTime:  30,
				EntriesSoftLimit: 100,
				EntriesHardLimit: 150,
				SafeListFile:     "",
				BlockListFile:    "",
			},
		},
		SFTPD: sftpd.Configuration{
			Banner:                  defaultSFTPDBanner,
			Bindings:                []sftpd.Binding{defaultSFTPDBinding},
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
			Bindings:                 []ftpd.Binding{defaultFTPDBinding},
			Banner:                   defaultFTPDBanner,
			BannerFile:               "",
			ActiveTransfersPortNon20: true,
			PassivePortRange: ftpd.PortRange{
				Start: 50000,
				End:   50100,
			},
			DisableActiveMode:  false,
			EnableSite:         false,
			HASHSupport:        0,
			CombineSupport:     0,
			CertificateFile:    "",
			CertificateKeyFile: "",
			CACertificates:     []string{},
			CARevocationLists:  []string{},
		},
		WebDAVD: webdavd.Configuration{
			Bindings:           []webdavd.Binding{defaultWebDAVDBinding},
			CertificateFile:    "",
			CertificateKeyFile: "",
			CACertificates:     []string{},
			CARevocationLists:  []string{},
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
			SkipNaturalKeysValidation: false,
		},
		HTTPDConfig: httpd.Conf{
			Bindings:           []httpd.Binding{defaultHTTPDBinding},
			TemplatesPath:      "templates",
			StaticFilesPath:    "static",
			BackupsPath:        "backups",
			CertificateFile:    "",
			CertificateKeyFile: "",
		},
		HTTPConfig: httpclient.Config{
			Timeout:        20,
			RetryWaitMin:   2,
			RetryWaitMax:   30,
			RetryMax:       3,
			CACertificates: nil,
			Certificates:   nil,
			SkipTLSVerify:  false,
		},
		KMSConfig: kms.Configuration{
			Secrets: kms.Secrets{
				URL:           "",
				MasterKeyPath: "",
			},
		},
		TelemetryConfig: telemetry.Conf{
			BindPort:           10000,
			BindAddress:        "127.0.0.1",
			EnableProfiler:     false,
			AuthUserFile:       "",
			CertificateFile:    "",
			CertificateKeyFile: "",
			TLSCipherSuites:    nil,
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

// GetTelemetryConfig returns the telemetry configuration
func GetTelemetryConfig() telemetry.Conf {
	return globalConf.TelemetryConfig
}

// SetTelemetryConfig sets the telemetry configuration
func SetTelemetryConfig(config telemetry.Conf) {
	globalConf.TelemetryConfig = config
}

// HasServicesToStart returns true if the config defines at least a service to start.
// Supported services are SFTP, FTP and WebDAV
func HasServicesToStart() bool {
	if globalConf.SFTPD.ShouldBind() {
		return true
	}
	if globalConf.FTPD.ShouldBind() {
		return true
	}
	if globalConf.WebDAVD.ShouldBind() {
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
		// if the user specify a configuration file we get os.ErrNotExist.
		// viper.ConfigFileNotFoundError is returned if viper is unable
		// to find sftpgo.{json,yaml, etc..} in any of the search paths
		if errors.As(err, &viper.ConfigFileNotFoundError{}) {
			logger.Debug(logSender, "", "no configuration file found")
		} else {
			// should we return the error and not start here?
			logger.Warn(logSender, "", "error loading configuration file: %v", err)
			logger.WarnToConsole("error loading configuration file: %v", err)
		}
	}
	err = viper.Unmarshal(&globalConf)
	if err != nil {
		logger.Warn(logSender, "", "error parsing configuration file: %v", err)
		logger.WarnToConsole("error parsing configuration file: %v", err)
		return err
	}
	// viper only supports slice of strings from env vars, so we use our custom method
	loadBindingsFromEnv()
	if strings.TrimSpace(globalConf.SFTPD.Banner) == "" {
		globalConf.SFTPD.Banner = defaultSFTPDBanner
	}
	if strings.TrimSpace(globalConf.FTPD.Banner) == "" {
		globalConf.FTPD.Banner = defaultFTPDBanner
	}
	if globalConf.ProviderConf.UsersBaseDir != "" && !utils.IsFileInputValid(globalConf.ProviderConf.UsersBaseDir) {
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
	if globalConf.ProviderConf.ExternalAuthScope < 0 || globalConf.ProviderConf.ExternalAuthScope > 15 {
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
	logger.Debug(logSender, "", "config file used: '%#v', config loaded: %+v", viper.ConfigFileUsed(), getRedactedGlobalConf())
	return nil
}

func checkSFTPDBindingsCompatibility() {
	if globalConf.SFTPD.BindPort == 0 { //nolint:staticcheck
		return
	}

	// we copy deprecated fields to new ones to keep backward compatibility so lint is disabled
	binding := sftpd.Binding{
		ApplyProxyConfig: true,
	}
	if globalConf.SFTPD.BindPort > 0 { //nolint:staticcheck
		binding.Port = globalConf.SFTPD.BindPort //nolint:staticcheck
	}
	if globalConf.SFTPD.BindAddress != "" { //nolint:staticcheck
		binding.Address = globalConf.SFTPD.BindAddress //nolint:staticcheck
	}

	globalConf.SFTPD.Bindings = []sftpd.Binding{binding}
}

func checkFTPDBindingCompatibility() {
	if globalConf.FTPD.BindPort == 0 { //nolint:staticcheck
		return
	}

	binding := ftpd.Binding{
		ApplyProxyConfig: true,
	}

	if globalConf.FTPD.BindPort > 0 { //nolint:staticcheck
		binding.Port = globalConf.FTPD.BindPort //nolint:staticcheck
	}
	if globalConf.FTPD.BindAddress != "" { //nolint:staticcheck
		binding.Address = globalConf.FTPD.BindAddress //nolint:staticcheck
	}
	if globalConf.FTPD.TLSMode > 0 { //nolint:staticcheck
		binding.TLSMode = globalConf.FTPD.TLSMode //nolint:staticcheck
	}
	if globalConf.FTPD.ForcePassiveIP != "" { //nolint:staticcheck
		binding.ForcePassiveIP = globalConf.FTPD.ForcePassiveIP //nolint:staticcheck
	}

	globalConf.FTPD.Bindings = []ftpd.Binding{binding}
}

func checkWebDAVDBindingCompatibility() {
	if globalConf.WebDAVD.BindPort == 0 { //nolint:staticcheck
		return
	}

	binding := webdavd.Binding{
		EnableHTTPS: globalConf.WebDAVD.CertificateFile != "" && globalConf.WebDAVD.CertificateKeyFile != "",
	}

	if globalConf.WebDAVD.BindPort > 0 { //nolint:staticcheck
		binding.Port = globalConf.WebDAVD.BindPort //nolint:staticcheck
	}
	if globalConf.WebDAVD.BindAddress != "" { //nolint:staticcheck
		binding.Address = globalConf.WebDAVD.BindAddress //nolint:staticcheck
	}

	globalConf.WebDAVD.Bindings = []webdavd.Binding{binding}
}

func checkHTTPDBindingCompatibility() {
	if globalConf.HTTPDConfig.BindPort == 0 { //nolint:staticcheck
		return
	}

	binding := httpd.Binding{
		EnableWebAdmin: globalConf.HTTPDConfig.StaticFilesPath != "" && globalConf.HTTPDConfig.TemplatesPath != "",
		EnableHTTPS:    globalConf.HTTPDConfig.CertificateFile != "" && globalConf.HTTPDConfig.CertificateKeyFile != "",
	}

	if globalConf.HTTPDConfig.BindPort > 0 { //nolint:staticcheck
		binding.Port = globalConf.HTTPDConfig.BindPort //nolint:staticcheck
	}
	if globalConf.HTTPDConfig.BindAddress != "" { //nolint:staticcheck
		binding.Address = globalConf.HTTPDConfig.BindAddress //nolint:staticcheck
	}

	globalConf.HTTPDConfig.Bindings = []httpd.Binding{binding}
}

func loadBindingsFromEnv() {
	checkSFTPDBindingsCompatibility()
	checkFTPDBindingCompatibility()
	checkWebDAVDBindingCompatibility()
	checkHTTPDBindingCompatibility()

	maxBindings := make([]int, 10)
	for idx := range maxBindings {
		getSFTPDBindindFromEnv(idx)
		getFTPDBindingFromEnv(idx)
		getWebDAVDBindingFromEnv(idx)
		getHTTPDBindingFromEnv(idx)
		getHTTPClientCertificatesFromEnv(idx)
	}
}

func getSFTPDBindindFromEnv(idx int) {
	binding := sftpd.Binding{}
	if len(globalConf.SFTPD.Bindings) > idx {
		binding = globalConf.SFTPD.Bindings[idx]
	}

	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_SFTPD__BINDINGS__%v__PORT", idx))
	if ok {
		binding.Port = port
		isSet = true
	}

	address, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_SFTPD__BINDINGS__%v__ADDRESS", idx))
	if ok {
		binding.Address = address
		isSet = true
	}

	applyProxyConfig, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_SFTPD__BINDINGS__%v__APPLY_PROXY_CONFIG", idx))
	if ok {
		binding.ApplyProxyConfig = applyProxyConfig
		isSet = true
	}

	if isSet {
		if len(globalConf.SFTPD.Bindings) > idx {
			globalConf.SFTPD.Bindings[idx] = binding
		} else {
			globalConf.SFTPD.Bindings = append(globalConf.SFTPD.Bindings, binding)
		}
	}
}

func getFTPDBindingFromEnv(idx int) {
	binding := ftpd.Binding{}
	if len(globalConf.FTPD.Bindings) > idx {
		binding = globalConf.FTPD.Bindings[idx]
	}

	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__PORT", idx))
	if ok {
		binding.Port = port
		isSet = true
	}

	address, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__ADDRESS", idx))
	if ok {
		binding.Address = address
		isSet = true
	}

	applyProxyConfig, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__APPLY_PROXY_CONFIG", idx))
	if ok {
		binding.ApplyProxyConfig = applyProxyConfig
		isSet = true
	}

	tlsMode, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__TLS_MODE", idx))
	if ok {
		binding.TLSMode = tlsMode
		isSet = true
	}

	passiveIP, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__FORCE_PASSIVE_IP", idx))
	if ok {
		binding.ForcePassiveIP = passiveIP
		isSet = true
	}

	clientAuthType, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__CLIENT_AUTH_TYPE", idx))
	if ok {
		binding.ClientAuthType = clientAuthType
		isSet = true
	}

	tlsCiphers, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__TLS_CIPHER_SUITES", idx))
	if ok {
		binding.TLSCipherSuites = tlsCiphers
		isSet = true
	}

	if isSet {
		if len(globalConf.FTPD.Bindings) > idx {
			globalConf.FTPD.Bindings[idx] = binding
		} else {
			globalConf.FTPD.Bindings = append(globalConf.FTPD.Bindings, binding)
		}
	}
}

func getWebDAVDBindingFromEnv(idx int) {
	binding := webdavd.Binding{}
	if len(globalConf.WebDAVD.Bindings) > idx {
		binding = globalConf.WebDAVD.Bindings[idx]
	}

	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__PORT", idx))
	if ok {
		binding.Port = port
		isSet = true
	}

	address, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__ADDRESS", idx))
	if ok {
		binding.Address = address
		isSet = true
	}

	enableHTTPS, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__ENABLE_HTTPS", idx))
	if ok {
		binding.EnableHTTPS = enableHTTPS
		isSet = true
	}

	clientAuthType, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__CLIENT_AUTH_TYPE", idx))
	if ok {
		binding.ClientAuthType = clientAuthType
		isSet = true
	}

	tlsCiphers, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__TLS_CIPHER_SUITES", idx))
	if ok {
		binding.TLSCipherSuites = tlsCiphers
		isSet = true
	}

	prefix, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__PREFIX", idx))
	if ok {
		binding.Prefix = prefix
		isSet = true
	}

	if isSet {
		if len(globalConf.WebDAVD.Bindings) > idx {
			globalConf.WebDAVD.Bindings[idx] = binding
		} else {
			globalConf.WebDAVD.Bindings = append(globalConf.WebDAVD.Bindings, binding)
		}
	}
}

func getHTTPDBindingFromEnv(idx int) {
	binding := httpd.Binding{}
	if len(globalConf.HTTPDConfig.Bindings) > idx {
		binding = globalConf.HTTPDConfig.Bindings[idx]
	}

	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__PORT", idx))
	if ok {
		binding.Port = port
		isSet = true
	}

	address, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ADDRESS", idx))
	if ok {
		binding.Address = address
		isSet = true
	}

	enableWebAdmin, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ENABLE_WEB_ADMIN", idx))
	if ok {
		binding.EnableWebAdmin = enableWebAdmin
		isSet = true
	}

	enableHTTPS, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ENABLE_HTTPS", idx))
	if ok {
		binding.EnableHTTPS = enableHTTPS
		isSet = true
	}

	clientAuthType, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__CLIENT_AUTH_TYPE", idx))
	if ok {
		binding.ClientAuthType = clientAuthType
		isSet = true
	}

	tlsCiphers, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__TLS_CIPHER_SUITES", idx))
	if ok {
		binding.TLSCipherSuites = tlsCiphers
		isSet = true
	}

	if isSet {
		if len(globalConf.HTTPDConfig.Bindings) > idx {
			globalConf.HTTPDConfig.Bindings[idx] = binding
		} else {
			globalConf.HTTPDConfig.Bindings = append(globalConf.HTTPDConfig.Bindings, binding)
		}
	}
}

func getHTTPClientCertificatesFromEnv(idx int) {
	tlsCert := httpclient.TLSKeyPair{}

	cert, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTP__CERTIFICATES__%v__CERT", idx))
	if ok {
		tlsCert.Cert = cert
	}

	key, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTP__CERTIFICATES__%v__KEY", idx))
	if ok {
		tlsCert.Key = key
	}

	if tlsCert.Cert != "" && tlsCert.Key != "" {
		if len(globalConf.HTTPConfig.Certificates) > idx {
			globalConf.HTTPConfig.Certificates[idx] = tlsCert
		} else {
			globalConf.HTTPConfig.Certificates = append(globalConf.HTTPConfig.Certificates, tlsCert)
		}
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
	viper.SetDefault("common.max_total_connections", globalConf.Common.MaxTotalConnections)
	viper.SetDefault("common.defender.enabled", globalConf.Common.DefenderConfig.Enabled)
	viper.SetDefault("common.defender.ban_time", globalConf.Common.DefenderConfig.BanTime)
	viper.SetDefault("common.defender.ban_time_increment", globalConf.Common.DefenderConfig.BanTimeIncrement)
	viper.SetDefault("common.defender.threshold", globalConf.Common.DefenderConfig.Threshold)
	viper.SetDefault("common.defender.score_invalid", globalConf.Common.DefenderConfig.ScoreInvalid)
	viper.SetDefault("common.defender.score_valid", globalConf.Common.DefenderConfig.ScoreValid)
	viper.SetDefault("common.defender.observation_time", globalConf.Common.DefenderConfig.ObservationTime)
	viper.SetDefault("common.defender.entries_soft_limit", globalConf.Common.DefenderConfig.EntriesSoftLimit)
	viper.SetDefault("common.defender.entries_hard_limit", globalConf.Common.DefenderConfig.EntriesHardLimit)
	viper.SetDefault("common.defender.safelist_file", globalConf.Common.DefenderConfig.SafeListFile)
	viper.SetDefault("common.defender.blocklist_file", globalConf.Common.DefenderConfig.BlockListFile)
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
	viper.SetDefault("ftpd.banner", globalConf.FTPD.Banner)
	viper.SetDefault("ftpd.banner_file", globalConf.FTPD.BannerFile)
	viper.SetDefault("ftpd.active_transfers_port_non_20", globalConf.FTPD.ActiveTransfersPortNon20)
	viper.SetDefault("ftpd.passive_port_range.start", globalConf.FTPD.PassivePortRange.Start)
	viper.SetDefault("ftpd.passive_port_range.end", globalConf.FTPD.PassivePortRange.End)
	viper.SetDefault("ftpd.disable_active_mode", globalConf.FTPD.DisableActiveMode)
	viper.SetDefault("ftpd.enable_site", globalConf.FTPD.EnableSite)
	viper.SetDefault("ftpd.hash_support", globalConf.FTPD.HASHSupport)
	viper.SetDefault("ftpd.combine_support", globalConf.FTPD.CombineSupport)
	viper.SetDefault("ftpd.certificate_file", globalConf.FTPD.CertificateFile)
	viper.SetDefault("ftpd.certificate_key_file", globalConf.FTPD.CertificateKeyFile)
	viper.SetDefault("ftpd.ca_certificates", globalConf.FTPD.CACertificates)
	viper.SetDefault("ftpd.ca_revocation_lists", globalConf.FTPD.CARevocationLists)
	viper.SetDefault("webdavd.certificate_file", globalConf.WebDAVD.CertificateFile)
	viper.SetDefault("webdavd.certificate_key_file", globalConf.WebDAVD.CertificateKeyFile)
	viper.SetDefault("webdavd.ca_certificates", globalConf.WebDAVD.CACertificates)
	viper.SetDefault("webdavd.ca_revocation_lists", globalConf.WebDAVD.CARevocationLists)
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
	viper.SetDefault("data_provider.skip_natural_keys_validation", globalConf.ProviderConf.SkipNaturalKeysValidation)
	viper.SetDefault("httpd.templates_path", globalConf.HTTPDConfig.TemplatesPath)
	viper.SetDefault("httpd.static_files_path", globalConf.HTTPDConfig.StaticFilesPath)
	viper.SetDefault("httpd.backups_path", globalConf.HTTPDConfig.BackupsPath)
	viper.SetDefault("httpd.certificate_file", globalConf.HTTPDConfig.CertificateFile)
	viper.SetDefault("httpd.certificate_key_file", globalConf.HTTPDConfig.CertificateKeyFile)
	viper.SetDefault("httpd.ca_certificates", globalConf.HTTPDConfig.CACertificates)
	viper.SetDefault("httpd.ca_revocation_lists", globalConf.HTTPDConfig.CARevocationLists)
	viper.SetDefault("http.timeout", globalConf.HTTPConfig.Timeout)
	viper.SetDefault("http.retry_wait_min", globalConf.HTTPConfig.RetryWaitMin)
	viper.SetDefault("http.retry_wait_max", globalConf.HTTPConfig.RetryWaitMax)
	viper.SetDefault("http.retry_max", globalConf.HTTPConfig.RetryMax)
	viper.SetDefault("http.ca_certificates", globalConf.HTTPConfig.CACertificates)
	viper.SetDefault("http.skip_tls_verify", globalConf.HTTPConfig.SkipTLSVerify)
	viper.SetDefault("kms.secrets.url", globalConf.KMSConfig.Secrets.URL)
	viper.SetDefault("kms.secrets.master_key_path", globalConf.KMSConfig.Secrets.MasterKeyPath)
	viper.SetDefault("telemetry.bind_port", globalConf.TelemetryConfig.BindPort)
	viper.SetDefault("telemetry.bind_address", globalConf.TelemetryConfig.BindAddress)
	viper.SetDefault("telemetry.enable_profiler", globalConf.TelemetryConfig.EnableProfiler)
	viper.SetDefault("telemetry.auth_user_file", globalConf.TelemetryConfig.AuthUserFile)
	viper.SetDefault("telemetry.certificate_file", globalConf.TelemetryConfig.CertificateFile)
	viper.SetDefault("telemetry.certificate_key_file", globalConf.TelemetryConfig.CertificateKeyFile)
	viper.SetDefault("telemetry.tls_cipher_suites", globalConf.TelemetryConfig.TLSCipherSuites)
}

func lookupBoolFromEnv(envName string) (bool, bool) {
	value, ok := os.LookupEnv(envName)
	if ok {
		converted, err := strconv.ParseBool(value)
		if err == nil {
			return converted, ok
		}
	}

	return false, false
}

func lookupIntFromEnv(envName string) (int, bool) {
	value, ok := os.LookupEnv(envName)
	if ok {
		converted, err := strconv.ParseInt(value, 10, 16)
		if err == nil {
			return int(converted), ok
		}
	}

	return 0, false
}

func lookupStringListFromEnv(envName string) ([]string, bool) {
	value, ok := os.LookupEnv(envName)
	if ok {
		var result []string
		for _, v := range strings.Split(value, ",") {
			result = append(result, strings.TrimSpace(v))
		}
		return result, true
	}
	return nil, false
}
