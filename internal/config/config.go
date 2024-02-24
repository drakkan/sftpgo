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
	"github.com/subosito/gotenv"

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/command"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/httpd"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/telemetry"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

const (
	logSender = "config"
	// configName defines the name for config file.
	// This name does not include the extension, viper will search for files
	// with supported extensions such as "sftpgo.json", "sftpgo.yaml" and so on
	configName = "sftpgo"
	// ConfigEnvPrefix defines a prefix that environment variables will use
	configEnvPrefix = "sftpgo"
	envFileMaxSize  = 1048576
)

var (
	globalConf             globalConfig
	defaultSFTPDBanner     = fmt.Sprintf("SFTPGo_%v", version.Get().Version)
	defaultFTPDBanner      = fmt.Sprintf("SFTPGo %v ready", version.Get().Version)
	defaultInstallCodeHint = "Installation code"
	defaultSFTPDBinding    = sftpd.Binding{
		Address:          "",
		Port:             2022,
		ApplyProxyConfig: true,
	}
	defaultFTPDBinding = ftpd.Binding{
		Address:                    "",
		Port:                       0,
		ApplyProxyConfig:           true,
		TLSMode:                    0,
		CertificateFile:            "",
		CertificateKeyFile:         "",
		MinTLSVersion:              12,
		ForcePassiveIP:             "",
		PassiveIPOverrides:         nil,
		PassiveHost:                "",
		ClientAuthType:             0,
		TLSCipherSuites:            nil,
		PassiveConnectionsSecurity: 0,
		ActiveConnectionsSecurity:  0,
		Debug:                      false,
	}
	defaultWebDAVDBinding = webdavd.Binding{
		Address:              "",
		Port:                 0,
		EnableHTTPS:          false,
		CertificateFile:      "",
		CertificateKeyFile:   "",
		MinTLSVersion:        12,
		ClientAuthType:       0,
		TLSCipherSuites:      nil,
		Protocols:            nil,
		Prefix:               "",
		ProxyAllowed:         nil,
		ClientIPProxyHeader:  "",
		ClientIPHeaderDepth:  0,
		DisableWWWAuthHeader: false,
	}
	defaultHTTPDBinding = httpd.Binding{
		Address:             "",
		Port:                8080,
		EnableWebAdmin:      true,
		EnableWebClient:     true,
		EnableRESTAPI:       true,
		EnabledLoginMethods: 0,
		EnableHTTPS:         false,
		CertificateFile:     "",
		CertificateKeyFile:  "",
		MinTLSVersion:       12,
		ClientAuthType:      0,
		TLSCipherSuites:     nil,
		Protocols:           nil,
		ProxyAllowed:        nil,
		ClientIPProxyHeader: "",
		ClientIPHeaderDepth: 0,
		HideLoginURL:        0,
		RenderOpenAPI:       true,
		OIDC: httpd.OIDC{
			ClientID:                   "",
			ClientSecret:               "",
			ClientSecretFile:           "",
			ConfigURL:                  "",
			RedirectBaseURL:            "",
			UsernameField:              "",
			RoleField:                  "",
			ImplicitRoles:              false,
			Scopes:                     []string{"openid", "profile", "email"},
			CustomFields:               []string{},
			InsecureSkipSignatureCheck: false,
			Debug:                      false,
		},
		Security: httpd.SecurityConf{
			Enabled:                 false,
			AllowedHosts:            nil,
			AllowedHostsAreRegex:    false,
			HostsProxyHeaders:       nil,
			HTTPSRedirect:           false,
			HTTPSHost:               "",
			HTTPSProxyHeaders:       nil,
			STSSeconds:              0,
			STSIncludeSubdomains:    false,
			STSPreload:              false,
			ContentTypeNosniff:      false,
			ContentSecurityPolicy:   "",
			PermissionsPolicy:       "",
			CrossOriginOpenerPolicy: "",
		},
		Branding: httpd.Branding{},
	}
	defaultRateLimiter = common.RateLimiterConfig{
		Average:                0,
		Period:                 1000,
		Burst:                  1,
		Type:                   2,
		Protocols:              []string{common.ProtocolSSH, common.ProtocolFTP, common.ProtocolWebDAV, common.ProtocolHTTP},
		GenerateDefenderEvents: false,
		EntriesSoftLimit:       100,
		EntriesHardLimit:       150,
	}
	defaultTOTP = mfa.TOTPConfig{
		Name:   "Default",
		Issuer: "SFTPGo",
		Algo:   mfa.TOTPAlgoSHA1,
	}
)

type globalConfig struct {
	Common          common.Configuration  `json:"common" mapstructure:"common"`
	ACME            acme.Configuration    `json:"acme" mapstructure:"acme"`
	SFTPD           sftpd.Configuration   `json:"sftpd" mapstructure:"sftpd"`
	FTPD            ftpd.Configuration    `json:"ftpd" mapstructure:"ftpd"`
	WebDAVD         webdavd.Configuration `json:"webdavd" mapstructure:"webdavd"`
	ProviderConf    dataprovider.Config   `json:"data_provider" mapstructure:"data_provider"`
	HTTPDConfig     httpd.Conf            `json:"httpd" mapstructure:"httpd"`
	HTTPConfig      httpclient.Config     `json:"http" mapstructure:"http"`
	CommandConfig   command.Config        `json:"command" mapstructure:"command"`
	KMSConfig       kms.Configuration     `json:"kms" mapstructure:"kms"`
	MFAConfig       mfa.Config            `json:"mfa" mapstructure:"mfa"`
	TelemetryConfig telemetry.Conf        `json:"telemetry" mapstructure:"telemetry"`
	PluginsConfig   []plugin.Config       `json:"plugins" mapstructure:"plugins"`
	SMTPConfig      smtp.Config           `json:"smtp" mapstructure:"smtp"`
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
				ExecuteOn:   []string{},
				ExecuteSync: []string{},
				Hook:        "",
			},
			SetstatMode:           0,
			RenameMode:            0,
			ResumeMaxSize:         0,
			TempPath:              "",
			ProxyProtocol:         0,
			ProxyAllowed:          []string{},
			ProxySkipped:          []string{},
			PostConnectHook:       "",
			PostDisconnectHook:    "",
			DataRetentionHook:     "",
			MaxTotalConnections:   0,
			MaxPerHostConnections: 20,
			AllowListStatus:       0,
			AllowSelfConnections:  0,
			DefenderConfig: common.DefenderConfig{
				Enabled:            false,
				Driver:             common.DefenderDriverMemory,
				BanTime:            30,
				BanTimeIncrement:   50,
				Threshold:          15,
				ScoreInvalid:       2,
				ScoreValid:         1,
				ScoreLimitExceeded: 3,
				ScoreNoAuth:        0,
				ObservationTime:    30,
				EntriesSoftLimit:   100,
				EntriesHardLimit:   150,
			},
			RateLimitersConfig: []common.RateLimiterConfig{defaultRateLimiter},
			Umask:              "",
			Metadata: common.MetadataConfig{
				Read: 0,
			},
		},
		ACME: acme.Configuration{
			Email:      "",
			KeyType:    "4096",
			CertsPath:  "certs",
			CAEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
			Domains:    []string{},
			RenewDays:  30,
			HTTP01Challenge: acme.HTTP01Challenge{
				Port:        80,
				WebRoot:     "",
				ProxyHeader: "",
			},
			TLSALPN01Challenge: acme.TLSALPN01Challenge{
				Port: 0,
			},
		},
		SFTPD: sftpd.Configuration{
			Bindings:                          []sftpd.Binding{defaultSFTPDBinding},
			MaxAuthTries:                      0,
			Banner:                            defaultSFTPDBanner,
			HostKeys:                          []string{},
			HostCertificates:                  []string{},
			HostKeyAlgorithms:                 []string{},
			KexAlgorithms:                     []string{},
			Ciphers:                           []string{},
			MACs:                              []string{},
			PublicKeyAlgorithms:               []string{},
			TrustedUserCAKeys:                 []string{},
			RevokedUserCertsFile:              "",
			LoginBannerFile:                   "",
			EnabledSSHCommands:                []string{},
			KeyboardInteractiveAuthentication: true,
			KeyboardInteractiveHook:           "",
			PasswordAuthentication:            true,
			FolderPrefix:                      "",
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
			Cors: webdavd.CorsConfig{
				Enabled:              false,
				AllowedOrigins:       []string{},
				AllowedMethods:       []string{},
				AllowedHeaders:       []string{},
				ExposedHeaders:       []string{},
				AllowCredentials:     false,
				MaxAge:               0,
				OptionsPassthrough:   false,
				OptionsSuccessStatus: 0,
				AllowPrivateNetwork:  false,
			},
			Cache: webdavd.Cache{
				Users: webdavd.UsersCacheConfig{
					ExpirationTime: 0,
					MaxSize:        50,
				},
				MimeTypes: webdavd.MimeCacheConfig{
					Enabled:        true,
					MaxSize:        1000,
					CustomMappings: nil,
				},
			},
		},
		ProviderConf: dataprovider.Config{
			Driver:             "sqlite",
			Name:               "sftpgo.db",
			Host:               "",
			Port:               0,
			Username:           "",
			UsernameFile:       "",
			Password:           "",
			PasswordFile:       "",
			ConnectionString:   "",
			SQLTablesPrefix:    "",
			SSLMode:            0,
			DisableSNI:         false,
			TargetSessionAttrs: "",
			RootCert:           "",
			ClientCert:         "",
			ClientKey:          "",
			TrackQuota:         2,
			PoolSize:           0,
			UsersBaseDir:       "",
			Actions: dataprovider.ObjectsActions{
				ExecuteOn:  []string{},
				ExecuteFor: []string{},
				Hook:       "",
			},
			ExternalAuthHook:   "",
			ExternalAuthScope:  0,
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
				BcryptOptions: dataprovider.BcryptOptions{
					Cost: 10,
				},
				Algo: dataprovider.HashingAlgoBcrypt,
			},
			PasswordValidation: dataprovider.PasswordValidation{
				Admins: dataprovider.PasswordValidationRules{
					MinEntropy: 0,
				},
				Users: dataprovider.PasswordValidationRules{
					MinEntropy: 0,
				},
			},
			PasswordCaching:    true,
			UpdateMode:         0,
			DelayedQuotaUpdate: 0,
			CreateDefaultAdmin: false,
			NamingRules:        1,
			IsShared:           0,
			Node: dataprovider.NodeConfig{
				Host:  "",
				Port:  0,
				Proto: "http",
			},
			BackupsPath: "backups",
		},
		HTTPDConfig: httpd.Conf{
			Bindings:              []httpd.Binding{defaultHTTPDBinding},
			TemplatesPath:         "templates",
			StaticFilesPath:       "static",
			OpenAPIPath:           "openapi",
			WebRoot:               "",
			CertificateFile:       "",
			CertificateKeyFile:    "",
			CACertificates:        nil,
			CARevocationLists:     nil,
			SigningPassphrase:     "",
			SigningPassphraseFile: "",
			TokenValidation:       0,
			MaxUploadFileSize:     0,
			Cors: httpd.CorsConfig{
				Enabled:              false,
				AllowedOrigins:       []string{},
				AllowedMethods:       []string{},
				AllowedHeaders:       []string{},
				ExposedHeaders:       []string{},
				AllowCredentials:     false,
				MaxAge:               0,
				OptionsPassthrough:   false,
				OptionsSuccessStatus: 0,
				AllowPrivateNetwork:  false,
			},
			Setup: httpd.SetupConfig{
				InstallationCode:     "",
				InstallationCodeHint: defaultInstallCodeHint,
			},
			HideSupportLink: false,
		},
		HTTPConfig: httpclient.Config{
			Timeout:        20,
			RetryWaitMin:   2,
			RetryWaitMax:   30,
			RetryMax:       3,
			CACertificates: nil,
			Certificates:   nil,
			SkipTLSVerify:  false,
			Headers:        nil,
		},
		CommandConfig: command.Config{
			Timeout:  30,
			Env:      nil,
			Commands: nil,
		},
		KMSConfig: kms.Configuration{
			Secrets: kms.Secrets{
				URL:             "",
				MasterKeyString: "",
				MasterKeyPath:   "",
			},
		},
		MFAConfig: mfa.Config{
			TOTP: []mfa.TOTPConfig{defaultTOTP},
		},
		TelemetryConfig: telemetry.Conf{
			BindPort:           0,
			BindAddress:        "127.0.0.1",
			EnableProfiler:     false,
			AuthUserFile:       "",
			CertificateFile:    "",
			CertificateKeyFile: "",
			MinTLSVersion:      12,
			TLSCipherSuites:    nil,
			Protocols:          nil,
		},
		SMTPConfig: smtp.Config{
			Host:          "",
			Port:          587,
			From:          "",
			User:          "",
			Password:      "",
			AuthType:      0,
			Encryption:    0,
			Domain:        "",
			TemplatesPath: "templates",
		},
		PluginsConfig: nil,
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

// GetCommandConfig returns the configuration for external commands
func GetCommandConfig() command.Config {
	return globalConf.CommandConfig
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

// GetPluginsConfig returns the plugins configuration
func GetPluginsConfig() []plugin.Config {
	return globalConf.PluginsConfig
}

// SetPluginsConfig sets the plugin configuration
func SetPluginsConfig(config []plugin.Config) {
	globalConf.PluginsConfig = config
}

// GetMFAConfig returns multi-factor authentication config
func GetMFAConfig() mfa.Config {
	return globalConf.MFAConfig
}

// GetSMTPConfig returns the SMTP configuration
func GetSMTPConfig() smtp.Config {
	return globalConf.SMTPConfig
}

// GetACMEConfig returns the ACME configuration
func GetACMEConfig() acme.Configuration {
	return globalConf.ACME
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
	if globalConf.HTTPDConfig.ShouldBind() {
		return true
	}
	return false
}

func getRedactedPassword(value string) string {
	if value == "" {
		return value
	}
	return "[redacted]"
}

func getRedactedGlobalConf() globalConfig {
	conf := globalConf
	conf.Common.Actions.Hook = util.GetRedactedURL(conf.Common.Actions.Hook)
	conf.Common.StartupHook = util.GetRedactedURL(conf.Common.StartupHook)
	conf.Common.PostConnectHook = util.GetRedactedURL(conf.Common.PostConnectHook)
	conf.Common.PostDisconnectHook = util.GetRedactedURL(conf.Common.PostDisconnectHook)
	conf.Common.DataRetentionHook = util.GetRedactedURL(conf.Common.DataRetentionHook)
	conf.SFTPD.KeyboardInteractiveHook = util.GetRedactedURL(conf.SFTPD.KeyboardInteractiveHook)
	conf.HTTPDConfig.SigningPassphrase = getRedactedPassword(conf.HTTPDConfig.SigningPassphrase)
	conf.HTTPDConfig.Setup.InstallationCode = getRedactedPassword(conf.HTTPDConfig.Setup.InstallationCode)
	conf.ProviderConf.Password = getRedactedPassword(conf.ProviderConf.Password)
	conf.ProviderConf.Actions.Hook = util.GetRedactedURL(conf.ProviderConf.Actions.Hook)
	conf.ProviderConf.ExternalAuthHook = util.GetRedactedURL(conf.ProviderConf.ExternalAuthHook)
	conf.ProviderConf.PreLoginHook = util.GetRedactedURL(conf.ProviderConf.PreLoginHook)
	conf.ProviderConf.PostLoginHook = util.GetRedactedURL(conf.ProviderConf.PostLoginHook)
	conf.ProviderConf.CheckPasswordHook = util.GetRedactedURL(conf.ProviderConf.CheckPasswordHook)
	conf.SMTPConfig.Password = getRedactedPassword(conf.SMTPConfig.Password)
	conf.HTTPDConfig.Bindings = nil
	for _, binding := range globalConf.HTTPDConfig.Bindings {
		binding.OIDC.ClientID = getRedactedPassword(binding.OIDC.ClientID)
		binding.OIDC.ClientSecret = getRedactedPassword(binding.OIDC.ClientSecret)
		conf.HTTPDConfig.Bindings = append(conf.HTTPDConfig.Bindings, binding)
	}
	return conf
}

func setConfigFile(configDir, configFile string) {
	if configFile == "" {
		return
	}
	if !filepath.IsAbs(configFile) && util.IsFileInputValid(configFile) {
		configFile = filepath.Join(configDir, configFile)
	}
	viper.SetConfigFile(configFile)
}

// readEnvFiles reads files inside the "env.d" directory relative to configDir
// and then export the valid variables into environment variables if they do
// not exist
func readEnvFiles(configDir string) {
	envd := filepath.Join(configDir, "env.d")
	entries, err := os.ReadDir(envd)
	if err != nil {
		logger.Info(logSender, "", "unable to read env files from %q: %v", envd, err)
		return
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() {
			envFile := filepath.Join(envd, entry.Name())
			if info.Size() > envFileMaxSize {
				logger.Info(logSender, "", "env file %q too big: %s, skipping", entry.Name(), util.ByteCountIEC(info.Size()))
				continue
			}
			err = gotenv.Load(envFile)
			if err != nil {
				logger.Error(logSender, "", "unable to load env vars from file %q, err: %v", envFile, err)
			} else {
				logger.Info(logSender, "", "set env vars from file %q", envFile)
			}
		}
	}
}

func checkOverrideDefaultSettings() {
	// for slices we need to set the defaults to nil if the key is set in the config file,
	// otherwise the values are merged and not replaced as expected
	rateLimiters := viper.Get("common.rate_limiters")
	if val, ok := rateLimiters.([]any); ok {
		if len(val) > 0 {
			if rl, ok := val[0].(map[string]any); ok {
				if _, ok := rl["protocols"]; ok {
					globalConf.Common.RateLimitersConfig[0].Protocols = nil
				}
			}
		}
	}

	httpdBindings := viper.Get("httpd.bindings")
	if val, ok := httpdBindings.([]any); ok {
		if len(val) > 0 {
			if binding, ok := val[0].(map[string]any); ok {
				if val, ok := binding["oidc"]; ok {
					if oidc, ok := val.(map[string]any); ok {
						if _, ok := oidc["scopes"]; ok {
							globalConf.HTTPDConfig.Bindings[0].OIDC.Scopes = nil
						}
					}
				}
			}
		}
	}

	if util.Contains(viper.AllKeys(), "mfa.totp") {
		globalConf.MFAConfig.TOTP = nil
	}
}

// LoadConfig loads the configuration
// configDir will be added to the configuration search paths.
// The search path contains by default the current directory and on linux it contains
// $HOME/.config/sftpgo and /etc/sftpgo too.
// configFile is an absolute or relative path (to the config dir) to the configuration file.
func LoadConfig(configDir, configFile string) error {
	var err error
	readEnvFiles(configDir)
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
			logger.Warn(logSender, "", "error loading configuration file: %v", err)
			logger.WarnToConsole("error loading configuration file: %v", err)
			return err
		}
	}
	checkOverrideDefaultSettings()
	err = viper.Unmarshal(&globalConf)
	if err != nil {
		logger.Warn(logSender, "", "error parsing configuration file: %v", err)
		logger.WarnToConsole("error parsing configuration file: %v", err)
		return err
	}
	// viper only supports slice of strings from env vars, so we use our custom method
	loadBindingsFromEnv()
	loadWebDAVCacheMappingsFromEnv()
	resetInvalidConfigs()
	logger.Debug(logSender, "", "config file used: '%q', config loaded: %+v", viper.ConfigFileUsed(), getRedactedGlobalConf())
	return nil
}

func isProxyProtocolValid() bool {
	return globalConf.Common.ProxyProtocol >= 0 && globalConf.Common.ProxyProtocol <= 2
}

func isExternalAuthScopeValid() bool {
	return globalConf.ProviderConf.ExternalAuthScope >= 0 && globalConf.ProviderConf.ExternalAuthScope <= 15
}

func resetInvalidConfigs() {
	if strings.TrimSpace(globalConf.SFTPD.Banner) == "" {
		globalConf.SFTPD.Banner = defaultSFTPDBanner
	}
	if strings.TrimSpace(globalConf.FTPD.Banner) == "" {
		globalConf.FTPD.Banner = defaultFTPDBanner
	}
	if strings.TrimSpace(globalConf.HTTPDConfig.Setup.InstallationCodeHint) == "" {
		globalConf.HTTPDConfig.Setup.InstallationCodeHint = defaultInstallCodeHint
	}
	if globalConf.ProviderConf.UsersBaseDir != "" && !util.IsFileInputValid(globalConf.ProviderConf.UsersBaseDir) {
		warn := fmt.Sprintf("invalid users base dir %q will be ignored", globalConf.ProviderConf.UsersBaseDir)
		globalConf.ProviderConf.UsersBaseDir = ""
		logger.Warn(logSender, "", "Non-fatal configuration error: %v", warn)
		logger.WarnToConsole("Non-fatal configuration error: %v", warn)
	}
	if !isProxyProtocolValid() {
		warn := fmt.Sprintf("invalid proxy_protocol 0, 1 and 2 are supported, configured: %v reset proxy_protocol to 0",
			globalConf.Common.ProxyProtocol)
		globalConf.Common.ProxyProtocol = 0
		logger.Warn(logSender, "", "Non-fatal configuration error: %v", warn)
		logger.WarnToConsole("Non-fatal configuration error: %v", warn)
	}
	if !isExternalAuthScopeValid() {
		warn := fmt.Sprintf("invalid external_auth_scope: %v reset to 0", globalConf.ProviderConf.ExternalAuthScope)
		globalConf.ProviderConf.ExternalAuthScope = 0
		logger.Warn(logSender, "", "Non-fatal configuration error: %v", warn)
		logger.WarnToConsole("Non-fatal configuration error: %v", warn)
	}
	if globalConf.Common.DefenderConfig.Enabled && globalConf.Common.DefenderConfig.Driver == common.DefenderDriverProvider {
		if !globalConf.ProviderConf.IsDefenderSupported() {
			warn := fmt.Sprintf("provider based defender is not supported with data provider %q, "+
				"the memory defender implementation will be used. If you want to use the provider defender "+
				"implementation please switch to a shared/distributed data provider",
				globalConf.ProviderConf.Driver)
			globalConf.Common.DefenderConfig.Driver = common.DefenderDriverMemory
			logger.Warn(logSender, "", "Non-fatal configuration error: %v", warn)
			logger.WarnToConsole("Non-fatal configuration error: %v", warn)
		}
	}
}

func loadBindingsFromEnv() {
	for idx := 0; idx < 10; idx++ {
		getTOTPFromEnv(idx)
		getRateLimitersFromEnv(idx)
		getPluginsFromEnv(idx)
		getSFTPDBindindFromEnv(idx)
		getFTPDBindingFromEnv(idx)
		getWebDAVDBindingFromEnv(idx)
		getHTTPDBindingFromEnv(idx)
		getHTTPClientCertificatesFromEnv(idx)
		getHTTPClientHeadersFromEnv(idx)
		getCommandConfigsFromEnv(idx)
	}
}

func getTOTPFromEnv(idx int) {
	totpConfig := defaultTOTP
	if len(globalConf.MFAConfig.TOTP) > idx {
		totpConfig = globalConf.MFAConfig.TOTP[idx]
	}

	isSet := false

	name, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_MFA__TOTP__%v__NAME", idx))
	if ok {
		totpConfig.Name = name
		isSet = true
	}

	issuer, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_MFA__TOTP__%v__ISSUER", idx))
	if ok {
		totpConfig.Issuer = issuer
		isSet = true
	}

	algo, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_MFA__TOTP__%v__ALGO", idx))
	if ok {
		totpConfig.Algo = algo
		isSet = true
	}

	if isSet {
		if len(globalConf.MFAConfig.TOTP) > idx {
			globalConf.MFAConfig.TOTP[idx] = totpConfig
		} else {
			globalConf.MFAConfig.TOTP = append(globalConf.MFAConfig.TOTP, totpConfig)
		}
	}
}

func getRateLimitersFromEnv(idx int) {
	rtlConfig := defaultRateLimiter
	if len(globalConf.Common.RateLimitersConfig) > idx {
		rtlConfig = globalConf.Common.RateLimitersConfig[idx]
	}

	isSet := false

	average, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__AVERAGE", idx), 64)
	if ok {
		rtlConfig.Average = average
		isSet = true
	}

	period, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__PERIOD", idx), 64)
	if ok {
		rtlConfig.Period = period
		isSet = true
	}

	burst, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__BURST", idx), 0)
	if ok {
		rtlConfig.Burst = int(burst)
		isSet = true
	}

	rtlType, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__TYPE", idx), 0)
	if ok {
		rtlConfig.Type = int(rtlType)
		isSet = true
	}

	protocols, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__PROTOCOLS", idx))
	if ok {
		rtlConfig.Protocols = protocols
		isSet = true
	}

	generateEvents, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__GENERATE_DEFENDER_EVENTS", idx))
	if ok {
		rtlConfig.GenerateDefenderEvents = generateEvents
		isSet = true
	}

	softLimit, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__ENTRIES_SOFT_LIMIT", idx), 0)
	if ok {
		rtlConfig.EntriesSoftLimit = int(softLimit)
		isSet = true
	}

	hardLimit, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_COMMON__RATE_LIMITERS__%v__ENTRIES_HARD_LIMIT", idx), 0)
	if ok {
		rtlConfig.EntriesHardLimit = int(hardLimit)
		isSet = true
	}

	if isSet {
		if len(globalConf.Common.RateLimitersConfig) > idx {
			globalConf.Common.RateLimitersConfig[idx] = rtlConfig
		} else {
			globalConf.Common.RateLimitersConfig = append(globalConf.Common.RateLimitersConfig, rtlConfig)
		}
	}
}

func getKMSPluginFromEnv(idx int, pluginConfig *plugin.Config) bool {
	isSet := false

	kmsScheme, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__KMS_OPTIONS__SCHEME", idx))
	if ok {
		pluginConfig.KMSOptions.Scheme = kmsScheme
		isSet = true
	}

	kmsEncStatus, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__KMS_OPTIONS__ENCRYPTED_STATUS", idx))
	if ok {
		pluginConfig.KMSOptions.EncryptedStatus = kmsEncStatus
		isSet = true
	}

	return isSet
}

func getAuthPluginFromEnv(idx int, pluginConfig *plugin.Config) bool {
	isSet := false

	authScope, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__AUTH_OPTIONS__SCOPE", idx), 0)
	if ok {
		pluginConfig.AuthOptions.Scope = int(authScope)
		isSet = true
	}

	return isSet
}

func getNotifierPluginFromEnv(idx int, pluginConfig *plugin.Config) bool {
	isSet := false

	notifierFsEvents, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__NOTIFIER_OPTIONS__FS_EVENTS", idx))
	if ok {
		pluginConfig.NotifierOptions.FsEvents = notifierFsEvents
		isSet = true
	}

	notifierProviderEvents, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__NOTIFIER_OPTIONS__PROVIDER_EVENTS", idx))
	if ok {
		pluginConfig.NotifierOptions.ProviderEvents = notifierProviderEvents
		isSet = true
	}

	notifierProviderObjects, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__NOTIFIER_OPTIONS__PROVIDER_OBJECTS", idx))
	if ok {
		pluginConfig.NotifierOptions.ProviderObjects = notifierProviderObjects
		isSet = true
	}

	notifierLogEventsString, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__NOTIFIER_OPTIONS__LOG_EVENTS", idx))
	if ok {
		var notifierLogEvents []int
		for _, e := range notifierLogEventsString {
			ev, err := strconv.Atoi(e)
			if err == nil {
				notifierLogEvents = append(notifierLogEvents, ev)
			}
		}
		if len(notifierLogEvents) > 0 {
			pluginConfig.NotifierOptions.LogEvents = notifierLogEvents
			isSet = true
		}
	}

	notifierRetryMaxTime, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__NOTIFIER_OPTIONS__RETRY_MAX_TIME", idx), 0)
	if ok {
		pluginConfig.NotifierOptions.RetryMaxTime = int(notifierRetryMaxTime)
		isSet = true
	}

	notifierRetryQueueMaxSize, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__NOTIFIER_OPTIONS__RETRY_QUEUE_MAX_SIZE", idx), 0)
	if ok {
		pluginConfig.NotifierOptions.RetryQueueMaxSize = int(notifierRetryQueueMaxSize)
		isSet = true
	}

	return isSet
}

func getPluginsFromEnv(idx int) {
	pluginConfig := plugin.Config{}
	if len(globalConf.PluginsConfig) > idx {
		pluginConfig = globalConf.PluginsConfig[idx]
	}

	isSet := false

	pluginType, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__TYPE", idx))
	if ok {
		pluginConfig.Type = pluginType
		isSet = true
	}

	if getNotifierPluginFromEnv(idx, &pluginConfig) {
		isSet = true
	}

	if getKMSPluginFromEnv(idx, &pluginConfig) {
		isSet = true
	}

	if getAuthPluginFromEnv(idx, &pluginConfig) {
		isSet = true
	}

	cmd, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__CMD", idx))
	if ok {
		pluginConfig.Cmd = cmd
		isSet = true
	}

	cmdArgs, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__ARGS", idx))
	if ok {
		pluginConfig.Args = cmdArgs
		isSet = true
	}

	pluginHash, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__SHA256SUM", idx))
	if ok {
		pluginConfig.SHA256Sum = pluginHash
		isSet = true
	}

	autoMTLS, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__AUTO_MTLS", idx))
	if ok {
		pluginConfig.AutoMTLS = autoMTLS
		isSet = true
	}

	envPrefix, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__ENV_PREFIX", idx))
	if ok {
		pluginConfig.EnvPrefix = envPrefix
		isSet = true
	}

	envVars, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_PLUGINS__%v__ENV_VARS", idx))
	if ok {
		pluginConfig.EnvVars = envVars
		isSet = true
	}

	if isSet {
		if len(globalConf.PluginsConfig) > idx {
			globalConf.PluginsConfig[idx] = pluginConfig
		} else {
			globalConf.PluginsConfig = append(globalConf.PluginsConfig, pluginConfig)
		}
	}
}

func getSFTPDBindindFromEnv(idx int) {
	binding := defaultSFTPDBinding
	if len(globalConf.SFTPD.Bindings) > idx {
		binding = globalConf.SFTPD.Bindings[idx]
	}

	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_SFTPD__BINDINGS__%v__PORT", idx), 0)
	if ok {
		binding.Port = int(port)
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

func getFTPDPassiveIPOverridesFromEnv(idx int) []ftpd.PassiveIPOverride {
	var overrides []ftpd.PassiveIPOverride
	if len(globalConf.FTPD.Bindings) > idx {
		overrides = globalConf.FTPD.Bindings[idx].PassiveIPOverrides
	}

	for subIdx := 0; subIdx < 10; subIdx++ {
		var override ftpd.PassiveIPOverride
		var replace bool
		if len(globalConf.FTPD.Bindings) > idx && len(globalConf.FTPD.Bindings[idx].PassiveIPOverrides) > subIdx {
			override = globalConf.FTPD.Bindings[idx].PassiveIPOverrides[subIdx]
			replace = true
		}

		ip, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__PASSIVE_IP_OVERRIDES__%v__IP", idx, subIdx))
		if ok {
			override.IP = ip
		}

		networks, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__PASSIVE_IP_OVERRIDES__%v__NETWORKS",
			idx, subIdx))
		if ok {
			override.Networks = networks
		}

		if len(override.Networks) > 0 {
			if replace {
				overrides[subIdx] = override
			} else {
				overrides = append(overrides, override)
			}
		}
	}

	return overrides
}

func getDefaultFTPDBinding(idx int) ftpd.Binding {
	binding := defaultFTPDBinding
	if len(globalConf.FTPD.Bindings) > idx {
		binding = globalConf.FTPD.Bindings[idx]
	}
	return binding
}

func getFTPDBindingSecurityFromEnv(idx int, binding *ftpd.Binding) bool {
	isSet := false

	certificateFile, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__CERTIFICATE_FILE", idx))
	if ok {
		binding.CertificateFile = certificateFile
		isSet = true
	}

	certificateKeyFile, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__CERTIFICATE_KEY_FILE", idx))
	if ok {
		binding.CertificateKeyFile = certificateKeyFile
		isSet = true
	}

	tlsMode, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__TLS_MODE", idx), 0)
	if ok {
		binding.TLSMode = int(tlsMode)
		isSet = true
	}

	tlsSessionReuse, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__TLS_SESSION_REUSE", idx), 0)
	if ok {
		binding.TLSSessionReuse = int(tlsSessionReuse)
		isSet = true
	}

	tlsVer, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__MIN_TLS_VERSION", idx), 0)
	if ok {
		binding.MinTLSVersion = int(tlsVer)
		isSet = true
	}

	tlsCiphers, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__TLS_CIPHER_SUITES", idx))
	if ok {
		binding.TLSCipherSuites = tlsCiphers
		isSet = true
	}

	clientAuthType, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__CLIENT_AUTH_TYPE", idx), 0)
	if ok {
		binding.ClientAuthType = int(clientAuthType)
		isSet = true
	}

	pasvSecurity, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__PASSIVE_CONNECTIONS_SECURITY", idx), 0)
	if ok {
		binding.PassiveConnectionsSecurity = int(pasvSecurity)
		isSet = true
	}

	activeSecurity, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__ACTIVE_CONNECTIONS_SECURITY", idx), 0)
	if ok {
		binding.ActiveConnectionsSecurity = int(activeSecurity)
		isSet = true
	}

	return isSet
}

func getFTPDBindingFromEnv(idx int) {
	binding := getDefaultFTPDBinding(idx)
	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__PORT", idx), 0)
	if ok {
		binding.Port = int(port)
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

	passiveIP, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__FORCE_PASSIVE_IP", idx))
	if ok {
		binding.ForcePassiveIP = passiveIP
		isSet = true
	}

	passiveIPOverrides := getFTPDPassiveIPOverridesFromEnv(idx)
	if len(passiveIPOverrides) > 0 {
		binding.PassiveIPOverrides = passiveIPOverrides
		isSet = true
	}

	passiveHost, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__PASSIVE_HOST", idx))
	if ok {
		binding.PassiveHost = passiveHost
		isSet = true
	}

	debug, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_FTPD__BINDINGS__%v__DEBUG", idx))
	if ok {
		binding.Debug = debug
		isSet = true
	}

	if getFTPDBindingSecurityFromEnv(idx, &binding) {
		isSet = true
	}

	applyFTPDBindingFromEnv(idx, isSet, binding)
}

func applyFTPDBindingFromEnv(idx int, isSet bool, binding ftpd.Binding) {
	if isSet {
		if len(globalConf.FTPD.Bindings) > idx {
			globalConf.FTPD.Bindings[idx] = binding
		} else {
			globalConf.FTPD.Bindings = append(globalConf.FTPD.Bindings, binding)
		}
	}
}

func getWebDAVBindingHTTPSConfigsFromEnv(idx int, binding *webdavd.Binding) bool {
	isSet := false

	enableHTTPS, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__ENABLE_HTTPS", idx))
	if ok {
		binding.EnableHTTPS = enableHTTPS
		isSet = true
	}

	certificateFile, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__CERTIFICATE_FILE", idx))
	if ok {
		binding.CertificateFile = certificateFile
		isSet = true
	}

	certificateKeyFile, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__CERTIFICATE_KEY_FILE", idx))
	if ok {
		binding.CertificateKeyFile = certificateKeyFile
		isSet = true
	}

	tlsVer, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__MIN_TLS_VERSION", idx), 0)
	if ok {
		binding.MinTLSVersion = int(tlsVer)
		isSet = true
	}

	clientAuthType, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__CLIENT_AUTH_TYPE", idx), 0)
	if ok {
		binding.ClientAuthType = int(clientAuthType)
		isSet = true
	}

	tlsCiphers, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__TLS_CIPHER_SUITES", idx))
	if ok {
		binding.TLSCipherSuites = tlsCiphers
		isSet = true
	}

	protocols, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%d__TLS_PROTOCOLS", idx))
	if ok {
		binding.Protocols = protocols
		isSet = true
	}

	return isSet
}

func getWebDAVDBindingProxyConfigsFromEnv(idx int, binding *webdavd.Binding) bool {
	isSet := false

	proxyAllowed, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__PROXY_ALLOWED", idx))
	if ok {
		binding.ProxyAllowed = proxyAllowed
		isSet = true
	}

	clientIPProxyHeader, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__CLIENT_IP_PROXY_HEADER", idx))
	if ok {
		binding.ClientIPProxyHeader = clientIPProxyHeader
		isSet = true
	}

	clientIPHeaderDepth, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__CLIENT_IP_HEADER_DEPTH", idx), 0)
	if ok {
		binding.ClientIPHeaderDepth = int(clientIPHeaderDepth)
		isSet = true
	}

	return isSet
}

func loadWebDAVCacheMappingsFromEnv() []webdavd.CustomMimeMapping {
	for idx := 0; idx < 30; idx++ {
		ext, extOK := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__CACHE__MIME_TYPES__CUSTOM_MAPPINGS__%d__EXT", idx))
		mime, mimeOK := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__CACHE__MIME_TYPES__CUSTOM_MAPPINGS__%d__MIME", idx))
		if extOK && mimeOK {
			if len(globalConf.WebDAVD.Cache.MimeTypes.CustomMappings) > idx {
				globalConf.WebDAVD.Cache.MimeTypes.CustomMappings[idx].Ext = ext
				globalConf.WebDAVD.Cache.MimeTypes.CustomMappings[idx].Mime = mime
			} else {
				globalConf.WebDAVD.Cache.MimeTypes.CustomMappings = append(globalConf.WebDAVD.Cache.MimeTypes.CustomMappings,
					webdavd.CustomMimeMapping{
						Ext:  ext,
						Mime: mime,
					})
			}
		}
	}

	return globalConf.WebDAVD.Cache.MimeTypes.CustomMappings
}

func getWebDAVDBindingFromEnv(idx int) {
	binding := defaultWebDAVDBinding
	if len(globalConf.WebDAVD.Bindings) > idx {
		binding = globalConf.WebDAVD.Bindings[idx]
	}

	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__PORT", idx), 0)
	if ok {
		binding.Port = int(port)
		isSet = true
	}

	address, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__ADDRESS", idx))
	if ok {
		binding.Address = address
		isSet = true
	}

	if getWebDAVBindingHTTPSConfigsFromEnv(idx, &binding) {
		isSet = true
	}

	prefix, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__PREFIX", idx))
	if ok {
		binding.Prefix = prefix
		isSet = true
	}

	if getWebDAVDBindingProxyConfigsFromEnv(idx, &binding) {
		isSet = true
	}

	disableWWWAuth, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_WEBDAVD__BINDINGS__%v__DISABLE_WWW_AUTH_HEADER", idx))
	if ok {
		binding.DisableWWWAuthHeader = disableWWWAuth
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

func getHTTPDSecurityProxyHeadersFromEnv(idx int) []httpd.HTTPSProxyHeader {
	var httpsProxyHeaders []httpd.HTTPSProxyHeader
	if len(globalConf.HTTPDConfig.Bindings) > idx {
		httpsProxyHeaders = globalConf.HTTPDConfig.Bindings[idx].Security.HTTPSProxyHeaders
	}

	for subIdx := 0; subIdx < 10; subIdx++ {
		var httpsProxyHeader httpd.HTTPSProxyHeader
		var replace bool
		if len(globalConf.HTTPDConfig.Bindings) > idx &&
			len(globalConf.HTTPDConfig.Bindings[idx].Security.HTTPSProxyHeaders) > subIdx {
			httpsProxyHeader = httpsProxyHeaders[subIdx]
			replace = true
		}
		proxyKey, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__HTTPS_PROXY_HEADERS__%v__KEY",
			idx, subIdx))
		if ok {
			httpsProxyHeader.Key = proxyKey
		}
		proxyVal, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__HTTPS_PROXY_HEADERS__%v__VALUE",
			idx, subIdx))
		if ok {
			httpsProxyHeader.Value = proxyVal
		}
		if httpsProxyHeader.Key != "" && httpsProxyHeader.Value != "" {
			if replace {
				httpsProxyHeaders[subIdx] = httpsProxyHeader
			} else {
				httpsProxyHeaders = append(httpsProxyHeaders, httpsProxyHeader)
			}
		}
	}
	return httpsProxyHeaders
}

func getHTTPDSecurityConfFromEnv(idx int) (httpd.SecurityConf, bool) { //nolint:gocyclo
	result := defaultHTTPDBinding.Security
	if len(globalConf.HTTPDConfig.Bindings) > idx {
		result = globalConf.HTTPDConfig.Bindings[idx].Security
	}
	isSet := false

	enabled, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__ENABLED", idx))
	if ok {
		result.Enabled = enabled
		isSet = true
	}

	allowedHosts, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__ALLOWED_HOSTS", idx))
	if ok {
		result.AllowedHosts = allowedHosts
		isSet = true
	}

	allowedHostsAreRegex, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__ALLOWED_HOSTS_ARE_REGEX", idx))
	if ok {
		result.AllowedHostsAreRegex = allowedHostsAreRegex
		isSet = true
	}

	hostsProxyHeaders, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__HOSTS_PROXY_HEADERS", idx))
	if ok {
		result.HostsProxyHeaders = hostsProxyHeaders
		isSet = true
	}

	httpsRedirect, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__HTTPS_REDIRECT", idx))
	if ok {
		result.HTTPSRedirect = httpsRedirect
		isSet = true
	}

	httpsHost, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__HTTPS_HOST", idx))
	if ok {
		result.HTTPSHost = httpsHost
		isSet = true
	}

	httpsProxyHeaders := getHTTPDSecurityProxyHeadersFromEnv(idx)
	if len(httpsProxyHeaders) > 0 {
		result.HTTPSProxyHeaders = httpsProxyHeaders
		isSet = true
	}

	stsSeconds, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__STS_SECONDS", idx), 64)
	if ok {
		result.STSSeconds = stsSeconds
		isSet = true
	}

	stsIncludeSubDomains, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__STS_INCLUDE_SUBDOMAINS", idx))
	if ok {
		result.STSIncludeSubdomains = stsIncludeSubDomains
		isSet = true
	}

	stsPreload, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__STS_PRELOAD", idx))
	if ok {
		result.STSPreload = stsPreload
		isSet = true
	}

	contentTypeNosniff, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__CONTENT_TYPE_NOSNIFF", idx))
	if ok {
		result.ContentTypeNosniff = contentTypeNosniff
		isSet = true
	}

	contentSecurityPolicy, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__CONTENT_SECURITY_POLICY", idx))
	if ok {
		result.ContentSecurityPolicy = contentSecurityPolicy
		isSet = true
	}

	permissionsPolicy, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__PERMISSIONS_POLICY", idx))
	if ok {
		result.PermissionsPolicy = permissionsPolicy
		isSet = true
	}

	crossOriginOpenedPolicy, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__SECURITY__CROSS_ORIGIN_OPENER_POLICY", idx))
	if ok {
		result.CrossOriginOpenerPolicy = crossOriginOpenedPolicy
		isSet = true
	}

	return result, isSet
}

func getHTTPDOIDCFromEnv(idx int) (httpd.OIDC, bool) {
	result := defaultHTTPDBinding.OIDC
	if len(globalConf.HTTPDConfig.Bindings) > idx {
		result = globalConf.HTTPDConfig.Bindings[idx].OIDC
	}
	isSet := false

	clientID, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__CLIENT_ID", idx))
	if ok {
		result.ClientID = clientID
		isSet = true
	}

	clientSecret, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__CLIENT_SECRET", idx))
	if ok {
		result.ClientSecret = clientSecret
		isSet = true
	}

	clientSecretFile, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__CLIENT_SECRET_FILE", idx))
	if ok {
		result.ClientSecretFile = clientSecretFile
		isSet = true
	}

	configURL, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__CONFIG_URL", idx))
	if ok {
		result.ConfigURL = configURL
		isSet = true
	}

	redirectBaseURL, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__REDIRECT_BASE_URL", idx))
	if ok {
		result.RedirectBaseURL = redirectBaseURL
		isSet = true
	}

	usernameField, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__USERNAME_FIELD", idx))
	if ok {
		result.UsernameField = usernameField
		isSet = true
	}

	scopes, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__SCOPES", idx))
	if ok {
		result.Scopes = scopes
		isSet = true
	}

	roleField, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__ROLE_FIELD", idx))
	if ok {
		result.RoleField = roleField
		isSet = true
	}

	implicitRoles, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__IMPLICIT_ROLES", idx))
	if ok {
		result.ImplicitRoles = implicitRoles
		isSet = true
	}

	customFields, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__CUSTOM_FIELDS", idx))
	if ok {
		result.CustomFields = customFields
		isSet = true
	}

	skipSignatureCheck, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__INSECURE_SKIP_SIGNATURE_CHECK", idx))
	if ok {
		result.InsecureSkipSignatureCheck = skipSignatureCheck
		isSet = true
	}

	debug, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__OIDC__DEBUG", idx))
	if ok {
		result.Debug = debug
		isSet = true
	}

	return result, isSet
}

func getHTTPDUIBrandingFromEnv(prefix string, branding httpd.UIBranding) (httpd.UIBranding, bool) {
	isSet := false

	name, ok := os.LookupEnv(fmt.Sprintf("%s__NAME", prefix))
	if ok {
		branding.Name = name
		isSet = true
	}

	shortName, ok := os.LookupEnv(fmt.Sprintf("%s__SHORT_NAME", prefix))
	if ok {
		branding.ShortName = shortName
		isSet = true
	}

	faviconPath, ok := os.LookupEnv(fmt.Sprintf("%s__FAVICON_PATH", prefix))
	if ok {
		branding.FaviconPath = faviconPath
		isSet = true
	}

	logoPath, ok := os.LookupEnv(fmt.Sprintf("%s__LOGO_PATH", prefix))
	if ok {
		branding.LogoPath = logoPath
		isSet = true
	}

	loginImagePath, ok := os.LookupEnv(fmt.Sprintf("%s__LOGIN_IMAGE_PATH", prefix))
	if ok {
		branding.LoginImagePath = loginImagePath
		isSet = true
	}

	disclaimerName, ok := os.LookupEnv(fmt.Sprintf("%s__DISCLAIMER_NAME", prefix))
	if ok {
		branding.DisclaimerName = disclaimerName
		isSet = true
	}

	disclaimerPath, ok := os.LookupEnv(fmt.Sprintf("%s__DISCLAIMER_PATH", prefix))
	if ok {
		branding.DisclaimerPath = disclaimerPath
		isSet = true
	}

	defaultCSSPath, ok := lookupStringListFromEnv(fmt.Sprintf("%s__DEFAULT_CSS", prefix))
	if ok {
		branding.DefaultCSS = defaultCSSPath
		isSet = true
	}

	extraCSS, ok := lookupStringListFromEnv(fmt.Sprintf("%s__EXTRA_CSS", prefix))
	if ok {
		branding.ExtraCSS = extraCSS
		isSet = true
	}

	return branding, isSet
}

func getHTTPDBrandingFromEnv(idx int) (httpd.Branding, bool) {
	result := defaultHTTPDBinding.Branding
	if len(globalConf.HTTPDConfig.Bindings) > idx {
		result = globalConf.HTTPDConfig.Bindings[idx].Branding
	}
	isSet := false

	webAdmin, ok := getHTTPDUIBrandingFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__BRANDING__WEB_ADMIN", idx),
		result.WebAdmin)
	if ok {
		result.WebAdmin = webAdmin
		isSet = true
	}

	webClient, ok := getHTTPDUIBrandingFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__BRANDING__WEB_CLIENT", idx),
		result.WebClient)
	if ok {
		result.WebClient = webClient
		isSet = true
	}

	return result, isSet
}

func getDefaultHTTPBinding(idx int) httpd.Binding {
	binding := defaultHTTPDBinding
	if len(globalConf.HTTPDConfig.Bindings) > idx {
		binding = globalConf.HTTPDConfig.Bindings[idx]
	}
	return binding
}

func getHTTPDNestedObjectsFromEnv(idx int, binding *httpd.Binding) bool {
	isSet := false

	oidc, ok := getHTTPDOIDCFromEnv(idx)
	if ok {
		binding.OIDC = oidc
		isSet = true
	}

	securityConf, ok := getHTTPDSecurityConfFromEnv(idx)
	if ok {
		binding.Security = securityConf
		isSet = true
	}

	brandingConf, ok := getHTTPDBrandingFromEnv(idx)
	if ok {
		binding.Branding = brandingConf
		isSet = true
	}

	return isSet
}

func getHTTPDBindingProxyConfigsFromEnv(idx int, binding *httpd.Binding) bool {
	isSet := false

	proxyAllowed, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__PROXY_ALLOWED", idx))
	if ok {
		binding.ProxyAllowed = proxyAllowed
		isSet = true
	}

	clientIPProxyHeader, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__CLIENT_IP_PROXY_HEADER", idx))
	if ok {
		binding.ClientIPProxyHeader = clientIPProxyHeader
		isSet = true
	}

	clientIPHeaderDepth, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__CLIENT_IP_HEADER_DEPTH", idx), 0)
	if ok {
		binding.ClientIPHeaderDepth = int(clientIPHeaderDepth)
		isSet = true
	}

	return isSet
}

func getHTTPDBindingFromEnv(idx int) { //nolint:gocyclo
	binding := getDefaultHTTPBinding(idx)
	isSet := false

	port, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__PORT", idx), 0)
	if ok {
		binding.Port = int(port)
		isSet = true
	}

	address, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ADDRESS", idx))
	if ok {
		binding.Address = address
		isSet = true
	}

	certificateFile, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__CERTIFICATE_FILE", idx))
	if ok {
		binding.CertificateFile = certificateFile
		isSet = true
	}

	certificateKeyFile, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__CERTIFICATE_KEY_FILE", idx))
	if ok {
		binding.CertificateKeyFile = certificateKeyFile
		isSet = true
	}

	enableWebAdmin, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ENABLE_WEB_ADMIN", idx))
	if ok {
		binding.EnableWebAdmin = enableWebAdmin
		isSet = true
	}

	enableWebClient, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ENABLE_WEB_CLIENT", idx))
	if ok {
		binding.EnableWebClient = enableWebClient
		isSet = true
	}

	enableRESTAPI, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ENABLE_REST_API", idx))
	if ok {
		binding.EnableRESTAPI = enableRESTAPI
		isSet = true
	}

	enabledLoginMethods, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ENABLED_LOGIN_METHODS", idx), 0)
	if ok {
		binding.EnabledLoginMethods = int(enabledLoginMethods)
		isSet = true
	}

	renderOpenAPI, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__RENDER_OPENAPI", idx))
	if ok {
		binding.RenderOpenAPI = renderOpenAPI
		isSet = true
	}

	enableHTTPS, ok := lookupBoolFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__ENABLE_HTTPS", idx))
	if ok {
		binding.EnableHTTPS = enableHTTPS
		isSet = true
	}

	tlsVer, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__MIN_TLS_VERSION", idx), 0)
	if ok {
		binding.MinTLSVersion = int(tlsVer)
		isSet = true
	}

	clientAuthType, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__CLIENT_AUTH_TYPE", idx), 0)
	if ok {
		binding.ClientAuthType = int(clientAuthType)
		isSet = true
	}

	tlsCiphers, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__TLS_CIPHER_SUITES", idx))
	if ok {
		binding.TLSCipherSuites = tlsCiphers
		isSet = true
	}

	protocols, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%d__TLS_PROTOCOLS", idx))
	if ok {
		binding.Protocols = protocols
		isSet = true
	}

	if getHTTPDBindingProxyConfigsFromEnv(idx, &binding) {
		isSet = true
	}

	hideLoginURL, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_HTTPD__BINDINGS__%v__HIDE_LOGIN_URL", idx), 0)
	if ok {
		binding.HideLoginURL = int(hideLoginURL)
		isSet = true
	}

	if getHTTPDNestedObjectsFromEnv(idx, &binding) {
		isSet = true
	}

	setHTTPDBinding(isSet, binding, idx)
}

func setHTTPDBinding(isSet bool, binding httpd.Binding, idx int) {
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
	if len(globalConf.HTTPConfig.Certificates) > idx {
		tlsCert = globalConf.HTTPConfig.Certificates[idx]
	}

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

func getHTTPClientHeadersFromEnv(idx int) {
	header := httpclient.Header{}
	if len(globalConf.HTTPConfig.Headers) > idx {
		header = globalConf.HTTPConfig.Headers[idx]
	}

	key, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTP__HEADERS__%v__KEY", idx))
	if ok {
		header.Key = key
	}

	value, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTP__HEADERS__%v__VALUE", idx))
	if ok {
		header.Value = value
	}

	url, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_HTTP__HEADERS__%v__URL", idx))
	if ok {
		header.URL = url
	}

	if header.Key != "" && header.Value != "" {
		if len(globalConf.HTTPConfig.Headers) > idx {
			globalConf.HTTPConfig.Headers[idx] = header
		} else {
			globalConf.HTTPConfig.Headers = append(globalConf.HTTPConfig.Headers, header)
		}
	}
}

func getCommandConfigsFromEnv(idx int) {
	cfg := command.Command{}
	if len(globalConf.CommandConfig.Commands) > idx {
		cfg = globalConf.CommandConfig.Commands[idx]
	}

	path, ok := os.LookupEnv(fmt.Sprintf("SFTPGO_COMMAND__COMMANDS__%v__PATH", idx))
	if ok {
		cfg.Path = path
	}

	timeout, ok := lookupIntFromEnv(fmt.Sprintf("SFTPGO_COMMAND__COMMANDS__%v__TIMEOUT", idx), 0)
	if ok {
		cfg.Timeout = int(timeout)
	}

	env, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_COMMAND__COMMANDS__%v__ENV", idx))
	if ok {
		cfg.Env = env
	}

	args, ok := lookupStringListFromEnv(fmt.Sprintf("SFTPGO_COMMAND__COMMANDS__%v__ARGS", idx))
	if ok {
		cfg.Args = args
	}

	if cfg.Path != "" {
		if len(globalConf.CommandConfig.Commands) > idx {
			globalConf.CommandConfig.Commands[idx] = cfg
		} else {
			globalConf.CommandConfig.Commands = append(globalConf.CommandConfig.Commands, cfg)
		}
	}
}

func setViperDefaults() {
	viper.SetDefault("common.idle_timeout", globalConf.Common.IdleTimeout)
	viper.SetDefault("common.upload_mode", globalConf.Common.UploadMode)
	viper.SetDefault("common.actions.execute_on", globalConf.Common.Actions.ExecuteOn)
	viper.SetDefault("common.actions.execute_sync", globalConf.Common.Actions.ExecuteSync)
	viper.SetDefault("common.actions.hook", globalConf.Common.Actions.Hook)
	viper.SetDefault("common.setstat_mode", globalConf.Common.SetstatMode)
	viper.SetDefault("common.rename_mode", globalConf.Common.RenameMode)
	viper.SetDefault("common.resume_max_size", globalConf.Common.ResumeMaxSize)
	viper.SetDefault("common.temp_path", globalConf.Common.TempPath)
	viper.SetDefault("common.proxy_protocol", globalConf.Common.ProxyProtocol)
	viper.SetDefault("common.proxy_allowed", globalConf.Common.ProxyAllowed)
	viper.SetDefault("common.proxy_skipped", globalConf.Common.ProxySkipped)
	viper.SetDefault("common.post_connect_hook", globalConf.Common.PostConnectHook)
	viper.SetDefault("common.post_disconnect_hook", globalConf.Common.PostDisconnectHook)
	viper.SetDefault("common.data_retention_hook", globalConf.Common.DataRetentionHook)
	viper.SetDefault("common.max_total_connections", globalConf.Common.MaxTotalConnections)
	viper.SetDefault("common.max_per_host_connections", globalConf.Common.MaxPerHostConnections)
	viper.SetDefault("common.allowlist_status", globalConf.Common.AllowListStatus)
	viper.SetDefault("common.allow_self_connections", globalConf.Common.AllowSelfConnections)
	viper.SetDefault("common.defender.enabled", globalConf.Common.DefenderConfig.Enabled)
	viper.SetDefault("common.defender.driver", globalConf.Common.DefenderConfig.Driver)
	viper.SetDefault("common.defender.ban_time", globalConf.Common.DefenderConfig.BanTime)
	viper.SetDefault("common.defender.ban_time_increment", globalConf.Common.DefenderConfig.BanTimeIncrement)
	viper.SetDefault("common.defender.threshold", globalConf.Common.DefenderConfig.Threshold)
	viper.SetDefault("common.defender.score_invalid", globalConf.Common.DefenderConfig.ScoreInvalid)
	viper.SetDefault("common.defender.score_valid", globalConf.Common.DefenderConfig.ScoreValid)
	viper.SetDefault("common.defender.score_limit_exceeded", globalConf.Common.DefenderConfig.ScoreLimitExceeded)
	viper.SetDefault("common.defender.score_no_auth", globalConf.Common.DefenderConfig.ScoreNoAuth)
	viper.SetDefault("common.defender.observation_time", globalConf.Common.DefenderConfig.ObservationTime)
	viper.SetDefault("common.defender.entries_soft_limit", globalConf.Common.DefenderConfig.EntriesSoftLimit)
	viper.SetDefault("common.defender.entries_hard_limit", globalConf.Common.DefenderConfig.EntriesHardLimit)
	viper.SetDefault("common.umask", globalConf.Common.Umask)
	viper.SetDefault("common.metadata.read", globalConf.Common.Metadata.Read)
	viper.SetDefault("acme.email", globalConf.ACME.Email)
	viper.SetDefault("acme.key_type", globalConf.ACME.KeyType)
	viper.SetDefault("acme.certs_path", globalConf.ACME.CertsPath)
	viper.SetDefault("acme.ca_endpoint", globalConf.ACME.CAEndpoint)
	viper.SetDefault("acme.domains", globalConf.ACME.Domains)
	viper.SetDefault("acme.renew_days", globalConf.ACME.RenewDays)
	viper.SetDefault("acme.http01_challenge.port", globalConf.ACME.HTTP01Challenge.Port)
	viper.SetDefault("acme.http01_challenge.webroot", globalConf.ACME.HTTP01Challenge.WebRoot)
	viper.SetDefault("acme.http01_challenge.proxy_header", globalConf.ACME.HTTP01Challenge.ProxyHeader)
	viper.SetDefault("acme.tls_alpn01_challenge.port", globalConf.ACME.TLSALPN01Challenge.Port)
	viper.SetDefault("sftpd.max_auth_tries", globalConf.SFTPD.MaxAuthTries)
	viper.SetDefault("sftpd.banner", globalConf.SFTPD.Banner)
	viper.SetDefault("sftpd.host_keys", globalConf.SFTPD.HostKeys)
	viper.SetDefault("sftpd.host_certificates", globalConf.SFTPD.HostCertificates)
	viper.SetDefault("sftpd.host_key_algorithms", globalConf.SFTPD.HostKeyAlgorithms)
	viper.SetDefault("sftpd.kex_algorithms", globalConf.SFTPD.KexAlgorithms)
	viper.SetDefault("sftpd.ciphers", globalConf.SFTPD.Ciphers)
	viper.SetDefault("sftpd.macs", globalConf.SFTPD.MACs)
	viper.SetDefault("sftpd.public_key_algorithms", globalConf.SFTPD.PublicKeyAlgorithms)
	viper.SetDefault("sftpd.trusted_user_ca_keys", globalConf.SFTPD.TrustedUserCAKeys)
	viper.SetDefault("sftpd.revoked_user_certs_file", globalConf.SFTPD.RevokedUserCertsFile)
	viper.SetDefault("sftpd.login_banner_file", globalConf.SFTPD.LoginBannerFile)
	viper.SetDefault("sftpd.enabled_ssh_commands", sftpd.GetDefaultSSHCommands())
	viper.SetDefault("sftpd.keyboard_interactive_authentication", globalConf.SFTPD.KeyboardInteractiveAuthentication)
	viper.SetDefault("sftpd.keyboard_interactive_auth_hook", globalConf.SFTPD.KeyboardInteractiveHook)
	viper.SetDefault("sftpd.password_authentication", globalConf.SFTPD.PasswordAuthentication)
	viper.SetDefault("sftpd.folder_prefix", globalConf.SFTPD.FolderPrefix)
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
	viper.SetDefault("webdavd.cors.options_passthrough", globalConf.WebDAVD.Cors.OptionsPassthrough)
	viper.SetDefault("webdavd.cors.options_success_status", globalConf.WebDAVD.Cors.OptionsSuccessStatus)
	viper.SetDefault("webdavd.cors.allow_private_network", globalConf.WebDAVD.Cors.AllowPrivateNetwork)
	viper.SetDefault("webdavd.cors.max_age", globalConf.WebDAVD.Cors.MaxAge)
	viper.SetDefault("webdavd.cache.users.expiration_time", globalConf.WebDAVD.Cache.Users.ExpirationTime)
	viper.SetDefault("webdavd.cache.users.max_size", globalConf.WebDAVD.Cache.Users.MaxSize)
	viper.SetDefault("webdavd.cache.mime_types.enabled", globalConf.WebDAVD.Cache.MimeTypes.Enabled)
	viper.SetDefault("webdavd.cache.mime_types.max_size", globalConf.WebDAVD.Cache.MimeTypes.MaxSize)
	viper.SetDefault("webdavd.cache.mime_types.custom_mappings", globalConf.WebDAVD.Cache.MimeTypes.CustomMappings)
	viper.SetDefault("data_provider.driver", globalConf.ProviderConf.Driver)
	viper.SetDefault("data_provider.name", globalConf.ProviderConf.Name)
	viper.SetDefault("data_provider.host", globalConf.ProviderConf.Host)
	viper.SetDefault("data_provider.port", globalConf.ProviderConf.Port)
	viper.SetDefault("data_provider.username", globalConf.ProviderConf.Username)
	viper.SetDefault("data_provider.username_file", globalConf.ProviderConf.UsernameFile)
	viper.SetDefault("data_provider.password", globalConf.ProviderConf.Password)
	viper.SetDefault("data_provider.password_file", globalConf.ProviderConf.PasswordFile)
	viper.SetDefault("data_provider.sslmode", globalConf.ProviderConf.SSLMode)
	viper.SetDefault("data_provider.disable_sni", globalConf.ProviderConf.DisableSNI)
	viper.SetDefault("data_provider.target_session_attrs", globalConf.ProviderConf.TargetSessionAttrs)
	viper.SetDefault("data_provider.root_cert", globalConf.ProviderConf.RootCert)
	viper.SetDefault("data_provider.client_cert", globalConf.ProviderConf.ClientCert)
	viper.SetDefault("data_provider.client_key", globalConf.ProviderConf.ClientKey)
	viper.SetDefault("data_provider.connection_string", globalConf.ProviderConf.ConnectionString)
	viper.SetDefault("data_provider.sql_tables_prefix", globalConf.ProviderConf.SQLTablesPrefix)
	viper.SetDefault("data_provider.track_quota", globalConf.ProviderConf.TrackQuota)
	viper.SetDefault("data_provider.pool_size", globalConf.ProviderConf.PoolSize)
	viper.SetDefault("data_provider.users_base_dir", globalConf.ProviderConf.UsersBaseDir)
	viper.SetDefault("data_provider.actions.execute_on", globalConf.ProviderConf.Actions.ExecuteOn)
	viper.SetDefault("data_provider.actions.execute_for", globalConf.ProviderConf.Actions.ExecuteFor)
	viper.SetDefault("data_provider.actions.hook", globalConf.ProviderConf.Actions.Hook)
	viper.SetDefault("data_provider.external_auth_hook", globalConf.ProviderConf.ExternalAuthHook)
	viper.SetDefault("data_provider.external_auth_scope", globalConf.ProviderConf.ExternalAuthScope)
	viper.SetDefault("data_provider.pre_login_hook", globalConf.ProviderConf.PreLoginHook)
	viper.SetDefault("data_provider.post_login_hook", globalConf.ProviderConf.PostLoginHook)
	viper.SetDefault("data_provider.post_login_scope", globalConf.ProviderConf.PostLoginScope)
	viper.SetDefault("data_provider.check_password_hook", globalConf.ProviderConf.CheckPasswordHook)
	viper.SetDefault("data_provider.check_password_scope", globalConf.ProviderConf.CheckPasswordScope)
	viper.SetDefault("data_provider.password_hashing.bcrypt_options.cost", globalConf.ProviderConf.PasswordHashing.BcryptOptions.Cost)
	viper.SetDefault("data_provider.password_hashing.argon2_options.memory", globalConf.ProviderConf.PasswordHashing.Argon2Options.Memory)
	viper.SetDefault("data_provider.password_hashing.argon2_options.iterations", globalConf.ProviderConf.PasswordHashing.Argon2Options.Iterations)
	viper.SetDefault("data_provider.password_hashing.argon2_options.parallelism", globalConf.ProviderConf.PasswordHashing.Argon2Options.Parallelism)
	viper.SetDefault("data_provider.password_hashing.algo", globalConf.ProviderConf.PasswordHashing.Algo)
	viper.SetDefault("data_provider.password_validation.admins.min_entropy", globalConf.ProviderConf.PasswordValidation.Admins.MinEntropy)
	viper.SetDefault("data_provider.password_validation.users.min_entropy", globalConf.ProviderConf.PasswordValidation.Users.MinEntropy)
	viper.SetDefault("data_provider.password_caching", globalConf.ProviderConf.PasswordCaching)
	viper.SetDefault("data_provider.update_mode", globalConf.ProviderConf.UpdateMode)
	viper.SetDefault("data_provider.delayed_quota_update", globalConf.ProviderConf.DelayedQuotaUpdate)
	viper.SetDefault("data_provider.create_default_admin", globalConf.ProviderConf.CreateDefaultAdmin)
	viper.SetDefault("data_provider.naming_rules", globalConf.ProviderConf.NamingRules)
	viper.SetDefault("data_provider.is_shared", globalConf.ProviderConf.IsShared)
	viper.SetDefault("data_provider.node.host", globalConf.ProviderConf.Node.Host)
	viper.SetDefault("data_provider.node.port", globalConf.ProviderConf.Node.Port)
	viper.SetDefault("data_provider.node.proto", globalConf.ProviderConf.Node.Proto)
	viper.SetDefault("data_provider.backups_path", globalConf.ProviderConf.BackupsPath)
	viper.SetDefault("httpd.templates_path", globalConf.HTTPDConfig.TemplatesPath)
	viper.SetDefault("httpd.static_files_path", globalConf.HTTPDConfig.StaticFilesPath)
	viper.SetDefault("httpd.openapi_path", globalConf.HTTPDConfig.OpenAPIPath)
	viper.SetDefault("httpd.web_root", globalConf.HTTPDConfig.WebRoot)
	viper.SetDefault("httpd.certificate_file", globalConf.HTTPDConfig.CertificateFile)
	viper.SetDefault("httpd.certificate_key_file", globalConf.HTTPDConfig.CertificateKeyFile)
	viper.SetDefault("httpd.ca_certificates", globalConf.HTTPDConfig.CACertificates)
	viper.SetDefault("httpd.ca_revocation_lists", globalConf.HTTPDConfig.CARevocationLists)
	viper.SetDefault("httpd.signing_passphrase", globalConf.HTTPDConfig.SigningPassphrase)
	viper.SetDefault("httpd.signing_passphrase_file", globalConf.HTTPDConfig.SigningPassphraseFile)
	viper.SetDefault("httpd.token_validation", globalConf.HTTPDConfig.TokenValidation)
	viper.SetDefault("httpd.max_upload_file_size", globalConf.HTTPDConfig.MaxUploadFileSize)
	viper.SetDefault("httpd.cors.enabled", globalConf.HTTPDConfig.Cors.Enabled)
	viper.SetDefault("httpd.cors.allowed_origins", globalConf.HTTPDConfig.Cors.AllowedOrigins)
	viper.SetDefault("httpd.cors.allowed_methods", globalConf.HTTPDConfig.Cors.AllowedMethods)
	viper.SetDefault("httpd.cors.allowed_headers", globalConf.HTTPDConfig.Cors.AllowedHeaders)
	viper.SetDefault("httpd.cors.exposed_headers", globalConf.HTTPDConfig.Cors.ExposedHeaders)
	viper.SetDefault("httpd.cors.allow_credentials", globalConf.HTTPDConfig.Cors.AllowCredentials)
	viper.SetDefault("httpd.cors.max_age", globalConf.HTTPDConfig.Cors.MaxAge)
	viper.SetDefault("httpd.cors.options_passthrough", globalConf.HTTPDConfig.Cors.OptionsPassthrough)
	viper.SetDefault("httpd.cors.options_success_status", globalConf.HTTPDConfig.Cors.OptionsSuccessStatus)
	viper.SetDefault("httpd.cors.allow_private_network", globalConf.HTTPDConfig.Cors.AllowPrivateNetwork)
	viper.SetDefault("httpd.setup.installation_code", globalConf.HTTPDConfig.Setup.InstallationCode)
	viper.SetDefault("httpd.setup.installation_code_hint", globalConf.HTTPDConfig.Setup.InstallationCodeHint)
	viper.SetDefault("httpd.hide_support_link", globalConf.HTTPDConfig.HideSupportLink)
	viper.SetDefault("http.timeout", globalConf.HTTPConfig.Timeout)
	viper.SetDefault("http.retry_wait_min", globalConf.HTTPConfig.RetryWaitMin)
	viper.SetDefault("http.retry_wait_max", globalConf.HTTPConfig.RetryWaitMax)
	viper.SetDefault("http.retry_max", globalConf.HTTPConfig.RetryMax)
	viper.SetDefault("http.ca_certificates", globalConf.HTTPConfig.CACertificates)
	viper.SetDefault("http.skip_tls_verify", globalConf.HTTPConfig.SkipTLSVerify)
	viper.SetDefault("command.timeout", globalConf.CommandConfig.Timeout)
	viper.SetDefault("command.env", globalConf.CommandConfig.Env)
	viper.SetDefault("kms.secrets.url", globalConf.KMSConfig.Secrets.URL)
	viper.SetDefault("kms.secrets.master_key", globalConf.KMSConfig.Secrets.MasterKeyString)
	viper.SetDefault("kms.secrets.master_key_path", globalConf.KMSConfig.Secrets.MasterKeyPath)
	viper.SetDefault("telemetry.bind_port", globalConf.TelemetryConfig.BindPort)
	viper.SetDefault("telemetry.bind_address", globalConf.TelemetryConfig.BindAddress)
	viper.SetDefault("telemetry.enable_profiler", globalConf.TelemetryConfig.EnableProfiler)
	viper.SetDefault("telemetry.auth_user_file", globalConf.TelemetryConfig.AuthUserFile)
	viper.SetDefault("telemetry.certificate_file", globalConf.TelemetryConfig.CertificateFile)
	viper.SetDefault("telemetry.certificate_key_file", globalConf.TelemetryConfig.CertificateKeyFile)
	viper.SetDefault("telemetry.min_tls_version", globalConf.TelemetryConfig.MinTLSVersion)
	viper.SetDefault("telemetry.tls_cipher_suites", globalConf.TelemetryConfig.TLSCipherSuites)
	viper.SetDefault("telemetry.tls_protocols", globalConf.TelemetryConfig.Protocols)
	viper.SetDefault("smtp.host", globalConf.SMTPConfig.Host)
	viper.SetDefault("smtp.port", globalConf.SMTPConfig.Port)
	viper.SetDefault("smtp.from", globalConf.SMTPConfig.From)
	viper.SetDefault("smtp.user", globalConf.SMTPConfig.User)
	viper.SetDefault("smtp.password", globalConf.SMTPConfig.Password)
	viper.SetDefault("smtp.auth_type", globalConf.SMTPConfig.AuthType)
	viper.SetDefault("smtp.encryption", globalConf.SMTPConfig.Encryption)
	viper.SetDefault("smtp.domain", globalConf.SMTPConfig.Domain)
	viper.SetDefault("smtp.templates_path", globalConf.SMTPConfig.TemplatesPath)
}

func lookupBoolFromEnv(envName string) (bool, bool) {
	value, ok := os.LookupEnv(envName)
	if ok {
		converted, err := strconv.ParseBool(strings.TrimSpace(value))
		if err == nil {
			return converted, ok
		}
	}

	return false, false
}

func lookupIntFromEnv(envName string, bitSize int) (int64, bool) {
	value, ok := os.LookupEnv(envName)
	if ok {
		converted, err := strconv.ParseInt(strings.TrimSpace(value), 10, bitSize)
		if err == nil {
			return converted, ok
		}
	}

	return 0, false
}

func lookupStringListFromEnv(envName string) ([]string, bool) {
	value, ok := os.LookupEnv(envName)
	if ok {
		var result []string
		for _, v := range strings.Split(value, ",") {
			val := strings.TrimSpace(v)
			if val != "" {
				result = append(result, val)
			}
		}
		return result, true
	}
	return nil, false
}
