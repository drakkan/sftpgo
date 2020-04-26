package config

import (
	"strings"

	"github.com/drakkan/sftpgo/ldapauthserver/logger"
	"github.com/spf13/viper"
)

const (
	logSender = "config"
	// DefaultConfigName defines the name for the default config file.
	// This is the file name without extension, we use viper and so we
	// support all the config files format supported by viper
	DefaultConfigName = "ldapauth"
	// ConfigEnvPrefix defines a prefix that ENVIRONMENT variables will use
	configEnvPrefix = "ldapauth"
)

// HTTPDConfig defines configuration for the HTTPD server
type HTTPDConfig struct {
	BindAddress        string `mapstructure:"bind_address"`
	BindPort           int    `mapstructure:"bind_port"`
	AuthUserFile       string `mapstructure:"auth_user_file"`
	CertificateFile    string `mapstructure:"certificate_file"`
	CertificateKeyFile string `mapstructure:"certificate_key_file"`
}

// LDAPConfig defines the configuration parameters for LDAP connections and searches
type LDAPConfig struct {
	BaseDN             string   `mapstructure:"basedn"`
	BindURL            string   `mapstructure:"bind_url"`
	BindUsername       string   `mapstructure:"bind_username"`
	BindPassword       string   `mapstructure:"bind_password"`
	SearchFilter       string   `mapstructure:"search_filter"`
	SearchBaseAttrs    []string `mapstructure:"search_base_attrs"`
	DefaultUID         int      `mapstructure:"default_uid"`
	DefaultGID         int      `mapstructure:"default_gid"`
	ForceDefaultUID    bool     `mapstructure:"force_default_uid"`
	ForceDefaultGID    bool     `mapstructure:"force_default_gid"`
	InsecureSkipVerify bool     `mapstructure:"insecure_skip_verify"`
	CACertificates     []string `mapstructure:"ca_certificates"`
}

type appConfig struct {
	HTTPD HTTPDConfig `mapstructure:"httpd"`
	LDAP  LDAPConfig  `mapstructure:"ldap"`
}

var conf appConfig

func init() {
	conf = appConfig{
		HTTPD: HTTPDConfig{
			BindAddress:        "",
			BindPort:           9000,
			AuthUserFile:       "",
			CertificateFile:    "",
			CertificateKeyFile: "",
		},
		LDAP: LDAPConfig{
			BaseDN:       "dc=example,dc=com",
			BindURL:      "ldap://192.168.1.103:389",
			BindUsername: "cn=Directory Manager",
			BindPassword: "YOUR_ADMIN_PASSWORD_HERE",
			SearchFilter: "(&(objectClass=nsPerson)(uid=%s))",
			SearchBaseAttrs: []string{
				"dn",
				"homeDirectory",
				"uidNumber",
				"gidNumber",
				"nsSshPublicKey",
			},
			DefaultUID:         0,
			DefaultGID:         0,
			ForceDefaultUID:    true,
			ForceDefaultGID:    true,
			InsecureSkipVerify: false,
			CACertificates:     nil,
		},
	}
	viper.SetEnvPrefix(configEnvPrefix)
	replacer := strings.NewReplacer(".", "__")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName(DefaultConfigName)
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(true)
}

// GetHomeDirectory returns the configured name for the LDAP field to use as home directory
func (l *LDAPConfig) GetHomeDirectory() string {
	if len(l.SearchBaseAttrs) > 1 {
		return l.SearchBaseAttrs[1]
	}
	return "homeDirectory"
}

// GetUIDNumber returns the configured name for the LDAP field to use as UID
func (l *LDAPConfig) GetUIDNumber() string {
	if len(l.SearchBaseAttrs) > 2 {
		return l.SearchBaseAttrs[2]
	}
	return "uidNumber"
}

// GetGIDNumber returns the configured name for the LDAP field to use as GID
func (l *LDAPConfig) GetGIDNumber() string {
	if len(l.SearchBaseAttrs) > 3 {
		return l.SearchBaseAttrs[3]
	}
	return "gidNumber"
}

// GetPublicKey returns the configured name for the LDAP field to use as public keys
func (l *LDAPConfig) GetPublicKey() string {
	if len(l.SearchBaseAttrs) > 4 {
		return l.SearchBaseAttrs[4]
	}
	return "nsSshPublicKey"
}

// GetHTTPDConfig returns the configuration for the HTTP server
func GetHTTPDConfig() HTTPDConfig {
	return conf.HTTPD
}

// GetLDAPConfig returns LDAP related settings
func GetLDAPConfig() LDAPConfig {
	return conf.LDAP
}

func getRedactedConf() appConfig {
	c := conf
	return c
}

// LoadConfig loads the configuration
func LoadConfig(configDir, configName string) error {
	var err error
	viper.AddConfigPath(configDir)
	viper.AddConfigPath(".")
	viper.SetConfigName(configName)
	if err = viper.ReadInConfig(); err != nil {
		logger.Warn(logSender, "", "error loading configuration file: %v. Default configuration will be used: %+v",
			err, getRedactedConf())
		logger.WarnToConsole("error loading configuration file: %v. Default configuration will be used.", err)
		return err
	}
	err = viper.Unmarshal(&conf)
	if err != nil {
		logger.Warn(logSender, "", "error parsing configuration file: %v. Default configuration will be used: %+v",
			err, getRedactedConf())
		logger.WarnToConsole("error parsing configuration file: %v. Default configuration will be used.", err)
		return err
	}
	logger.Debug(logSender, "", "config file used: '%#v', config loaded: %+v", viper.ConfigFileUsed(), getRedactedConf())
	return err
}
