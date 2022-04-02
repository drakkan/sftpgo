// Package dataprovider provides data access.
// It abstracts different data providers and exposes a common API.
package dataprovider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/alexedwards/argon2id"
	"github.com/go-chi/render"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	// SQLiteDataProviderName defines the name for SQLite database provider
	SQLiteDataProviderName = "sqlite"
	// PGSQLDataProviderName defines the name for PostgreSQL database provider
	PGSQLDataProviderName = "postgresql"
	// MySQLDataProviderName defines the name for MySQL database provider
	MySQLDataProviderName = "mysql"
	// BoltDataProviderName defines the name for bbolt key/value store provider
	BoltDataProviderName = "bolt"
	// MemoryDataProviderName defines the name for memory provider
	MemoryDataProviderName = "memory"
	// CockroachDataProviderName defines the for CockroachDB provider
	CockroachDataProviderName = "cockroachdb"
	// DumpVersion defines the version for the dump.
	// For restore/load we support the current version and the previous one
	DumpVersion = 11

	argonPwdPrefix            = "$argon2id$"
	bcryptPwdPrefix           = "$2a$"
	pbkdf2SHA1Prefix          = "$pbkdf2-sha1$"
	pbkdf2SHA256Prefix        = "$pbkdf2-sha256$"
	pbkdf2SHA512Prefix        = "$pbkdf2-sha512$"
	pbkdf2SHA256B64SaltPrefix = "$pbkdf2-b64salt-sha256$"
	md5cryptPwdPrefix         = "$1$"
	md5cryptApr1PwdPrefix     = "$apr1$"
	sha512cryptPwdPrefix      = "$6$"
	md5LDAPPwdPrefix          = "{MD5}"
	trackQuotaDisabledError   = "please enable track_quota in your configuration to use this method"
	operationAdd              = "add"
	operationUpdate           = "update"
	operationDelete           = "delete"
	sqlPrefixValidChars       = "abcdefghijklmnopqrstuvwxyz_0123456789"
	maxHookResponseSize       = 1048576 // 1MB
)

// Supported algorithms for hashing passwords.
// These algorithms can be used when SFTPGo hashes a plain text password
const (
	HashingAlgoBcrypt   = "bcrypt"
	HashingAlgoArgon2ID = "argon2id"
)

// ordering constants
const (
	OrderASC  = "ASC"
	OrderDESC = "DESC"
)

const (
	protocolSSH    = "SSH"
	protocolFTP    = "FTP"
	protocolWebDAV = "DAV"
	protocolHTTP   = "HTTP"
)

var (
	// SupportedProviders defines the supported data providers
	SupportedProviders = []string{SQLiteDataProviderName, PGSQLDataProviderName, MySQLDataProviderName,
		BoltDataProviderName, MemoryDataProviderName, CockroachDataProviderName}
	// ValidPerms defines all the valid permissions for a user
	ValidPerms = []string{PermAny, PermListItems, PermDownload, PermUpload, PermOverwrite, PermCreateDirs, PermRename,
		PermRenameFiles, PermRenameDirs, PermDelete, PermDeleteFiles, PermDeleteDirs, PermCreateSymlinks, PermChmod,
		PermChown, PermChtimes}
	// ValidLoginMethods defines all the valid login methods
	ValidLoginMethods = []string{SSHLoginMethodPublicKey, LoginMethodPassword, SSHLoginMethodPassword,
		SSHLoginMethodKeyboardInteractive, SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt,
		LoginMethodTLSCertificate, LoginMethodTLSCertificateAndPwd}
	// SSHMultiStepsLoginMethods defines the supported Multi-Step Authentications
	SSHMultiStepsLoginMethods = []string{SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt}
	// ErrNoAuthTryed defines the error for connection closed before authentication
	ErrNoAuthTryed = errors.New("no auth tryed")
	// ErrNotImplemented defines the error for features not supported for a particular data provider
	ErrNotImplemented = errors.New("feature not supported with the configured data provider")
	// ValidProtocols defines all the valid protcols
	ValidProtocols = []string{protocolSSH, protocolFTP, protocolWebDAV, protocolHTTP}
	// MFAProtocols defines the supported protocols for multi-factor authentication
	MFAProtocols = []string{protocolHTTP, protocolSSH, protocolFTP}
	// ErrNoInitRequired defines the error returned by InitProvider if no inizialization/update is required
	ErrNoInitRequired = errors.New("the data provider is up to date")
	// ErrInvalidCredentials defines the error to return if the supplied credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrLoginNotAllowedFromIP defines the error to return if login is denied from the current IP
	ErrLoginNotAllowedFromIP = errors.New("login is not allowed from this IP")
	isAdminCreated           = int32(0)
	validTLSUsernames        = []string{string(sdk.TLSUsernameNone), string(sdk.TLSUsernameCN)}
	config                   Config
	provider                 Provider
	sqlPlaceholders          []string
	internalHashPwdPrefixes  = []string{argonPwdPrefix, bcryptPwdPrefix}
	hashPwdPrefixes          = []string{argonPwdPrefix, bcryptPwdPrefix, pbkdf2SHA1Prefix, pbkdf2SHA256Prefix,
		pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix, md5cryptPwdPrefix, md5cryptApr1PwdPrefix, md5LDAPPwdPrefix,
		sha512cryptPwdPrefix}
	pbkdfPwdPrefixes        = []string{pbkdf2SHA1Prefix, pbkdf2SHA256Prefix, pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix}
	pbkdfPwdB64SaltPrefixes = []string{pbkdf2SHA256B64SaltPrefix}
	unixPwdPrefixes         = []string{md5cryptPwdPrefix, md5cryptApr1PwdPrefix, sha512cryptPwdPrefix}
	sharedProviders         = []string{PGSQLDataProviderName, MySQLDataProviderName, CockroachDataProviderName}
	logSender               = "dataprovider"
	credentialsDirPath      string
	sqlTableUsers           = "users"
	sqlTableFolders         = "folders"
	sqlTableFoldersMapping  = "folders_mapping"
	sqlTableAdmins          = "admins"
	sqlTableAPIKeys         = "api_keys"
	sqlTableShares          = "shares"
	sqlTableDefenderHosts   = "defender_hosts"
	sqlTableDefenderEvents  = "defender_events"
	sqlTableActiveTransfers = "active_transfers"
	sqlTableSchemaVersion   = "schema_version"
	argon2Params            *argon2id.Params
	lastLoginMinDelay       = 10 * time.Minute
	usernameRegex           = regexp.MustCompile("^[a-zA-Z0-9-_.~]+$")
	tempPath                string
)

type schemaVersion struct {
	Version int
}

// BcryptOptions defines the options for bcrypt password hashing
type BcryptOptions struct {
	Cost int `json:"cost" mapstructure:"cost"`
}

// Argon2Options defines the options for argon2 password hashing
type Argon2Options struct {
	Memory      uint32 `json:"memory" mapstructure:"memory"`
	Iterations  uint32 `json:"iterations" mapstructure:"iterations"`
	Parallelism uint8  `json:"parallelism" mapstructure:"parallelism"`
}

// PasswordHashing defines the configuration for password hashing
type PasswordHashing struct {
	BcryptOptions BcryptOptions `json:"bcrypt_options" mapstructure:"bcrypt_options"`
	Argon2Options Argon2Options `json:"argon2_options" mapstructure:"argon2_options"`
	// Algorithm to use for hashing passwords. Available algorithms: argon2id, bcrypt. Default: bcrypt
	Algo string `json:"algo" mapstructure:"algo"`
}

// PasswordValidationRules defines the password validation rules
type PasswordValidationRules struct {
	// MinEntropy defines the minimum password entropy.
	// 0 means disabled, any password will be accepted.
	// Take a look at the following link for more details
	// https://github.com/wagslane/go-password-validator#what-entropy-value-should-i-use
	MinEntropy float64 `json:"min_entropy" mapstructure:"min_entropy"`
}

// PasswordValidation defines the password validation rules for admins and protocol users
type PasswordValidation struct {
	// Password validation rules for SFTPGo admin users
	Admins PasswordValidationRules `json:"admins" mapstructure:"admins"`
	// Password validation rules for SFTPGo protocol users
	Users PasswordValidationRules `json:"users" mapstructure:"users"`
}

// ObjectsActions defines the action to execute on user create, update, delete for the specified objects
type ObjectsActions struct {
	// Valid values are add, update, delete. Empty slice to disable
	ExecuteOn []string `json:"execute_on" mapstructure:"execute_on"`
	// Valid values are user, admin, api_key
	ExecuteFor []string `json:"execute_for" mapstructure:"execute_for"`
	// Absolute path to an external program or an HTTP URL
	Hook string `json:"hook" mapstructure:"hook"`
}

// ProviderStatus defines the provider status
type ProviderStatus struct {
	Driver   string `json:"driver"`
	IsActive bool   `json:"is_active"`
	Error    string `json:"error"`
}

// AutoBackup defines the settings for automatic provider backups.
// Example: hour "0" and day_of_week "*" means a backup every day at midnight.
// The backup file name is in the format backup_<day_of_week>_<hour>.json
// files with the same name will be overwritten
type AutoBackup struct {
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// hour as standard cron expression. Allowed values: 0-23.
	// Allowed special characters: asterisk (*), slash (/), comma (,), hyphen (-).
	// More info about special characters here:
	// https://pkg.go.dev/github.com/robfig/cron#hdr-Special_Characters
	Hour string `json:"hour" mapstructure:"hour"`
	// Day of the week as cron expression. Allowed values: 0-6 (Sunday to Saturday).
	// Allowed special characters: asterisk (*), slash (/), comma (,), hyphen (-), question mark (?).
	// More info about special characters here:
	// https://pkg.go.dev/github.com/robfig/cron#hdr-Special_Characters
	DayOfWeek string `json:"day_of_week" mapstructure:"day_of_week"`
}

// Config provider configuration
type Config struct {
	// Driver name, must be one of the SupportedProviders
	Driver string `json:"driver" mapstructure:"driver"`
	// Database name. For driver sqlite this can be the database name relative to the config dir
	// or the absolute path to the SQLite database.
	Name string `json:"name" mapstructure:"name"`
	// Database host
	Host string `json:"host" mapstructure:"host"`
	// Database port
	Port int `json:"port" mapstructure:"port"`
	// Database username
	Username string `json:"username" mapstructure:"username"`
	// Database password
	Password string `json:"password" mapstructure:"password"`
	// Used for drivers mysql and postgresql.
	// 0 disable SSL/TLS connections.
	// 1 require ssl.
	// 2 set ssl mode to verify-ca for driver postgresql and skip-verify for driver mysql.
	// 3 set ssl mode to verify-full for driver postgresql and preferred for driver mysql.
	SSLMode int `json:"sslmode" mapstructure:"sslmode"`
	// Path to the root certificate authority used to verify that the server certificate was signed by a trusted CA
	RootCert string `json:"root_cert" mapstructure:"root_cert"`
	// Path to the client certificate for two-way TLS authentication
	ClientCert string `json:"client_cert" mapstructure:"client_cert"`
	// Path to the client key for two-way TLS authentication
	ClientKey string `json:"client_key" mapstructure:"client_key"`
	// Custom database connection string.
	// If not empty this connection string will be used instead of build one using the previous parameters
	ConnectionString string `json:"connection_string" mapstructure:"connection_string"`
	// prefix for SQL tables
	SQLTablesPrefix string `json:"sql_tables_prefix" mapstructure:"sql_tables_prefix"`
	// Set the preferred way to track users quota between the following choices:
	// 0, disable quota tracking. REST API to scan user dir and update quota will do nothing
	// 1, quota is updated each time a user upload or delete a file even if the user has no quota restrictions
	// 2, quota is updated each time a user upload or delete a file but only for users with quota restrictions
	//    and for virtual folders.
	//    With this configuration the "quota scan" REST API can still be used to periodically update space usage
	//    for users without quota restrictions
	TrackQuota int `json:"track_quota" mapstructure:"track_quota"`
	// Sets the maximum number of open connections for mysql and postgresql driver.
	// Default 0 (unlimited)
	PoolSize int `json:"pool_size" mapstructure:"pool_size"`
	// Users default base directory.
	// If no home dir is defined while adding a new user, and this value is
	// a valid absolute path, then the user home dir will be automatically
	// defined as the path obtained joining the base dir and the username
	UsersBaseDir string `json:"users_base_dir" mapstructure:"users_base_dir"`
	// Actions to execute on objects add, update, delete.
	// The supported objects are user, admin, api_key.
	// Update action will not be fired for internal updates such as the last login or the user quota fields.
	Actions ObjectsActions `json:"actions" mapstructure:"actions"`
	// Absolute path to an external program or an HTTP URL to invoke for users authentication.
	// Leave empty to use builtin authentication.
	// If the authentication succeed the user will be automatically added/updated inside the defined data provider.
	// Actions defined for user added/updated will not be executed in this case.
	// This method is slower than built-in authentication methods, but it's very flexible as anyone can
	// easily write his own authentication hooks.
	ExternalAuthHook string `json:"external_auth_hook" mapstructure:"external_auth_hook"`
	// ExternalAuthScope defines the scope for the external authentication hook.
	// - 0 means all supported authentication scopes, the external hook will be executed for password,
	//     public key, keyboard interactive authentication and TLS certificates
	// - 1 means passwords only
	// - 2 means public keys only
	// - 4 means keyboard interactive only
	// - 8 means TLS certificates only
	// you can combine the scopes, for example 3 means password and public key, 5 password and keyboard
	// interactive and so on
	ExternalAuthScope int `json:"external_auth_scope" mapstructure:"external_auth_scope"`
	// CredentialsPath defines the directory for storing user provided credential files such as
	// Google Cloud Storage credentials. It can be a path relative to the config dir or an
	// absolute path
	CredentialsPath string `json:"credentials_path" mapstructure:"credentials_path"`
	// Absolute path to an external program or an HTTP URL to invoke just before the user login.
	// This program/URL allows to modify or create the user trying to login.
	// It is useful if you have users with dynamic fields to update just before the login.
	// Please note that if you want to create a new user, the pre-login hook response must
	// include all the mandatory user fields.
	//
	// The pre-login hook must finish within 30 seconds.
	//
	// If an error happens while executing the "PreLoginHook" then login will be denied.
	// PreLoginHook and ExternalAuthHook are mutally exclusive.
	// Leave empty to disable.
	PreLoginHook string `json:"pre_login_hook" mapstructure:"pre_login_hook"`
	// Absolute path to an external program or an HTTP URL to invoke after the user login.
	// Based on the configured scope you can choose if notify failed or successful logins
	// or both
	PostLoginHook string `json:"post_login_hook" mapstructure:"post_login_hook"`
	// PostLoginScope defines the scope for the post-login hook.
	// - 0 means notify both failed and successful logins
	// - 1 means notify failed logins
	// - 2 means notify successful logins
	PostLoginScope int `json:"post_login_scope" mapstructure:"post_login_scope"`
	// Absolute path to an external program or an HTTP URL to invoke just before password
	// authentication. This hook allows you to externally check the provided password,
	// its main use case is to allow to easily support things like password+OTP for protocols
	// without keyboard interactive support such as FTP and WebDAV. You can ask your users
	// to login using a string consisting of a fixed password and a One Time Token, you
	// can verify the token inside the hook and ask to SFTPGo to verify the fixed part.
	CheckPasswordHook string `json:"check_password_hook" mapstructure:"check_password_hook"`
	// CheckPasswordScope defines the scope for the check password hook.
	// - 0 means all protocols
	// - 1 means SSH
	// - 2 means FTP
	// - 4 means WebDAV
	// you can combine the scopes, for example 6 means FTP and WebDAV
	CheckPasswordScope int `json:"check_password_scope" mapstructure:"check_password_scope"`
	// Defines how the database will be initialized/updated:
	// - 0 means automatically
	// - 1 means manually using the initprovider sub-command
	UpdateMode int `json:"update_mode" mapstructure:"update_mode"`
	// PasswordHashing defines the configuration for password hashing
	PasswordHashing PasswordHashing `json:"password_hashing" mapstructure:"password_hashing"`
	// PreferDatabaseCredentials indicates whether credential files (currently used for Google
	// Cloud Storage) should be stored in the database instead of in the directory specified by
	// CredentialsPath.
	PreferDatabaseCredentials bool `json:"prefer_database_credentials" mapstructure:"prefer_database_credentials"`
	// PasswordValidation defines the password validation rules
	PasswordValidation PasswordValidation `json:"password_validation" mapstructure:"password_validation"`
	// Verifying argon2 passwords has a high memory and computational cost,
	// by enabling, in memory, password caching you reduce this cost.
	PasswordCaching bool `json:"password_caching" mapstructure:"password_caching"`
	// DelayedQuotaUpdate defines the number of seconds to accumulate quota updates.
	// If there are a lot of close uploads, accumulating quota updates can save you many
	// queries to the data provider.
	// If you want to track quotas, a scheduled quota update is recommended in any case, the stored
	// quota size may be incorrect for several reasons, such as an unexpected shutdown, temporary provider
	// failures, file copied outside of SFTPGo, and so on.
	// 0 means immediate quota update.
	DelayedQuotaUpdate int `json:"delayed_quota_update" mapstructure:"delayed_quota_update"`
	// If enabled, a default admin user with username "admin" and password "password" will be created
	// on first start.
	// You can also create the first admin user by using the web interface or by loading initial data.
	CreateDefaultAdmin bool `json:"create_default_admin" mapstructure:"create_default_admin"`
	// Rules for usernames and folder names:
	// - 0 means no rules
	// - 1 means you can use any UTF-8 character. The names are used in URIs for REST API and Web admin.
	//     By default only unreserved URI characters are allowed: ALPHA / DIGIT / "-" / "." / "_" / "~".
	// - 2 means names are converted to lowercase before saving/matching and so case
	//     insensitive matching is possible
	// - 4 means trimming trailing and leading white spaces before saving/matching
	// Rules can be combined, for example 3 means both converting to lowercase and allowing any UTF-8 character.
	// Enabling these options for existing installations could be backward incompatible, some users
	// could be unable to login, for example existing users with mixed cases in their usernames.
	// You have to ensure that all existing users respect the defined rules.
	NamingRules int `json:"naming_rules" mapstructure:"naming_rules"`
	// If the data provider is shared across multiple SFTPGo instances, set this parameter to 1.
	// MySQL, PostgreSQL and CockroachDB can be shared, this setting is ignored for other data
	// providers. For shared data providers, SFTPGo periodically reloads the latest updated users,
	// based on the "updated_at" field, and updates its internal caches if users are updated from
	// a different instance. This check, if enabled, is executed every 10 minutes.
	// For shared data providers, active transfers are persisted in the database and thus
	// quota checks between ongoing transfers will work cross multiple instances
	IsShared int `json:"is_shared" mapstructure:"is_shared"`
	// Path to the backup directory. This can be an absolute path or a path relative to the config dir
	BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
	// Settings for automatic backups
	AutoBackup AutoBackup `json:"auto_backup" mapstructure:"auto_backup"`
}

// GetShared returns the provider share mode
func (c *Config) GetShared() int {
	if !util.IsStringInSlice(c.Driver, sharedProviders) {
		return 0
	}
	return c.IsShared
}

func (c *Config) convertName(name string) string {
	if c.NamingRules == 0 {
		return name
	}
	if c.NamingRules&2 != 0 {
		name = strings.ToLower(name)
	}
	if c.NamingRules&4 != 0 {
		name = strings.TrimSpace(name)
	}

	return name
}

// IsDefenderSupported returns true if the configured provider supports the defender
func (c *Config) IsDefenderSupported() bool {
	switch c.Driver {
	case MySQLDataProviderName, PGSQLDataProviderName, CockroachDataProviderName:
		return true
	default:
		return false
	}
}

func (c *Config) requireCustomTLSForMySQL() bool {
	if config.RootCert != "" && util.IsFileInputValid(config.RootCert) {
		return config.SSLMode != 0
	}
	if config.ClientCert != "" && config.ClientKey != "" && util.IsFileInputValid(config.ClientCert) &&
		util.IsFileInputValid(config.ClientKey) {
		return config.SSLMode != 0
	}
	return false
}

func (c *Config) doBackup() {
	now := time.Now()
	outputFile := filepath.Join(c.BackupsPath, fmt.Sprintf("backup_%v_%v.json", now.Weekday(), now.Hour()))
	providerLog(logger.LevelDebug, "starting auto backup to file %#v", outputFile)
	err := os.MkdirAll(filepath.Dir(outputFile), 0700)
	if err != nil {
		providerLog(logger.LevelError, "unable to create backup dir %#v: %v", outputFile, err)
		return
	}
	backup, err := DumpData()
	if err != nil {
		providerLog(logger.LevelError, "unable to execute backup: %v", err)
		return
	}
	dump, err := json.Marshal(backup)
	if err != nil {
		providerLog(logger.LevelError, "unable to marshal backup as JSON: %v", err)
		return
	}
	err = os.WriteFile(outputFile, dump, 0600)
	if err != nil {
		providerLog(logger.LevelError, "unable to save backup: %v", err)
		return
	}
	providerLog(logger.LevelDebug, "auto backup saved to %#v", outputFile)
}

// ConvertName converts the given name based on the configured rules
func ConvertName(name string) string {
	return config.convertName(name)
}

// ActiveTransfer defines an active protocol transfer
type ActiveTransfer struct {
	ID            int64
	Type          int
	ConnID        string
	Username      string
	FolderName    string
	IP            string
	TruncatedSize int64
	CurrentULSize int64
	CurrentDLSize int64
	CreatedAt     int64
	UpdatedAt     int64
}

// TransferQuota stores the allowed transfer quota fields
type TransferQuota struct {
	ULSize           int64
	DLSize           int64
	TotalSize        int64
	AllowedULSize    int64
	AllowedDLSize    int64
	AllowedTotalSize int64
}

// HasSizeLimits returns true if any size limit is set
func (q *TransferQuota) HasSizeLimits() bool {
	return q.AllowedDLSize > 0 || q.AllowedULSize > 0 || q.AllowedTotalSize > 0
}

// HasUploadSpace returns true if there is transfer upload space available
func (q *TransferQuota) HasUploadSpace() bool {
	if q.TotalSize <= 0 && q.ULSize <= 0 {
		return true
	}
	if q.TotalSize > 0 {
		return q.AllowedTotalSize > 0
	}
	return q.AllowedULSize > 0
}

// HasDownloadSpace returns true if there is transfer download space available
func (q *TransferQuota) HasDownloadSpace() bool {
	if q.TotalSize <= 0 && q.DLSize <= 0 {
		return true
	}
	if q.TotalSize > 0 {
		return q.AllowedTotalSize > 0
	}
	return q.AllowedDLSize > 0
}

// DefenderEntry defines a defender entry
type DefenderEntry struct {
	ID      int64     `json:"-"`
	IP      string    `json:"ip"`
	Score   int       `json:"score,omitempty"`
	BanTime time.Time `json:"ban_time,omitempty"`
}

// GetID returns an unique ID for a defender entry
func (d *DefenderEntry) GetID() string {
	return hex.EncodeToString([]byte(d.IP))
}

// GetBanTime returns the ban time for a defender entry as string
func (d *DefenderEntry) GetBanTime() string {
	if d.BanTime.IsZero() {
		return ""
	}
	return d.BanTime.UTC().Format(time.RFC3339)
}

// MarshalJSON returns the JSON encoding of a DefenderEntry.
func (d *DefenderEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID      string `json:"id"`
		IP      string `json:"ip"`
		Score   int    `json:"score,omitempty"`
		BanTime string `json:"ban_time,omitempty"`
	}{
		ID:      d.GetID(),
		IP:      d.IP,
		Score:   d.Score,
		BanTime: d.GetBanTime(),
	})
}

// BackupData defines the structure for the backup/restore files
type BackupData struct {
	Users   []User                  `json:"users"`
	Folders []vfs.BaseVirtualFolder `json:"folders"`
	Admins  []Admin                 `json:"admins"`
	APIKeys []APIKey                `json:"api_keys"`
	Shares  []Share                 `json:"shares"`
	Version int                     `json:"version"`
}

// HasFolder returns true if the folder with the given name is included
func (d *BackupData) HasFolder(name string) bool {
	for _, folder := range d.Folders {
		if folder.Name == name {
			return true
		}
	}
	return false
}

type checkPasswordRequest struct {
	Username string `json:"username"`
	IP       string `json:"ip"`
	Password string `json:"password"`
	Protocol string `json:"protocol"`
}

type checkPasswordResponse struct {
	// 0 KO, 1 OK, 2 partial success, -1 not executed
	Status int `json:"status"`
	// for status = 2 this is the password to check against the one stored
	// inside the SFTPGo data provider
	ToVerify string `json:"to_verify"`
}

// GetQuotaTracking returns the configured mode for user's quota tracking
func GetQuotaTracking() int {
	return config.TrackQuota
}

// HasUsersBaseDir returns true if users base dir is set
func HasUsersBaseDir() bool {
	return config.UsersBaseDir != ""
}

// Provider defines the interface that data providers must implement.
type Provider interface {
	validateUserAndPass(username, password, ip, protocol string) (User, error)
	validateUserAndPubKey(username string, pubKey []byte, isSSHCert bool) (User, string, error)
	validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error)
	updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error
	updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error
	getUsedQuota(username string) (int, int64, int64, int64, error)
	userExists(username string) (User, error)
	addUser(user *User) error
	updateUser(user *User) error
	deleteUser(user *User) error
	updateUserPassword(username, password string) error
	getUsers(limit int, offset int, order string) ([]User, error)
	dumpUsers() ([]User, error)
	getRecentlyUpdatedUsers(after int64) ([]User, error)
	getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error)
	updateLastLogin(username string) error
	updateAdminLastLogin(username string) error
	setUpdatedAt(username string)
	getFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error)
	getFolderByName(name string) (vfs.BaseVirtualFolder, error)
	addFolder(folder *vfs.BaseVirtualFolder) error
	updateFolder(folder *vfs.BaseVirtualFolder) error
	deleteFolder(folder *vfs.BaseVirtualFolder) error
	updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error
	getUsedFolderQuota(name string) (int, int64, error)
	dumpFolders() ([]vfs.BaseVirtualFolder, error)
	adminExists(username string) (Admin, error)
	addAdmin(admin *Admin) error
	updateAdmin(admin *Admin) error
	deleteAdmin(admin *Admin) error
	getAdmins(limit int, offset int, order string) ([]Admin, error)
	dumpAdmins() ([]Admin, error)
	validateAdminAndPass(username, password, ip string) (Admin, error)
	apiKeyExists(keyID string) (APIKey, error)
	addAPIKey(apiKey *APIKey) error
	updateAPIKey(apiKey *APIKey) error
	deleteAPIKey(apiKey *APIKey) error
	getAPIKeys(limit int, offset int, order string) ([]APIKey, error)
	dumpAPIKeys() ([]APIKey, error)
	updateAPIKeyLastUse(keyID string) error
	shareExists(shareID, username string) (Share, error)
	addShare(share *Share) error
	updateShare(share *Share) error
	deleteShare(share *Share) error
	getShares(limit int, offset int, order, username string) ([]Share, error)
	dumpShares() ([]Share, error)
	updateShareLastUse(shareID string, numTokens int) error
	getDefenderHosts(from int64, limit int) ([]DefenderEntry, error)
	getDefenderHostByIP(ip string, from int64) (DefenderEntry, error)
	isDefenderHostBanned(ip string) (DefenderEntry, error)
	updateDefenderBanTime(ip string, minutes int) error
	deleteDefenderHost(ip string) error
	addDefenderEvent(ip string, score int) error
	setDefenderBanTime(ip string, banTime int64) error
	cleanupDefender(from int64) error
	addActiveTransfer(transfer ActiveTransfer) error
	updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error
	removeActiveTransfer(transferID int64, connectionID string) error
	cleanupActiveTransfers(before time.Time) error
	getActiveTransfers(from time.Time) ([]ActiveTransfer, error)
	checkAvailability() error
	close() error
	reloadConfig() error
	initializeDatabase() error
	migrateDatabase() error
	revertDatabase(targetVersion int) error
	resetDatabase() error
}

// SetTempPath sets the path for temporary files
func SetTempPath(fsPath string) {
	tempPath = fsPath
}

// Initialize the data provider.
// An error is returned if the configured driver is invalid or if the data provider cannot be initialized
func Initialize(cnf Config, basePath string, checkAdmins bool) error {
	var err error
	config = cnf

	cnf.BackupsPath = getConfigPath(cnf.BackupsPath, basePath)
	if cnf.BackupsPath == "" {
		return fmt.Errorf("required directory is invalid, backup path %#v", cnf.BackupsPath)
	}
	credentialsDirPath = getConfigPath(config.CredentialsPath, basePath)
	vfs.SetCredentialsDirPath(credentialsDirPath)

	if err = initializeHashingAlgo(&cnf); err != nil {
		return err
	}

	if err = validateHooks(); err != nil {
		return err
	}
	err = createProvider(basePath)
	if err != nil {
		return err
	}
	if cnf.UpdateMode == 0 {
		err = provider.initializeDatabase()
		if err != nil && err != ErrNoInitRequired {
			logger.WarnToConsole("Unable to initialize data provider: %v", err)
			providerLog(logger.LevelError, "Unable to initialize data provider: %v", err)
			return err
		}
		if err == nil {
			logger.DebugToConsole("Data provider successfully initialized")
		}
		err = provider.migrateDatabase()
		if err != nil && err != ErrNoInitRequired {
			providerLog(logger.LevelError, "database migration error: %v", err)
			return err
		}
		if checkAdmins && cnf.CreateDefaultAdmin {
			err = checkDefaultAdmin()
			if err != nil {
				providerLog(logger.LevelError, "erro checking the default admin: %v", err)
				return err
			}
		}
	} else {
		providerLog(logger.LevelInfo, "database initialization/migration skipped, manual mode is configured")
	}
	admins, err := provider.getAdmins(1, 0, OrderASC)
	if err != nil {
		return err
	}
	atomic.StoreInt32(&isAdminCreated, int32(len(admins)))
	delayedQuotaUpdater.start()
	return startScheduler()
}

func validateHooks() error {
	var hooks []string
	if config.PreLoginHook != "" && !strings.HasPrefix(config.PreLoginHook, "http") {
		hooks = append(hooks, config.PreLoginHook)
	}
	if config.ExternalAuthHook != "" && !strings.HasPrefix(config.ExternalAuthHook, "http") {
		hooks = append(hooks, config.ExternalAuthHook)
	}
	if config.PostLoginHook != "" && !strings.HasPrefix(config.PostLoginHook, "http") {
		hooks = append(hooks, config.PostLoginHook)
	}
	if config.CheckPasswordHook != "" && !strings.HasPrefix(config.CheckPasswordHook, "http") {
		hooks = append(hooks, config.CheckPasswordHook)
	}

	for _, hook := range hooks {
		if !filepath.IsAbs(hook) {
			return fmt.Errorf("invalid hook: %#v must be an absolute path", hook)
		}
		_, err := os.Stat(hook)
		if err != nil {
			providerLog(logger.LevelError, "invalid hook: %v", err)
			return err
		}
	}

	return nil
}

// GetBackupsPath returns the normalized backups path
func GetBackupsPath() string {
	return config.BackupsPath
}

func initializeHashingAlgo(cnf *Config) error {
	argon2Params = &argon2id.Params{
		Memory:      cnf.PasswordHashing.Argon2Options.Memory,
		Iterations:  cnf.PasswordHashing.Argon2Options.Iterations,
		Parallelism: cnf.PasswordHashing.Argon2Options.Parallelism,
		SaltLength:  16,
		KeyLength:   32,
	}

	if config.PasswordHashing.Algo == HashingAlgoBcrypt {
		if config.PasswordHashing.BcryptOptions.Cost > bcrypt.MaxCost {
			err := fmt.Errorf("invalid bcrypt cost %v, max allowed %v", config.PasswordHashing.BcryptOptions.Cost, bcrypt.MaxCost)
			logger.WarnToConsole("Unable to initialize data provider: %v", err)
			providerLog(logger.LevelError, "Unable to initialize data provider: %v", err)
			return err
		}
	}
	return nil
}

func validateSQLTablesPrefix() error {
	if config.SQLTablesPrefix != "" {
		for _, char := range config.SQLTablesPrefix {
			if !strings.Contains(sqlPrefixValidChars, strings.ToLower(string(char))) {
				return errors.New("invalid sql_tables_prefix only chars in range 'a..z', 'A..Z', '0-9' and '_' are allowed")
			}
		}
		sqlTableUsers = config.SQLTablesPrefix + sqlTableUsers
		sqlTableFolders = config.SQLTablesPrefix + sqlTableFolders
		sqlTableFoldersMapping = config.SQLTablesPrefix + sqlTableFoldersMapping
		sqlTableAdmins = config.SQLTablesPrefix + sqlTableAdmins
		sqlTableAPIKeys = config.SQLTablesPrefix + sqlTableAPIKeys
		sqlTableShares = config.SQLTablesPrefix + sqlTableShares
		sqlTableDefenderEvents = config.SQLTablesPrefix + sqlTableDefenderEvents
		sqlTableDefenderHosts = config.SQLTablesPrefix + sqlTableDefenderHosts
		sqlTableActiveTransfers = config.SQLTablesPrefix + sqlTableActiveTransfers
		sqlTableSchemaVersion = config.SQLTablesPrefix + sqlTableSchemaVersion
		providerLog(logger.LevelDebug, "sql table for users %#v, folders %#v folders mapping %#v admins %#v "+
			"api keys %#v shares %#v defender hosts %#v defender events %#v transfers %#v schema version %#v",
			sqlTableUsers, sqlTableFolders, sqlTableFoldersMapping, sqlTableAdmins, sqlTableAPIKeys,
			sqlTableShares, sqlTableDefenderHosts, sqlTableDefenderEvents, sqlTableActiveTransfers, sqlTableSchemaVersion)
	}
	return nil
}

func checkDefaultAdmin() error {
	admins, err := provider.getAdmins(1, 0, OrderASC)
	if err != nil {
		return err
	}
	if len(admins) > 0 {
		return nil
	}
	logger.Debug(logSender, "", "no admins found, try to create the default one")
	// we need to create the default admin
	admin := &Admin{}
	if err := admin.setFromEnv(); err != nil {
		return err
	}
	return provider.addAdmin(admin)
}

// InitializeDatabase creates the initial database structure
func InitializeDatabase(cnf Config, basePath string) error {
	config = cnf

	if filepath.IsAbs(config.CredentialsPath) {
		credentialsDirPath = config.CredentialsPath
	} else {
		credentialsDirPath = filepath.Join(basePath, config.CredentialsPath)
	}
	vfs.SetCredentialsDirPath(credentialsDirPath)

	if err := initializeHashingAlgo(&cnf); err != nil {
		return err
	}

	err := createProvider(basePath)
	if err != nil {
		return err
	}
	err = provider.initializeDatabase()
	if err != nil && err != ErrNoInitRequired {
		return err
	}
	return provider.migrateDatabase()
}

// RevertDatabase restores schema and/or data to a previous version
func RevertDatabase(cnf Config, basePath string, targetVersion int) error {
	config = cnf

	if filepath.IsAbs(config.CredentialsPath) {
		credentialsDirPath = config.CredentialsPath
	} else {
		credentialsDirPath = filepath.Join(basePath, config.CredentialsPath)
	}

	err := createProvider(basePath)
	if err != nil {
		return err
	}
	err = provider.initializeDatabase()
	if err != nil && err != ErrNoInitRequired {
		return err
	}
	return provider.revertDatabase(targetVersion)
}

// ResetDatabase restores schema and/or data to a previous version
func ResetDatabase(cnf Config, basePath string) error {
	config = cnf

	if filepath.IsAbs(config.CredentialsPath) {
		credentialsDirPath = config.CredentialsPath
	} else {
		credentialsDirPath = filepath.Join(basePath, config.CredentialsPath)
	}

	if err := createProvider(basePath); err != nil {
		return err
	}
	return provider.resetDatabase()
}

// CheckAdminAndPass validates the given admin and password connecting from ip
func CheckAdminAndPass(username, password, ip string) (Admin, error) {
	username = config.convertName(username)
	return provider.validateAdminAndPass(username, password, ip)
}

// CheckCachedUserCredentials checks the credentials for a cached user
func CheckCachedUserCredentials(user *CachedUser, password, loginMethod, protocol string, tlsCert *x509.Certificate) error {
	if loginMethod != LoginMethodPassword {
		_, err := checkUserAndTLSCertificate(&user.User, protocol, tlsCert)
		if err != nil {
			return err
		}
		if loginMethod == LoginMethodTLSCertificate {
			if !user.User.IsLoginMethodAllowed(LoginMethodTLSCertificate, protocol, nil) {
				return fmt.Errorf("certificate login method is not allowed for user %#v", user.User.Username)
			}
			return nil
		}
	}
	if err := user.User.CheckLoginConditions(); err != nil {
		return err
	}
	if password == "" {
		return ErrInvalidCredentials
	}
	if user.Password != "" {
		if password == user.Password {
			return nil
		}
	} else {
		if ok, _ := isPasswordOK(&user.User, password); ok {
			return nil
		}
	}
	return ErrInvalidCredentials
}

// CheckCompositeCredentials checks multiple credentials.
// WebDAV users can send both a password and a TLS certificate within the same request
func CheckCompositeCredentials(username, password, ip, loginMethod, protocol string, tlsCert *x509.Certificate) (User, string, error) {
	username = config.convertName(username)
	if loginMethod == LoginMethodPassword {
		user, err := CheckUserAndPass(username, password, ip, protocol)
		return user, loginMethod, err
	}
	user, err := CheckUserBeforeTLSAuth(username, ip, protocol, tlsCert)
	if err != nil {
		return user, loginMethod, err
	}
	if !user.IsTLSUsernameVerificationEnabled() {
		// for backward compatibility with 2.0.x we only check the password and change the login method here
		// in future updates we have to return an error
		user, err := CheckUserAndPass(username, password, ip, protocol)
		return user, LoginMethodPassword, err
	}
	user, err = checkUserAndTLSCertificate(&user, protocol, tlsCert)
	if err != nil {
		return user, loginMethod, err
	}
	if loginMethod == LoginMethodTLSCertificate && !user.IsLoginMethodAllowed(LoginMethodTLSCertificate, protocol, nil) {
		return user, loginMethod, fmt.Errorf("certificate login method is not allowed for user %#v", user.Username)
	}
	if loginMethod == LoginMethodTLSCertificateAndPwd {
		if plugin.Handler.HasAuthScope(plugin.AuthScopePassword) {
			user, err = doPluginAuth(username, password, nil, ip, protocol, nil, plugin.AuthScopePassword)
		} else if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&1 != 0) {
			user, err = doExternalAuth(username, password, nil, "", ip, protocol, nil)
		} else if config.PreLoginHook != "" {
			user, err = executePreLoginHook(username, LoginMethodPassword, ip, protocol)
		}
		if err != nil {
			return user, loginMethod, err
		}
		user, err = checkUserAndPass(&user, password, ip, protocol)
	}
	return user, loginMethod, err
}

// CheckUserBeforeTLSAuth checks if a user exits before trying mutual TLS
func CheckUserBeforeTLSAuth(username, ip, protocol string, tlsCert *x509.Certificate) (User, error) {
	username = config.convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate) {
		return doPluginAuth(username, "", nil, ip, protocol, tlsCert, plugin.AuthScopeTLSCertificate)
	}
	if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&8 != 0) {
		return doExternalAuth(username, "", nil, "", ip, protocol, tlsCert)
	}
	if config.PreLoginHook != "" {
		return executePreLoginHook(username, LoginMethodTLSCertificate, ip, protocol)
	}
	return UserExists(username)
}

// CheckUserAndTLSCert returns the SFTPGo user with the given username and check if the
// given TLS certificate allow authentication without password
func CheckUserAndTLSCert(username, ip, protocol string, tlsCert *x509.Certificate) (User, error) {
	username = config.convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate) {
		user, err := doPluginAuth(username, "", nil, ip, protocol, tlsCert, plugin.AuthScopeTLSCertificate)
		if err != nil {
			return user, err
		}
		return checkUserAndTLSCertificate(&user, protocol, tlsCert)
	}
	if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&8 != 0) {
		user, err := doExternalAuth(username, "", nil, "", ip, protocol, tlsCert)
		if err != nil {
			return user, err
		}
		return checkUserAndTLSCertificate(&user, protocol, tlsCert)
	}
	if config.PreLoginHook != "" {
		user, err := executePreLoginHook(username, LoginMethodTLSCertificate, ip, protocol)
		if err != nil {
			return user, err
		}
		return checkUserAndTLSCertificate(&user, protocol, tlsCert)
	}
	return provider.validateUserAndTLSCert(username, protocol, tlsCert)
}

// CheckUserAndPass retrieves the SFTPGo user with the given username and password if a match is found or an error
func CheckUserAndPass(username, password, ip, protocol string) (User, error) {
	username = config.convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopePassword) {
		user, err := doPluginAuth(username, password, nil, ip, protocol, nil, plugin.AuthScopePassword)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(&user, password, ip, protocol)
	}
	if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&1 != 0) {
		user, err := doExternalAuth(username, password, nil, "", ip, protocol, nil)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(&user, password, ip, protocol)
	}
	if config.PreLoginHook != "" {
		user, err := executePreLoginHook(username, LoginMethodPassword, ip, protocol)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(&user, password, ip, protocol)
	}
	return provider.validateUserAndPass(username, password, ip, protocol)
}

// CheckUserAndPubKey retrieves the SFTP user with the given username and public key if a match is found or an error
func CheckUserAndPubKey(username string, pubKey []byte, ip, protocol string, isSSHCert bool) (User, string, error) {
	username = config.convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopePublicKey) {
		user, err := doPluginAuth(username, "", pubKey, ip, protocol, nil, plugin.AuthScopePublicKey)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(&user, pubKey, isSSHCert)
	}
	if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&2 != 0) {
		user, err := doExternalAuth(username, "", pubKey, "", ip, protocol, nil)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(&user, pubKey, isSSHCert)
	}
	if config.PreLoginHook != "" {
		user, err := executePreLoginHook(username, SSHLoginMethodPublicKey, ip, protocol)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(&user, pubKey, isSSHCert)
	}
	return provider.validateUserAndPubKey(username, pubKey, isSSHCert)
}

// CheckKeyboardInteractiveAuth checks the keyboard interactive authentication and returns
// the authenticated user or an error
func CheckKeyboardInteractiveAuth(username, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (User, error) {
	var user User
	var err error
	username = config.convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopeKeyboardInteractive) {
		user, err = doPluginAuth(username, "", nil, ip, protocol, nil, plugin.AuthScopeKeyboardInteractive)
	} else if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&4 != 0) {
		user, err = doExternalAuth(username, "", nil, "1", ip, protocol, nil)
	} else if config.PreLoginHook != "" {
		user, err = executePreLoginHook(username, SSHLoginMethodKeyboardInteractive, ip, protocol)
	} else {
		user, err = provider.userExists(username)
	}
	if err != nil {
		return user, err
	}
	return doKeyboardInteractiveAuth(&user, authHook, client, ip, protocol)
}

// GetUserAfterIDPAuth returns the SFTPGo user with the specified username
// after a successful authentication with an external identity provider.
// If a pre-login hook is defined it will be executed so the SFTPGo user
// can be created if it does not exist
func GetUserAfterIDPAuth(username, ip, protocol string) (User, error) {
	if config.PreLoginHook != "" {
		return executePreLoginHook(username, LoginMethodIDP, ip, protocol)
	}
	return UserExists(username)
}

// GetDefenderHosts returns hosts that are banned or for which some violations have been detected
func GetDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return provider.getDefenderHosts(from, limit)
}

// GetDefenderHostByIP returns a defender host by ip, if any
func GetDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return provider.getDefenderHostByIP(ip, from)
}

// IsDefenderHostBanned returns a defender entry and no error if the specified host is banned
func IsDefenderHostBanned(ip string) (DefenderEntry, error) {
	return provider.isDefenderHostBanned(ip)
}

// UpdateDefenderBanTime increments ban time for the specified ip
func UpdateDefenderBanTime(ip string, minutes int) error {
	return provider.updateDefenderBanTime(ip, minutes)
}

// DeleteDefenderHost removes the specified IP from the defender lists
func DeleteDefenderHost(ip string) error {
	return provider.deleteDefenderHost(ip)
}

// AddDefenderEvent adds an event for the given IP with the given score
// and returns the host with the updated score
func AddDefenderEvent(ip string, score int, from int64) (DefenderEntry, error) {
	if err := provider.addDefenderEvent(ip, score); err != nil {
		return DefenderEntry{}, err
	}
	return provider.getDefenderHostByIP(ip, from)
}

// SetDefenderBanTime sets the ban time for the specified IP
func SetDefenderBanTime(ip string, banTime int64) error {
	return provider.setDefenderBanTime(ip, banTime)
}

// CleanupDefender removes events and hosts older than "from" from the data provider
func CleanupDefender(from int64) error {
	return provider.cleanupDefender(from)
}

// UpdateShareLastUse updates the LastUseAt and UsedTokens for the given share
func UpdateShareLastUse(share *Share, numTokens int) error {
	return provider.updateShareLastUse(share.ShareID, numTokens)
}

// UpdateAPIKeyLastUse updates the LastUseAt field for the given API key
func UpdateAPIKeyLastUse(apiKey *APIKey) error {
	lastUse := util.GetTimeFromMsecSinceEpoch(apiKey.LastUseAt)
	diff := -time.Until(lastUse)
	if diff < 0 || diff > lastLoginMinDelay {
		return provider.updateAPIKeyLastUse(apiKey.KeyID)
	}
	return nil
}

// UpdateLastLogin updates the last login field for the given SFTPGo user
func UpdateLastLogin(user *User) {
	delay := lastLoginMinDelay
	if user.Filters.ExternalAuthCacheTime > 0 {
		delay = time.Duration(user.Filters.ExternalAuthCacheTime) * time.Second
	}
	if user.LastLogin <= user.UpdatedAt || !isLastActivityRecent(user.LastLogin, delay) {
		err := provider.updateLastLogin(user.Username)
		if err == nil {
			webDAVUsersCache.updateLastLogin(user.Username)
		}
	}
}

// UpdateAdminLastLogin updates the last login field for the given SFTPGo admin
func UpdateAdminLastLogin(admin *Admin) {
	if !isLastActivityRecent(admin.LastLogin, lastLoginMinDelay) {
		provider.updateAdminLastLogin(admin.Username) //nolint:errcheck
	}
}

// UpdateUserQuota updates the quota for the given SFTPGo user adding filesAdd and sizeAdd.
// If reset is true filesAdd and sizeAdd indicates the total files and the total size instead of the difference.
func UpdateUserQuota(user *User, filesAdd int, sizeAdd int64, reset bool) error {
	if config.TrackQuota == 0 {
		return util.NewMethodDisabledError(trackQuotaDisabledError)
	} else if config.TrackQuota == 2 && !reset && !user.HasQuotaRestrictions() {
		return nil
	}
	if filesAdd == 0 && sizeAdd == 0 && !reset {
		return nil
	}
	if config.DelayedQuotaUpdate == 0 || reset {
		if reset {
			delayedQuotaUpdater.resetUserQuota(user.Username)
		}
		return provider.updateQuota(user.Username, filesAdd, sizeAdd, reset)
	}
	delayedQuotaUpdater.updateUserQuota(user.Username, filesAdd, sizeAdd)
	return nil
}

// UpdateVirtualFolderQuota updates the quota for the given virtual folder adding filesAdd and sizeAdd.
// If reset is true filesAdd and sizeAdd indicates the total files and the total size instead of the difference.
func UpdateVirtualFolderQuota(vfolder *vfs.BaseVirtualFolder, filesAdd int, sizeAdd int64, reset bool) error {
	if config.TrackQuota == 0 {
		return util.NewMethodDisabledError(trackQuotaDisabledError)
	}
	if filesAdd == 0 && sizeAdd == 0 && !reset {
		return nil
	}
	if config.DelayedQuotaUpdate == 0 || reset {
		if reset {
			delayedQuotaUpdater.resetFolderQuota(vfolder.Name)
		}
		return provider.updateFolderQuota(vfolder.Name, filesAdd, sizeAdd, reset)
	}
	delayedQuotaUpdater.updateFolderQuota(vfolder.Name, filesAdd, sizeAdd)
	return nil
}

// UpdateUserTransferQuota updates the transfer quota for the given SFTPGo user.
// If reset is true uploadSize and downloadSize indicates the actual sizes instead of the difference.
func UpdateUserTransferQuota(user *User, uploadSize, downloadSize int64, reset bool) error {
	if config.TrackQuota == 0 {
		return util.NewMethodDisabledError(trackQuotaDisabledError)
	} else if config.TrackQuota == 2 && !reset && !user.HasTransferQuotaRestrictions() {
		return nil
	}
	if downloadSize == 0 && uploadSize == 0 && !reset {
		return nil
	}
	if config.DelayedQuotaUpdate == 0 || reset {
		if reset {
			delayedQuotaUpdater.resetUserTransferQuota(user.Username)
		}
		return provider.updateTransferQuota(user.Username, uploadSize, downloadSize, reset)
	}
	delayedQuotaUpdater.updateUserTransferQuota(user.Username, uploadSize, downloadSize)
	return nil
}

// GetUsedQuota returns the used quota for the given SFTPGo user.
func GetUsedQuota(username string) (int, int64, int64, int64, error) {
	if config.TrackQuota == 0 {
		return 0, 0, 0, 0, util.NewMethodDisabledError(trackQuotaDisabledError)
	}
	files, size, ulTransferSize, dlTransferSize, err := provider.getUsedQuota(username)
	if err != nil {
		return files, size, ulTransferSize, dlTransferSize, err
	}
	delayedFiles, delayedSize := delayedQuotaUpdater.getUserPendingQuota(username)
	delayedUlTransferSize, delayedDLTransferSize := delayedQuotaUpdater.getUserPendingTransferQuota(username)

	return files + delayedFiles, size + delayedSize, ulTransferSize + delayedUlTransferSize,
		dlTransferSize + delayedDLTransferSize, err
}

// GetUsedVirtualFolderQuota returns the used quota for the given virtual folder.
func GetUsedVirtualFolderQuota(name string) (int, int64, error) {
	if config.TrackQuota == 0 {
		return 0, 0, util.NewMethodDisabledError(trackQuotaDisabledError)
	}
	files, size, err := provider.getUsedFolderQuota(name)
	if err != nil {
		return files, size, err
	}
	delayedFiles, delayedSize := delayedQuotaUpdater.getFolderPendingQuota(name)
	return files + delayedFiles, size + delayedSize, err
}

// AddShare adds a new share
func AddShare(share *Share, executor, ipAddress string) error {
	err := provider.addShare(share)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectShare, share.ShareID, share)
	}
	return err
}

// UpdateShare updates an existing share
func UpdateShare(share *Share, executor, ipAddress string) error {
	err := provider.updateShare(share)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectShare, share.ShareID, share)
	}
	return err
}

// DeleteShare deletes an existing share
func DeleteShare(shareID string, executor, ipAddress string) error {
	share, err := provider.shareExists(shareID, executor)
	if err != nil {
		return err
	}
	err = provider.deleteShare(&share)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectShare, shareID, &share)
	}
	return err
}

// ShareExists returns the share with the given ID if it exists
func ShareExists(shareID, username string) (Share, error) {
	if shareID == "" {
		return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %#v does not exist", shareID))
	}
	return provider.shareExists(shareID, username)
}

// AddAPIKey adds a new API key
func AddAPIKey(apiKey *APIKey, executor, ipAddress string) error {
	err := provider.addAPIKey(apiKey)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, apiKey)
	}
	return err
}

// UpdateAPIKey updates an existing API key
func UpdateAPIKey(apiKey *APIKey, executor, ipAddress string) error {
	err := provider.updateAPIKey(apiKey)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, apiKey)
	}
	return err
}

// DeleteAPIKey deletes an existing API key
func DeleteAPIKey(keyID string, executor, ipAddress string) error {
	apiKey, err := provider.apiKeyExists(keyID)
	if err != nil {
		return err
	}
	err = provider.deleteAPIKey(&apiKey)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, &apiKey)
	}
	return err
}

// APIKeyExists returns the API key with the given ID if it exists
func APIKeyExists(keyID string) (APIKey, error) {
	if keyID == "" {
		return APIKey{}, util.NewRecordNotFoundError(fmt.Sprintf("API key %#v does not exist", keyID))
	}
	return provider.apiKeyExists(keyID)
}

// HasAdmin returns true if the first admin has been created
// and so SFTPGo is ready to be used
func HasAdmin() bool {
	return atomic.LoadInt32(&isAdminCreated) > 0
}

// AddAdmin adds a new SFTPGo admin
func AddAdmin(admin *Admin, executor, ipAddress string) error {
	admin.Filters.RecoveryCodes = nil
	admin.Filters.TOTPConfig = AdminTOTPConfig{
		Enabled: false,
	}
	admin.Username = config.convertName(admin.Username)
	err := provider.addAdmin(admin)
	if err == nil {
		atomic.StoreInt32(&isAdminCreated, 1)
		executeAction(operationAdd, executor, ipAddress, actionObjectAdmin, admin.Username, admin)
	}
	return err
}

// UpdateAdmin updates an existing SFTPGo admin
func UpdateAdmin(admin *Admin, executor, ipAddress string) error {
	err := provider.updateAdmin(admin)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectAdmin, admin.Username, admin)
	}
	return err
}

// DeleteAdmin deletes an existing SFTPGo admin
func DeleteAdmin(username, executor, ipAddress string) error {
	username = config.convertName(username)
	admin, err := provider.adminExists(username)
	if err != nil {
		return err
	}
	err = provider.deleteAdmin(&admin)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectAdmin, admin.Username, &admin)
	}
	return err
}

// AdminExists returns the admin with the given username if it exists
func AdminExists(username string) (Admin, error) {
	username = config.convertName(username)
	return provider.adminExists(username)
}

// UserExists checks if the given SFTPGo username exists, returns an error if no match is found
func UserExists(username string) (User, error) {
	username = config.convertName(username)
	return provider.userExists(username)
}

// AddUser adds a new SFTPGo user.
func AddUser(user *User, executor, ipAddress string) error {
	user.Filters.RecoveryCodes = nil
	user.Filters.TOTPConfig = UserTOTPConfig{
		Enabled: false,
	}
	user.Username = config.convertName(user.Username)
	err := provider.addUser(user)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectUser, user.Username, user)
	}
	return err
}

// UpdateUser updates an existing SFTPGo user.
func UpdateUser(user *User, executor, ipAddress string) error {
	err := provider.updateUser(user)
	if err == nil {
		webDAVUsersCache.swap(user)
		cachedPasswords.Remove(user.Username)
		executeAction(operationUpdate, executor, ipAddress, actionObjectUser, user.Username, user)
	}
	return err
}

// DeleteUser deletes an existing SFTPGo user.
func DeleteUser(username, executor, ipAddress string) error {
	username = config.convertName(username)
	user, err := provider.userExists(username)
	if err != nil {
		return err
	}
	err = provider.deleteUser(&user)
	if err == nil {
		RemoveCachedWebDAVUser(user.Username)
		delayedQuotaUpdater.resetUserQuota(username)
		cachedPasswords.Remove(username)
		executeAction(operationDelete, executor, ipAddress, actionObjectUser, user.Username, &user)
	}
	return err
}

// AddActiveTransfer stores the specified transfer
func AddActiveTransfer(transfer ActiveTransfer) {
	if err := provider.addActiveTransfer(transfer); err != nil {
		providerLog(logger.LevelError, "unable to add transfer id %v, connection id %v: %v",
			transfer.ID, transfer.ConnID, err)
	}
}

// UpdateActiveTransferSizes updates the current upload and download sizes for the specified transfer
func UpdateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) {
	if err := provider.updateActiveTransferSizes(ulSize, dlSize, transferID, connectionID); err != nil {
		providerLog(logger.LevelError, "unable to update sizes for transfer id %v, connection id %v: %v",
			transferID, connectionID, err)
	}
}

// RemoveActiveTransfer removes the specified transfer
func RemoveActiveTransfer(transferID int64, connectionID string) {
	if err := provider.removeActiveTransfer(transferID, connectionID); err != nil {
		providerLog(logger.LevelError, "unable to delete transfer id %v, connection id %v: %v",
			transferID, connectionID, err)
	}
}

// CleanupActiveTransfers removes the transfer before the specified time
func CleanupActiveTransfers(before time.Time) error {
	err := provider.cleanupActiveTransfers(before)
	if err == nil {
		providerLog(logger.LevelDebug, "deleted active transfers updated before: %v", before)
	} else {
		providerLog(logger.LevelError, "error deleting active transfers updated before %v: %v", before, err)
	}
	return err
}

// GetActiveTransfers retrieves the active transfers with an update time after the specified value
func GetActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return provider.getActiveTransfers(from)
}

// ReloadConfig reloads provider configuration.
// Currently only implemented for memory provider, allows to reload the users
// from the configured file, if defined
func ReloadConfig() error {
	return provider.reloadConfig()
}

// GetShares returns an array of shares respecting limit and offset
func GetShares(limit, offset int, order, username string) ([]Share, error) {
	return provider.getShares(limit, offset, order, username)
}

// GetAPIKeys returns an array of API keys respecting limit and offset
func GetAPIKeys(limit, offset int, order string) ([]APIKey, error) {
	return provider.getAPIKeys(limit, offset, order)
}

// GetAdmins returns an array of admins respecting limit and offset
func GetAdmins(limit, offset int, order string) ([]Admin, error) {
	return provider.getAdmins(limit, offset, order)
}

// GetUsers returns an array of users respecting limit and offset and filtered by username exact match if not empty
func GetUsers(limit, offset int, order string) ([]User, error) {
	return provider.getUsers(limit, offset, order)
}

// GetUsersForQuotaCheck returns the users with the fields required for a quota check
func GetUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return provider.getUsersForQuotaCheck(toFetch)
}

// AddFolder adds a new virtual folder.
func AddFolder(folder *vfs.BaseVirtualFolder) error {
	folder.Name = config.convertName(folder.Name)
	return provider.addFolder(folder)
}

// UpdateFolder updates the specified virtual folder
func UpdateFolder(folder *vfs.BaseVirtualFolder, users []string, executor, ipAddress string) error {
	err := provider.updateFolder(folder)
	if err == nil {
		for _, user := range users {
			provider.setUpdatedAt(user)
			u, err := provider.userExists(user)
			if err == nil {
				webDAVUsersCache.swap(&u)
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, &u)
			} else {
				RemoveCachedWebDAVUser(user)
			}
		}
	}
	return err
}

// DeleteFolder deletes an existing folder.
func DeleteFolder(folderName, executor, ipAddress string) error {
	folderName = config.convertName(folderName)
	folder, err := provider.getFolderByName(folderName)
	if err != nil {
		return err
	}
	err = provider.deleteFolder(&folder)
	if err == nil {
		for _, user := range folder.Users {
			provider.setUpdatedAt(user)
			u, err := provider.userExists(user)
			if err == nil {
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, &u)
			}
			RemoveCachedWebDAVUser(user)
		}
		delayedQuotaUpdater.resetFolderQuota(folderName)
	}
	return err
}

// GetFolderByName returns the folder with the specified name if any
func GetFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	name = config.convertName(name)
	return provider.getFolderByName(name)
}

// GetFolders returns an array of folders respecting limit and offset
func GetFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error) {
	return provider.getFolders(limit, offset, order)
}

// DumpData returns all users, folders, admins, api keys, shares
func DumpData() (BackupData, error) {
	var data BackupData
	users, err := provider.dumpUsers()
	if err != nil {
		return data, err
	}
	folders, err := provider.dumpFolders()
	if err != nil {
		return data, err
	}
	admins, err := provider.dumpAdmins()
	if err != nil {
		return data, err
	}
	apiKeys, err := provider.dumpAPIKeys()
	if err != nil {
		return data, err
	}
	shares, err := provider.dumpShares()
	if err != nil {
		return data, err
	}
	data.Users = users
	data.Folders = folders
	data.Admins = admins
	data.APIKeys = apiKeys
	data.Shares = shares
	data.Version = DumpVersion
	return data, err
}

// ParseDumpData tries to parse data as BackupData
func ParseDumpData(data []byte) (BackupData, error) {
	var dump BackupData
	err := json.Unmarshal(data, &dump)
	return dump, err
}

// GetProviderConfig returns the current provider configuration
func GetProviderConfig() Config {
	return config
}

// GetProviderStatus returns an error if the provider is not available
func GetProviderStatus() ProviderStatus {
	err := provider.checkAvailability()
	status := ProviderStatus{
		Driver: config.Driver,
	}
	if err == nil {
		status.IsActive = true
	} else {
		status.IsActive = false
		status.Error = err.Error()
	}
	return status
}

// Close releases all provider resources.
// This method is used in test cases.
// Closing an uninitialized provider is not supported
func Close() error {
	stopScheduler()
	return provider.close()
}

func createProvider(basePath string) error {
	var err error
	sqlPlaceholders = getSQLPlaceholders()
	if err = validateSQLTablesPrefix(); err != nil {
		return err
	}
	logSender = fmt.Sprintf("dataprovider_%v", config.Driver)

	switch config.Driver {
	case SQLiteDataProviderName:
		return initializeSQLiteProvider(basePath)
	case PGSQLDataProviderName, CockroachDataProviderName:
		return initializePGSQLProvider()
	case MySQLDataProviderName:
		return initializeMySQLProvider()
	case BoltDataProviderName:
		return initializeBoltProvider(basePath)
	case MemoryDataProviderName:
		initializeMemoryProvider(basePath)
		return nil
	default:
		return fmt.Errorf("unsupported data provider: %v", config.Driver)
	}
}

func buildUserHomeDir(user *User) {
	if user.HomeDir == "" {
		if config.UsersBaseDir != "" {
			user.HomeDir = filepath.Join(config.UsersBaseDir, user.Username)
			return
		}
		switch user.FsConfig.Provider {
		case sdk.SFTPFilesystemProvider, sdk.S3FilesystemProvider, sdk.AzureBlobFilesystemProvider, sdk.GCSFilesystemProvider:
			if tempPath != "" {
				user.HomeDir = filepath.Join(tempPath, user.Username)
			} else {
				user.HomeDir = filepath.Join(os.TempDir(), user.Username)
			}
		}
	}
}

func isVirtualDirOverlapped(dir1, dir2 string, fullCheck bool) bool {
	if dir1 == dir2 {
		return true
	}
	if fullCheck {
		if len(dir1) > len(dir2) {
			if strings.HasPrefix(dir1, dir2+"/") {
				return true
			}
		}
		if len(dir2) > len(dir1) {
			if strings.HasPrefix(dir2, dir1+"/") {
				return true
			}
		}
	}
	return false
}

func validateFolderQuotaLimits(folder vfs.VirtualFolder) error {
	if folder.QuotaSize < -1 {
		return util.NewValidationError(fmt.Sprintf("invalid quota_size: %v folder path %#v", folder.QuotaSize, folder.MappedPath))
	}
	if folder.QuotaFiles < -1 {
		return util.NewValidationError(fmt.Sprintf("invalid quota_file: %v folder path %#v", folder.QuotaFiles, folder.MappedPath))
	}
	if (folder.QuotaSize == -1 && folder.QuotaFiles != -1) || (folder.QuotaFiles == -1 && folder.QuotaSize != -1) {
		return util.NewValidationError(fmt.Sprintf("virtual folder quota_size and quota_files must be both -1 or >= 0, quota_size: %v quota_files: %v",
			folder.QuotaFiles, folder.QuotaSize))
	}
	return nil
}

func getVirtualFolderIfInvalid(folder *vfs.BaseVirtualFolder) *vfs.BaseVirtualFolder {
	if err := ValidateFolder(folder); err == nil {
		return folder
	}
	// we try to get the folder from the data provider if only the Name is populated
	if folder.MappedPath != "" {
		return folder
	}
	if folder.Name == "" {
		return folder
	}
	if folder.FsConfig.Provider != sdk.LocalFilesystemProvider {
		return folder
	}
	if f, err := GetFolderByName(folder.Name); err == nil {
		return &f
	}
	return folder
}

func validateUserVirtualFolders(user *User) error {
	if len(user.VirtualFolders) == 0 {
		user.VirtualFolders = []vfs.VirtualFolder{}
		return nil
	}
	var virtualFolders []vfs.VirtualFolder
	folderNames := make(map[string]bool)

	for _, v := range user.VirtualFolders {
		cleanedVPath := util.CleanPath(v.VirtualPath)
		if err := validateFolderQuotaLimits(v); err != nil {
			return err
		}
		folder := getVirtualFolderIfInvalid(&v.BaseVirtualFolder)
		if err := ValidateFolder(folder); err != nil {
			return err
		}
		if folderNames[folder.Name] {
			return util.NewValidationError(fmt.Sprintf("the folder %#v is duplicated", folder.Name))
		}
		for _, vFolder := range virtualFolders {
			if isVirtualDirOverlapped(vFolder.VirtualPath, cleanedVPath, false) {
				return util.NewValidationError(fmt.Sprintf("invalid virtual folder %#v, it overlaps with virtual folder %#v",
					v.VirtualPath, vFolder.VirtualPath))
			}
		}
		virtualFolders = append(virtualFolders, vfs.VirtualFolder{
			BaseVirtualFolder: *folder,
			VirtualPath:       cleanedVPath,
			QuotaSize:         v.QuotaSize,
			QuotaFiles:        v.QuotaFiles,
		})
		folderNames[folder.Name] = true
	}
	user.VirtualFolders = virtualFolders
	return nil
}

func validateUserTOTPConfig(c *UserTOTPConfig, username string) error {
	if !c.Enabled {
		c.ConfigName = ""
		c.Secret = kms.NewEmptySecret()
		c.Protocols = nil
		return nil
	}
	if c.ConfigName == "" {
		return util.NewValidationError("totp: config name is mandatory")
	}
	if !util.IsStringInSlice(c.ConfigName, mfa.GetAvailableTOTPConfigNames()) {
		return util.NewValidationError(fmt.Sprintf("totp: config name %#v not found", c.ConfigName))
	}
	if c.Secret.IsEmpty() {
		return util.NewValidationError("totp: secret is mandatory")
	}
	if c.Secret.IsPlain() {
		c.Secret.SetAdditionalData(username)
		if err := c.Secret.Encrypt(); err != nil {
			return util.NewValidationError(fmt.Sprintf("totp: unable to encrypt secret: %v", err))
		}
	}
	if len(c.Protocols) == 0 {
		return util.NewValidationError("totp: specify at least one protocol")
	}
	for _, protocol := range c.Protocols {
		if !util.IsStringInSlice(protocol, MFAProtocols) {
			return util.NewValidationError(fmt.Sprintf("totp: invalid protocol %#v", protocol))
		}
	}
	return nil
}

func validateUserRecoveryCodes(user *User) error {
	for i := 0; i < len(user.Filters.RecoveryCodes); i++ {
		code := &user.Filters.RecoveryCodes[i]
		if code.Secret.IsEmpty() {
			return util.NewValidationError("mfa: recovery code cannot be empty")
		}
		if code.Secret.IsPlain() {
			code.Secret.SetAdditionalData(user.Username)
			if err := code.Secret.Encrypt(); err != nil {
				return util.NewValidationError(fmt.Sprintf("mfa: unable to encrypt recovery code: %v", err))
			}
		}
	}
	return nil
}

func validatePermissions(user *User) error {
	if len(user.Permissions) == 0 {
		return util.NewValidationError("please grant some permissions to this user")
	}
	permissions := make(map[string][]string)
	if _, ok := user.Permissions["/"]; !ok {
		return util.NewValidationError("permissions for the root dir \"/\" must be set")
	}
	for dir, perms := range user.Permissions {
		if len(perms) == 0 && dir == "/" {
			return util.NewValidationError(fmt.Sprintf("no permissions granted for the directory: %#v", dir))
		}
		if len(perms) > len(ValidPerms) {
			return util.NewValidationError("invalid permissions")
		}
		for _, p := range perms {
			if !util.IsStringInSlice(p, ValidPerms) {
				return util.NewValidationError(fmt.Sprintf("invalid permission: %#v", p))
			}
		}
		cleanedDir := filepath.ToSlash(path.Clean(dir))
		if cleanedDir != "/" {
			cleanedDir = strings.TrimSuffix(cleanedDir, "/")
		}
		if !path.IsAbs(cleanedDir) {
			return util.NewValidationError(fmt.Sprintf("cannot set permissions for non absolute path: %#v", dir))
		}
		if dir != cleanedDir && cleanedDir == "/" {
			return util.NewValidationError(fmt.Sprintf("cannot set permissions for invalid subdirectory: %#v is an alias for \"/\"", dir))
		}
		if util.IsStringInSlice(PermAny, perms) {
			permissions[cleanedDir] = []string{PermAny}
		} else {
			permissions[cleanedDir] = util.RemoveDuplicates(perms)
		}
	}
	user.Permissions = permissions
	return nil
}

func validatePublicKeys(user *User) error {
	if len(user.PublicKeys) == 0 {
		user.PublicKeys = []string{}
	}
	var validatedKeys []string
	for i, k := range user.PublicKeys {
		if k == "" {
			continue
		}
		_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse key nr. %d: %s", i+1, err))
		}
		validatedKeys = append(validatedKeys, k)
	}
	user.PublicKeys = util.RemoveDuplicates(validatedKeys)
	return nil
}

func validateFiltersPatternExtensions(user *User) error {
	if len(user.Filters.FilePatterns) == 0 {
		user.Filters.FilePatterns = []sdk.PatternsFilter{}
		return nil
	}
	filteredPaths := []string{}
	var filters []sdk.PatternsFilter
	for _, f := range user.Filters.FilePatterns {
		cleanedPath := filepath.ToSlash(path.Clean(f.Path))
		if !path.IsAbs(cleanedPath) {
			return util.NewValidationError(fmt.Sprintf("invalid path %#v for file patterns filter", f.Path))
		}
		if util.IsStringInSlice(cleanedPath, filteredPaths) {
			return util.NewValidationError(fmt.Sprintf("duplicate file patterns filter for path %#v", f.Path))
		}
		if len(f.AllowedPatterns) == 0 && len(f.DeniedPatterns) == 0 {
			return util.NewValidationError(fmt.Sprintf("empty file patterns filter for path %#v", f.Path))
		}
		if f.DenyPolicy < sdk.DenyPolicyDefault || f.DenyPolicy > sdk.DenyPolicyHide {
			return util.NewValidationError(fmt.Sprintf("invalid deny policy %v for path %#v", f.DenyPolicy, f.Path))
		}
		f.Path = cleanedPath
		allowed := make([]string, 0, len(f.AllowedPatterns))
		denied := make([]string, 0, len(f.DeniedPatterns))
		for _, pattern := range f.AllowedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return util.NewValidationError(fmt.Sprintf("invalid file pattern filter %#v", pattern))
			}
			allowed = append(allowed, strings.ToLower(pattern))
		}
		for _, pattern := range f.DeniedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return util.NewValidationError(fmt.Sprintf("invalid file pattern filter %#v", pattern))
			}
			denied = append(denied, strings.ToLower(pattern))
		}
		f.AllowedPatterns = util.RemoveDuplicates(allowed)
		f.DeniedPatterns = util.RemoveDuplicates(denied)
		filters = append(filters, f)
		filteredPaths = append(filteredPaths, cleanedPath)
	}
	user.Filters.FilePatterns = filters
	return nil
}

func checkEmptyFiltersStruct(user *User) {
	if len(user.Filters.AllowedIP) == 0 {
		user.Filters.AllowedIP = []string{}
	}
	if len(user.Filters.DeniedIP) == 0 {
		user.Filters.DeniedIP = []string{}
	}
	if len(user.Filters.DeniedLoginMethods) == 0 {
		user.Filters.DeniedLoginMethods = []string{}
	}
	if len(user.Filters.DeniedProtocols) == 0 {
		user.Filters.DeniedProtocols = []string{}
	}
}

func validateIPFilters(user *User) error {
	user.Filters.DeniedIP = util.RemoveDuplicates(user.Filters.DeniedIP)
	for _, IPMask := range user.Filters.DeniedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse denied IP/Mask %#v: %v", IPMask, err))
		}
	}
	user.Filters.AllowedIP = util.RemoveDuplicates(user.Filters.AllowedIP)
	for _, IPMask := range user.Filters.AllowedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse allowed IP/Mask %#v: %v", IPMask, err))
		}
	}
	return nil
}

func validateBandwidthLimit(bl sdk.BandwidthLimit) error {
	if len(bl.Sources) == 0 {
		return util.NewValidationError("no bandwidth limit source specified")
	}
	for _, source := range bl.Sources {
		_, _, err := net.ParseCIDR(source)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse bandwidth limit source %#v: %v", source, err))
		}
	}
	return nil
}

func validateBandwidthLimitsFilter(user *User) error {
	for idx, bandwidthLimit := range user.Filters.BandwidthLimits {
		if err := validateBandwidthLimit(bandwidthLimit); err != nil {
			return err
		}
		if bandwidthLimit.DownloadBandwidth < 0 {
			user.Filters.BandwidthLimits[idx].DownloadBandwidth = 0
		}
		if bandwidthLimit.UploadBandwidth < 0 {
			user.Filters.BandwidthLimits[idx].UploadBandwidth = 0
		}
	}
	return nil
}

func validateTransferLimitsFilter(user *User) error {
	for idx, limit := range user.Filters.DataTransferLimits {
		user.Filters.DataTransferLimits[idx].Sources = util.RemoveDuplicates(limit.Sources)
		if len(limit.Sources) == 0 {
			return util.NewValidationError("no data transfer limit source specified")
		}
		for _, source := range limit.Sources {
			_, _, err := net.ParseCIDR(source)
			if err != nil {
				return util.NewValidationError(fmt.Sprintf("could not parse data transfer limit source %#v: %v", source, err))
			}
		}
		if limit.TotalDataTransfer > 0 {
			user.Filters.DataTransferLimits[idx].UploadDataTransfer = 0
			user.Filters.DataTransferLimits[idx].DownloadDataTransfer = 0
		}
	}
	return nil
}

func updateFiltersValues(user *User) {
	if !user.HasExternalAuth() {
		user.Filters.ExternalAuthCacheTime = 0
	}
	if user.Filters.StartDirectory != "" {
		user.Filters.StartDirectory = util.CleanPath(user.Filters.StartDirectory)
		if user.Filters.StartDirectory == "/" {
			user.Filters.StartDirectory = ""
		}
	}
}

func validateFilterProtocols(user *User) error {
	if len(user.Filters.DeniedProtocols) >= len(ValidProtocols) {
		return util.NewValidationError("invalid denied_protocols")
	}
	for _, p := range user.Filters.DeniedProtocols {
		if !util.IsStringInSlice(p, ValidProtocols) {
			return util.NewValidationError(fmt.Sprintf("invalid denied protocol %#v", p))
		}
	}

	for _, p := range user.Filters.TwoFactorAuthProtocols {
		if !util.IsStringInSlice(p, MFAProtocols) {
			return util.NewValidationError(fmt.Sprintf("invalid two factor protocol %#v", p))
		}
	}
	return nil
}

func validateFilters(user *User) error {
	checkEmptyFiltersStruct(user)
	if err := validateIPFilters(user); err != nil {
		return err
	}
	if err := validateBandwidthLimitsFilter(user); err != nil {
		return err
	}
	if err := validateTransferLimitsFilter(user); err != nil {
		return err
	}
	if len(user.Filters.DeniedLoginMethods) >= len(ValidLoginMethods) {
		return util.NewValidationError("invalid denied_login_methods")
	}
	for _, loginMethod := range user.Filters.DeniedLoginMethods {
		if !util.IsStringInSlice(loginMethod, ValidLoginMethods) {
			return util.NewValidationError(fmt.Sprintf("invalid login method: %#v", loginMethod))
		}
	}
	if err := validateFilterProtocols(user); err != nil {
		return err
	}
	if user.Filters.TLSUsername != "" {
		if !util.IsStringInSlice(string(user.Filters.TLSUsername), validTLSUsernames) {
			return util.NewValidationError(fmt.Sprintf("invalid TLS username: %#v", user.Filters.TLSUsername))
		}
	}
	for _, opts := range user.Filters.WebClient {
		if !util.IsStringInSlice(opts, sdk.WebClientOptions) {
			return util.NewValidationError(fmt.Sprintf("invalid web client options %#v", opts))
		}
	}
	updateFiltersValues(user)

	return validateFiltersPatternExtensions(user)
}

func saveGCSCredentials(fsConfig *vfs.Filesystem, helper vfs.ValidatorHelper) error {
	if fsConfig.Provider != sdk.GCSFilesystemProvider {
		return nil
	}
	if fsConfig.GCSConfig.Credentials.GetPayload() == "" {
		return nil
	}
	if config.PreferDatabaseCredentials {
		if fsConfig.GCSConfig.Credentials.IsPlain() {
			fsConfig.GCSConfig.Credentials.SetAdditionalData(helper.GetEncryptionAdditionalData())
			err := fsConfig.GCSConfig.Credentials.Encrypt()
			if err != nil {
				return err
			}
		}
		return nil
	}
	if fsConfig.GCSConfig.Credentials.IsPlain() {
		fsConfig.GCSConfig.Credentials.SetAdditionalData(helper.GetEncryptionAdditionalData())
		err := fsConfig.GCSConfig.Credentials.Encrypt()
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt GCS credentials: %v", err))
		}
	}
	creds, err := json.Marshal(fsConfig.GCSConfig.Credentials)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("could not marshal GCS credentials: %v", err))
	}
	credentialsFilePath := helper.GetGCSCredentialsFilePath()
	err = os.MkdirAll(filepath.Dir(credentialsFilePath), 0700)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("could not create GCS credentials dir: %v", err))
	}
	err = os.WriteFile(credentialsFilePath, creds, 0600)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("could not save GCS credentials: %v", err))
	}
	fsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	return nil
}

func validateBaseParams(user *User) error {
	if user.Username == "" {
		return util.NewValidationError("username is mandatory")
	}
	if user.Email != "" && !emailRegex.MatchString(user.Email) {
		return util.NewValidationError(fmt.Sprintf("email %#v is not valid", user.Email))
	}
	if config.NamingRules&1 == 0 && !usernameRegex.MatchString(user.Username) {
		return util.NewValidationError(fmt.Sprintf("username %#v is not valid, the following characters are allowed: a-zA-Z0-9-_.~",
			user.Username))
	}
	if user.HomeDir == "" {
		return util.NewValidationError("home_dir is mandatory")
	}
	// we can have users with no passwords and public keys, they can authenticate via SSH user certs or OIDC
	/*if user.Password == "" && len(user.PublicKeys) == 0 {
		return util.NewValidationError("please set a password or at least a public_key")
	}*/
	if !filepath.IsAbs(user.HomeDir) {
		return util.NewValidationError(fmt.Sprintf("home_dir must be an absolute path, actual value: %v", user.HomeDir))
	}
	if user.DownloadBandwidth < 0 {
		user.DownloadBandwidth = 0
	}
	if user.UploadBandwidth < 0 {
		user.UploadBandwidth = 0
	}
	if user.TotalDataTransfer > 0 {
		// if a total data transfer is defined we reset the separate upload and download limits
		user.UploadDataTransfer = 0
		user.DownloadDataTransfer = 0
	}
	return nil
}

func hashPlainPassword(plainPwd string) (string, error) {
	if config.PasswordHashing.Algo == HashingAlgoBcrypt {
		pwd, err := bcrypt.GenerateFromPassword([]byte(plainPwd), config.PasswordHashing.BcryptOptions.Cost)
		if err != nil {
			return "", fmt.Errorf("bcrypt hashing error: %w", err)
		}
		return string(pwd), nil
	}
	pwd, err := argon2id.CreateHash(plainPwd, argon2Params)
	if err != nil {
		return "", fmt.Errorf("argon2ID hashing error: %w", err)
	}
	return pwd, nil
}

func createUserPasswordHash(user *User) error {
	if user.Password != "" && !user.IsPasswordHashed() {
		if config.PasswordValidation.Users.MinEntropy > 0 {
			if err := passwordvalidator.Validate(user.Password, config.PasswordValidation.Users.MinEntropy); err != nil {
				return util.NewValidationError(err.Error())
			}
		}
		hashedPwd, err := hashPlainPassword(user.Password)
		if err != nil {
			return err
		}
		user.Password = hashedPwd
	}
	return nil
}

// ValidateFolder returns an error if the folder is not valid
// FIXME: this should be defined as Folder struct method
func ValidateFolder(folder *vfs.BaseVirtualFolder) error {
	folder.FsConfig.SetEmptySecretsIfNil()
	if folder.Name == "" {
		return util.NewValidationError("folder name is mandatory")
	}
	if config.NamingRules&1 == 0 && !usernameRegex.MatchString(folder.Name) {
		return util.NewValidationError(fmt.Sprintf("folder name %#v is not valid, the following characters are allowed: a-zA-Z0-9-_.~",
			folder.Name))
	}
	if folder.FsConfig.Provider == sdk.LocalFilesystemProvider || folder.FsConfig.Provider == sdk.CryptedFilesystemProvider ||
		folder.MappedPath != "" {
		cleanedMPath := filepath.Clean(folder.MappedPath)
		if !filepath.IsAbs(cleanedMPath) {
			return util.NewValidationError(fmt.Sprintf("invalid folder mapped path %#v", folder.MappedPath))
		}
		folder.MappedPath = cleanedMPath
	}
	if folder.HasRedactedSecret() {
		return errors.New("cannot save a folder with a redacted secret")
	}
	if err := folder.FsConfig.Validate(folder); err != nil {
		return err
	}
	return saveGCSCredentials(&folder.FsConfig, folder)
}

// ValidateUser returns an error if the user is not valid
// FIXME: this should be defined as User struct method
func ValidateUser(user *User) error {
	user.SetEmptySecretsIfNil()
	buildUserHomeDir(user)
	if err := validateBaseParams(user); err != nil {
		return err
	}
	if err := validatePermissions(user); err != nil {
		return err
	}
	if user.hasRedactedSecret() {
		return util.NewValidationError("cannot save a user with a redacted secret")
	}
	if err := validateUserTOTPConfig(&user.Filters.TOTPConfig, user.Username); err != nil {
		return err
	}
	if err := validateUserRecoveryCodes(user); err != nil {
		return err
	}
	if err := user.FsConfig.Validate(user); err != nil {
		return err
	}
	if err := validateUserVirtualFolders(user); err != nil {
		return err
	}
	if user.Status < 0 || user.Status > 1 {
		return util.NewValidationError(fmt.Sprintf("invalid user status: %v", user.Status))
	}
	if err := createUserPasswordHash(user); err != nil {
		return err
	}
	if err := validatePublicKeys(user); err != nil {
		return err
	}
	if err := validateFilters(user); err != nil {
		return err
	}
	if user.Filters.TOTPConfig.Enabled && util.IsStringInSlice(sdk.WebClientMFADisabled, user.Filters.WebClient) {
		return util.NewValidationError("two-factor authentication cannot be disabled for a user with an active configuration")
	}
	return saveGCSCredentials(&user.FsConfig, user)
}

func isPasswordOK(user *User, password string) (bool, error) {
	if config.PasswordCaching {
		found, match := cachedPasswords.Check(user.Username, password)
		if found {
			return match, nil
		}
	}

	match := false
	updatePwd := true
	var err error
	if strings.HasPrefix(user.Password, bcryptPwdPrefix) {
		if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			return match, ErrInvalidCredentials
		}
		match = true
		updatePwd = config.PasswordHashing.Algo != HashingAlgoBcrypt
	} else if strings.HasPrefix(user.Password, argonPwdPrefix) {
		match, err = argon2id.ComparePasswordAndHash(password, user.Password)
		if err != nil {
			providerLog(logger.LevelError, "error comparing password with argon hash: %v", err)
			return match, err
		}
		updatePwd = config.PasswordHashing.Algo != HashingAlgoArgon2ID
	} else if util.IsStringPrefixInSlice(user.Password, pbkdfPwdPrefixes) {
		match, err = comparePbkdf2PasswordAndHash(password, user.Password)
		if err != nil {
			return match, err
		}
	} else if util.IsStringPrefixInSlice(user.Password, unixPwdPrefixes) {
		match, err = compareUnixPasswordAndHash(user, password)
		if err != nil {
			return match, err
		}
	} else if strings.HasPrefix(user.Password, md5LDAPPwdPrefix) {
		h := md5.New()
		h.Write([]byte(password))
		match = fmt.Sprintf("%s%x", md5LDAPPwdPrefix, h.Sum(nil)) == user.Password
	}
	if err == nil && match {
		cachedPasswords.Add(user.Username, password)
		if updatePwd {
			convertUserPassword(user.Username, password)
		}
	}
	return match, err
}

func convertUserPassword(username, plainPwd string) {
	hashedPwd, err := hashPlainPassword(plainPwd)
	if err == nil {
		err = provider.updateUserPassword(username, hashedPwd)
	}
	if err != nil {
		providerLog(logger.LevelWarn, "unable to convert password for user %s: %v", username, err)
	} else {
		providerLog(logger.LevelDebug, "password converted for user %s", username)
	}
}

func checkUserAndTLSCertificate(user *User, protocol string, tlsCert *x509.Certificate) (User, error) {
	err := user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	switch protocol {
	case protocolFTP, protocolWebDAV:
		if user.Filters.TLSUsername == sdk.TLSUsernameCN {
			if user.Username == tlsCert.Subject.CommonName {
				return *user, nil
			}
			return *user, fmt.Errorf("CN %#v does not match username %#v", tlsCert.Subject.CommonName, user.Username)
		}
		return *user, errors.New("TLS certificate is not valid")
	default:
		return *user, fmt.Errorf("certificate authentication is not supported for protocol %v", protocol)
	}
}

func checkUserAndPass(user *User, password, ip, protocol string) (User, error) {
	err := user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	password, err = checkUserPasscode(user, password, protocol)
	if err != nil {
		return *user, ErrInvalidCredentials
	}
	if user.Password == "" {
		return *user, errors.New("credentials cannot be null or empty")
	}
	if !user.Filters.Hooks.CheckPasswordDisabled {
		hookResponse, err := executeCheckPasswordHook(user.Username, password, ip, protocol)
		if err != nil {
			providerLog(logger.LevelDebug, "error executing check password hook for user %#v, ip %v, protocol %v: %v",
				user.Username, ip, protocol, err)
			return *user, errors.New("unable to check credentials")
		}
		switch hookResponse.Status {
		case -1:
			// no hook configured
		case 1:
			providerLog(logger.LevelDebug, "password accepted by check password hook for user %#v, ip %v, protocol %v",
				user.Username, ip, protocol)
			return *user, nil
		case 2:
			providerLog(logger.LevelDebug, "partial success from check password hook for user %#v, ip %v, protocol %v",
				user.Username, ip, protocol)
			password = hookResponse.ToVerify
		default:
			providerLog(logger.LevelDebug, "password rejected by check password hook for user %#v, ip %v, protocol %v, status: %v",
				user.Username, ip, protocol, hookResponse.Status)
			return *user, ErrInvalidCredentials
		}
	}

	match, err := isPasswordOK(user, password)
	if !match {
		err = ErrInvalidCredentials
	}
	return *user, err
}

func checkUserPasscode(user *User, password, protocol string) (string, error) {
	if user.Filters.TOTPConfig.Enabled {
		switch protocol {
		case protocolFTP:
			if util.IsStringInSlice(protocol, user.Filters.TOTPConfig.Protocols) {
				// the TOTP passcode has six digits
				pwdLen := len(password)
				if pwdLen < 7 {
					providerLog(logger.LevelDebug, "password len %v is too short to contain a passcode, user %#v, protocol %v",
						pwdLen, user.Username, protocol)
					return "", util.NewValidationError("password too short, cannot contain the passcode")
				}
				err := user.Filters.TOTPConfig.Secret.TryDecrypt()
				if err != nil {
					providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %#v, protocol %v, err: %v",
						user.Username, protocol, err)
					return "", err
				}
				pwd := password[0:(pwdLen - 6)]
				passcode := password[(pwdLen - 6):]
				match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
					user.Filters.TOTPConfig.Secret.GetPayload())
				if !match || err != nil {
					providerLog(logger.LevelWarn, "invalid passcode for user %#v, protocol %v, err: %v",
						user.Username, protocol, err)
					return "", util.NewValidationError("invalid passcode")
				}
				return pwd, nil
			}
		}
	}
	return password, nil
}

func checkUserAndPubKey(user *User, pubKey []byte, isSSHCert bool) (User, string, error) {
	err := user.CheckLoginConditions()
	if err != nil {
		return *user, "", err
	}
	if isSSHCert {
		return *user, "", nil
	}
	if len(user.PublicKeys) == 0 {
		return *user, "", ErrInvalidCredentials
	}
	for i, k := range user.PublicKeys {
		storedPubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			providerLog(logger.LevelError, "error parsing stored public key %d for user %s: %v", i, user.Username, err)
			return *user, "", err
		}
		if bytes.Equal(storedPubKey.Marshal(), pubKey) {
			return *user, fmt.Sprintf("%s:%s", ssh.FingerprintSHA256(storedPubKey), comment), nil
		}
	}
	return *user, "", ErrInvalidCredentials
}

func compareUnixPasswordAndHash(user *User, password string) (bool, error) {
	var crypter crypt.Crypter
	if strings.HasPrefix(user.Password, sha512cryptPwdPrefix) {
		crypter = sha512_crypt.New()
	} else if strings.HasPrefix(user.Password, md5cryptPwdPrefix) {
		crypter = md5_crypt.New()
	} else if strings.HasPrefix(user.Password, md5cryptApr1PwdPrefix) {
		crypter = apr1_crypt.New()
	} else {
		return false, errors.New("unix crypt: invalid or unsupported hash format")
	}
	if err := crypter.Verify(user.Password, []byte(password)); err != nil {
		return false, err
	}
	return true, nil
}

func comparePbkdf2PasswordAndHash(password, hashedPassword string) (bool, error) {
	vals := strings.Split(hashedPassword, "$")
	if len(vals) != 5 {
		return false, fmt.Errorf("pbkdf2: hash is not in the correct format")
	}
	iterations, err := strconv.Atoi(vals[2])
	if err != nil {
		return false, err
	}
	expected, err := base64.StdEncoding.DecodeString(vals[4])
	if err != nil {
		return false, err
	}
	var salt []byte
	if util.IsStringPrefixInSlice(hashedPassword, pbkdfPwdB64SaltPrefixes) {
		salt, err = base64.StdEncoding.DecodeString(vals[3])
		if err != nil {
			return false, err
		}
	} else {
		salt = []byte(vals[3])
	}
	var hashFunc func() hash.Hash
	if strings.HasPrefix(hashedPassword, pbkdf2SHA256Prefix) || strings.HasPrefix(hashedPassword, pbkdf2SHA256B64SaltPrefix) {
		hashFunc = sha256.New
	} else if strings.HasPrefix(hashedPassword, pbkdf2SHA512Prefix) {
		hashFunc = sha512.New
	} else if strings.HasPrefix(hashedPassword, pbkdf2SHA1Prefix) {
		hashFunc = sha1.New
	} else {
		return false, fmt.Errorf("pbkdf2: invalid or unsupported hash format %v", vals[1])
	}
	df := pbkdf2.Key([]byte(password), salt, iterations, len(expected), hashFunc)
	return subtle.ConstantTimeCompare(df, expected) == 1, nil
}

func addCredentialsToUser(user *User) error {
	if err := addFolderCredentialsToUser(user); err != nil {
		return err
	}
	if user.FsConfig.Provider != sdk.GCSFilesystemProvider {
		return nil
	}
	if user.FsConfig.GCSConfig.AutomaticCredentials > 0 {
		return nil
	}

	// Don't read from file if credentials have already been set
	if user.FsConfig.GCSConfig.Credentials.IsValid() {
		return nil
	}

	cred, err := os.ReadFile(user.GetGCSCredentialsFilePath())
	if err != nil {
		return err
	}
	return json.Unmarshal(cred, &user.FsConfig.GCSConfig.Credentials)
}

func addFolderCredentialsToUser(user *User) error {
	for idx := range user.VirtualFolders {
		f := &user.VirtualFolders[idx]
		if f.FsConfig.Provider != sdk.GCSFilesystemProvider {
			continue
		}
		if f.FsConfig.GCSConfig.AutomaticCredentials > 0 {
			continue
		}
		// Don't read from file if credentials have already been set
		if f.FsConfig.GCSConfig.Credentials.IsValid() {
			continue
		}
		cred, err := os.ReadFile(f.GetGCSCredentialsFilePath())
		if err != nil {
			return err
		}
		err = json.Unmarshal(cred, f.FsConfig.GCSConfig.Credentials)
		if err != nil {
			return err
		}
	}
	return nil
}

func getSSLMode() string {
	if config.Driver == PGSQLDataProviderName || config.Driver == CockroachDataProviderName {
		switch config.SSLMode {
		case 0:
			return "disable"
		case 1:
			return "require"
		case 2:
			return "verify-ca"
		case 3:
			return "verify-full"
		}
	} else if config.Driver == MySQLDataProviderName {
		if config.requireCustomTLSForMySQL() {
			return "custom"
		}
		switch config.SSLMode {
		case 0:
			return "false"
		case 1:
			return "true"
		case 2:
			return "skip-verify"
		case 3:
			return "preferred"
		}
	}
	return ""
}

func terminateInteractiveAuthProgram(cmd *exec.Cmd, isFinished bool) {
	if isFinished {
		return
	}
	providerLog(logger.LevelInfo, "kill interactive auth program after an unexpected error")
	err := cmd.Process.Kill()
	if err != nil {
		providerLog(logger.LevelDebug, "error killing interactive auth program: %v", err)
	}
}

func sendKeyboardAuthHTTPReq(url string, request *plugin.KeyboardAuthRequest) (*plugin.KeyboardAuthResponse, error) {
	reqAsJSON, err := json.Marshal(request)
	if err != nil {
		providerLog(logger.LevelError, "error serializing keyboard interactive auth request: %v", err)
		return nil, err
	}
	resp, err := httpclient.Post(url, "application/json", bytes.NewBuffer(reqAsJSON))
	if err != nil {
		providerLog(logger.LevelError, "error getting keyboard interactive auth hook HTTP response: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wrong keyboard interactive auth http status code: %v, expected 200", resp.StatusCode)
	}
	var response plugin.KeyboardAuthResponse
	err = render.DecodeJSON(resp.Body, &response)
	return &response, err
}

func doBuiltinKeyboardInteractiveAuth(user *User, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	answers, err := client("", "", []string{"Password: "}, []bool{false})
	if err != nil {
		return 0, err
	}
	if len(answers) != 1 {
		return 0, fmt.Errorf("unexpected number of answers: %v", len(answers))
	}
	_, err = checkUserAndPass(user, answers[0], ip, protocol)
	if err != nil {
		return 0, err
	}
	if !user.Filters.TOTPConfig.Enabled || !util.IsStringInSlice(protocolSSH, user.Filters.TOTPConfig.Protocols) {
		return 1, nil
	}
	err = user.Filters.TOTPConfig.Secret.TryDecrypt()
	if err != nil {
		providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %#v, protocol %v, err: %v",
			user.Username, protocol, err)
		return 0, err
	}
	answers, err = client("", "", []string{"Authentication code: "}, []bool{false})
	if err != nil {
		return 0, err
	}
	if len(answers) != 1 {
		return 0, fmt.Errorf("unexpected number of answers: %v", len(answers))
	}
	match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, answers[0],
		user.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		providerLog(logger.LevelWarn, "invalid passcode for user %#v, protocol %v, err: %v",
			user.Username, protocol, err)
		return 0, util.NewValidationError("invalid passcode")
	}
	return 1, nil
}

func executeKeyboardInteractivePlugin(user *User, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	authResult := 0
	requestID := xid.New().String()
	authStep := 1
	req := &plugin.KeyboardAuthRequest{
		Username:  user.Username,
		IP:        ip,
		Password:  user.Password,
		RequestID: requestID,
		Step:      authStep,
	}
	var response *plugin.KeyboardAuthResponse
	var err error
	for {
		response, err = plugin.Handler.ExecuteKeyboardInteractiveStep(req)
		if err != nil {
			return authResult, err
		}
		if response.AuthResult != 0 {
			return response.AuthResult, err
		}
		if err = response.Validate(); err != nil {
			providerLog(logger.LevelInfo, "invalid response from keyboard interactive plugin: %v", err)
			return authResult, err
		}
		answers, err := getKeyboardInteractiveAnswers(client, response, user, ip, protocol)
		if err != nil {
			return authResult, err
		}
		authStep++
		req = &plugin.KeyboardAuthRequest{
			RequestID: requestID,
			Step:      authStep,
			Username:  user.Username,
			Password:  user.Password,
			Answers:   answers,
			Questions: response.Questions,
		}
	}
}

func executeKeyboardInteractiveHTTPHook(user *User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	authResult := 0
	requestID := xid.New().String()
	authStep := 1
	req := &plugin.KeyboardAuthRequest{
		Username:  user.Username,
		IP:        ip,
		Password:  user.Password,
		RequestID: requestID,
		Step:      authStep,
	}
	var response *plugin.KeyboardAuthResponse
	var err error
	for {
		response, err = sendKeyboardAuthHTTPReq(authHook, req)
		if err != nil {
			return authResult, err
		}
		if response.AuthResult != 0 {
			return response.AuthResult, err
		}
		if err = response.Validate(); err != nil {
			providerLog(logger.LevelInfo, "invalid response from keyboard interactive http hook: %v", err)
			return authResult, err
		}
		answers, err := getKeyboardInteractiveAnswers(client, response, user, ip, protocol)
		if err != nil {
			return authResult, err
		}
		authStep++
		req = &plugin.KeyboardAuthRequest{
			RequestID: requestID,
			Step:      authStep,
			Username:  user.Username,
			Password:  user.Password,
			Answers:   answers,
			Questions: response.Questions,
		}
	}
}

func getKeyboardInteractiveAnswers(client ssh.KeyboardInteractiveChallenge, response *plugin.KeyboardAuthResponse,
	user *User, ip, protocol string,
) ([]string, error) {
	questions := response.Questions
	answers, err := client("", response.Instruction, questions, response.Echos)
	if err != nil {
		providerLog(logger.LevelInfo, "error getting interactive auth client response: %v", err)
		return answers, err
	}
	if len(answers) != len(questions) {
		err = fmt.Errorf("client answers does not match questions, expected: %v actual: %v", questions, answers)
		providerLog(logger.LevelInfo, "keyboard interactive auth error: %v", err)
		return answers, err
	}
	if len(answers) == 1 && response.CheckPwd > 0 {
		if response.CheckPwd == 2 {
			if !user.Filters.TOTPConfig.Enabled || !util.IsStringInSlice(protocolSSH, user.Filters.TOTPConfig.Protocols) {
				providerLog(logger.LevelInfo, "keyboard interactive auth error: unable to check TOTP passcode, TOTP is not enabled for user %#v",
					user.Username)
				return answers, errors.New("TOTP not enabled for SSH protocol")
			}
			err := user.Filters.TOTPConfig.Secret.TryDecrypt()
			if err != nil {
				providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %#v, protocol %v, err: %v",
					user.Username, protocol, err)
				return answers, fmt.Errorf("unable to decrypt TOTP secret: %w", err)
			}
			match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, answers[0],
				user.Filters.TOTPConfig.Secret.GetPayload())
			if !match || err != nil {
				providerLog(logger.LevelInfo, "keyboard interactive auth error: unable to validate passcode for user %#v, match? %v, err: %v",
					user.Username, match, err)
				return answers, errors.New("unable to validate TOTP passcode")
			}
		} else {
			_, err = checkUserAndPass(user, answers[0], ip, protocol)
			providerLog(logger.LevelInfo, "interactive auth hook requested password validation for user %#v, validation error: %v",
				user.Username, err)
			if err != nil {
				return answers, err
			}
		}
		answers[0] = "OK"
	}
	return answers, err
}

func handleProgramInteractiveQuestions(client ssh.KeyboardInteractiveChallenge, response *plugin.KeyboardAuthResponse,
	user *User, stdin io.WriteCloser, ip, protocol string,
) error {
	answers, err := getKeyboardInteractiveAnswers(client, response, user, ip, protocol)
	if err != nil {
		return err
	}
	for _, answer := range answers {
		if runtime.GOOS == "windows" {
			answer += "\r"
		}
		answer += "\n"
		_, err = stdin.Write([]byte(answer))
		if err != nil {
			providerLog(logger.LevelError, "unable to write client answer to keyboard interactive program: %v", err)
			return err
		}
	}
	return nil
}

func executeKeyboardInteractiveProgram(user *User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	authResult := 0
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, authHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_AUTHD_USERNAME=%v", user.Username),
		fmt.Sprintf("SFTPGO_AUTHD_IP=%v", ip),
		fmt.Sprintf("SFTPGO_AUTHD_PASSWORD=%v", user.Password))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return authResult, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return authResult, err
	}
	err = cmd.Start()
	if err != nil {
		return authResult, err
	}
	var once sync.Once
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var response plugin.KeyboardAuthResponse
		err = json.Unmarshal(scanner.Bytes(), &response)
		if err != nil {
			providerLog(logger.LevelInfo, "interactive auth error parsing response: %v", err)
			once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
			break
		}
		if response.AuthResult != 0 {
			authResult = response.AuthResult
			break
		}
		if err = response.Validate(); err != nil {
			providerLog(logger.LevelInfo, "invalid response from keyboard interactive program: %v", err)
			once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
			break
		}
		go func() {
			err := handleProgramInteractiveQuestions(client, &response, user, stdin, ip, protocol)
			if err != nil {
				once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
			}
		}()
	}
	stdin.Close()
	once.Do(func() { terminateInteractiveAuthProgram(cmd, true) })
	go func() {
		_, err := cmd.Process.Wait()
		if err != nil {
			providerLog(logger.LevelWarn, "error waiting for #%v process to exit: %v", authHook, err)
		}
	}()

	return authResult, err
}

func doKeyboardInteractiveAuth(user *User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (User, error) {
	var authResult int
	var err error
	if plugin.Handler.HasAuthScope(plugin.AuthScopeKeyboardInteractive) {
		authResult, err = executeKeyboardInteractivePlugin(user, client, ip, protocol)
	} else if authHook != "" {
		if strings.HasPrefix(authHook, "http") {
			authResult, err = executeKeyboardInteractiveHTTPHook(user, authHook, client, ip, protocol)
		} else {
			authResult, err = executeKeyboardInteractiveProgram(user, authHook, client, ip, protocol)
		}
	} else {
		authResult, err = doBuiltinKeyboardInteractiveAuth(user, client, ip, protocol)
	}
	if err != nil {
		return *user, err
	}
	if authResult != 1 {
		return *user, fmt.Errorf("keyboard interactive auth failed, result: %v", authResult)
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	return *user, nil
}

func isCheckPasswordHookDefined(protocol string) bool {
	if config.CheckPasswordHook == "" {
		return false
	}
	if config.CheckPasswordScope == 0 {
		return true
	}
	switch protocol {
	case protocolSSH:
		return config.CheckPasswordScope&1 != 0
	case protocolFTP:
		return config.CheckPasswordScope&2 != 0
	case protocolWebDAV:
		return config.CheckPasswordScope&4 != 0
	default:
		return false
	}
}

func getPasswordHookResponse(username, password, ip, protocol string) ([]byte, error) {
	if strings.HasPrefix(config.CheckPasswordHook, "http") {
		var result []byte
		req := checkPasswordRequest{
			Username: username,
			Password: password,
			IP:       ip,
			Protocol: protocol,
		}
		reqAsJSON, err := json.Marshal(req)
		if err != nil {
			return result, err
		}
		resp, err := httpclient.Post(config.CheckPasswordHook, "application/json", bytes.NewBuffer(reqAsJSON))
		if err != nil {
			providerLog(logger.LevelError, "error getting check password hook response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong http status code from chek password hook: %v, expected 200", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxHookResponseSize))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, config.CheckPasswordHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_AUTHD_USERNAME=%v", username),
		fmt.Sprintf("SFTPGO_AUTHD_PASSWORD=%v", password),
		fmt.Sprintf("SFTPGO_AUTHD_IP=%v", ip),
		fmt.Sprintf("SFTPGO_AUTHD_PROTOCOL=%v", protocol),
	)
	return cmd.Output()
}

func executeCheckPasswordHook(username, password, ip, protocol string) (checkPasswordResponse, error) {
	var response checkPasswordResponse

	if !isCheckPasswordHookDefined(protocol) {
		response.Status = -1
		return response, nil
	}

	startTime := time.Now()
	out, err := getPasswordHookResponse(username, password, ip, protocol)
	providerLog(logger.LevelDebug, "check password hook executed, error: %v, elapsed: %v", err, time.Since(startTime))
	if err != nil {
		return response, err
	}
	err = json.Unmarshal(out, &response)
	return response, err
}

func getPreLoginHookResponse(loginMethod, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	if strings.HasPrefix(config.PreLoginHook, "http") {
		var url *url.URL
		var result []byte
		url, err := url.Parse(config.PreLoginHook)
		if err != nil {
			providerLog(logger.LevelError, "invalid url for pre-login hook %#v, error: %v", config.PreLoginHook, err)
			return result, err
		}
		q := url.Query()
		q.Add("login_method", loginMethod)
		q.Add("ip", ip)
		q.Add("protocol", protocol)
		url.RawQuery = q.Encode()

		resp, err := httpclient.Post(url.String(), "application/json", bytes.NewBuffer(userAsJSON))
		if err != nil {
			providerLog(logger.LevelWarn, "error getting pre-login hook response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			return result, nil
		}
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong pre-login hook http status code: %v, expected 200", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxHookResponseSize))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, config.PreLoginHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_LOGIND_USER=%v", string(userAsJSON)),
		fmt.Sprintf("SFTPGO_LOGIND_METHOD=%v", loginMethod),
		fmt.Sprintf("SFTPGO_LOGIND_IP=%v", ip),
		fmt.Sprintf("SFTPGO_LOGIND_PROTOCOL=%v", protocol),
	)
	return cmd.Output()
}

func executePreLoginHook(username, loginMethod, ip, protocol string) (User, error) {
	u, userAsJSON, err := getUserAndJSONForHook(username)
	if err != nil {
		return u, err
	}
	if u.Filters.Hooks.PreLoginDisabled {
		return u, nil
	}
	startTime := time.Now()
	out, err := getPreLoginHookResponse(loginMethod, ip, protocol, userAsJSON)
	if err != nil {
		return u, fmt.Errorf("pre-login hook error: %v, username %#v, ip %v, protocol %v elapsed %v",
			err, username, ip, protocol, time.Since(startTime))
	}
	providerLog(logger.LevelDebug, "pre-login hook completed, elapsed: %v", time.Since(startTime))
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from pre-login hook, no modification requested for user %#v id: %v",
			username, u.ID)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
		}
		return u, nil
	}

	userID := u.ID
	userPwd := u.Password
	userUsedQuotaSize := u.UsedQuotaSize
	userUsedQuotaFiles := u.UsedQuotaFiles
	userUsedDownloadTransfer := u.UsedDownloadDataTransfer
	userUsedUploadTransfer := u.UsedUploadDataTransfer
	userLastQuotaUpdate := u.LastQuotaUpdate
	userLastLogin := u.LastLogin
	userCreatedAt := u.CreatedAt
	totpConfig := u.Filters.TOTPConfig
	recoveryCodes := u.Filters.RecoveryCodes
	err = json.Unmarshal(out, &u)
	if err != nil {
		return u, fmt.Errorf("invalid pre-login hook response %#v, error: %v", string(out), err)
	}
	u.ID = userID
	u.UsedQuotaSize = userUsedQuotaSize
	u.UsedQuotaFiles = userUsedQuotaFiles
	u.UsedUploadDataTransfer = userUsedUploadTransfer
	u.UsedDownloadDataTransfer = userUsedDownloadTransfer
	u.LastQuotaUpdate = userLastQuotaUpdate
	u.LastLogin = userLastLogin
	u.CreatedAt = userCreatedAt
	if userID == 0 {
		err = provider.addUser(&u)
	} else {
		u.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		// preserve TOTP config and recovery codes
		u.Filters.TOTPConfig = totpConfig
		u.Filters.RecoveryCodes = recoveryCodes
		err = provider.updateUser(&u)
		if err == nil {
			webDAVUsersCache.swap(&u)
			if u.Password != userPwd {
				cachedPasswords.Remove(username)
			}
		}
	}
	if err != nil {
		return u, err
	}
	providerLog(logger.LevelDebug, "user %#v added/updated from pre-login hook response, id: %v", username, userID)
	if userID == 0 {
		return provider.userExists(username)
	}
	return u, nil
}

// ExecutePostLoginHook executes the post login hook if defined
func ExecutePostLoginHook(user *User, loginMethod, ip, protocol string, err error) {
	if config.PostLoginHook == "" {
		return
	}
	if config.PostLoginScope == 1 && err == nil {
		return
	}
	if config.PostLoginScope == 2 && err != nil {
		return
	}

	go func() {
		status := "0"
		if err == nil {
			status = "1"
		}

		user.PrepareForRendering()
		userAsJSON, err := json.Marshal(user)
		if err != nil {
			providerLog(logger.LevelError, "error serializing user in post login hook: %v", err)
			return
		}
		if strings.HasPrefix(config.PostLoginHook, "http") {
			var url *url.URL
			url, err := url.Parse(config.PostLoginHook)
			if err != nil {
				providerLog(logger.LevelDebug, "Invalid post-login hook %#v", config.PostLoginHook)
				return
			}
			q := url.Query()
			q.Add("login_method", loginMethod)
			q.Add("ip", ip)
			q.Add("protocol", protocol)
			q.Add("status", status)
			url.RawQuery = q.Encode()

			startTime := time.Now()
			respCode := 0
			resp, err := httpclient.RetryablePost(url.String(), "application/json", bytes.NewBuffer(userAsJSON))
			if err == nil {
				respCode = resp.StatusCode
				resp.Body.Close()
			}
			providerLog(logger.LevelDebug, "post login hook executed for user %#v, ip %v, protocol %v, response code: %v, elapsed: %v err: %v",
				user.Username, ip, protocol, respCode, time.Since(startTime), err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, config.PostLoginHook)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("SFTPGO_LOGIND_USER=%v", string(userAsJSON)),
			fmt.Sprintf("SFTPGO_LOGIND_IP=%v", ip),
			fmt.Sprintf("SFTPGO_LOGIND_METHOD=%v", loginMethod),
			fmt.Sprintf("SFTPGO_LOGIND_STATUS=%v", status),
			fmt.Sprintf("SFTPGO_LOGIND_PROTOCOL=%v", protocol))
		startTime := time.Now()
		err = cmd.Run()
		providerLog(logger.LevelDebug, "post login hook executed for user %#v, ip %v, protocol %v, elapsed %v err: %v",
			user.Username, ip, protocol, time.Since(startTime), err)
	}()
}

func getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol string, cert *x509.Certificate, userAsJSON []byte) ([]byte, error) {
	var tlsCert string
	if cert != nil {
		var err error
		tlsCert, err = util.EncodeTLSCertToPem(cert)
		if err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(config.ExternalAuthHook, "http") {
		var result []byte
		authRequest := make(map[string]string)
		authRequest["username"] = username
		authRequest["ip"] = ip
		authRequest["password"] = password
		authRequest["public_key"] = pkey
		authRequest["protocol"] = protocol
		authRequest["keyboard_interactive"] = keyboardInteractive
		authRequest["tls_cert"] = tlsCert
		if len(userAsJSON) > 0 {
			authRequest["user"] = string(userAsJSON)
		}
		authRequestAsJSON, err := json.Marshal(authRequest)
		if err != nil {
			providerLog(logger.LevelError, "error serializing external auth request: %v", err)
			return result, err
		}
		resp, err := httpclient.Post(config.ExternalAuthHook, "application/json", bytes.NewBuffer(authRequestAsJSON))
		if err != nil {
			providerLog(logger.LevelWarn, "error getting external auth hook HTTP response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		providerLog(logger.LevelDebug, "external auth hook executed, response code: %v", resp.StatusCode)
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong external auth http status code: %v, expected 200", resp.StatusCode)
		}

		return io.ReadAll(io.LimitReader(resp.Body, maxHookResponseSize))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, config.ExternalAuthHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_AUTHD_USERNAME=%v", username),
		fmt.Sprintf("SFTPGO_AUTHD_USER=%v", string(userAsJSON)),
		fmt.Sprintf("SFTPGO_AUTHD_IP=%v", ip),
		fmt.Sprintf("SFTPGO_AUTHD_PASSWORD=%v", password),
		fmt.Sprintf("SFTPGO_AUTHD_PUBLIC_KEY=%v", pkey),
		fmt.Sprintf("SFTPGO_AUTHD_PROTOCOL=%v", protocol),
		fmt.Sprintf("SFTPGO_AUTHD_TLS_CERT=%v", strings.ReplaceAll(tlsCert, "\n", "\\n")),
		fmt.Sprintf("SFTPGO_AUTHD_KEYBOARD_INTERACTIVE=%v", keyboardInteractive))
	return cmd.Output()
}

func updateUserFromExtAuthResponse(user *User, password, pkey string) {
	if password != "" {
		user.Password = password
	}
	if pkey != "" && !util.IsStringPrefixInSlice(pkey, user.PublicKeys) {
		user.PublicKeys = append(user.PublicKeys, pkey)
	}
}

func doExternalAuth(username, password string, pubKey []byte, keyboardInteractive, ip, protocol string,
	tlsCert *x509.Certificate,
) (User, error) {
	var user User

	u, userAsJSON, err := getUserAndJSONForHook(username)
	if err != nil {
		return user, err
	}

	if u.Filters.Hooks.ExternalAuthDisabled {
		return u, nil
	}

	if u.isExternalAuthCached() {
		return u, nil
	}

	pkey, err := util.GetSSHPublicKeyAsString(pubKey)
	if err != nil {
		return user, err
	}

	startTime := time.Now()
	out, err := getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol, tlsCert, userAsJSON)
	if err != nil {
		return user, fmt.Errorf("external auth error for user %#v: %v, elapsed: %v", username, err, time.Since(startTime))
	}
	providerLog(logger.LevelDebug, "external auth completed for user %#v, elapsed: %v", username, time.Since(startTime))
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from external hook, no modification requested for user %#v id: %v",
			username, u.ID)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
		}
		return u, nil
	}
	err = json.Unmarshal(out, &user)
	if err != nil {
		return user, fmt.Errorf("invalid external auth response: %v", err)
	}
	// an empty username means authentication failure
	if user.Username == "" {
		return user, ErrInvalidCredentials
	}
	updateUserFromExtAuthResponse(&user, password, pkey)
	// some users want to map multiple login usernames with a single SFTPGo account
	// for example an SFTP user logins using "user1" or "user2" and the external auth
	// returns "user" in both cases, so we use the username returned from
	// external auth and not the one used to login
	if user.Username != username {
		u, err = provider.userExists(user.Username)
	}
	if u.ID > 0 && err == nil {
		user.ID = u.ID
		user.UsedQuotaSize = u.UsedQuotaSize
		user.UsedQuotaFiles = u.UsedQuotaFiles
		user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
		user.LastQuotaUpdate = u.LastQuotaUpdate
		user.LastLogin = u.LastLogin
		user.CreatedAt = u.CreatedAt
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		// preserve TOTP config and recovery codes
		user.Filters.TOTPConfig = u.Filters.TOTPConfig
		user.Filters.RecoveryCodes = u.Filters.RecoveryCodes
		err = provider.updateUser(&user)
		if err == nil {
			webDAVUsersCache.swap(&user)
			cachedPasswords.Add(user.Username, password)
		}
		return user, err
	}
	err = provider.addUser(&user)
	if err != nil {
		return user, err
	}
	return provider.userExists(user.Username)
}

func doPluginAuth(username, password string, pubKey []byte, ip, protocol string,
	tlsCert *x509.Certificate, authScope int,
) (User, error) {
	var user User

	u, userAsJSON, err := getUserAndJSONForHook(username)
	if err != nil {
		return user, err
	}

	if u.Filters.Hooks.ExternalAuthDisabled {
		return u, nil
	}

	if u.isExternalAuthCached() {
		return u, nil
	}

	pkey, err := util.GetSSHPublicKeyAsString(pubKey)
	if err != nil {
		return user, err
	}

	startTime := time.Now()

	out, err := plugin.Handler.Authenticate(username, password, ip, protocol, pkey, tlsCert, authScope, userAsJSON)
	if err != nil {
		return user, fmt.Errorf("plugin auth error for user %#v: %v, elapsed: %v, auth scope: %v",
			username, err, time.Since(startTime), authScope)
	}
	providerLog(logger.LevelDebug, "plugin auth completed for user %#v, elapsed: %v,auth scope: %v",
		username, time.Since(startTime), authScope)
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from plugin auth, no modification requested for user %#v id: %v",
			username, u.ID)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
		}
		return u, nil
	}
	err = json.Unmarshal(out, &user)
	if err != nil {
		return user, fmt.Errorf("invalid plugin auth response: %v", err)
	}
	updateUserFromExtAuthResponse(&user, password, pkey)
	if u.ID > 0 {
		user.ID = u.ID
		user.UsedQuotaSize = u.UsedQuotaSize
		user.UsedQuotaFiles = u.UsedQuotaFiles
		user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
		user.LastQuotaUpdate = u.LastQuotaUpdate
		user.LastLogin = u.LastLogin
		// preserve TOTP config and recovery codes
		user.Filters.TOTPConfig = u.Filters.TOTPConfig
		user.Filters.RecoveryCodes = u.Filters.RecoveryCodes
		err = provider.updateUser(&user)
		if err == nil {
			webDAVUsersCache.swap(&user)
			cachedPasswords.Add(user.Username, password)
		}
		return user, err
	}
	err = provider.addUser(&user)
	if err != nil {
		return user, err
	}
	return provider.userExists(user.Username)
}

func getUserAndJSONForHook(username string) (User, []byte, error) {
	var userAsJSON []byte
	u, err := provider.userExists(username)
	if err != nil {
		if _, ok := err.(*util.RecordNotFoundError); !ok {
			return u, userAsJSON, err
		}
		u = User{
			BaseUser: sdk.BaseUser{
				ID:       0,
				Username: username,
			},
		}
	}
	userAsJSON, err = json.Marshal(u)
	if err != nil {
		return u, userAsJSON, err
	}
	return u, userAsJSON, err
}

func isLastActivityRecent(lastActivity int64, minDelay time.Duration) bool {
	lastActivityTime := util.GetTimeFromMsecSinceEpoch(lastActivity)
	diff := -time.Until(lastActivityTime)
	if diff < -10*time.Second {
		return false
	}
	return diff < minDelay
}

func getConfigPath(name, configDir string) string {
	if !util.IsFileInputValid(name) {
		return ""
	}
	if name != "" && !filepath.IsAbs(name) {
		return filepath.Join(configDir, name)
	}
	return name
}

func providerLog(level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, logSender, "", format, v...)
}
