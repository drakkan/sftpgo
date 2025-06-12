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

// Package dataprovider provides data access.
// It abstracts different data providers using a common API.
package dataprovider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/alexedwards/argon2id"
	"github.com/go-chi/render"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/command"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
	DumpVersion = 17

	argonPwdPrefix            = "$argon2id$"
	bcryptPwdPrefix           = "$2a$"
	pbkdf2SHA1Prefix          = "$pbkdf2-sha1$"
	pbkdf2SHA256Prefix        = "$pbkdf2-sha256$"
	pbkdf2SHA512Prefix        = "$pbkdf2-sha512$"
	pbkdf2SHA256B64SaltPrefix = "$pbkdf2-b64salt-sha256$"
	md5cryptPwdPrefix         = "$1$"
	md5cryptApr1PwdPrefix     = "$apr1$"
	sha256cryptPwdPrefix      = "$5$"
	sha512cryptPwdPrefix      = "$6$"
	yescryptPwdPrefix         = "$y$"
	md5DigestPwdPrefix        = "{MD5}"
	sha256DigestPwdPrefix     = "{SHA256}"
	sha512DigestPwdPrefix     = "{SHA512}"
	trackQuotaDisabledError   = "please enable track_quota in your configuration to use this method"
	operationAdd              = "add"
	operationUpdate           = "update"
	operationDelete           = "delete"
	sqlPrefixValidChars       = "abcdefghijklmnopqrstuvwxyz_0123456789"
	maxHookResponseSize       = 1048576 // 1MB
	iso8601UTCFormat          = "2006-01-02T15:04:05Z"
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

// Dump scopes
const (
	DumpScopeUsers   = "users"
	DumpScopeFolders = "folders"
	DumpScopeGroups  = "groups"
	DumpScopeAdmins  = "admins"
	DumpScopeAPIKeys = "api_keys"
	DumpScopeShares  = "shares"
	DumpScopeActions = "actions"
	DumpScopeRules   = "rules"
	DumpScopeRoles   = "roles"
	DumpScopeIPLists = "ip_lists"
	DumpScopeConfigs = "configs"
)

const (
	fieldUsername = 1
	fieldName     = 2
	fieldIPNet    = 3
)

var (
	// SupportedProviders defines the supported data providers
	SupportedProviders = []string{SQLiteDataProviderName, PGSQLDataProviderName, MySQLDataProviderName,
		BoltDataProviderName, MemoryDataProviderName, CockroachDataProviderName}
	// ValidPerms defines all the valid permissions for a user
	ValidPerms = []string{PermAny, PermListItems, PermDownload, PermUpload, PermOverwrite, PermCreateDirs, PermRename,
		PermRenameFiles, PermRenameDirs, PermDelete, PermDeleteFiles, PermDeleteDirs, PermCopy, PermCreateSymlinks,
		PermChmod, PermChown, PermChtimes}
	// ValidLoginMethods defines all the valid login methods
	ValidLoginMethods = []string{SSHLoginMethodPublicKey, LoginMethodPassword, SSHLoginMethodPassword,
		SSHLoginMethodKeyboardInteractive, SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt,
		LoginMethodTLSCertificate, LoginMethodTLSCertificateAndPwd}
	// SSHMultiStepsLoginMethods defines the supported Multi-Step Authentications
	SSHMultiStepsLoginMethods = []string{SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt}
	// ErrNoAuthTried defines the error for connection closed before authentication
	ErrNoAuthTried = errors.New("no auth tried")
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
	// ErrDuplicatedKey occurs when there is a unique key constraint violation
	ErrDuplicatedKey = errors.New("duplicated key not allowed")
	// ErrForeignKeyViolated occurs when there is a foreign key constraint violation
	ErrForeignKeyViolated   = errors.New("violates foreign key constraint")
	tz                      = ""
	isAdminCreated          atomic.Bool
	validTLSUsernames       = []string{string(sdk.TLSUsernameNone), string(sdk.TLSUsernameCN)}
	config                  Config
	provider                Provider
	sqlPlaceholders         []string
	internalHashPwdPrefixes = []string{argonPwdPrefix, bcryptPwdPrefix}
	hashPwdPrefixes         = []string{argonPwdPrefix, bcryptPwdPrefix, pbkdf2SHA1Prefix, pbkdf2SHA256Prefix,
		pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix, md5cryptPwdPrefix, md5cryptApr1PwdPrefix, md5DigestPwdPrefix,
		sha256DigestPwdPrefix, sha512DigestPwdPrefix, sha256cryptPwdPrefix, sha512cryptPwdPrefix, yescryptPwdPrefix}
	pbkdfPwdPrefixes        = []string{pbkdf2SHA1Prefix, pbkdf2SHA256Prefix, pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix}
	pbkdfPwdB64SaltPrefixes = []string{pbkdf2SHA256B64SaltPrefix}
	unixPwdPrefixes         = []string{md5cryptPwdPrefix, md5cryptApr1PwdPrefix, sha256cryptPwdPrefix, sha512cryptPwdPrefix,
		yescryptPwdPrefix}
	digestPwdPrefixes            = []string{md5DigestPwdPrefix, sha256DigestPwdPrefix, sha512DigestPwdPrefix}
	sharedProviders              = []string{PGSQLDataProviderName, MySQLDataProviderName, CockroachDataProviderName}
	logSender                    = "dataprovider"
	sqlTableUsers                string
	sqlTableFolders              string
	sqlTableUsersFoldersMapping  string
	sqlTableAdmins               string
	sqlTableAPIKeys              string
	sqlTableShares               string
	sqlTableDefenderHosts        string
	sqlTableDefenderEvents       string
	sqlTableActiveTransfers      string
	sqlTableGroups               string
	sqlTableUsersGroupsMapping   string
	sqlTableAdminsGroupsMapping  string
	sqlTableGroupsFoldersMapping string
	sqlTableSharedSessions       string
	sqlTableEventsActions        string
	sqlTableEventsRules          string
	sqlTableRulesActionsMapping  string
	sqlTableTasks                string
	sqlTableNodes                string
	sqlTableRoles                string
	sqlTableIPLists              string
	sqlTableConfigs              string
	sqlTableSchemaVersion        string
	argon2Params                 *argon2id.Params
	lastLoginMinDelay            = 10 * time.Minute
	usernameRegex                = regexp.MustCompile("^[a-zA-Z0-9-_.~]+$")
	tempPath                     string
	allowSelfConnections         int
	fnReloadRules                FnReloadRules
	fnRemoveRule                 FnRemoveRule
	fnHandleRuleForProviderEvent FnHandleRuleForProviderEvent
)

func initSQLTables() {
	sqlTableUsers = "users"
	sqlTableFolders = "folders"
	sqlTableUsersFoldersMapping = "users_folders_mapping"
	sqlTableAdmins = "admins"
	sqlTableAPIKeys = "api_keys"
	sqlTableShares = "shares"
	sqlTableDefenderHosts = "defender_hosts"
	sqlTableDefenderEvents = "defender_events"
	sqlTableActiveTransfers = "active_transfers"
	sqlTableGroups = "groups"
	sqlTableUsersGroupsMapping = "users_groups_mapping"
	sqlTableGroupsFoldersMapping = "groups_folders_mapping"
	sqlTableAdminsGroupsMapping = "admins_groups_mapping"
	sqlTableSharedSessions = "shared_sessions"
	sqlTableEventsActions = "events_actions"
	sqlTableEventsRules = "events_rules"
	sqlTableRulesActionsMapping = "rules_actions_mapping"
	sqlTableTasks = "tasks"
	sqlTableNodes = "nodes"
	sqlTableRoles = "roles"
	sqlTableIPLists = "ip_lists"
	sqlTableConfigs = "configurations"
	sqlTableSchemaVersion = "schema_version"
}

// FnReloadRules defined the callback to reload event rules
type FnReloadRules func()

// FnRemoveRule defines the callback to remove an event rule
type FnRemoveRule func(name string)

// FnHandleRuleForProviderEvent define the callback to handle event rules for provider events
type FnHandleRuleForProviderEvent func(operation, executor, ip, objectType, objectName, role string, object plugin.Renderer)

// SetEventRulesCallbacks sets the event rules callbacks
func SetEventRulesCallbacks(reload FnReloadRules, remove FnRemoveRule, handle FnHandleRuleForProviderEvent) {
	fnReloadRules = reload
	fnRemoveRule = remove
	fnHandleRuleForProviderEvent = handle
}

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

type wrappedFolder struct {
	Folder vfs.BaseVirtualFolder
}

func (w *wrappedFolder) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		folder, err := provider.getFolderByName(w.Folder.Name)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload folder before rendering as json: %v", err)
			return nil, err
		}
		folder.PrepareForRendering()
		return json.Marshal(folder)
	}
	w.Folder.PrepareForRendering()
	return json.Marshal(w.Folder)
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

// Config defines the provider configuration
type Config struct {
	// Driver name, must be one of the SupportedProviders
	Driver string `json:"driver" mapstructure:"driver"`
	// Database name. For driver sqlite this can be the database name relative to the config dir
	// or the absolute path to the SQLite database.
	Name string `json:"name" mapstructure:"name"`
	// Database host. For postgresql and cockroachdb driver you can specify multiple hosts separated by commas
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
	// Used for drivers mysql, postgresql and cockroachdb. Set to true to disable SNI
	DisableSNI bool `json:"disable_sni" mapstructure:"disable_sni"`
	// TargetSessionAttrs is a postgresql and cockroachdb specific option.
	// It determines whether the session must have certain properties to be acceptable.
	// It's typically used in combination with multiple host names to select the first
	// acceptable alternative among several hosts
	TargetSessionAttrs string `json:"target_session_attrs" mapstructure:"target_session_attrs"`
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
	// Node defines the configuration for this cluster node.
	// Ignored if the provider is not shared/shareable
	Node NodeConfig `json:"node" mapstructure:"node"`
	// Path to the backup directory. This can be an absolute path or a path relative to the config dir
	BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
}

// GetShared returns the provider share mode.
// This method is called before the provider is initialized
func (c *Config) GetShared() int {
	if !slices.Contains(sharedProviders, c.Driver) {
		return 0
	}
	return c.IsShared
}

func (c *Config) convertName(name string) string {
	if c.NamingRules <= 1 {
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
	if config.DisableSNI {
		return config.SSLMode != 0
	}
	if config.RootCert != "" && util.IsFileInputValid(config.RootCert) {
		return config.SSLMode != 0
	}
	if config.ClientCert != "" && config.ClientKey != "" && util.IsFileInputValid(config.ClientCert) &&
		util.IsFileInputValid(config.ClientKey) {
		return config.SSLMode != 0
	}
	return false
}

func (c *Config) doBackup() (string, error) {
	now := time.Now().UTC()
	outputFile := filepath.Join(c.BackupsPath, fmt.Sprintf("backup_%s_%d.json", now.Weekday(), now.Hour()))
	providerLog(logger.LevelDebug, "starting backup to file %q", outputFile)
	err := os.MkdirAll(filepath.Dir(outputFile), 0700)
	if err != nil {
		providerLog(logger.LevelError, "unable to create backup dir %q: %v", outputFile, err)
		return outputFile, fmt.Errorf("unable to create backup dir: %w", err)
	}
	backup, err := DumpData(nil)
	if err != nil {
		providerLog(logger.LevelError, "unable to execute backup: %v", err)
		return outputFile, fmt.Errorf("unable to dump backup data: %w", err)
	}
	dump, err := json.Marshal(backup)
	if err != nil {
		providerLog(logger.LevelError, "unable to marshal backup as JSON: %v", err)
		return outputFile, fmt.Errorf("unable to marshal backup data as JSON: %w", err)
	}
	err = os.WriteFile(outputFile, dump, 0600)
	if err != nil {
		providerLog(logger.LevelError, "unable to save backup: %v", err)
		return outputFile, fmt.Errorf("unable to save backup: %w", err)
	}
	providerLog(logger.LevelDebug, "backup saved to %q", outputFile)
	return outputFile, nil
}

// SetTZ sets the configured timezone.
func SetTZ(val string) {
	tz = val
}

// UseLocalTime returns true if local time should be used instead of UTC.
func UseLocalTime() bool {
	return tz == "local"
}

// ExecuteBackup executes a backup
func ExecuteBackup() (string, error) {
	return config.doBackup()
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
	Users        []User                  `json:"users"`
	Groups       []Group                 `json:"groups"`
	Folders      []vfs.BaseVirtualFolder `json:"folders"`
	Admins       []Admin                 `json:"admins"`
	APIKeys      []APIKey                `json:"api_keys"`
	Shares       []Share                 `json:"shares"`
	EventActions []BaseEventAction       `json:"event_actions"`
	EventRules   []EventRule             `json:"event_rules"`
	Roles        []Role                  `json:"roles"`
	IPLists      []IPListEntry           `json:"ip_lists"`
	Configs      *Configs                `json:"configs"`
	Version      int                     `json:"version"`
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
	userExists(username, role string) (User, error)
	addUser(user *User) error
	updateUser(user *User) error
	deleteUser(user User, softDelete bool) error
	updateUserPassword(username, password string) error // used internally when converting passwords from other hash
	getUsers(limit int, offset int, order, role string) ([]User, error)
	dumpUsers() ([]User, error)
	getRecentlyUpdatedUsers(after int64) ([]User, error)
	getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error)
	updateLastLogin(username string) error
	updateAdminLastLogin(username string) error
	setUpdatedAt(username string)
	getAdminSignature(username string) (string, error)
	getUserSignature(username string) (string, error)
	getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error)
	getFolderByName(name string) (vfs.BaseVirtualFolder, error)
	addFolder(folder *vfs.BaseVirtualFolder) error
	updateFolder(folder *vfs.BaseVirtualFolder) error
	deleteFolder(folder vfs.BaseVirtualFolder) error
	updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error
	getUsedFolderQuota(name string) (int, int64, error)
	dumpFolders() ([]vfs.BaseVirtualFolder, error)
	getGroups(limit, offset int, order string, minimal bool) ([]Group, error)
	getGroupsWithNames(names []string) ([]Group, error)
	getUsersInGroups(names []string) ([]string, error)
	groupExists(name string) (Group, error)
	addGroup(group *Group) error
	updateGroup(group *Group) error
	deleteGroup(group Group) error
	dumpGroups() ([]Group, error)
	adminExists(username string) (Admin, error)
	addAdmin(admin *Admin) error
	updateAdmin(admin *Admin) error
	deleteAdmin(admin Admin) error
	getAdmins(limit int, offset int, order string) ([]Admin, error)
	dumpAdmins() ([]Admin, error)
	validateAdminAndPass(username, password, ip string) (Admin, error)
	apiKeyExists(keyID string) (APIKey, error)
	addAPIKey(apiKey *APIKey) error
	updateAPIKey(apiKey *APIKey) error
	deleteAPIKey(apiKey APIKey) error
	getAPIKeys(limit int, offset int, order string) ([]APIKey, error)
	dumpAPIKeys() ([]APIKey, error)
	updateAPIKeyLastUse(keyID string) error
	shareExists(shareID, username string) (Share, error)
	addShare(share *Share) error
	updateShare(share *Share) error
	deleteShare(share Share) error
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
	addSharedSession(session Session) error
	deleteSharedSession(key string, sessionType SessionType) error
	getSharedSession(key string, sessionType SessionType) (Session, error)
	cleanupSharedSessions(sessionType SessionType, before int64) error
	getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error)
	dumpEventActions() ([]BaseEventAction, error)
	eventActionExists(name string) (BaseEventAction, error)
	addEventAction(action *BaseEventAction) error
	updateEventAction(action *BaseEventAction) error
	deleteEventAction(action BaseEventAction) error
	getEventRules(limit, offset int, order string) ([]EventRule, error)
	dumpEventRules() ([]EventRule, error)
	getRecentlyUpdatedRules(after int64) ([]EventRule, error)
	eventRuleExists(name string) (EventRule, error)
	addEventRule(rule *EventRule) error
	updateEventRule(rule *EventRule) error
	deleteEventRule(rule EventRule, softDelete bool) error
	getTaskByName(name string) (Task, error)
	addTask(name string) error
	updateTask(name string, version int64) error
	updateTaskTimestamp(name string) error
	setFirstDownloadTimestamp(username string) error
	setFirstUploadTimestamp(username string) error
	addNode() error
	getNodeByName(name string) (Node, error)
	getNodes() ([]Node, error)
	updateNodeTimestamp() error
	cleanupNodes() error
	roleExists(name string) (Role, error)
	addRole(role *Role) error
	updateRole(role *Role) error
	deleteRole(role Role) error
	getRoles(limit int, offset int, order string, minimal bool) ([]Role, error)
	dumpRoles() ([]Role, error)
	ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error)
	addIPListEntry(entry *IPListEntry) error
	updateIPListEntry(entry *IPListEntry) error
	deleteIPListEntry(entry IPListEntry, softDelete bool) error
	getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error)
	getRecentlyUpdatedIPListEntries(after int64) ([]IPListEntry, error)
	dumpIPListEntries() ([]IPListEntry, error)
	countIPListEntries(listType IPListType) (int64, error)
	getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error)
	getConfigs() (Configs, error)
	setConfigs(configs *Configs) error
	checkAvailability() error
	close() error
	reloadConfig() error
	initializeDatabase() error
	migrateDatabase() error
	revertDatabase(targetVersion int) error
	resetDatabase() error
}

// SetAllowSelfConnections sets the desired behaviour for self connections
func SetAllowSelfConnections(value int) {
	allowSelfConnections = value
}

// SetTempPath sets the path for temporary files
func SetTempPath(fsPath string) {
	tempPath = fsPath
}

func checkSharedMode() {
	if !slices.Contains(sharedProviders, config.Driver) {
		config.IsShared = 0
	}
}

// Initialize the data provider.
// An error is returned if the configured driver is invalid or if the data provider cannot be initialized
func Initialize(cnf Config, basePath string, checkAdmins bool) error {
	config = cnf
	checkSharedMode()
	config.Actions.ExecuteOn = util.RemoveDuplicates(config.Actions.ExecuteOn, true)
	config.Actions.ExecuteFor = util.RemoveDuplicates(config.Actions.ExecuteFor, true)

	cnf.BackupsPath = getConfigPath(cnf.BackupsPath, basePath)
	if cnf.BackupsPath == "" {
		return fmt.Errorf("required directory is invalid, backup path %q", cnf.BackupsPath)
	}
	absoluteBackupPath, err := util.GetAbsolutePath(cnf.BackupsPath)
	if err != nil {
		return fmt.Errorf("unable to get absolute backup path: %w", err)
	}
	config.BackupsPath = absoluteBackupPath

	if err := initializeHashingAlgo(&cnf); err != nil {
		return err
	}
	if err := validateHooks(); err != nil {
		return err
	}
	if err := createProvider(basePath); err != nil {
		return err
	}
	if err := checkDatabase(checkAdmins); err != nil {
		return err
	}
	admins, err := provider.getAdmins(1, 0, OrderASC)
	if err != nil {
		return err
	}
	isAdminCreated.Store(len(admins) > 0)
	if err := config.Node.validate(); err != nil {
		return err
	}
	delayedQuotaUpdater.start()
	if currentNode != nil {
		config.BackupsPath = filepath.Join(config.BackupsPath, currentNode.Name)
	}
	providerLog(logger.LevelDebug, "absolute backup path %q", config.BackupsPath)
	return startScheduler()
}

func checkDatabase(checkAdmins bool) error {
	if config.UpdateMode == 0 {
		err := provider.initializeDatabase()
		if err != nil && err != ErrNoInitRequired {
			logger.WarnToConsole("unable to initialize data provider: %v", err)
			providerLog(logger.LevelError, "unable to initialize data provider: %v", err)
			return err
		}
		if err == nil {
			logger.DebugToConsole("data provider successfully initialized")
			providerLog(logger.LevelInfo, "data provider successfully initialized")
		}
		err = provider.migrateDatabase()
		if err != nil && err != ErrNoInitRequired {
			providerLog(logger.LevelError, "database migration error: %v", err)
			return err
		}
		if checkAdmins && config.CreateDefaultAdmin {
			err = checkDefaultAdmin()
			if err != nil {
				providerLog(logger.LevelError, "erro checking the default admin: %v", err)
				return err
			}
		}
	} else {
		providerLog(logger.LevelInfo, "database initialization/migration skipped, manual mode is configured")
	}
	return nil
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
			return fmt.Errorf("invalid hook: %q must be an absolute path", hook)
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

// GetProviderFromValue returns the FilesystemProvider matching the specified value.
// If no match is found LocalFilesystemProvider is returned.
func GetProviderFromValue(value string) sdk.FilesystemProvider {
	val, err := strconv.Atoi(value)
	if err != nil {
		return sdk.LocalFilesystemProvider
	}
	result := sdk.FilesystemProvider(val)
	if sdk.IsProviderSupported(result) {
		return result
	}
	return sdk.LocalFilesystemProvider
}

func initializeHashingAlgo(cnf *Config) error {
	parallelism := cnf.PasswordHashing.Argon2Options.Parallelism
	if parallelism == 0 {
		parallelism = uint8(runtime.NumCPU())
	}
	argon2Params = &argon2id.Params{
		Memory:      cnf.PasswordHashing.Argon2Options.Memory,
		Iterations:  cnf.PasswordHashing.Argon2Options.Iterations,
		Parallelism: parallelism,
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
	initSQLTables()
	if config.SQLTablesPrefix != "" {
		for _, char := range config.SQLTablesPrefix {
			if !strings.Contains(sqlPrefixValidChars, strings.ToLower(string(char))) {
				return errors.New("invalid sql_tables_prefix only chars in range 'a..z', 'A..Z', '0-9' and '_' are allowed")
			}
		}
		sqlTableUsers = config.SQLTablesPrefix + sqlTableUsers
		sqlTableFolders = config.SQLTablesPrefix + sqlTableFolders
		sqlTableUsersFoldersMapping = config.SQLTablesPrefix + sqlTableUsersFoldersMapping
		sqlTableAdmins = config.SQLTablesPrefix + sqlTableAdmins
		sqlTableAPIKeys = config.SQLTablesPrefix + sqlTableAPIKeys
		sqlTableShares = config.SQLTablesPrefix + sqlTableShares
		sqlTableDefenderEvents = config.SQLTablesPrefix + sqlTableDefenderEvents
		sqlTableDefenderHosts = config.SQLTablesPrefix + sqlTableDefenderHosts
		sqlTableActiveTransfers = config.SQLTablesPrefix + sqlTableActiveTransfers
		sqlTableGroups = config.SQLTablesPrefix + sqlTableGroups
		sqlTableUsersGroupsMapping = config.SQLTablesPrefix + sqlTableUsersGroupsMapping
		sqlTableAdminsGroupsMapping = config.SQLTablesPrefix + sqlTableAdminsGroupsMapping
		sqlTableGroupsFoldersMapping = config.SQLTablesPrefix + sqlTableGroupsFoldersMapping
		sqlTableSharedSessions = config.SQLTablesPrefix + sqlTableSharedSessions
		sqlTableEventsActions = config.SQLTablesPrefix + sqlTableEventsActions
		sqlTableEventsRules = config.SQLTablesPrefix + sqlTableEventsRules
		sqlTableRulesActionsMapping = config.SQLTablesPrefix + sqlTableRulesActionsMapping
		sqlTableTasks = config.SQLTablesPrefix + sqlTableTasks
		sqlTableNodes = config.SQLTablesPrefix + sqlTableNodes
		sqlTableRoles = config.SQLTablesPrefix + sqlTableRoles
		sqlTableIPLists = config.SQLTablesPrefix + sqlTableIPLists
		sqlTableConfigs = config.SQLTablesPrefix + sqlTableConfigs
		sqlTableSchemaVersion = config.SQLTablesPrefix + sqlTableSchemaVersion
		providerLog(logger.LevelDebug, "sql table for users %q, folders %q users folders mapping %q admins %q "+
			"api keys %q shares %q defender hosts %q defender events %q transfers %q  groups %q "+
			"users groups mapping %q admins groups mapping %q groups folders mapping %q shared sessions %q "+
			"schema version %q events actions %q events rules %q rules actions mapping %q tasks %q nodes %q roles %q"+
			"ip lists %q configs %q",
			sqlTableUsers, sqlTableFolders, sqlTableUsersFoldersMapping, sqlTableAdmins, sqlTableAPIKeys,
			sqlTableShares, sqlTableDefenderHosts, sqlTableDefenderEvents, sqlTableActiveTransfers, sqlTableGroups,
			sqlTableUsersGroupsMapping, sqlTableAdminsGroupsMapping, sqlTableGroupsFoldersMapping, sqlTableSharedSessions,
			sqlTableSchemaVersion, sqlTableEventsActions, sqlTableEventsRules, sqlTableRulesActionsMapping,
			sqlTableTasks, sqlTableNodes, sqlTableRoles, sqlTableIPLists, sqlTableConfigs)
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
func CheckCachedUserCredentials(user *CachedUser, password, ip, loginMethod, protocol string, tlsCert *x509.Certificate) (*CachedUser, *User, error) {
	if !user.User.skipExternalAuth() && isExternalAuthConfigured(loginMethod) {
		u, _, err := CheckCompositeCredentials(user.User.Username, password, ip, loginMethod, protocol, tlsCert)
		if err != nil {
			return nil, nil, err
		}
		webDAVUsersCache.swap(&u, password)
		cu, _ := webDAVUsersCache.get(u.Username)
		return cu, &u, nil
	}
	if err := user.User.CheckLoginConditions(); err != nil {
		return user, nil, err
	}
	if loginMethod == LoginMethodPassword && user.User.Filters.IsAnonymous {
		return user, nil, nil
	}
	if loginMethod != LoginMethodPassword {
		_, err := checkUserAndTLSCertificate(&user.User, protocol, tlsCert)
		if err != nil {
			return user, nil, err
		}
		if loginMethod == LoginMethodTLSCertificate {
			if !user.User.IsLoginMethodAllowed(LoginMethodTLSCertificate, protocol) {
				return user, nil, fmt.Errorf("certificate login method is not allowed for user %q", user.User.Username)
			}
			return user, nil, nil
		}
	}
	if password == "" {
		return user, nil, ErrInvalidCredentials
	}
	if user.Password != "" {
		if password == user.Password {
			return user, nil, nil
		}
	} else {
		if ok, _ := isPasswordOK(&user.User, password); ok {
			return user, nil, nil
		}
	}
	return user, nil, ErrInvalidCredentials
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
	if !user.IsTLSVerificationEnabled() {
		// for backward compatibility with 2.0.x we only check the password and change the login method here
		// in future updates we have to return an error
		user, err := CheckUserAndPass(username, password, ip, protocol)
		return user, LoginMethodPassword, err
	}
	user, err = checkUserAndTLSCertificate(&user, protocol, tlsCert)
	if err != nil {
		return user, loginMethod, err
	}
	if loginMethod == LoginMethodTLSCertificate && !user.IsLoginMethodAllowed(LoginMethodTLSCertificate, protocol) {
		return user, loginMethod, fmt.Errorf("certificate login method is not allowed for user %q", user.Username)
	}
	if loginMethod == LoginMethodTLSCertificateAndPwd {
		if plugin.Handler.HasAuthScope(plugin.AuthScopePassword) {
			user, err = doPluginAuth(username, password, nil, ip, protocol, nil, plugin.AuthScopePassword)
		} else if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&1 != 0) {
			user, err = doExternalAuth(username, password, nil, "", ip, protocol, nil)
		} else if config.PreLoginHook != "" {
			user, err = executePreLoginHook(username, LoginMethodPassword, ip, protocol, nil)
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
		user, err := doPluginAuth(username, "", nil, ip, protocol, tlsCert, plugin.AuthScopeTLSCertificate)
		if err != nil {
			return user, err
		}
		err = user.LoadAndApplyGroupSettings()
		return user, err
	}
	if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&8 != 0) {
		user, err := doExternalAuth(username, "", nil, "", ip, protocol, tlsCert)
		if err != nil {
			return user, err
		}
		err = user.LoadAndApplyGroupSettings()
		return user, err
	}
	if config.PreLoginHook != "" {
		user, err := executePreLoginHook(username, LoginMethodTLSCertificate, ip, protocol, nil)
		if err != nil {
			return user, err
		}
		err = user.LoadAndApplyGroupSettings()
		return user, err
	}
	user, err := UserExists(username, "")
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
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
		user, err := executePreLoginHook(username, LoginMethodTLSCertificate, ip, protocol, nil)
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
		user, err := executePreLoginHook(username, LoginMethodPassword, ip, protocol, nil)
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
		user, err := executePreLoginHook(username, SSHLoginMethodPublicKey, ip, protocol, nil)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(&user, pubKey, isSSHCert)
	}
	return provider.validateUserAndPubKey(username, pubKey, isSSHCert)
}

// CheckKeyboardInteractiveAuth checks the keyboard interactive authentication and returns
// the authenticated user or an error
func CheckKeyboardInteractiveAuth(username, authHook string, client ssh.KeyboardInteractiveChallenge,
	ip, protocol string, isPartialAuth bool,
) (User, error) {
	var user User
	var err error
	username = config.convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopeKeyboardInteractive) {
		user, err = doPluginAuth(username, "", nil, ip, protocol, nil, plugin.AuthScopeKeyboardInteractive)
	} else if config.ExternalAuthHook != "" && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&4 != 0) {
		user, err = doExternalAuth(username, "", nil, "1", ip, protocol, nil)
	} else if config.PreLoginHook != "" {
		user, err = executePreLoginHook(username, SSHLoginMethodKeyboardInteractive, ip, protocol, nil)
	} else {
		user, err = provider.userExists(username, "")
	}
	if err != nil {
		return user, err
	}
	return doKeyboardInteractiveAuth(&user, authHook, client, ip, protocol, isPartialAuth)
}

// GetFTPPreAuthUser returns the SFTPGo user with the specified username
// after receiving the FTP "USER" command.
// If a pre-login hook is defined it will be executed so the SFTPGo user
// can be created if it does not exist
func GetFTPPreAuthUser(username, ip string) (User, error) {
	var user User
	var err error
	if config.PreLoginHook != "" {
		user, err = executePreLoginHook(username, "", ip, protocolFTP, nil)
	} else {
		user, err = UserExists(username, "")
	}
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
}

// GetUserAfterIDPAuth returns the SFTPGo user with the specified username
// after a successful authentication with an external identity provider.
// If a pre-login hook is defined it will be executed so the SFTPGo user
// can be created if it does not exist
func GetUserAfterIDPAuth(username, ip, protocol string, oidcTokenFields *map[string]any) (User, error) {
	var user User
	var err error
	if config.PreLoginHook != "" {
		user, err = executePreLoginHook(username, LoginMethodIDP, ip, protocol, oidcTokenFields)
		user.Filters.RequirePasswordChange = false
	} else {
		user, err = UserExists(username, "")
	}
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
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

// UpdateUserFolderQuota updates the quota for the given user and virtual folder.
func UpdateUserFolderQuota(folder *vfs.VirtualFolder, user *User, filesAdd int, sizeAdd int64, reset bool) {
	if folder.IsIncludedInUserQuota() {
		UpdateUserQuota(user, filesAdd, sizeAdd, reset) //nolint:errcheck
		return
	}
	UpdateVirtualFolderQuota(&folder.BaseVirtualFolder, filesAdd, sizeAdd, reset) //nolint:errcheck
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

// UpdateUserTransferTimestamps updates the first download/upload fields if unset
func UpdateUserTransferTimestamps(username string, isUpload bool) error {
	if isUpload {
		err := provider.setFirstUploadTimestamp(username)
		if err != nil {
			providerLog(logger.LevelWarn, "unable to set first upload: %v", err)
		}
		return err
	}
	err := provider.setFirstDownloadTimestamp(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to set first download: %v", err)
	}
	return err
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

// GetConfigs returns the configurations
func GetConfigs() (Configs, error) {
	return provider.getConfigs()
}

// UpdateConfigs updates configurations
func UpdateConfigs(configs *Configs, executor, ipAddress, role string) error {
	if configs == nil {
		configs = &Configs{}
	} else {
		configs.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	err := provider.setConfigs(configs)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectConfigs, "configs", role, configs)
	}
	return err
}

// AddShare adds a new share
func AddShare(share *Share, executor, ipAddress, role string) error {
	err := provider.addShare(share)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectShare, share.ShareID, role, share)
	}
	return err
}

// UpdateShare updates an existing share
func UpdateShare(share *Share, executor, ipAddress, role string) error {
	err := provider.updateShare(share)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectShare, share.ShareID, role, share)
	}
	return err
}

// DeleteShare deletes an existing share
func DeleteShare(shareID string, executor, ipAddress, role string) error {
	share, err := provider.shareExists(shareID, executor)
	if err != nil {
		return err
	}
	err = provider.deleteShare(share)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectShare, shareID, role, &share)
	}
	return err
}

// ShareExists returns the share with the given ID if it exists
func ShareExists(shareID, username string) (Share, error) {
	if shareID == "" {
		return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %q does not exist", shareID))
	}
	return provider.shareExists(shareID, username)
}

// AddIPListEntry adds a new IP list entry
func AddIPListEntry(entry *IPListEntry, executor, ipAddress, executorRole string) error {
	err := provider.addIPListEntry(entry)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectIPListEntry, entry.getName(), executorRole, entry)
		for _, l := range inMemoryLists {
			l.addEntry(entry)
		}
	}
	return err
}

// UpdateIPListEntry updates an existing IP list entry
func UpdateIPListEntry(entry *IPListEntry, executor, ipAddress, executorRole string) error {
	err := provider.updateIPListEntry(entry)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectIPListEntry, entry.getName(), executorRole, entry)
		for _, l := range inMemoryLists {
			l.updateEntry(entry)
		}
	}
	return err
}

// DeleteIPListEntry deletes an existing IP list entry
func DeleteIPListEntry(ipOrNet string, listType IPListType, executor, ipAddress, executorRole string) error {
	entry, err := provider.ipListEntryExists(ipOrNet, listType)
	if err != nil {
		return err
	}
	err = provider.deleteIPListEntry(entry, config.IsShared == 1)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectIPListEntry, entry.getName(), executorRole, &entry)
		for _, l := range inMemoryLists {
			l.removeEntry(&entry)
		}
	}
	return err
}

// IPListEntryExists returns the IP list entry with the given IP/net and type if it exists
func IPListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	return provider.ipListEntryExists(ipOrNet, listType)
}

// GetIPListEntries returns the IP list entries applying the specified criteria and search limit
func GetIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	if !slices.Contains(supportedIPListType, listType) {
		return nil, util.NewValidationError(fmt.Sprintf("invalid list type %d", listType))
	}
	return provider.getIPListEntries(listType, filter, from, order, limit)
}

// AddRole adds a new role
func AddRole(role *Role, executor, ipAddress, executorRole string) error {
	role.Name = config.convertName(role.Name)
	err := provider.addRole(role)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectRole, role.Name, executorRole, role)
	}
	return err
}

// UpdateRole updates an existing Role
func UpdateRole(role *Role, executor, ipAddress, executorRole string) error {
	err := provider.updateRole(role)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectRole, role.Name, executorRole, role)
	}
	return err
}

// DeleteRole deletes an existing Role
func DeleteRole(name string, executor, ipAddress, executorRole string) error {
	name = config.convertName(name)
	role, err := provider.roleExists(name)
	if err != nil {
		return err
	}
	if len(role.Admins) > 0 {
		errorString := fmt.Sprintf("the role %q is referenced, it cannot be removed", role.Name)
		return util.NewValidationError(errorString)
	}
	err = provider.deleteRole(role)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectRole, role.Name, executorRole, &role)
		for _, user := range role.Users {
			provider.setUpdatedAt(user)
			u, err := provider.userExists(user, "")
			if err == nil {
				webDAVUsersCache.swap(&u, "")
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
			}
		}
	}
	return err
}

// RoleExists returns the Role with the given name if it exists
func RoleExists(name string) (Role, error) {
	name = config.convertName(name)
	return provider.roleExists(name)
}

// AddGroup adds a new group
func AddGroup(group *Group, executor, ipAddress, role string) error {
	group.Name = config.convertName(group.Name)
	err := provider.addGroup(group)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectGroup, group.Name, role, group)
	}
	return err
}

// UpdateGroup updates an existing Group
func UpdateGroup(group *Group, users []string, executor, ipAddress, role string) error {
	err := provider.updateGroup(group)
	if err == nil {
		for _, user := range users {
			provider.setUpdatedAt(user)
			u, err := provider.userExists(user, "")
			if err == nil {
				webDAVUsersCache.swap(&u, "")
			} else {
				RemoveCachedWebDAVUser(user)
			}
		}
		executeAction(operationUpdate, executor, ipAddress, actionObjectGroup, group.Name, role, group)
	}
	return err
}

// DeleteGroup deletes an existing Group
func DeleteGroup(name string, executor, ipAddress, role string) error {
	name = config.convertName(name)
	group, err := provider.groupExists(name)
	if err != nil {
		return err
	}
	if len(group.Users) > 0 {
		errorString := fmt.Sprintf("the group %q is referenced, it cannot be removed", group.Name)
		return util.NewValidationError(errorString)
	}
	err = provider.deleteGroup(group)
	if err == nil {
		for _, user := range group.Users {
			provider.setUpdatedAt(user)
			u, err := provider.userExists(user, "")
			if err == nil {
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
			}
			RemoveCachedWebDAVUser(user)
		}
		executeAction(operationDelete, executor, ipAddress, actionObjectGroup, group.Name, role, &group)
	}
	return err
}

// GroupExists returns the Group with the given name if it exists
func GroupExists(name string) (Group, error) {
	name = config.convertName(name)
	return provider.groupExists(name)
}

// AddAPIKey adds a new API key
func AddAPIKey(apiKey *APIKey, executor, ipAddress, role string) error {
	err := provider.addAPIKey(apiKey)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, role, apiKey)
	}
	return err
}

// UpdateAPIKey updates an existing API key
func UpdateAPIKey(apiKey *APIKey, executor, ipAddress, role string) error {
	err := provider.updateAPIKey(apiKey)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, role, apiKey)
	}
	return err
}

// DeleteAPIKey deletes an existing API key
func DeleteAPIKey(keyID string, executor, ipAddress, role string) error {
	apiKey, err := provider.apiKeyExists(keyID)
	if err != nil {
		return err
	}
	err = provider.deleteAPIKey(apiKey)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, role, &apiKey)
		cachedAPIKeys.Remove(keyID)
	}
	return err
}

// APIKeyExists returns the API key with the given ID if it exists
func APIKeyExists(keyID string) (APIKey, error) {
	if keyID == "" {
		return APIKey{}, util.NewRecordNotFoundError(fmt.Sprintf("API key %q does not exist", keyID))
	}
	return provider.apiKeyExists(keyID)
}

// GetEventActions returns an array of event actions respecting limit and offset
func GetEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	return provider.getEventActions(limit, offset, order, minimal)
}

// EventActionExists returns the event action with the given name if it exists
func EventActionExists(name string) (BaseEventAction, error) {
	name = config.convertName(name)
	return provider.eventActionExists(name)
}

// AddEventAction adds a new event action
func AddEventAction(action *BaseEventAction, executor, ipAddress, role string) error {
	action.Name = config.convertName(action.Name)
	err := provider.addEventAction(action)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectEventAction, action.Name, role, action)
	}
	return err
}

// UpdateEventAction updates an existing event action
func UpdateEventAction(action *BaseEventAction, executor, ipAddress, role string) error {
	err := provider.updateEventAction(action)
	if err == nil {
		if fnReloadRules != nil {
			fnReloadRules()
		}
		executeAction(operationUpdate, executor, ipAddress, actionObjectEventAction, action.Name, role, action)
	}
	return err
}

// DeleteEventAction deletes an existing event action
func DeleteEventAction(name string, executor, ipAddress, role string) error {
	name = config.convertName(name)
	action, err := provider.eventActionExists(name)
	if err != nil {
		return err
	}
	if len(action.Rules) > 0 {
		errorString := fmt.Sprintf("the event action %#q is referenced, it cannot be removed", action.Name)
		return util.NewValidationError(errorString)
	}
	err = provider.deleteEventAction(action)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectEventAction, action.Name, role, &action)
	}
	return err
}

// GetEventRules returns an array of event rules respecting limit and offset
func GetEventRules(limit, offset int, order string) ([]EventRule, error) {
	return provider.getEventRules(limit, offset, order)
}

// GetRecentlyUpdatedRules returns the event rules updated after the specified time
func GetRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	return provider.getRecentlyUpdatedRules(after)
}

// EventRuleExists returns the event rule with the given name if it exists
func EventRuleExists(name string) (EventRule, error) {
	name = config.convertName(name)
	return provider.eventRuleExists(name)
}

// AddEventRule adds a new event rule
func AddEventRule(rule *EventRule, executor, ipAddress, role string) error {
	rule.Name = config.convertName(rule.Name)
	err := provider.addEventRule(rule)
	if err == nil {
		if fnReloadRules != nil {
			fnReloadRules()
		}
		executeAction(operationAdd, executor, ipAddress, actionObjectEventRule, rule.Name, role, rule)
	}
	return err
}

// UpdateEventRule updates an existing event rule
func UpdateEventRule(rule *EventRule, executor, ipAddress, role string) error {
	err := provider.updateEventRule(rule)
	if err == nil {
		if fnReloadRules != nil {
			fnReloadRules()
		}
		executeAction(operationUpdate, executor, ipAddress, actionObjectEventRule, rule.Name, role, rule)
	}
	return err
}

// DeleteEventRule deletes an existing event rule
func DeleteEventRule(name string, executor, ipAddress, role string) error {
	name = config.convertName(name)
	rule, err := provider.eventRuleExists(name)
	if err != nil {
		return err
	}
	err = provider.deleteEventRule(rule, config.IsShared == 1)
	if err == nil {
		if fnRemoveRule != nil {
			fnRemoveRule(rule.Name)
		}
		executeAction(operationDelete, executor, ipAddress, actionObjectEventRule, rule.Name, role, &rule)
	}
	return err
}

// RemoveEventRule delets an existing event rule without marking it as deleted
func RemoveEventRule(rule EventRule) error {
	return provider.deleteEventRule(rule, false)
}

// GetTaskByName returns the task with the specified name
func GetTaskByName(name string) (Task, error) {
	return provider.getTaskByName(name)
}

// AddTask add a task with the specified name
func AddTask(name string) error {
	return provider.addTask(name)
}

// UpdateTask updates the task with the specified name and version
func UpdateTask(name string, version int64) error {
	return provider.updateTask(name, version)
}

// UpdateTaskTimestamp updates the timestamp for the task with the specified name
func UpdateTaskTimestamp(name string) error {
	return provider.updateTaskTimestamp(name)
}

// GetNodes returns the other cluster nodes
func GetNodes() ([]Node, error) {
	if currentNode == nil {
		return nil, nil
	}
	nodes, err := provider.getNodes()
	if err != nil {
		providerLog(logger.LevelError, "unable to get other cluster nodes %v", err)
	}
	return nodes, err
}

// GetNodeByName returns a node, different from the current one, by name
func GetNodeByName(name string) (Node, error) {
	if currentNode == nil {
		return Node{}, util.NewRecordNotFoundError(errNoClusterNodes.Error())
	}
	if name == currentNode.Name {
		return Node{}, util.NewValidationError(fmt.Sprintf("%s is the current node, it must refer to other nodes", name))
	}
	return provider.getNodeByName(name)
}

// HasAdmin returns true if the first admin has been created
// and so SFTPGo is ready to be used
func HasAdmin() bool {
	return isAdminCreated.Load()
}

// AddAdmin adds a new SFTPGo admin
func AddAdmin(admin *Admin, executor, ipAddress, role string) error {
	admin.Filters.RecoveryCodes = nil
	admin.Filters.TOTPConfig = AdminTOTPConfig{
		Enabled: false,
	}
	admin.Username = config.convertName(admin.Username)
	err := provider.addAdmin(admin)
	if err == nil {
		isAdminCreated.Store(true)
		executeAction(operationAdd, executor, ipAddress, actionObjectAdmin, admin.Username, role, admin)
	}
	return err
}

// UpdateAdmin updates an existing SFTPGo admin
func UpdateAdmin(admin *Admin, executor, ipAddress, role string) error {
	err := provider.updateAdmin(admin)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectAdmin, admin.Username, role, admin)
	}
	return err
}

// DeleteAdmin deletes an existing SFTPGo admin
func DeleteAdmin(username, executor, ipAddress, role string) error {
	username = config.convertName(username)
	admin, err := provider.adminExists(username)
	if err != nil {
		return err
	}
	err = provider.deleteAdmin(admin)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectAdmin, admin.Username, role, &admin)
		cachedAdminPasswords.Remove(username)
	}
	return err
}

// AdminExists returns the admin with the given username if it exists
func AdminExists(username string) (Admin, error) {
	username = config.convertName(username)
	return provider.adminExists(username)
}

// UserExists checks if the given SFTPGo username exists, returns an error if no match is found
func UserExists(username, role string) (User, error) {
	username = config.convertName(username)
	return provider.userExists(username, role)
}

// GetAdminSignature returns the signature for the admin with the specified
// username.
func GetAdminSignature(username string) (string, error) {
	username = config.convertName(username)
	return provider.getAdminSignature(username)
}

// GetUserSignature returns the signature for the user with the specified
// username.
func GetUserSignature(username string) (string, error) {
	username = config.convertName(username)
	return provider.getUserSignature(username)
}

// GetUserWithGroupSettings tries to return the user with the specified username
// loading also the group settings
func GetUserWithGroupSettings(username, role string) (User, error) {
	username = config.convertName(username)
	user, err := provider.userExists(username, role)
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
}

// GetUserVariants tries to return the user with the specified username with and without
// group settings applied
func GetUserVariants(username, role string) (User, User, error) {
	username = config.convertName(username)
	user, err := provider.userExists(username, role)
	if err != nil {
		return user, User{}, err
	}
	userWithGroupSettings := user.getACopy()
	err = userWithGroupSettings.LoadAndApplyGroupSettings()
	return user, userWithGroupSettings, err
}

// AddUser adds a new SFTPGo user.
func AddUser(user *User, executor, ipAddress, role string) error {
	user.Username = config.convertName(user.Username)
	err := provider.addUser(user)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectUser, user.Username, role, user)
	}
	return err
}

// UpdateUserPassword updates the user password
func UpdateUserPassword(username, plainPwd, executor, ipAddress, role string) error {
	user, err := provider.userExists(username, role)
	if err != nil {
		return err
	}
	userCopy := user.getACopy()
	if err := userCopy.LoadAndApplyGroupSettings(); err != nil {
		return err
	}
	userCopy.Password = plainPwd
	if err := createUserPasswordHash(&userCopy); err != nil {
		return err
	}
	user.LastPasswordChange = userCopy.LastPasswordChange
	user.Password = userCopy.Password
	user.Filters.RequirePasswordChange = false
	// the last password change is set when validating the user
	if err := provider.updateUser(&user); err != nil {
		return err
	}
	webDAVUsersCache.swap(&user, plainPwd)
	executeAction(operationUpdate, executor, ipAddress, actionObjectUser, username, role, &user)
	return nil
}

// UpdateUser updates an existing SFTPGo user.
func UpdateUser(user *User, executor, ipAddress, role string) error {
	if user.groupSettingsApplied {
		return errors.New("cannot save a user with group settings applied")
	}
	err := provider.updateUser(user)
	if err == nil {
		webDAVUsersCache.swap(user, "")
		executeAction(operationUpdate, executor, ipAddress, actionObjectUser, user.Username, role, user)
	}
	return err
}

// DeleteUser deletes an existing SFTPGo user.
func DeleteUser(username, executor, ipAddress, role string) error {
	username = config.convertName(username)
	user, err := provider.userExists(username, role)
	if err != nil {
		return err
	}
	err = provider.deleteUser(user, config.IsShared == 1)
	if err == nil {
		RemoveCachedWebDAVUser(user.Username)
		delayedQuotaUpdater.resetUserQuota(user.Username)
		cachedUserPasswords.Remove(username)
		executeAction(operationDelete, executor, ipAddress, actionObjectUser, user.Username, role, &user)
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

// AddSharedSession stores a new session within the data provider
func AddSharedSession(session Session) error {
	err := provider.addSharedSession(session)
	if err != nil {
		providerLog(logger.LevelError, "unable to add shared session, key %q, type: %v, err: %v",
			session.Key, session.Type, err)
	}
	return err
}

// DeleteSharedSession deletes the session with the specified key
func DeleteSharedSession(key string, sessionType SessionType) error {
	err := provider.deleteSharedSession(key, sessionType)
	if err != nil {
		providerLog(logger.LevelError, "unable to add shared session, key %q, err: %v", key, err)
	}
	return err
}

// GetSharedSession retrieves the session with the specified key
func GetSharedSession(key string, sessionType SessionType) (Session, error) {
	return provider.getSharedSession(key, sessionType)
}

// CleanupSharedSessions removes the shared session with the specified type and
// before the specified time
func CleanupSharedSessions(sessionType SessionType, before time.Time) error {
	err := provider.cleanupSharedSessions(sessionType, util.GetTimeAsMsSinceEpoch(before))
	if err == nil {
		providerLog(logger.LevelDebug, "deleted shared sessions before: %v, type: %v", before, sessionType)
	} else {
		providerLog(logger.LevelError, "error deleting shared session before %v, type %v: %v", before, sessionType, err)
	}
	return err
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

// GetRoles returns an array of roles respecting limit and offset
func GetRoles(limit, offset int, order string, minimal bool) ([]Role, error) {
	return provider.getRoles(limit, offset, order, minimal)
}

// GetGroups returns an array of groups respecting limit and offset
func GetGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	return provider.getGroups(limit, offset, order, minimal)
}

// GetUsers returns an array of users respecting limit and offset
func GetUsers(limit, offset int, order, role string) ([]User, error) {
	return provider.getUsers(limit, offset, order, role)
}

// GetUsersForQuotaCheck returns the users with the fields required for a quota check
func GetUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return provider.getUsersForQuotaCheck(toFetch)
}

// AddFolder adds a new virtual folder.
func AddFolder(folder *vfs.BaseVirtualFolder, executor, ipAddress, role string) error {
	folder.Name = config.convertName(folder.Name)
	err := provider.addFolder(folder)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectFolder, folder.Name, role, &wrappedFolder{Folder: *folder})
	}
	return err
}

// UpdateFolder updates the specified virtual folder
func UpdateFolder(folder *vfs.BaseVirtualFolder, users []string, groups []string, executor, ipAddress, role string) error {
	err := provider.updateFolder(folder)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectFolder, folder.Name, role, &wrappedFolder{Folder: *folder})
		usersInGroups, errGrp := provider.getUsersInGroups(groups)
		if errGrp == nil {
			users = append(users, usersInGroups...)
			users = util.RemoveDuplicates(users, false)
		} else {
			providerLog(logger.LevelWarn, "unable to get users in groups %+v: %v", groups, errGrp)
		}
		for _, user := range users {
			provider.setUpdatedAt(user)
			u, err := provider.userExists(user, "")
			if err == nil {
				webDAVUsersCache.swap(&u, "")
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
			} else {
				RemoveCachedWebDAVUser(user)
			}
		}
	}
	return err
}

// DeleteFolder deletes an existing folder.
func DeleteFolder(folderName, executor, ipAddress, role string) error {
	folderName = config.convertName(folderName)
	folder, err := provider.getFolderByName(folderName)
	if err != nil {
		return err
	}
	err = provider.deleteFolder(folder)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectFolder, folder.Name, role, &wrappedFolder{Folder: folder})
		users := folder.Users
		usersInGroups, errGrp := provider.getUsersInGroups(folder.Groups)
		if errGrp == nil {
			users = append(users, usersInGroups...)
			users = util.RemoveDuplicates(users, false)
		} else {
			providerLog(logger.LevelWarn, "unable to get users in groups %+v: %v", folder.Groups, errGrp)
		}
		for _, user := range users {
			provider.setUpdatedAt(user)
			u, err := provider.userExists(user, "")
			if err == nil {
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
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
func GetFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	return provider.getFolders(limit, offset, order, minimal)
}

func dumpUsers(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeUsers) {
		users, err := provider.dumpUsers()
		if err != nil {
			return err
		}
		data.Users = users
	}
	return nil
}

func dumpFolders(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeFolders) {
		folders, err := provider.dumpFolders()
		if err != nil {
			return err
		}
		data.Folders = folders
	}
	return nil
}

func dumpGroups(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeGroups) {
		groups, err := provider.dumpGroups()
		if err != nil {
			return err
		}
		data.Groups = groups
	}
	return nil
}

func dumpAdmins(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeAdmins) {
		admins, err := provider.dumpAdmins()
		if err != nil {
			return err
		}
		data.Admins = admins
	}
	return nil
}

func dumpAPIKeys(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeAPIKeys) {
		apiKeys, err := provider.dumpAPIKeys()
		if err != nil {
			return err
		}
		data.APIKeys = apiKeys
	}
	return nil
}

func dumpShares(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeShares) {
		shares, err := provider.dumpShares()
		if err != nil {
			return err
		}
		data.Shares = shares
	}
	return nil
}

func dumpActions(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeActions) {
		actions, err := provider.dumpEventActions()
		if err != nil {
			return err
		}
		data.EventActions = actions
	}
	return nil
}

func dumpRules(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeRules) {
		rules, err := provider.dumpEventRules()
		if err != nil {
			return err
		}
		data.EventRules = rules
	}
	return nil
}

func dumpRoles(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeRoles) {
		roles, err := provider.dumpRoles()
		if err != nil {
			return err
		}
		data.Roles = roles
	}
	return nil
}

func dumpIPLists(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeIPLists) {
		ipLists, err := provider.dumpIPListEntries()
		if err != nil {
			return err
		}
		data.IPLists = ipLists
	}
	return nil
}

func dumpConfigs(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeConfigs) {
		configs, err := provider.getConfigs()
		if err != nil {
			return err
		}
		data.Configs = &configs
	}
	return nil
}

// DumpData returns a dump containing the requested scopes.
// Empty scopes means all
func DumpData(scopes []string) (BackupData, error) {
	data := BackupData{
		Version: DumpVersion,
	}
	if err := dumpGroups(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpUsers(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpFolders(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpAdmins(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpAPIKeys(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpShares(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpActions(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpRules(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpRoles(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpIPLists(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpConfigs(&data, scopes); err != nil {
		return data, err
	}

	return data, nil
}

// ParseDumpData tries to parse data as BackupData
func ParseDumpData(data []byte) (BackupData, error) {
	var dump BackupData
	err := json.Unmarshal(data, &dump)
	if err != nil {
		return dump, err
	}
	if dump.Version < 17 {
		providerLog(logger.LevelInfo, "updating placeholders for actions restored from dump version %d", dump.Version)
		eventActions, err := updateEventActionPlaceholders(dump.EventActions)
		if err != nil {
			return dump, fmt.Errorf("unable to update event action placeholders for dump version %d: %w", dump.Version, err)
		}
		dump.EventActions = eventActions
	}
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
	sqlPlaceholders = getSQLPlaceholders()
	if err := validateSQLTablesPrefix(); err != nil {
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
		if err := initializeMemoryProvider(basePath); err != nil {
			logger.Warn(logSender, "", "provider initialized but data loading failed: %v", err)
			logger.WarnToConsole("provider initialized but data loading failed: %v", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported data provider: %v", config.Driver)
	}
}

func copyBaseUserFilters(in sdk.BaseUserFilters) sdk.BaseUserFilters {
	filters := sdk.BaseUserFilters{}
	filters.MaxUploadFileSize = in.MaxUploadFileSize
	filters.TLSUsername = in.TLSUsername
	filters.UserType = in.UserType
	filters.AllowedIP = make([]string, len(in.AllowedIP))
	copy(filters.AllowedIP, in.AllowedIP)
	filters.DeniedIP = make([]string, len(in.DeniedIP))
	copy(filters.DeniedIP, in.DeniedIP)
	filters.DeniedLoginMethods = make([]string, len(in.DeniedLoginMethods))
	copy(filters.DeniedLoginMethods, in.DeniedLoginMethods)
	filters.FilePatterns = make([]sdk.PatternsFilter, len(in.FilePatterns))
	copy(filters.FilePatterns, in.FilePatterns)
	filters.DeniedProtocols = make([]string, len(in.DeniedProtocols))
	copy(filters.DeniedProtocols, in.DeniedProtocols)
	filters.TwoFactorAuthProtocols = make([]string, len(in.TwoFactorAuthProtocols))
	copy(filters.TwoFactorAuthProtocols, in.TwoFactorAuthProtocols)
	filters.Hooks.ExternalAuthDisabled = in.Hooks.ExternalAuthDisabled
	filters.Hooks.PreLoginDisabled = in.Hooks.PreLoginDisabled
	filters.Hooks.CheckPasswordDisabled = in.Hooks.CheckPasswordDisabled
	filters.DisableFsChecks = in.DisableFsChecks
	filters.StartDirectory = in.StartDirectory
	filters.FTPSecurity = in.FTPSecurity
	filters.IsAnonymous = in.IsAnonymous
	filters.AllowAPIKeyAuth = in.AllowAPIKeyAuth
	filters.ExternalAuthCacheTime = in.ExternalAuthCacheTime
	filters.DefaultSharesExpiration = in.DefaultSharesExpiration
	filters.MaxSharesExpiration = in.MaxSharesExpiration
	filters.PasswordExpiration = in.PasswordExpiration
	filters.PasswordStrength = in.PasswordStrength
	filters.WebClient = make([]string, len(in.WebClient))
	copy(filters.WebClient, in.WebClient)
	filters.TLSCerts = make([]string, len(in.TLSCerts))
	copy(filters.TLSCerts, in.TLSCerts)
	filters.BandwidthLimits = make([]sdk.BandwidthLimit, 0, len(in.BandwidthLimits))
	for _, limit := range in.BandwidthLimits {
		bwLimit := sdk.BandwidthLimit{
			UploadBandwidth:   limit.UploadBandwidth,
			DownloadBandwidth: limit.DownloadBandwidth,
			Sources:           make([]string, 0, len(limit.Sources)),
		}
		bwLimit.Sources = make([]string, len(limit.Sources))
		copy(bwLimit.Sources, limit.Sources)
		filters.BandwidthLimits = append(filters.BandwidthLimits, bwLimit)
	}
	filters.AccessTime = make([]sdk.TimePeriod, 0, len(in.AccessTime))
	for _, period := range in.AccessTime {
		filters.AccessTime = append(filters.AccessTime, sdk.TimePeriod{
			DayOfWeek: period.DayOfWeek,
			From:      period.From,
			To:        period.To,
		})
	}
	return filters
}

func buildUserHomeDir(user *User) {
	if user.HomeDir == "" {
		if config.UsersBaseDir != "" {
			user.HomeDir = filepath.Join(config.UsersBaseDir, user.Username)
			return
		}
		switch user.FsConfig.Provider {
		case sdk.SFTPFilesystemProvider, sdk.S3FilesystemProvider, sdk.AzureBlobFilesystemProvider, sdk.GCSFilesystemProvider, sdk.HTTPFilesystemProvider:
			if tempPath != "" {
				user.HomeDir = filepath.Join(tempPath, user.Username)
			} else {
				user.HomeDir = filepath.Join(os.TempDir(), user.Username)
			}
		}
	} else {
		user.HomeDir = filepath.Clean(user.HomeDir)
	}
}

func validateFolderQuotaLimits(folder vfs.VirtualFolder) error {
	if folder.QuotaSize < -1 {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("invalid quota_size: %v folder path %q", folder.QuotaSize, folder.MappedPath)),
			util.I18nErrorFolderQuotaSizeInvalid,
		)
	}
	if folder.QuotaFiles < -1 {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("invalid quota_file: %v folder path %q", folder.QuotaFiles, folder.MappedPath)),
			util.I18nErrorFolderQuotaFileInvalid,
		)
	}
	if (folder.QuotaSize == -1 && folder.QuotaFiles != -1) || (folder.QuotaFiles == -1 && folder.QuotaSize != -1) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("virtual folder quota_size and quota_files must be both -1 or >= 0, quota_size: %v quota_files: %v",
				folder.QuotaFiles, folder.QuotaSize)),
			util.I18nErrorFolderQuotaInvalid,
		)
	}
	return nil
}

func validateUserGroups(user *User) error {
	if len(user.Groups) == 0 {
		return nil
	}
	hasPrimary := false
	groupNames := make(map[string]bool)

	for _, g := range user.Groups {
		if g.Type < sdk.GroupTypePrimary && g.Type > sdk.GroupTypeMembership {
			return util.NewValidationError(fmt.Sprintf("invalid group type: %v", g.Type))
		}
		if g.Type == sdk.GroupTypePrimary {
			if hasPrimary {
				return util.NewI18nError(
					util.NewValidationError("only one primary group is allowed"),
					util.I18nErrorPrimaryGroup,
				)
			}
			hasPrimary = true
		}
		if groupNames[g.Name] {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("the group %q is duplicated", g.Name)),
				util.I18nErrorDuplicateGroup,
			)
		}
		groupNames[g.Name] = true
	}
	return nil
}

func validateAssociatedVirtualFolders(vfolders []vfs.VirtualFolder) ([]vfs.VirtualFolder, error) {
	if len(vfolders) == 0 {
		return []vfs.VirtualFolder{}, nil
	}
	var virtualFolders []vfs.VirtualFolder
	folderNames := make(map[string]bool)

	for _, v := range vfolders {
		if v.VirtualPath == "" {
			return nil, util.NewI18nError(
				util.NewValidationError("mount/virtual path is mandatory"),
				util.I18nErrorFolderMountPathRequired,
			)
		}
		cleanedVPath := util.CleanPath(v.VirtualPath)
		if err := validateFolderQuotaLimits(v); err != nil {
			return nil, err
		}
		if v.Name == "" {
			return nil, util.NewI18nError(util.NewValidationError("folder name is mandatory"), util.I18nErrorFolderNameRequired)
		}
		if folderNames[v.Name] {
			return nil, util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("the folder %q is duplicated", v.Name)),
				util.I18nErrorDuplicatedFolders,
			)
		}
		for _, vFolder := range virtualFolders {
			if util.IsDirOverlapped(vFolder.VirtualPath, cleanedVPath, false, "/") {
				return nil, util.NewI18nError(
					util.NewValidationError(fmt.Sprintf("invalid virtual folder %q, it overlaps with virtual folder %q",
						v.VirtualPath, vFolder.VirtualPath)),
					util.I18nErrorOverlappedFolders,
				)
			}
		}
		virtualFolders = append(virtualFolders, vfs.VirtualFolder{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name: v.Name,
			},
			VirtualPath: cleanedVPath,
			QuotaSize:   v.QuotaSize,
			QuotaFiles:  v.QuotaFiles,
		})
		folderNames[v.Name] = true
	}
	return virtualFolders, nil
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
	if !slices.Contains(mfa.GetAvailableTOTPConfigNames(), c.ConfigName) {
		return util.NewValidationError(fmt.Sprintf("totp: config name %q not found", c.ConfigName))
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
		if !slices.Contains(MFAProtocols, protocol) {
			return util.NewValidationError(fmt.Sprintf("totp: invalid protocol %q", protocol))
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

func validateUserPermissions(permsToCheck map[string][]string) (map[string][]string, error) {
	permissions := make(map[string][]string)
	for dir, perms := range permsToCheck {
		if len(perms) == 0 && dir == "/" {
			return permissions, util.NewValidationError(fmt.Sprintf("no permissions granted for the directory: %q", dir))
		}
		if len(perms) > len(ValidPerms) {
			return permissions, util.NewValidationError("invalid permissions")
		}
		for _, p := range perms {
			if !slices.Contains(ValidPerms, p) {
				return permissions, util.NewValidationError(fmt.Sprintf("invalid permission: %q", p))
			}
		}
		cleanedDir := filepath.ToSlash(path.Clean(dir))
		if cleanedDir != "/" {
			cleanedDir = strings.TrimSuffix(cleanedDir, "/")
		}
		if !path.IsAbs(cleanedDir) {
			return permissions, util.NewValidationError(fmt.Sprintf("cannot set permissions for non absolute path: %q", dir))
		}
		if dir != cleanedDir && cleanedDir == "/" {
			return permissions, util.NewValidationError(fmt.Sprintf("cannot set permissions for invalid subdirectory: %q is an alias for \"/\"", dir))
		}
		if slices.Contains(perms, PermAny) {
			permissions[cleanedDir] = []string{PermAny}
		} else {
			permissions[cleanedDir] = util.RemoveDuplicates(perms, false)
		}
	}

	return permissions, nil
}

func validatePermissions(user *User) error {
	if len(user.Permissions) == 0 {
		return util.NewI18nError(util.NewValidationError("please grant some permissions to this user"), util.I18nErrorNoPermission)
	}
	if _, ok := user.Permissions["/"]; !ok {
		return util.NewI18nError(util.NewValidationError("permissions for the root dir \"/\" must be set"), util.I18nErrorNoRootPermission)
	}
	permissions, err := validateUserPermissions(user.Permissions)
	if err != nil {
		return util.NewI18nError(err, util.I18nErrorGenericPermission)
	}
	user.Permissions = permissions
	return nil
}

func validatePublicKeys(user *User) error {
	if len(user.PublicKeys) == 0 {
		user.PublicKeys = []string{}
	}
	var validatedKeys []string
	for idx, key := range user.PublicKeys {
		if key == "" {
			continue
		}
		out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
		if err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("error parsing public key at position %d: %v", idx, err)),
				util.I18nErrorPubKeyInvalid,
			)
		}
		if out.Type() == ssh.InsecureKeyAlgoDSA { //nolint:staticcheck
			providerLog(logger.LevelError, "dsa public key not accepted, position: %d", idx)
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("DSA key format is insecure and it is not allowed for key at position %d", idx)),
				util.I18nErrorKeyInsecure,
			)
		}
		if k, ok := out.(ssh.CryptoPublicKey); ok {
			cryptoKey := k.CryptoPublicKey()
			if rsaKey, ok := cryptoKey.(*rsa.PublicKey); ok {
				if size := rsaKey.N.BitLen(); size < 2048 {
					providerLog(logger.LevelError, "rsa key with size %d at position %d not accepted, minimum 2048", size, idx)
					return util.NewI18nError(
						util.NewValidationError(fmt.Sprintf("invalid size %d for rsa key at position %d, minimum 2048",
							size, idx)),
						util.I18nErrorKeySizeInvalid,
					)
				}
			}
		}

		validatedKeys = append(validatedKeys, key)
	}
	user.PublicKeys = util.RemoveDuplicates(validatedKeys, false)
	return nil
}

func validateFiltersPatternExtensions(baseFilters *sdk.BaseUserFilters) error {
	if len(baseFilters.FilePatterns) == 0 {
		baseFilters.FilePatterns = []sdk.PatternsFilter{}
		return nil
	}
	filteredPaths := []string{}
	var filters []sdk.PatternsFilter
	for _, f := range baseFilters.FilePatterns {
		cleanedPath := filepath.ToSlash(path.Clean(f.Path))
		if !path.IsAbs(cleanedPath) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("invalid path %q for file patterns filter", f.Path)),
				util.I18nErrorFilePatternPathInvalid,
			)
		}
		if slices.Contains(filteredPaths, cleanedPath) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("duplicate file patterns filter for path %q", f.Path)),
				util.I18nErrorFilePatternDuplicated,
			)
		}
		if len(f.AllowedPatterns) == 0 && len(f.DeniedPatterns) == 0 {
			return util.NewValidationError(fmt.Sprintf("empty file patterns filter for path %q", f.Path))
		}
		if f.DenyPolicy < sdk.DenyPolicyDefault || f.DenyPolicy > sdk.DenyPolicyHide {
			return util.NewValidationError(fmt.Sprintf("invalid deny policy %v for path %q", f.DenyPolicy, f.Path))
		}
		f.Path = cleanedPath
		allowed := make([]string, 0, len(f.AllowedPatterns))
		denied := make([]string, 0, len(f.DeniedPatterns))
		for _, pattern := range f.AllowedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return util.NewI18nError(
					util.NewValidationError(fmt.Sprintf("invalid file pattern filter %q", pattern)),
					util.I18nErrorFilePatternInvalid,
				)
			}
			allowed = append(allowed, strings.ToLower(pattern))
		}
		for _, pattern := range f.DeniedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return util.NewI18nError(
					util.NewValidationError(fmt.Sprintf("invalid file pattern filter %q", pattern)),
					util.I18nErrorFilePatternInvalid,
				)
			}
			denied = append(denied, strings.ToLower(pattern))
		}
		f.AllowedPatterns = util.RemoveDuplicates(allowed, false)
		f.DeniedPatterns = util.RemoveDuplicates(denied, false)
		filters = append(filters, f)
		filteredPaths = append(filteredPaths, cleanedPath)
	}
	baseFilters.FilePatterns = filters
	return nil
}

func checkEmptyFiltersStruct(filters *sdk.BaseUserFilters) {
	if len(filters.AllowedIP) == 0 {
		filters.AllowedIP = []string{}
	}
	if len(filters.DeniedIP) == 0 {
		filters.DeniedIP = []string{}
	}
	if len(filters.DeniedLoginMethods) == 0 {
		filters.DeniedLoginMethods = []string{}
	}
	if len(filters.DeniedProtocols) == 0 {
		filters.DeniedProtocols = []string{}
	}
}

func validateIPFilters(filters *sdk.BaseUserFilters) error {
	filters.DeniedIP = util.RemoveDuplicates(filters.DeniedIP, false)
	for _, IPMask := range filters.DeniedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse denied IP/Mask %q: %v", IPMask, err))
		}
	}
	filters.AllowedIP = util.RemoveDuplicates(filters.AllowedIP, false)
	for _, IPMask := range filters.AllowedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse allowed IP/Mask %q: %v", IPMask, err))
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
			return util.NewValidationError(fmt.Sprintf("could not parse bandwidth limit source %q: %v", source, err))
		}
	}
	return nil
}

func validateBandwidthLimitsFilter(filters *sdk.BaseUserFilters) error {
	for idx, bandwidthLimit := range filters.BandwidthLimits {
		if err := validateBandwidthLimit(bandwidthLimit); err != nil {
			return err
		}
		if bandwidthLimit.DownloadBandwidth < 0 {
			filters.BandwidthLimits[idx].DownloadBandwidth = 0
		}
		if bandwidthLimit.UploadBandwidth < 0 {
			filters.BandwidthLimits[idx].UploadBandwidth = 0
		}
	}
	return nil
}

func updateFiltersValues(filters *sdk.BaseUserFilters) {
	if filters.StartDirectory != "" {
		filters.StartDirectory = util.CleanPath(filters.StartDirectory)
		if filters.StartDirectory == "/" {
			filters.StartDirectory = ""
		}
	}
}

func validateFilterProtocols(filters *sdk.BaseUserFilters) error {
	if len(filters.DeniedProtocols) >= len(ValidProtocols) {
		return util.NewValidationError("invalid denied_protocols")
	}
	for _, p := range filters.DeniedProtocols {
		if !slices.Contains(ValidProtocols, p) {
			return util.NewValidationError(fmt.Sprintf("invalid denied protocol %q", p))
		}
	}

	for _, p := range filters.TwoFactorAuthProtocols {
		if !slices.Contains(MFAProtocols, p) {
			return util.NewValidationError(fmt.Sprintf("invalid two factor protocol %q", p))
		}
	}
	return nil
}

func validateTLSCerts(certs []string) ([]string, error) {
	var validateCerts []string
	for idx, cert := range certs {
		if cert == "" {
			continue
		}
		derBlock, _ := pem.Decode([]byte(cert))
		if derBlock == nil {
			return nil, util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("invalid TLS certificate %d", idx)),
				util.I18nErrorInvalidTLSCert,
			)
		}
		crt, err := x509.ParseCertificate(derBlock.Bytes)
		if err != nil {
			return nil, util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("error parsing TLS certificate %d", idx)),
				util.I18nErrorInvalidTLSCert,
			)
		}
		if crt.PublicKeyAlgorithm == x509.RSA {
			if rsaCert, ok := crt.PublicKey.(*rsa.PublicKey); ok {
				if size := rsaCert.N.BitLen(); size < 2048 {
					providerLog(logger.LevelError, "rsa cert with size %d not accepted, minimum 2048", size)
					return nil, util.NewI18nError(
						util.NewValidationError(fmt.Sprintf("invalid size %d for rsa cert at position %d, minimum 2048",
							size, idx)),
						util.I18nErrorKeySizeInvalid,
					)
				}
			}
		}
		validateCerts = append(validateCerts, cert)
	}
	return validateCerts, nil
}

func validateBaseFilters(filters *sdk.BaseUserFilters) error {
	checkEmptyFiltersStruct(filters)
	if err := validateIPFilters(filters); err != nil {
		return util.NewI18nError(err, util.I18nErrorIPFiltersInvalid)
	}
	if err := validateBandwidthLimitsFilter(filters); err != nil {
		return util.NewI18nError(err, util.I18nErrorSourceBWLimitInvalid)
	}
	if len(filters.DeniedLoginMethods) >= len(ValidLoginMethods) {
		return util.NewValidationError("invalid denied_login_methods")
	}
	for _, loginMethod := range filters.DeniedLoginMethods {
		if !slices.Contains(ValidLoginMethods, loginMethod) {
			return util.NewValidationError(fmt.Sprintf("invalid login method: %q", loginMethod))
		}
	}
	if err := validateFilterProtocols(filters); err != nil {
		return err
	}
	if filters.TLSUsername != "" {
		if !slices.Contains(validTLSUsernames, string(filters.TLSUsername)) {
			return util.NewValidationError(fmt.Sprintf("invalid TLS username: %q", filters.TLSUsername))
		}
	}
	certs, err := validateTLSCerts(filters.TLSCerts)
	if err != nil {
		return err
	}
	filters.TLSCerts = certs
	for _, opts := range filters.WebClient {
		if !slices.Contains(sdk.WebClientOptions, opts) {
			return util.NewValidationError(fmt.Sprintf("invalid web client options %q", opts))
		}
	}
	if filters.MaxSharesExpiration > 0 && filters.MaxSharesExpiration < filters.DefaultSharesExpiration {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("default shares expiration: %d must be less than or equal to max shares expiration: %d",
				filters.DefaultSharesExpiration, filters.MaxSharesExpiration)),
			util.I18nErrorShareExpirationInvalid,
		)
	}
	updateFiltersValues(filters)

	if err := validateAccessTimeFilters(filters); err != nil {
		return err
	}

	return validateFiltersPatternExtensions(filters)
}

func isTimeOfDayValid(value string) bool {
	if len(value) != 5 {
		return false
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	if hour < 0 || hour > 23 {
		return false
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	if minute < 0 || minute > 59 {
		return false
	}
	return true
}

func validateAccessTimeFilters(filters *sdk.BaseUserFilters) error {
	for _, period := range filters.AccessTime {
		if period.DayOfWeek < int(time.Sunday) || period.DayOfWeek > int(time.Saturday) {
			return util.NewValidationError(fmt.Sprintf("invalid day of week: %d", period.DayOfWeek))
		}
		if !isTimeOfDayValid(period.From) || !isTimeOfDayValid(period.To) {
			return util.NewI18nError(
				util.NewValidationError("invalid time of day. Supported format: HH:MM"),
				util.I18nErrorTimeOfDayInvalid,
			)
		}
		if period.To <= period.From {
			return util.NewI18nError(
				util.NewValidationError("invalid time of day. The end time cannot be earlier than the start time"),
				util.I18nErrorTimeOfDayConflict,
			)
		}
	}

	return nil
}

func validateCombinedUserFilters(user *User) error {
	if user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.WebClient, sdk.WebClientMFADisabled) {
		return util.NewI18nError(
			util.NewValidationError("two-factor authentication cannot be disabled for a user with an active configuration"),
			util.I18nErrorDisableActive2FA,
		)
	}
	if user.Filters.RequirePasswordChange && slices.Contains(user.Filters.WebClient, sdk.WebClientPasswordChangeDisabled) {
		return util.NewI18nError(
			util.NewValidationError("you cannot require password change and at the same time disallow it"),
			util.I18nErrorPwdChangeConflict,
		)
	}
	if len(user.Filters.TwoFactorAuthProtocols) > 0 && slices.Contains(user.Filters.WebClient, sdk.WebClientMFADisabled) {
		return util.NewI18nError(
			util.NewValidationError("you cannot require two-factor authentication and at the same time disallow it"),
			util.I18nError2FAConflict,
		)
	}
	return nil
}

func validateEmails(user *User) error {
	if user.Email != "" && !util.IsEmailValid(user.Email) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("email %q is not valid", user.Email)),
			util.I18nErrorInvalidEmail,
		)
	}
	for _, email := range user.Filters.AdditionalEmails {
		if !util.IsEmailValid(email) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("email %q is not valid", email)),
				util.I18nErrorInvalidEmail,
			)
		}
	}
	return nil
}

func validateBaseParams(user *User) error {
	if user.Username == "" {
		return util.NewI18nError(util.NewValidationError("username is mandatory"), util.I18nErrorUsernameRequired)
	}
	if err := checkReservedUsernames(user.Username); err != nil {
		return util.NewI18nError(err, util.I18nErrorReservedUsername)
	}
	if err := validateEmails(user); err != nil {
		return err
	}
	if config.NamingRules&1 == 0 && !usernameRegex.MatchString(user.Username) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("username %q is not valid, the following characters are allowed: a-zA-Z0-9-_.~", user.Username)),
			util.I18nErrorInvalidUser,
		)
	}
	if user.hasRedactedSecret() {
		return util.NewValidationError("cannot save a user with a redacted secret")
	}
	if user.HomeDir == "" {
		return util.NewI18nError(util.NewValidationError("home_dir is mandatory"), util.I18nErrorHomeRequired)
	}
	// we can have users with no passwords and public keys, they can authenticate via SSH user certs or OIDC
	/*if user.Password == "" && len(user.PublicKeys) == 0 {
		return util.NewValidationError("please set a password or at least a public_key")
	}*/
	if !filepath.IsAbs(user.HomeDir) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("home_dir must be an absolute path, actual value: %v", user.HomeDir)),
			util.I18nErrorHomeInvalid,
		)
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
	if user.Filters.IsAnonymous {
		user.setAnonymousSettings()
	}
	err := user.FsConfig.Validate(user.GetEncryptionAdditionalData())
	if err != nil {
		return err
	}
	return nil
}

func hashPlainPassword(plainPwd string) (string, error) {
	if config.PasswordHashing.Algo == HashingAlgoBcrypt {
		pwd, err := bcrypt.GenerateFromPassword([]byte(plainPwd), config.PasswordHashing.BcryptOptions.Cost)
		if err != nil {
			return "", fmt.Errorf("bcrypt hashing error: %w", err)
		}
		return util.BytesToString(pwd), nil
	}
	pwd, err := argon2id.CreateHash(plainPwd, argon2Params)
	if err != nil {
		return "", fmt.Errorf("argon2ID hashing error: %w", err)
	}
	return pwd, nil
}

func createUserPasswordHash(user *User) error {
	if user.Password != "" && !user.IsPasswordHashed() {
		if minEntropy := user.getMinPasswordEntropy(); minEntropy > 0 {
			if err := passwordvalidator.Validate(user.Password, minEntropy); err != nil {
				return util.NewI18nError(util.NewValidationError(err.Error()), util.I18nErrorPasswordComplexity)
			}
		}
		hashedPwd, err := hashPlainPassword(user.Password)
		if err != nil {
			return err
		}
		user.Password = hashedPwd
		user.LastPasswordChange = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	return nil
}

// ValidateFolder returns an error if the folder is not valid
// FIXME: this should be defined as Folder struct method
func ValidateFolder(folder *vfs.BaseVirtualFolder) error {
	folder.FsConfig.SetEmptySecretsIfNil()
	if folder.Name == "" {
		return util.NewI18nError(util.NewValidationError("folder name is mandatory"), util.I18nErrorNameRequired)
	}
	if config.NamingRules&1 == 0 && !usernameRegex.MatchString(folder.Name) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("folder name %q is not valid, the following characters are allowed: a-zA-Z0-9-_.~", folder.Name)),
			util.I18nErrorInvalidName,
		)
	}
	if folder.FsConfig.Provider == sdk.LocalFilesystemProvider || folder.FsConfig.Provider == sdk.CryptedFilesystemProvider ||
		folder.MappedPath != "" {
		cleanedMPath := filepath.Clean(folder.MappedPath)
		if !filepath.IsAbs(cleanedMPath) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("invalid folder mapped path %q", folder.MappedPath)),
				util.I18nErrorInvalidHomeDir,
			)
		}
		folder.MappedPath = cleanedMPath
	}
	if folder.HasRedactedSecret() {
		return errors.New("cannot save a folder with a redacted secret")
	}
	return folder.FsConfig.Validate(folder.GetEncryptionAdditionalData())
}

// ValidateUser returns an error if the user is not valid
// FIXME: this should be defined as User struct method
func ValidateUser(user *User) error {
	user.OIDCCustomFields = nil
	user.HasPassword = false
	user.SetEmptySecretsIfNil()
	buildUserHomeDir(user)
	if err := validateBaseParams(user); err != nil {
		return err
	}
	if err := validateUserGroups(user); err != nil {
		return err
	}
	if err := validatePermissions(user); err != nil {
		return err
	}
	if err := validateUserTOTPConfig(&user.Filters.TOTPConfig, user.Username); err != nil {
		return util.NewI18nError(err, util.I18nError2FAInvalid)
	}
	if err := validateUserRecoveryCodes(user); err != nil {
		return util.NewI18nError(err, util.I18nErrorRecoveryCodesInvalid)
	}
	vfolders, err := validateAssociatedVirtualFolders(user.VirtualFolders)
	if err != nil {
		return err
	}
	user.VirtualFolders = vfolders
	if user.Status < 0 || user.Status > 1 {
		return util.NewValidationError(fmt.Sprintf("invalid user status: %v", user.Status))
	}
	if err := createUserPasswordHash(user); err != nil {
		return err
	}
	if err := validatePublicKeys(user); err != nil {
		return err
	}
	if err := validateBaseFilters(&user.Filters.BaseUserFilters); err != nil {
		return err
	}
	if !user.HasExternalAuth() {
		user.Filters.ExternalAuthCacheTime = 0
	}
	return validateCombinedUserFilters(user)
}

func isPasswordOK(user *User, password string) (bool, error) {
	if config.PasswordCaching {
		found, match := cachedUserPasswords.Check(user.Username, password, user.Password)
		if found {
			return match, nil
		}
	}

	match := false
	updatePwd := true
	var err error

	switch {
	case strings.HasPrefix(user.Password, bcryptPwdPrefix):
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			return match, ErrInvalidCredentials
		}
		match = true
		updatePwd = config.PasswordHashing.Algo != HashingAlgoBcrypt
	case strings.HasPrefix(user.Password, argonPwdPrefix):
		match, err = argon2id.ComparePasswordAndHash(password, user.Password)
		if err != nil {
			providerLog(logger.LevelError, "error comparing password with argon hash: %v", err)
			return match, err
		}
		updatePwd = config.PasswordHashing.Algo != HashingAlgoArgon2ID
	case util.IsStringPrefixInSlice(user.Password, unixPwdPrefixes):
		match, err = compareUnixPasswordAndHash(user, password)
		if err != nil {
			return match, err
		}
	case util.IsStringPrefixInSlice(user.Password, pbkdfPwdPrefixes):
		match, err = comparePbkdf2PasswordAndHash(password, user.Password)
		if err != nil {
			return match, err
		}
	case util.IsStringPrefixInSlice(user.Password, digestPwdPrefixes):
		match = compareDigestPasswordAndHash(user, password)
	}

	if err == nil && match {
		cachedUserPasswords.Add(user.Username, password, user.Password)
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
	err := user.LoadAndApplyGroupSettings()
	if err != nil {
		return *user, err
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	switch protocol {
	case protocolFTP, protocolWebDAV:
		for _, cert := range user.Filters.TLSCerts {
			derBlock, _ := pem.Decode(util.StringToBytes(cert))
			if derBlock != nil && bytes.Equal(derBlock.Bytes, tlsCert.Raw) {
				return *user, nil
			}
		}
		if user.Filters.TLSUsername == sdk.TLSUsernameCN {
			if user.Username == tlsCert.Subject.CommonName {
				return *user, nil
			}
			return *user, fmt.Errorf("CN %q does not match username %q", tlsCert.Subject.CommonName, user.Username)
		}
		return *user, errors.New("TLS certificate is not valid")
	default:
		return *user, fmt.Errorf("certificate authentication is not supported for protocol %v", protocol)
	}
}

func checkUserAndPass(user *User, password, ip, protocol string) (User, error) {
	err := user.LoadAndApplyGroupSettings()
	if err != nil {
		return *user, err
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	if protocol != protocolHTTP && user.MustChangePassword() {
		return *user, errors.New("login not allowed, password change required")
	}
	if user.Filters.IsAnonymous {
		user.setAnonymousSettings()
		return *user, nil
	}
	password, err = checkUserPasscode(user, password, protocol)
	if err != nil {
		return *user, ErrInvalidCredentials
	}
	if user.Password == "" || strings.TrimSpace(password) == "" {
		return *user, errors.New("credentials cannot be null or empty")
	}
	if !user.Filters.Hooks.CheckPasswordDisabled {
		hookResponse, err := executeCheckPasswordHook(user.Username, password, ip, protocol)
		if err != nil {
			providerLog(logger.LevelDebug, "error executing check password hook for user %q, ip %v, protocol %v: %v",
				user.Username, ip, protocol, err)
			return *user, errors.New("unable to check credentials")
		}
		switch hookResponse.Status {
		case -1:
			// no hook configured
		case 1:
			providerLog(logger.LevelDebug, "password accepted by check password hook for user %q, ip %v, protocol %v",
				user.Username, ip, protocol)
			return *user, nil
		case 2:
			providerLog(logger.LevelDebug, "partial success from check password hook for user %q, ip %v, protocol %v",
				user.Username, ip, protocol)
			password = hookResponse.ToVerify
		default:
			providerLog(logger.LevelDebug, "password rejected by check password hook for user %q, ip %v, protocol %v, status: %v",
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
			if slices.Contains(user.Filters.TOTPConfig.Protocols, protocol) {
				// the TOTP passcode has six digits
				pwdLen := len(password)
				if pwdLen < 7 {
					providerLog(logger.LevelDebug, "password len %v is too short to contain a passcode, user %q, protocol %v",
						pwdLen, user.Username, protocol)
					return "", util.NewValidationError("password too short, cannot contain the passcode")
				}
				err := user.Filters.TOTPConfig.Secret.TryDecrypt()
				if err != nil {
					providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %q, protocol %v, err: %v",
						user.Username, protocol, err)
					return "", err
				}
				pwd := password[0:(pwdLen - 6)]
				passcode := password[(pwdLen - 6):]
				match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
					user.Filters.TOTPConfig.Secret.GetPayload())
				if !match || err != nil {
					providerLog(logger.LevelWarn, "invalid passcode for user %q, protocol %v, err: %v",
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
	err := user.LoadAndApplyGroupSettings()
	if err != nil {
		return *user, "", err
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, "", err
	}
	if isSSHCert {
		return *user, "", nil
	}
	if len(user.PublicKeys) == 0 {
		return *user, "", ErrInvalidCredentials
	}
	for idx, key := range user.PublicKeys {
		storedKey, comment, _, _, err := ssh.ParseAuthorizedKey(util.StringToBytes(key))
		if err != nil {
			providerLog(logger.LevelError, "error parsing stored public key %d for user %s: %v", idx, user.Username, err)
			return *user, "", err
		}
		if bytes.Equal(storedKey.Marshal(), pubKey) {
			return *user, fmt.Sprintf("%s:%s", ssh.FingerprintSHA256(storedKey), comment), nil
		}
	}
	return *user, "", ErrInvalidCredentials
}

func compareDigestPasswordAndHash(user *User, password string) bool {
	if strings.HasPrefix(user.Password, md5DigestPwdPrefix) {
		h := md5.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", md5DigestPwdPrefix, h.Sum(nil)) == user.Password
	}
	if strings.HasPrefix(user.Password, sha256DigestPwdPrefix) {
		h := sha256.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", sha256DigestPwdPrefix, h.Sum(nil)) == user.Password
	}
	if strings.HasPrefix(user.Password, sha512DigestPwdPrefix) {
		h := sha512.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", sha512DigestPwdPrefix, h.Sum(nil)) == user.Password
	}
	return false
}

func compareUnixPasswordAndHash(user *User, password string) (bool, error) {
	if strings.HasPrefix(user.Password, yescryptPwdPrefix) {
		return compareYescryptPassword(user.Password, password)
	}
	var crypter crypt.Crypter
	if strings.HasPrefix(user.Password, sha512cryptPwdPrefix) {
		crypter = sha512_crypt.New()
	} else if strings.HasPrefix(user.Password, sha256cryptPwdPrefix) {
		crypter = sha256_crypt.New()
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

func getSSLMode() string {
	switch config.Driver {
	case PGSQLDataProviderName, CockroachDataProviderName:
		switch config.SSLMode {
		case 0:
			return "disable"
		case 1:
			return "require"
		case 2:
			return "verify-ca"
		case 3:
			return "verify-full"
		case 4:
			return "prefer"
		case 5:
			return "allow"
		}
	case MySQLDataProviderName:
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

func doBuiltinKeyboardInteractiveAuth(user *User, client ssh.KeyboardInteractiveChallenge,
	ip, protocol string, isPartialAuth bool,
) (int, error) {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		return 0, err
	}
	hasSecondFactor := user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.TOTPConfig.Protocols, protocolSSH)
	if !isPartialAuth || !hasSecondFactor {
		answers, err := client("", "", []string{"Password: "}, []bool{false})
		if err != nil {
			return 0, err
		}
		if len(answers) != 1 {
			return 0, fmt.Errorf("unexpected number of answers: %d", len(answers))
		}
		_, err = checkUserAndPass(user, answers[0], ip, protocol)
		if err != nil {
			return 0, err
		}
	}
	return checkKeyboardInteractiveSecondFactor(user, client, protocol)
}

func checkKeyboardInteractiveSecondFactor(user *User, client ssh.KeyboardInteractiveChallenge, protocol string) (int, error) {
	if !user.Filters.TOTPConfig.Enabled || !slices.Contains(user.Filters.TOTPConfig.Protocols, protocolSSH) {
		return 1, nil
	}
	err := user.Filters.TOTPConfig.Secret.TryDecrypt()
	if err != nil {
		providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %q, protocol %v, err: %v",
			user.Username, protocol, err)
		return 0, err
	}
	answers, err := client("", "", []string{"Authentication code: "}, []bool{false})
	if err != nil {
		return 0, err
	}
	if len(answers) != 1 {
		return 0, fmt.Errorf("unexpected number of answers: %v", len(answers))
	}
	match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, answers[0],
		user.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		providerLog(logger.LevelWarn, "invalid passcode for user %q, protocol %v, err: %v",
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
			if !user.Filters.TOTPConfig.Enabled || !slices.Contains(user.Filters.TOTPConfig.Protocols, protocolSSH) {
				providerLog(logger.LevelInfo, "keyboard interactive auth error: unable to check TOTP passcode, TOTP is not enabled for user %q",
					user.Username)
				return answers, errors.New("TOTP not enabled for SSH protocol")
			}
			err := user.Filters.TOTPConfig.Secret.TryDecrypt()
			if err != nil {
				providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %q, protocol %v, err: %v",
					user.Username, protocol, err)
				return answers, fmt.Errorf("unable to decrypt TOTP secret: %w", err)
			}
			match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, answers[0],
				user.Filters.TOTPConfig.Secret.GetPayload())
			if !match || err != nil {
				providerLog(logger.LevelInfo, "keyboard interactive auth error: unable to validate passcode for user %q, match? %v, err: %v",
					user.Username, match, err)
				return answers, errors.New("unable to validate TOTP passcode")
			}
		} else {
			_, err = checkUserAndPass(user, answers[0], ip, protocol)
			providerLog(logger.LevelInfo, "interactive auth hook requested password validation for user %q, validation error: %v",
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
	timeout, env, args := command.GetConfig(authHook, command.HookKeyboardInteractive)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, authHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_AUTHD_USERNAME=%s", user.Username),
		fmt.Sprintf("SFTPGO_AUTHD_IP=%s", ip),
		fmt.Sprintf("SFTPGO_AUTHD_PASSWORD=%s", user.Password))
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
			providerLog(logger.LevelWarn, "error waiting for %q process to exit: %v", authHook, err)
		}
	}()

	return authResult, err
}

func doKeyboardInteractiveAuth(user *User, authHook string, client ssh.KeyboardInteractiveChallenge,
	ip, protocol string, isPartialAuth bool,
) (User, error) {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		return *user, err
	}
	var authResult int
	var err error
	if !user.Filters.Hooks.ExternalAuthDisabled {
		if plugin.Handler.HasAuthScope(plugin.AuthScopeKeyboardInteractive) {
			authResult, err = executeKeyboardInteractivePlugin(user, client, ip, protocol)
			if authResult == 1 && err == nil {
				authResult, err = checkKeyboardInteractiveSecondFactor(user, client, protocol)
			}
		} else if authHook != "" {
			if strings.HasPrefix(authHook, "http") {
				authResult, err = executeKeyboardInteractiveHTTPHook(user, authHook, client, ip, protocol)
			} else {
				authResult, err = executeKeyboardInteractiveProgram(user, authHook, client, ip, protocol)
			}
		} else {
			authResult, err = doBuiltinKeyboardInteractiveAuth(user, client, ip, protocol, isPartialAuth)
		}
	} else {
		authResult, err = doBuiltinKeyboardInteractiveAuth(user, client, ip, protocol, isPartialAuth)
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
	timeout, env, args := command.GetConfig(config.CheckPasswordHook, command.HookCheckPassword)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, config.CheckPasswordHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_AUTHD_USERNAME=%s", username),
		fmt.Sprintf("SFTPGO_AUTHD_PASSWORD=%s", password),
		fmt.Sprintf("SFTPGO_AUTHD_IP=%s", ip),
		fmt.Sprintf("SFTPGO_AUTHD_PROTOCOL=%s", protocol),
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
			providerLog(logger.LevelError, "invalid url for pre-login hook %q, error: %v", config.PreLoginHook, err)
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
	timeout, env, args := command.GetConfig(config.PreLoginHook, command.HookPreLogin)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, config.PreLoginHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_LOGIND_USER=%s", userAsJSON),
		fmt.Sprintf("SFTPGO_LOGIND_METHOD=%s", loginMethod),
		fmt.Sprintf("SFTPGO_LOGIND_IP=%s", ip),
		fmt.Sprintf("SFTPGO_LOGIND_PROTOCOL=%s", protocol),
	)
	return cmd.Output()
}

func executePreLoginHook(username, loginMethod, ip, protocol string, oidcTokenFields *map[string]any) (User, error) {
	u, mergedUser, userAsJSON, err := getUserAndJSONForHook(username, oidcTokenFields)
	if err != nil {
		return u, err
	}
	if mergedUser.Filters.Hooks.PreLoginDisabled {
		return u, nil
	}
	startTime := time.Now()
	out, err := getPreLoginHookResponse(loginMethod, ip, protocol, userAsJSON)
	if err != nil {
		return u, fmt.Errorf("pre-login hook error: %v, username %q, ip %v, protocol %v elapsed %v",
			err, username, ip, protocol, time.Since(startTime))
	}
	providerLog(logger.LevelDebug, "pre-login hook completed, elapsed: %s", time.Since(startTime))
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from pre-login hook, no modification requested for user %q id: %d",
			username, u.ID)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		return u, nil
	}

	userID := u.ID
	userUsedQuotaSize := u.UsedQuotaSize
	userUsedQuotaFiles := u.UsedQuotaFiles
	userUsedDownloadTransfer := u.UsedDownloadDataTransfer
	userUsedUploadTransfer := u.UsedUploadDataTransfer
	userLastQuotaUpdate := u.LastQuotaUpdate
	userLastLogin := u.LastLogin
	userFirstDownload := u.FirstDownload
	userFirstUpload := u.FirstUpload
	userLastPwdChange := u.LastPasswordChange
	userCreatedAt := u.CreatedAt
	totpConfig := u.Filters.TOTPConfig
	recoveryCodes := u.Filters.RecoveryCodes
	err = json.Unmarshal(out, &u)
	if err != nil {
		return u, fmt.Errorf("invalid pre-login hook response %q, error: %v", out, err)
	}
	u.ID = userID
	u.UsedQuotaSize = userUsedQuotaSize
	u.UsedQuotaFiles = userUsedQuotaFiles
	u.UsedUploadDataTransfer = userUsedUploadTransfer
	u.UsedDownloadDataTransfer = userUsedDownloadTransfer
	u.LastQuotaUpdate = userLastQuotaUpdate
	u.LastLogin = userLastLogin
	u.LastPasswordChange = userLastPwdChange
	u.FirstDownload = userFirstDownload
	u.FirstUpload = userFirstUpload
	u.CreatedAt = userCreatedAt
	if userID == 0 {
		err = provider.addUser(&u)
	} else {
		u.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		// preserve TOTP config and recovery codes
		u.Filters.TOTPConfig = totpConfig
		u.Filters.RecoveryCodes = recoveryCodes
		err = provider.updateUser(&u)
	}
	if err != nil {
		return u, err
	}
	user, err := provider.userExists(username, "")
	if err != nil {
		return u, err
	}
	providerLog(logger.LevelDebug, "user %q added/updated from pre-login hook response, id: %d", username, userID)
	if userID > 0 {
		webDAVUsersCache.swap(&user, "")
	}
	return user, nil
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
		actionsConcurrencyGuard <- struct{}{}
		defer func() {
			<-actionsConcurrencyGuard
		}()

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
				providerLog(logger.LevelDebug, "Invalid post-login hook %q", config.PostLoginHook)
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
			providerLog(logger.LevelDebug, "post login hook executed for user %q, ip %v, protocol %v, response code: %v, elapsed: %v err: %v",
				user.Username, ip, protocol, respCode, time.Since(startTime), err)
			return
		}
		timeout, env, args := command.GetConfig(config.PostLoginHook, command.HookPostLogin)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, config.PostLoginHook, args...)
		cmd.Env = append(env,
			fmt.Sprintf("SFTPGO_LOGIND_USER=%s", userAsJSON),
			fmt.Sprintf("SFTPGO_LOGIND_IP=%s", ip),
			fmt.Sprintf("SFTPGO_LOGIND_METHOD=%s", loginMethod),
			fmt.Sprintf("SFTPGO_LOGIND_STATUS=%s", status),
			fmt.Sprintf("SFTPGO_LOGIND_PROTOCOL=%s", protocol))
		startTime := time.Now()
		err = cmd.Run()
		providerLog(logger.LevelDebug, "post login hook executed for user %q, ip %v, protocol %v, elapsed %v err: %v",
			user.Username, ip, protocol, time.Since(startTime), err)
	}()
}

func getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol string, cert *x509.Certificate,
	user User,
) ([]byte, error) {
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
		authRequest := make(map[string]any)
		authRequest["username"] = username
		authRequest["ip"] = ip
		authRequest["password"] = password
		authRequest["public_key"] = pkey
		authRequest["protocol"] = protocol
		authRequest["keyboard_interactive"] = keyboardInteractive
		authRequest["tls_cert"] = tlsCert
		if user.ID > 0 {
			authRequest["user"] = user
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
	var userAsJSON []byte
	var err error
	if user.ID > 0 {
		userAsJSON, err = json.Marshal(user)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize user as JSON: %w", err)
		}
	}
	timeout, env, args := command.GetConfig(config.ExternalAuthHook, command.HookExternalAuth)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, config.ExternalAuthHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_AUTHD_USERNAME=%s", username),
		fmt.Sprintf("SFTPGO_AUTHD_USER=%s", userAsJSON),
		fmt.Sprintf("SFTPGO_AUTHD_IP=%s", ip),
		fmt.Sprintf("SFTPGO_AUTHD_PASSWORD=%s", password),
		fmt.Sprintf("SFTPGO_AUTHD_PUBLIC_KEY=%s", pkey),
		fmt.Sprintf("SFTPGO_AUTHD_PROTOCOL=%s", protocol),
		fmt.Sprintf("SFTPGO_AUTHD_TLS_CERT=%s", strings.ReplaceAll(tlsCert, "\n", "\\n")),
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
	user.LastPasswordChange = 0
}

func checkPasswordAfterEmptyExtAuthResponse(user *User, plainPwd, protocol string) error {
	if plainPwd == "" {
		return nil
	}
	match, err := isPasswordOK(user, plainPwd)
	if match && err == nil {
		return nil
	}

	hashedPwd, err := hashPlainPassword(plainPwd)
	if err != nil {
		providerLog(logger.LevelError, "unable to hash password for user %q after empty external response: %v",
			user.Username, err)
		return err
	}
	err = provider.updateUserPassword(user.Username, hashedPwd)
	if err != nil {
		providerLog(logger.LevelError, "unable to update password for user %q after empty external response: %v",
			user.Username, err)
	}
	user.Password = hashedPwd
	cachedUserPasswords.Add(user.Username, plainPwd, user.Password)
	if protocol != protocolWebDAV {
		webDAVUsersCache.swap(user, plainPwd)
	}
	providerLog(logger.LevelDebug, "updated password for user %q after empty external auth response", user.Username)
	return nil
}

func doExternalAuth(username, password string, pubKey []byte, keyboardInteractive, ip, protocol string,
	tlsCert *x509.Certificate,
) (User, error) {
	var user User

	u, mergedUser, err := getUserForHook(username, nil)
	if err != nil {
		return user, err
	}

	if mergedUser.skipExternalAuth() {
		return u, nil
	}

	pkey, err := util.GetSSHPublicKeyAsString(pubKey)
	if err != nil {
		return user, err
	}

	startTime := time.Now()
	out, err := getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol, tlsCert, u)
	if err != nil {
		return user, fmt.Errorf("external auth error for user %q, elapsed: %s: %w", username, time.Since(startTime), err)
	}
	providerLog(logger.LevelDebug, "external auth completed for user %q, elapsed: %s", username, time.Since(startTime))
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from external hook, no modification requested for user %q, id: %d",
			username, u.ID)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		err = checkPasswordAfterEmptyExtAuthResponse(&u, password, protocol)
		return u, err
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
		u, err = provider.userExists(user.Username, "")
	}
	if u.ID > 0 && err == nil {
		user.ID = u.ID
		user.UsedQuotaSize = u.UsedQuotaSize
		user.UsedQuotaFiles = u.UsedQuotaFiles
		user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
		user.LastQuotaUpdate = u.LastQuotaUpdate
		user.LastLogin = u.LastLogin
		user.LastPasswordChange = u.LastPasswordChange
		user.FirstDownload = u.FirstDownload
		user.FirstUpload = u.FirstUpload
		user.CreatedAt = u.CreatedAt
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		// preserve TOTP config and recovery codes
		user.Filters.TOTPConfig = u.Filters.TOTPConfig
		user.Filters.RecoveryCodes = u.Filters.RecoveryCodes
		user, err = updateUserAfterExternalAuth(&user)
		if err == nil {
			if protocol != protocolWebDAV {
				webDAVUsersCache.swap(&user, password)
			}
			cachedUserPasswords.Add(user.Username, password, user.Password)
			executeAction(operationUpdate, ActionExecutorSelf, "", actionObjectUser, user.Username, "", &user)
		}
		return user, err
	}
	err = provider.addUser(&user)
	if err != nil {
		return user, err
	}
	executeAction(operationAdd, ActionExecutorSelf, "", actionObjectUser, user.Username, "", &user)
	return provider.userExists(user.Username, "")
}

func doPluginAuth(username, password string, pubKey []byte, ip, protocol string,
	tlsCert *x509.Certificate, authScope int,
) (User, error) {
	var user User

	u, mergedUser, userAsJSON, err := getUserAndJSONForHook(username, nil)
	if err != nil {
		return user, err
	}

	if mergedUser.skipExternalAuth() {
		return u, nil
	}

	pkey, err := util.GetSSHPublicKeyAsString(pubKey)
	if err != nil {
		return user, err
	}

	startTime := time.Now()

	out, err := plugin.Handler.Authenticate(username, password, ip, protocol, pkey, tlsCert, authScope, userAsJSON)
	if err != nil {
		return user, fmt.Errorf("plugin auth error for user %q: %v, elapsed: %v, auth scope: %d",
			username, err, time.Since(startTime), authScope)
	}
	providerLog(logger.LevelDebug, "plugin auth completed for user %q, elapsed: %v, auth scope: %d",
		username, time.Since(startTime), authScope)
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from plugin auth, no modification requested for user %q id: %d, auth scope: %d",
			username, u.ID, authScope)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		err = checkPasswordAfterEmptyExtAuthResponse(&u, password, protocol)
		return u, err
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
		user.LastPasswordChange = u.LastPasswordChange
		user.FirstDownload = u.FirstDownload
		user.FirstUpload = u.FirstUpload
		// preserve TOTP config and recovery codes
		user.Filters.TOTPConfig = u.Filters.TOTPConfig
		user.Filters.RecoveryCodes = u.Filters.RecoveryCodes
		user, err = updateUserAfterExternalAuth(&user)
		if err == nil {
			if protocol != protocolWebDAV {
				webDAVUsersCache.swap(&user, password)
			}
			cachedUserPasswords.Add(user.Username, password, user.Password)
			executeAction(operationUpdate, ActionExecutorSelf, "", actionObjectUser, user.Username, "", &user)
		}
		return user, err
	}
	err = provider.addUser(&user)
	if err != nil {
		return user, err
	}
	executeAction(operationAdd, ActionExecutorSelf, "", actionObjectUser, user.Username, "", &user)
	return provider.userExists(user.Username, "")
}

func updateUserAfterExternalAuth(user *User) (User, error) {
	if err := provider.updateUser(user); err != nil {
		return *user, err
	}
	return provider.userExists(user.Username, "")
}

func getUserForHook(username string, oidcTokenFields *map[string]any) (User, User, error) {
	u, err := provider.userExists(username, "")
	if err != nil {
		if !errors.Is(err, util.ErrNotFound) {
			return u, u, err
		}
		u = User{
			BaseUser: sdk.BaseUser{
				ID:       0,
				Username: username,
			},
		}
	}
	mergedUser := u.getACopy()
	err = mergedUser.LoadAndApplyGroupSettings()
	if err != nil {
		return u, mergedUser, err
	}

	u.OIDCCustomFields = oidcTokenFields
	return u, mergedUser, err
}

func getUserAndJSONForHook(username string, oidcTokenFields *map[string]any) (User, User, []byte, error) {
	u, mergedUser, err := getUserForHook(username, oidcTokenFields)
	if err != nil {
		return u, mergedUser, nil, err
	}
	userAsJSON, err := json.Marshal(u)
	if err != nil {
		return u, mergedUser, userAsJSON, err
	}
	return u, mergedUser, userAsJSON, err
}

func isLastActivityRecent(lastActivity int64, minDelay time.Duration) bool {
	lastActivityTime := util.GetTimeFromMsecSinceEpoch(lastActivity)
	diff := -time.Until(lastActivityTime)
	if diff < -10*time.Second {
		return false
	}
	return diff < minDelay
}

func isExternalAuthConfigured(loginMethod string) bool {
	if config.ExternalAuthHook != "" {
		if config.ExternalAuthScope == 0 {
			return true
		}
		switch loginMethod {
		case LoginMethodPassword:
			return config.ExternalAuthScope&1 != 0
		case LoginMethodTLSCertificate:
			return config.ExternalAuthScope&8 != 0
		case LoginMethodTLSCertificateAndPwd:
			return config.ExternalAuthScope&1 != 0 || config.ExternalAuthScope&8 != 0
		}
	}
	switch loginMethod {
	case LoginMethodPassword:
		return plugin.Handler.HasAuthScope(plugin.AuthScopePassword)
	case LoginMethodTLSCertificate:
		return plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate)
	case LoginMethodTLSCertificateAndPwd:
		return plugin.Handler.HasAuthScope(plugin.AuthScopePassword) ||
			plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate)
	default:
		return false
	}
}

func replaceTemplateVars(input string) string {
	var result strings.Builder
	i := 0
	for i < len(input) {
		if i+2 <= len(input) && input[i:i+2] == "{{" {
			if i+2 < len(input) {
				nextChar := input[i+2]
				if nextChar == ' ' || nextChar == '.' || nextChar == '-' {
					// Don't replace if followed by space, dot or minus.
					result.WriteString("{{")
					i += 2
					continue
				}
			}

			// Find the closing "}}"
			closing := strings.Index(input[i:], "}}")
			if closing != -1 {
				// Replace with {{. only if it's a proper template variable.
				result.WriteString("{{.")
				result.WriteString(input[i+2 : i+closing])
				result.WriteString("}}")
				i += closing + 2
				continue
			}
		}
		result.WriteByte(input[i])
		i++
	}
	return result.String()
}

func restoreTemplateVars(input string) string {
	var result strings.Builder
	i := 0

	for i < len(input) {
		if i+3 <= len(input) && input[i:i+3] == "{{." {
			if i+3 < len(input) {
				nextChar := input[i+3]
				if nextChar == ' ' || nextChar == '.' || nextChar == '-' {
					// Don't change if it's a space, dot, or minus
					result.WriteString("{{.")
					i += 3
					continue
				}
			}
			// Find the closing "}}"
			closing := strings.Index(input[i:], "}}")
			if closing != -1 {
				// Strip the dot and write the rest
				result.WriteString("{{")
				result.WriteString(input[i+3 : i+closing])
				result.WriteString("}}")
				i += closing + 2
				continue
			}
		}

		result.WriteByte(input[i])
		i++
	}

	return result.String()
}

func updateEventActionPlaceholders(actions []BaseEventAction) ([]BaseEventAction, error) {
	var result []BaseEventAction

	for _, action := range actions {
		options, err := json.Marshal(action.Options)
		if err != nil {
			return nil, err
		}
		convertedOptions := replaceTemplateVars(string(options))
		var opts BaseEventActionOptions
		err = json.Unmarshal([]byte(convertedOptions), &opts)
		if err != nil {
			return nil, err
		}
		action.Options = opts
		result = append(result, action)
	}

	return result, nil
}

func restoreEventActionsPlaceholders(actions []BaseEventAction) ([]BaseEventAction, error) {
	var result []BaseEventAction

	for _, action := range actions {
		options, err := json.Marshal(action.Options)
		if err != nil {
			return nil, err
		}
		convertedOptions := restoreTemplateVars(string(options))
		var opts BaseEventActionOptions
		err = json.Unmarshal([]byte(convertedOptions), &opts)
		if err != nil {
			return nil, err
		}
		action.Options = opts
		result = append(result, action)
	}

	return result, nil
}

func updateEventActions() error {
	actions, err := provider.dumpEventActions()
	if err != nil {
		return err
	}
	convertedActions, err := updateEventActionPlaceholders(actions)
	if err != nil {
		return err
	}
	for _, action := range convertedActions {
		providerLog(logger.LevelInfo, "updating placeholders for event action %q", action.Name)
		if err := provider.updateEventAction(&action); err != nil {
			return fmt.Errorf("unable to save updated event action %q: %w", action.Name, err)
		}
	}
	return nil
}

func restoreEventActions() error {
	actions, err := provider.dumpEventActions()
	if err != nil {
		return err
	}
	convertedActions, err := restoreEventActionsPlaceholders(actions)
	if err != nil {
		return err
	}
	for _, action := range convertedActions {
		providerLog(logger.LevelInfo, "restoring placeholders for event action %q", action.Name)
		if err := provider.updateEventAction(&action); err != nil {
			return fmt.Errorf("unable to save updated event action %q: %w", action.Name, err)
		}
	}
	return nil
}

func updateSQLDatabaseFrom31To32(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database data version: 31 -> 32")
	providerLog(logger.LevelInfo, "updating database data version: 31 -> 32")

	if err := updateEventActions(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	return sqlCommonUpdateDatabaseVersion(ctx, dbHandle, 32)
}

func downgradeSQLDatabaseFrom32To31(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database data version: 32 -> 31")
	providerLog(logger.LevelInfo, "downgrading database data version: 32 -> 31")

	if err := restoreEventActions(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	return sqlCommonUpdateDatabaseVersion(ctx, dbHandle, 31)
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

func checkReservedUsernames(username string) error {
	if slices.Contains(reservedUsers, username) {
		return util.NewValidationError("this username is reserved")
	}
	return nil
}

func errSchemaVersionTooOld(version int) error {
	return fmt.Errorf("database schema version %d is too old, please see the upgrading docs: https://docs.sftpgo.com/latest/data-provider/#upgrading", version)
}

func providerLog(level logger.LogLevel, format string, v ...any) {
	logger.Log(level, logSender, "", format, v...)
}
