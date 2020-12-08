// Package dataprovider provides data access.
// It abstracts different data providers and exposes a common API.
package dataprovider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/alexedwards/argon2id"
	"github.com/go-chi/render"
	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	// SQLiteDataProviderName name for SQLite database provider
	SQLiteDataProviderName = "sqlite"
	// PGSQLDataProviderName name for PostgreSQL database provider
	PGSQLDataProviderName = "postgresql"
	// MySQLDataProviderName name for MySQL database provider
	MySQLDataProviderName = "mysql"
	// BoltDataProviderName name for bbolt key/value store provider
	BoltDataProviderName = "bolt"
	// MemoryDataProviderName name for memory provider
	MemoryDataProviderName = "memory"
	// DumpVersion defines the version for the dump.
	// For restore/load we support the current version and the previous one
	DumpVersion = 5

	argonPwdPrefix            = "$argon2id$"
	bcryptPwdPrefix           = "$2a$"
	pbkdf2SHA1Prefix          = "$pbkdf2-sha1$"
	pbkdf2SHA256Prefix        = "$pbkdf2-sha256$"
	pbkdf2SHA512Prefix        = "$pbkdf2-sha512$"
	pbkdf2SHA256B64SaltPrefix = "$pbkdf2-b64salt-sha256$"
	md5cryptPwdPrefix         = "$1$"
	md5cryptApr1PwdPrefix     = "$apr1$"
	sha512cryptPwdPrefix      = "$6$"
	manageUsersDisabledError  = "please set manage_users to 1 in your configuration to enable this method"
	trackQuotaDisabledError   = "please enable track_quota in your configuration to use this method"
	operationAdd              = "add"
	operationUpdate           = "update"
	operationDelete           = "delete"
	sqlPrefixValidChars       = "abcdefghijklmnopqrstuvwxyz_"
)

// ordering constants
const (
	OrderASC  = "ASC"
	OrderDESC = "DESC"
)

var (
	// SupportedProviders defines the supported data providers
	SupportedProviders = []string{SQLiteDataProviderName, PGSQLDataProviderName, MySQLDataProviderName,
		BoltDataProviderName, MemoryDataProviderName}
	// ValidPerms defines all the valid permissions for a user
	ValidPerms = []string{PermAny, PermListItems, PermDownload, PermUpload, PermOverwrite, PermRename, PermDelete,
		PermCreateDirs, PermCreateSymlinks, PermChmod, PermChown, PermChtimes}
	// ValidSSHLoginMethods defines all the valid SSH login methods
	ValidSSHLoginMethods = []string{SSHLoginMethodPublicKey, LoginMethodPassword, SSHLoginMethodKeyboardInteractive,
		SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt}
	// SSHMultiStepsLoginMethods defines the supported Multi-Step Authentications
	SSHMultiStepsLoginMethods = []string{SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt}
	// ErrNoAuthTryed defines the error for connection closed before authentication
	ErrNoAuthTryed = errors.New("no auth tryed")
	// ValidProtocols defines all the valid protcols
	ValidProtocols = []string{"SSH", "FTP", "DAV"}
	// ErrNoInitRequired defines the error returned by InitProvider if no inizialization/update is required
	ErrNoInitRequired = errors.New("The data provider is already up to date")
	// ErrInvalidCredentials defines the error to return if the supplied credentials are invalid
	ErrInvalidCredentials = errors.New("Invalid credentials")
	webDAVUsersCache      sync.Map
	config                Config
	provider              Provider
	sqlPlaceholders       []string
	hashPwdPrefixes       = []string{argonPwdPrefix, bcryptPwdPrefix, pbkdf2SHA1Prefix, pbkdf2SHA256Prefix,
		pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix, md5cryptPwdPrefix, md5cryptApr1PwdPrefix, sha512cryptPwdPrefix}
	pbkdfPwdPrefixes        = []string{pbkdf2SHA1Prefix, pbkdf2SHA256Prefix, pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix}
	pbkdfPwdB64SaltPrefixes = []string{pbkdf2SHA256B64SaltPrefix}
	unixPwdPrefixes         = []string{md5cryptPwdPrefix, md5cryptApr1PwdPrefix, sha512cryptPwdPrefix}
	logSender               = "dataProvider"
	availabilityTicker      *time.Ticker
	availabilityTickerDone  chan bool
	credentialsDirPath      string
	sqlTableUsers           = "users"
	sqlTableFolders         = "folders"
	sqlTableFoldersMapping  = "folders_mapping"
	sqlTableSchemaVersion   = "schema_version"
	argon2Params            *argon2id.Params
	lastLoginMinDelay       = 10 * time.Minute
)

type schemaVersion struct {
	Version int
}

// Argon2Options defines the options for argon2 password hashing
type Argon2Options struct {
	Memory      uint32 `json:"memory" mapstructure:"memory"`
	Iterations  uint32 `json:"iterations" mapstructure:"iterations"`
	Parallelism uint8  `json:"parallelism" mapstructure:"parallelism"`
}

// PasswordHashing defines the configuration for password hashing
type PasswordHashing struct {
	Argon2Options Argon2Options `json:"argon2_options" mapstructure:"argon2_options"`
}

// UserActions defines the action to execute on user create, update, delete.
type UserActions struct {
	// Valid values are add, update, delete. Empty slice to disable
	ExecuteOn []string `json:"execute_on" mapstructure:"execute_on"`
	// Absolute path to an external program or an HTTP URL
	Hook string `json:"hook" mapstructure:"hook"`
}

// ProviderStatus defines the provider status
type ProviderStatus struct {
	Driver   string `json:"driver"`
	IsActive bool   `json:"is_active"`
	Error    string `json:"error"`
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
	// Custom database connection string.
	// If not empty this connection string will be used instead of build one using the previous parameters
	ConnectionString string `json:"connection_string" mapstructure:"connection_string"`
	// prefix for SQL tables
	SQLTablesPrefix string `json:"sql_tables_prefix" mapstructure:"sql_tables_prefix"`
	// Set to 0 to disable users management, 1 to enable
	ManageUsers int `json:"manage_users" mapstructure:"manage_users"`
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
	// Actions to execute on user add, update, delete.
	// Update action will not be fired for internal updates such as the last login or the user quota fields.
	Actions UserActions `json:"actions" mapstructure:"actions"`
	// Absolute path to an external program or an HTTP URL to invoke for users authentication.
	// Leave empty to use builtin authentication.
	// If the authentication succeed the user will be automatically added/updated inside the defined data provider.
	// Actions defined for user added/updated will not be executed in this case.
	// This method is slower than built-in authentication methods, but it's very flexible as anyone can
	// easily write his own authentication hooks.
	ExternalAuthHook string `json:"external_auth_hook" mapstructure:"external_auth_hook"`
	// ExternalAuthScope defines the scope for the external authentication hook.
	// - 0 means all supported authentication scopes, the external hook will be executed for password,
	//     public key and keyboard interactive authentication
	// - 1 means passwords only
	// - 2 means public keys only
	// - 4 means keyboard interactive only
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
}

// BackupData defines the structure for the backup/restore files
type BackupData struct {
	Users   []User                  `json:"users"`
	Folders []vfs.BaseVirtualFolder `json:"folders"`
	Version int                     `json:"version"`
}

type keyboardAuthHookRequest struct {
	RequestID string   `json:"request_id"`
	Username  string   `json:"username,omitempty"`
	IP        string   `json:"ip,omitempty"`
	Password  string   `json:"password,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	Questions []string `json:"questions,omitempty"`
}

type keyboardAuthHookResponse struct {
	Instruction string   `json:"instruction"`
	Questions   []string `json:"questions"`
	Echos       []bool   `json:"echos"`
	AuthResult  int      `json:"auth_result"`
	CheckPwd    int      `json:"check_password"`
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

type virtualFoldersCompact struct {
	VirtualPath      string `json:"virtual_path"`
	MappedPath       string `json:"mapped_path"`
	ExcludeFromQuota bool   `json:"exclude_from_quota"`
}

type userCompactVFolders struct {
	ID             int64                   `json:"id"`
	Username       string                  `json:"username"`
	VirtualFolders []virtualFoldersCompact `json:"virtual_folders"`
}

// ValidationError raised if input data is not valid
type ValidationError struct {
	err string
}

// Validation error details
func (e *ValidationError) Error() string {
	return fmt.Sprintf("Validation error: %s", e.err)
}

// MethodDisabledError raised if a method is disabled in config file.
// For example, if user management is disabled, this error is raised
// every time a user operation is done using the REST API
type MethodDisabledError struct {
	err string
}

// Method disabled error details
func (e *MethodDisabledError) Error() string {
	return fmt.Sprintf("Method disabled error: %s", e.err)
}

// RecordNotFoundError raised if a requested user is not found
type RecordNotFoundError struct {
	err string
}

func (e *RecordNotFoundError) Error() string {
	return fmt.Sprintf("Not found: %s", e.err)
}

// GetQuotaTracking returns the configured mode for user's quota tracking
func GetQuotaTracking() int {
	return config.TrackQuota
}

// Provider defines the interface that data providers must implement.
type Provider interface {
	validateUserAndPass(username, password, ip, protocol string) (User, error)
	validateUserAndPubKey(username string, pubKey []byte) (User, string, error)
	updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error
	getUsedQuota(username string) (int, int64, error)
	userExists(username string) (User, error)
	addUser(user User) error
	updateUser(user User) error
	deleteUser(user User) error
	getUsers(limit int, offset int, order string, username string) ([]User, error)
	dumpUsers() ([]User, error)
	getUserByID(ID int64) (User, error)
	updateLastLogin(username string) error
	getFolders(limit, offset int, order, folderPath string) ([]vfs.BaseVirtualFolder, error)
	getFolderByPath(mappedPath string) (vfs.BaseVirtualFolder, error)
	addFolder(folder vfs.BaseVirtualFolder) error
	deleteFolder(folder vfs.BaseVirtualFolder) error
	updateFolderQuota(mappedPath string, filesAdd int, sizeAdd int64, reset bool) error
	getUsedFolderQuota(mappedPath string) (int, int64, error)
	dumpFolders() ([]vfs.BaseVirtualFolder, error)
	checkAvailability() error
	close() error
	reloadConfig() error
	initializeDatabase() error
	migrateDatabase() error
	revertDatabase(targetVersion int) error
}

// Initialize the data provider.
// An error is returned if the configured driver is invalid or if the data provider cannot be initialized
func Initialize(cnf Config, basePath string) error {
	var err error
	config = cnf

	if filepath.IsAbs(config.CredentialsPath) {
		credentialsDirPath = config.CredentialsPath
	} else {
		credentialsDirPath = filepath.Join(basePath, config.CredentialsPath)
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
			providerLog(logger.LevelWarn, "Unable to initialize data provider: %v", err)
			return err
		}
		if err == nil {
			logger.DebugToConsole("Data provider successfully initialized")
		}
		err = provider.migrateDatabase()
		if err != nil && err != ErrNoInitRequired {
			providerLog(logger.LevelWarn, "database migration error: %v", err)
			return err
		}
	} else {
		providerLog(logger.LevelInfo, "database initialization/migration skipped, manual mode is configured")
	}
	argon2Params = &argon2id.Params{
		Memory:      cnf.PasswordHashing.Argon2Options.Memory,
		Iterations:  cnf.PasswordHashing.Argon2Options.Iterations,
		Parallelism: cnf.PasswordHashing.Argon2Options.Parallelism,
		SaltLength:  16,
		KeyLength:   32,
	}
	startAvailabilityTimer()
	return nil
}

func validateHooks() error {
	var hooks []string
	if len(config.PreLoginHook) > 0 && !strings.HasPrefix(config.PreLoginHook, "http") {
		hooks = append(hooks, config.PreLoginHook)
	}
	if len(config.ExternalAuthHook) > 0 && !strings.HasPrefix(config.ExternalAuthHook, "http") {
		hooks = append(hooks, config.ExternalAuthHook)
	}
	if len(config.PostLoginHook) > 0 && !strings.HasPrefix(config.PostLoginHook, "http") {
		hooks = append(hooks, config.PostLoginHook)
	}
	if len(config.CheckPasswordHook) > 0 && !strings.HasPrefix(config.CheckPasswordHook, "http") {
		hooks = append(hooks, config.CheckPasswordHook)
	}

	for _, hook := range hooks {
		if !filepath.IsAbs(hook) {
			return fmt.Errorf("invalid hook: %#v must be an absolute path", hook)
		}
		_, err := os.Stat(hook)
		if err != nil {
			providerLog(logger.LevelWarn, "invalid hook: %v", err)
			return err
		}
	}

	return nil
}

func validateSQLTablesPrefix() error {
	if len(config.SQLTablesPrefix) > 0 {
		for _, char := range config.SQLTablesPrefix {
			if !strings.Contains(sqlPrefixValidChars, strings.ToLower(string(char))) {
				return errors.New("Invalid sql_tables_prefix only chars in range 'a..z', 'A..Z' and '_' are allowed")
			}
		}
		sqlTableUsers = config.SQLTablesPrefix + sqlTableUsers
		sqlTableFolders = config.SQLTablesPrefix + sqlTableFolders
		sqlTableFoldersMapping = config.SQLTablesPrefix + sqlTableFoldersMapping
		sqlTableSchemaVersion = config.SQLTablesPrefix + sqlTableSchemaVersion
		providerLog(logger.LevelDebug, "sql table for users %#v, folders %#v folders mapping %#v schema version %#v",
			sqlTableUsers, sqlTableFolders, sqlTableFoldersMapping, sqlTableSchemaVersion)
	}
	return nil
}

// InitializeDatabase creates the initial database structure
func InitializeDatabase(cnf Config, basePath string) error {
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

// CheckUserAndPass retrieves the SFTP user with the given username and password if a match is found or an error
func CheckUserAndPass(username, password, ip, protocol string) (User, error) {
	if len(config.ExternalAuthHook) > 0 && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&1 != 0) {
		user, err := doExternalAuth(username, password, nil, "", ip, protocol)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(user, password, ip, protocol)
	}
	if len(config.PreLoginHook) > 0 {
		user, err := executePreLoginHook(username, LoginMethodPassword, ip, protocol)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(user, password, ip, protocol)
	}
	return provider.validateUserAndPass(username, password, ip, protocol)
}

// CheckUserAndPubKey retrieves the SFTP user with the given username and public key if a match is found or an error
func CheckUserAndPubKey(username string, pubKey []byte, ip, protocol string) (User, string, error) {
	if len(config.ExternalAuthHook) > 0 && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&2 != 0) {
		user, err := doExternalAuth(username, "", pubKey, "", ip, protocol)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(user, pubKey)
	}
	if len(config.PreLoginHook) > 0 {
		user, err := executePreLoginHook(username, SSHLoginMethodPublicKey, ip, protocol)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(user, pubKey)
	}
	return provider.validateUserAndPubKey(username, pubKey)
}

// CheckKeyboardInteractiveAuth checks the keyboard interactive authentication and returns
// the authenticated user or an error
func CheckKeyboardInteractiveAuth(username, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (User, error) {
	var user User
	var err error
	if len(config.ExternalAuthHook) > 0 && (config.ExternalAuthScope == 0 || config.ExternalAuthScope&4 != 0) {
		user, err = doExternalAuth(username, "", nil, "1", ip, protocol)
	} else if len(config.PreLoginHook) > 0 {
		user, err = executePreLoginHook(username, SSHLoginMethodKeyboardInteractive, ip, protocol)
	} else {
		user, err = provider.userExists(username)
	}
	if err != nil {
		return user, err
	}
	return doKeyboardInteractiveAuth(user, authHook, client, ip, protocol)
}

// UpdateLastLogin updates the last login fields for the given SFTP user
func UpdateLastLogin(user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	lastLogin := utils.GetTimeFromMsecSinceEpoch(user.LastLogin)
	diff := -time.Until(lastLogin)
	if diff < 0 || diff > lastLoginMinDelay {
		err := provider.updateLastLogin(user.Username)
		if err == nil {
			updateWebDavCachedUserLastLogin(user.Username)
		}
		return err
	}
	return nil
}

// UpdateUserQuota updates the quota for the given SFTP user adding filesAdd and sizeAdd.
// If reset is true filesAdd and sizeAdd indicates the total files and the total size instead of the difference.
func UpdateUserQuota(user User, filesAdd int, sizeAdd int64, reset bool) error {
	if config.TrackQuota == 0 {
		return &MethodDisabledError{err: trackQuotaDisabledError}
	} else if config.TrackQuota == 2 && !reset && !user.HasQuotaRestrictions() {
		return nil
	}
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	if filesAdd == 0 && sizeAdd == 0 && !reset {
		return nil
	}
	return provider.updateQuota(user.Username, filesAdd, sizeAdd, reset)
}

// UpdateVirtualFolderQuota updates the quota for the given virtual folder adding filesAdd and sizeAdd.
// If reset is true filesAdd and sizeAdd indicates the total files and the total size instead of the difference.
func UpdateVirtualFolderQuota(vfolder vfs.BaseVirtualFolder, filesAdd int, sizeAdd int64, reset bool) error {
	if config.TrackQuota == 0 {
		return &MethodDisabledError{err: trackQuotaDisabledError}
	}
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	if filesAdd == 0 && sizeAdd == 0 && !reset {
		return nil
	}
	return provider.updateFolderQuota(vfolder.MappedPath, filesAdd, sizeAdd, reset)
}

// GetUsedQuota returns the used quota for the given SFTP user.
func GetUsedQuota(username string) (int, int64, error) {
	if config.TrackQuota == 0 {
		return 0, 0, &MethodDisabledError{err: trackQuotaDisabledError}
	}
	return provider.getUsedQuota(username)
}

// GetUsedVirtualFolderQuota returns the used quota for the given virtual folder.
func GetUsedVirtualFolderQuota(mappedPath string) (int, int64, error) {
	if config.TrackQuota == 0 {
		return 0, 0, &MethodDisabledError{err: trackQuotaDisabledError}
	}
	return provider.getUsedFolderQuota(mappedPath)
}

// UserExists checks if the given SFTP username exists, returns an error if no match is found
func UserExists(username string) (User, error) {
	return provider.userExists(username)
}

// AddUser adds a new SFTPGo user.
// ManageUsers configuration must be set to 1 to enable this method
func AddUser(user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	err := provider.addUser(user)
	if err == nil {
		go executeAction(operationAdd, user)
	}
	return err
}

// UpdateUser updates an existing SFTPGo user.
// ManageUsers configuration must be set to 1 to enable this method
func UpdateUser(user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	err := provider.updateUser(user)
	if err == nil {
		RemoveCachedWebDAVUser(user.Username)
		go executeAction(operationUpdate, user)
	}
	return err
}

// DeleteUser deletes an existing SFTPGo user.
// ManageUsers configuration must be set to 1 to enable this method
func DeleteUser(user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	err := provider.deleteUser(user)
	if err == nil {
		RemoveCachedWebDAVUser(user.Username)
		go executeAction(operationDelete, user)
	}
	return err
}

// ReloadConfig reloads provider configuration.
// Currently only implemented for memory provider, allows to reload the users
// from the configured file, if defined
func ReloadConfig() error {
	return provider.reloadConfig()
}

// GetUsers returns an array of users respecting limit and offset and filtered by username exact match if not empty
func GetUsers(limit, offset int, order string, username string) ([]User, error) {
	return provider.getUsers(limit, offset, order, username)
}

// GetUserByID returns the user with the given database ID if a match is found or an error
func GetUserByID(ID int64) (User, error) {
	return provider.getUserByID(ID)
}

// AddFolder adds a new virtual folder.
// ManageUsers configuration must be set to 1 to enable this method
func AddFolder(folder vfs.BaseVirtualFolder) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return provider.addFolder(folder)
}

// DeleteFolder deletes an existing folder.
// ManageUsers configuration must be set to 1 to enable this method
func DeleteFolder(folder vfs.BaseVirtualFolder) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return provider.deleteFolder(folder)
}

// GetFolderByPath returns the folder with the specified path if any
func GetFolderByPath(mappedPath string) (vfs.BaseVirtualFolder, error) {
	return provider.getFolderByPath(mappedPath)
}

// GetFolders returns an array of folders respecting limit and offset
func GetFolders(limit, offset int, order, folderPath string) ([]vfs.BaseVirtualFolder, error) {
	return provider.getFolders(limit, offset, order, folderPath)
}

// DumpData returns all users and folders
func DumpData() (BackupData, error) {
	var data BackupData
	data.Version = DumpVersion
	users, err := provider.dumpUsers()
	if err != nil {
		return data, err
	}
	folders, err := provider.dumpFolders()
	if err != nil {
		return data, err
	}
	data.Users = users
	data.Folders = folders
	return data, err
}

// ParseDumpData tries to parse data as BackupData
func ParseDumpData(data []byte) (BackupData, error) {
	var dump BackupData
	err := json.Unmarshal(data, &dump)
	if err == nil {
		return dump, err
	}
	dump = BackupData{}
	// try to parse as version 4
	var dumpCompat backupDataV4Compat
	err = json.Unmarshal(data, &dumpCompat)
	if err != nil {
		return dump, err
	}
	logger.WarnToConsole("You are loading data from an old format, please update to the latest supported one. We only support the current and the previous format.")
	providerLog(logger.LevelWarn, "You are loading data from an old format, please update to the latest supported one. We only support the current and the previous format.")
	dump.Folders = dumpCompat.Folders
	for _, compatUser := range dumpCompat.Users {
		fsConfig, err := convertFsConfigFromV4(compatUser.FsConfig, compatUser.Username)
		if err != nil {
			return dump, err
		}
		dump.Users = append(dump.Users, createUserFromV4(compatUser, fsConfig))
	}
	return dump, err
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
	if availabilityTicker != nil {
		availabilityTicker.Stop()
		availabilityTickerDone <- true
		availabilityTicker = nil
	}
	return provider.close()
}

func createProvider(basePath string) error {
	var err error
	sqlPlaceholders = getSQLPlaceholders()
	if err = validateSQLTablesPrefix(); err != nil {
		return err
	}
	if config.Driver == SQLiteDataProviderName {
		err = initializeSQLiteProvider(basePath)
	} else if config.Driver == PGSQLDataProviderName {
		err = initializePGSQLProvider()
	} else if config.Driver == MySQLDataProviderName {
		err = initializeMySQLProvider()
	} else if config.Driver == BoltDataProviderName {
		err = initializeBoltProvider(basePath)
	} else if config.Driver == MemoryDataProviderName {
		initializeMemoryProvider(basePath)
	} else {
		err = fmt.Errorf("unsupported data provider: %v", config.Driver)
	}
	return err
}

func buildUserHomeDir(user *User) {
	if len(user.HomeDir) == 0 {
		if len(config.UsersBaseDir) > 0 {
			user.HomeDir = filepath.Join(config.UsersBaseDir, user.Username)
		}
	}
}

func isVirtualDirOverlapped(dir1, dir2 string) bool {
	if dir1 == dir2 {
		return true
	}
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
	return false
}

func isMappedDirOverlapped(dir1, dir2 string) bool {
	if dir1 == dir2 {
		return true
	}
	if len(dir1) > len(dir2) {
		if strings.HasPrefix(dir1, dir2+string(os.PathSeparator)) {
			return true
		}
	}
	if len(dir2) > len(dir1) {
		if strings.HasPrefix(dir2, dir1+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func validateFolderQuotaLimits(folder vfs.VirtualFolder) error {
	if folder.QuotaSize < -1 {
		return &ValidationError{err: fmt.Sprintf("invalid quota_size: %v folder path %#v", folder.QuotaSize, folder.MappedPath)}
	}
	if folder.QuotaFiles < -1 {
		return &ValidationError{err: fmt.Sprintf("invalid quota_file: %v folder path %#v", folder.QuotaSize, folder.MappedPath)}
	}
	if (folder.QuotaSize == -1 && folder.QuotaFiles != -1) || (folder.QuotaFiles == -1 && folder.QuotaSize != -1) {
		return &ValidationError{err: fmt.Sprintf("virtual folder quota_size and quota_files must be both -1 or >= 0, quota_size: %v quota_files: %v",
			folder.QuotaFiles, folder.QuotaSize)}
	}
	return nil
}

func validateUserVirtualFolders(user *User) error {
	if len(user.VirtualFolders) == 0 || user.FsConfig.Provider != LocalFilesystemProvider {
		user.VirtualFolders = []vfs.VirtualFolder{}
		return nil
	}
	var virtualFolders []vfs.VirtualFolder
	mappedPaths := make(map[string]string)
	for _, v := range user.VirtualFolders {
		cleanedVPath := filepath.ToSlash(path.Clean(v.VirtualPath))
		if !path.IsAbs(cleanedVPath) || cleanedVPath == "/" {
			return &ValidationError{err: fmt.Sprintf("invalid virtual folder %#v", v.VirtualPath)}
		}
		if err := validateFolderQuotaLimits(v); err != nil {
			return err
		}
		cleanedMPath := filepath.Clean(v.MappedPath)
		if !filepath.IsAbs(cleanedMPath) {
			return &ValidationError{err: fmt.Sprintf("invalid mapped folder %#v", v.MappedPath)}
		}
		if isMappedDirOverlapped(cleanedMPath, user.GetHomeDir()) {
			return &ValidationError{err: fmt.Sprintf("invalid mapped folder %#v cannot be inside or contain the user home dir %#v",
				v.MappedPath, user.GetHomeDir())}
		}
		virtualFolders = append(virtualFolders, vfs.VirtualFolder{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				MappedPath: cleanedMPath,
			},
			VirtualPath: cleanedVPath,
			QuotaSize:   v.QuotaSize,
			QuotaFiles:  v.QuotaFiles,
		})
		for k, virtual := range mappedPaths {
			if GetQuotaTracking() > 0 {
				if isMappedDirOverlapped(k, cleanedMPath) {
					return &ValidationError{err: fmt.Sprintf("invalid mapped folder %#v overlaps with mapped folder %#v",
						v.MappedPath, k)}
				}
			} else {
				if k == cleanedMPath {
					return &ValidationError{err: fmt.Sprintf("duplicated mapped folder %#v", v.MappedPath)}
				}
			}
			if isVirtualDirOverlapped(virtual, cleanedVPath) {
				return &ValidationError{err: fmt.Sprintf("invalid virtual folder %#v overlaps with virtual folder %#v",
					v.VirtualPath, virtual)}
			}
		}
		mappedPaths[cleanedMPath] = cleanedVPath
	}
	user.VirtualFolders = virtualFolders
	return nil
}

func validatePermissions(user *User) error {
	if len(user.Permissions) == 0 {
		return &ValidationError{err: "please grant some permissions to this user"}
	}
	permissions := make(map[string][]string)
	if _, ok := user.Permissions["/"]; !ok {
		return &ValidationError{err: "permissions for the root dir \"/\" must be set"}
	}
	for dir, perms := range user.Permissions {
		if len(perms) == 0 && dir == "/" {
			return &ValidationError{err: fmt.Sprintf("no permissions granted for the directory: %#v", dir)}
		}
		if len(perms) > len(ValidPerms) {
			return &ValidationError{err: "invalid permissions"}
		}
		for _, p := range perms {
			if !utils.IsStringInSlice(p, ValidPerms) {
				return &ValidationError{err: fmt.Sprintf("invalid permission: %#v", p)}
			}
		}
		cleanedDir := filepath.ToSlash(path.Clean(dir))
		if cleanedDir != "/" {
			cleanedDir = strings.TrimSuffix(cleanedDir, "/")
		}
		if !path.IsAbs(cleanedDir) {
			return &ValidationError{err: fmt.Sprintf("cannot set permissions for non absolute path: %#v", dir)}
		}
		if dir != cleanedDir && cleanedDir == "/" {
			return &ValidationError{err: fmt.Sprintf("cannot set permissions for invalid subdirectory: %#v is an alias for \"/\"", dir)}
		}
		if utils.IsStringInSlice(PermAny, perms) {
			permissions[cleanedDir] = []string{PermAny}
		} else {
			permissions[cleanedDir] = perms
		}
	}
	user.Permissions = permissions
	return nil
}

func validatePublicKeys(user *User) error {
	if len(user.PublicKeys) == 0 {
		user.PublicKeys = []string{}
	}
	for i, k := range user.PublicKeys {
		_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not parse key nr. %d: %s", i, err)}
		}
	}
	return nil
}

func validateFiltersPatternExtensions(user *User) error {
	if len(user.Filters.FilePatterns) == 0 {
		user.Filters.FilePatterns = []PatternsFilter{}
		return nil
	}
	filteredPaths := []string{}
	var filters []PatternsFilter
	for _, f := range user.Filters.FilePatterns {
		cleanedPath := filepath.ToSlash(path.Clean(f.Path))
		if !path.IsAbs(cleanedPath) {
			return &ValidationError{err: fmt.Sprintf("invalid path %#v for file patterns filter", f.Path)}
		}
		if utils.IsStringInSlice(cleanedPath, filteredPaths) {
			return &ValidationError{err: fmt.Sprintf("duplicate file patterns filter for path %#v", f.Path)}
		}
		if len(f.AllowedPatterns) == 0 && len(f.DeniedPatterns) == 0 {
			return &ValidationError{err: fmt.Sprintf("empty file patterns filter for path %#v", f.Path)}
		}
		f.Path = cleanedPath
		allowed := make([]string, 0, len(f.AllowedPatterns))
		denied := make([]string, 0, len(f.DeniedPatterns))
		for _, pattern := range f.AllowedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return &ValidationError{err: fmt.Sprintf("invalid file pattern filter %#v", pattern)}
			}
			allowed = append(allowed, strings.ToLower(pattern))
		}
		for _, pattern := range f.DeniedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return &ValidationError{err: fmt.Sprintf("invalid file pattern filter %#v", pattern)}
			}
			denied = append(denied, strings.ToLower(pattern))
		}
		f.AllowedPatterns = allowed
		f.DeniedPatterns = denied
		filters = append(filters, f)
		filteredPaths = append(filteredPaths, cleanedPath)
	}
	user.Filters.FilePatterns = filters
	return nil
}

func validateFiltersFileExtensions(user *User) error {
	if len(user.Filters.FileExtensions) == 0 {
		user.Filters.FileExtensions = []ExtensionsFilter{}
		return nil
	}
	filteredPaths := []string{}
	var filters []ExtensionsFilter
	for _, f := range user.Filters.FileExtensions {
		cleanedPath := filepath.ToSlash(path.Clean(f.Path))
		if !path.IsAbs(cleanedPath) {
			return &ValidationError{err: fmt.Sprintf("invalid path %#v for file extensions filter", f.Path)}
		}
		if utils.IsStringInSlice(cleanedPath, filteredPaths) {
			return &ValidationError{err: fmt.Sprintf("duplicate file extensions filter for path %#v", f.Path)}
		}
		if len(f.AllowedExtensions) == 0 && len(f.DeniedExtensions) == 0 {
			return &ValidationError{err: fmt.Sprintf("empty file extensions filter for path %#v", f.Path)}
		}
		f.Path = cleanedPath
		allowed := make([]string, 0, len(f.AllowedExtensions))
		denied := make([]string, 0, len(f.DeniedExtensions))
		for _, ext := range f.AllowedExtensions {
			allowed = append(allowed, strings.ToLower(ext))
		}
		for _, ext := range f.DeniedExtensions {
			denied = append(denied, strings.ToLower(ext))
		}
		f.AllowedExtensions = allowed
		f.DeniedExtensions = denied
		filters = append(filters, f)
		filteredPaths = append(filteredPaths, cleanedPath)
	}
	user.Filters.FileExtensions = filters
	return nil
}

func validateFileFilters(user *User) error {
	if err := validateFiltersFileExtensions(user); err != nil {
		return err
	}
	return validateFiltersPatternExtensions(user)
}

func validateFilters(user *User) error {
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
	for _, IPMask := range user.Filters.DeniedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not parse denied IP/Mask %#v : %v", IPMask, err)}
		}
	}
	for _, IPMask := range user.Filters.AllowedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not parse allowed IP/Mask %#v : %v", IPMask, err)}
		}
	}
	if len(user.Filters.DeniedLoginMethods) >= len(ValidSSHLoginMethods) {
		return &ValidationError{err: "invalid denied_login_methods"}
	}
	for _, loginMethod := range user.Filters.DeniedLoginMethods {
		if !utils.IsStringInSlice(loginMethod, ValidSSHLoginMethods) {
			return &ValidationError{err: fmt.Sprintf("invalid login method: %#v", loginMethod)}
		}
	}
	if len(user.Filters.DeniedProtocols) >= len(ValidProtocols) {
		return &ValidationError{err: "invalid denied_protocols"}
	}
	for _, p := range user.Filters.DeniedProtocols {
		if !utils.IsStringInSlice(p, ValidProtocols) {
			return &ValidationError{err: fmt.Sprintf("invalid protocol: %#v", p)}
		}
	}
	return validateFileFilters(user)
}

func saveGCSCredentials(user *User) error {
	if user.FsConfig.Provider != GCSFilesystemProvider {
		return nil
	}
	if user.FsConfig.GCSConfig.Credentials.GetPayload() == "" {
		return nil
	}
	if config.PreferDatabaseCredentials {
		if user.FsConfig.GCSConfig.Credentials.IsPlain() {
			user.FsConfig.GCSConfig.Credentials.SetAdditionalData(user.Username)
			err := user.FsConfig.GCSConfig.Credentials.Encrypt()
			if err != nil {
				return err
			}
		}
		return nil
	}
	if user.FsConfig.GCSConfig.Credentials.IsPlain() {
		user.FsConfig.GCSConfig.Credentials.SetAdditionalData(user.Username)
		err := user.FsConfig.GCSConfig.Credentials.Encrypt()
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not encrypt GCS credentials: %v", err)}
		}
	}
	creds, err := json.Marshal(user.FsConfig.GCSConfig.Credentials)
	if err != nil {
		return &ValidationError{err: fmt.Sprintf("could not marshal GCS credentials: %v", err)}
	}
	credentialsFilePath := user.getGCSCredentialsFilePath()
	err = os.MkdirAll(filepath.Dir(credentialsFilePath), 0700)
	if err != nil {
		return &ValidationError{err: fmt.Sprintf("could not create GCS credentials dir: %v", err)}
	}
	err = ioutil.WriteFile(credentialsFilePath, creds, 0600)
	if err != nil {
		return &ValidationError{err: fmt.Sprintf("could not save GCS credentials: %v", err)}
	}
	user.FsConfig.GCSConfig.Credentials = kms.NewEmptySecret()
	return nil
}

func validateFilesystemConfig(user *User) error {
	if user.FsConfig.Provider == S3FilesystemProvider {
		err := vfs.ValidateS3FsConfig(&user.FsConfig.S3Config)
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not validate s3config: %v", err)}
		}
		if user.FsConfig.S3Config.AccessSecret.IsPlain() {
			user.FsConfig.S3Config.AccessSecret.SetAdditionalData(user.Username)
			err = user.FsConfig.S3Config.AccessSecret.Encrypt()
			if err != nil {
				return &ValidationError{err: fmt.Sprintf("could not encrypt s3 access secret: %v", err)}
			}
		}
		user.FsConfig.GCSConfig = vfs.GCSFsConfig{}
		user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
		user.FsConfig.CryptConfig = vfs.CryptFsConfig{}
		return nil
	} else if user.FsConfig.Provider == GCSFilesystemProvider {
		err := vfs.ValidateGCSFsConfig(&user.FsConfig.GCSConfig, user.getGCSCredentialsFilePath())
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not validate GCS config: %v", err)}
		}
		user.FsConfig.S3Config = vfs.S3FsConfig{}
		user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
		user.FsConfig.CryptConfig = vfs.CryptFsConfig{}
		return nil
	} else if user.FsConfig.Provider == AzureBlobFilesystemProvider {
		err := vfs.ValidateAzBlobFsConfig(&user.FsConfig.AzBlobConfig)
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not validate Azure Blob config: %v", err)}
		}
		if user.FsConfig.AzBlobConfig.AccountKey.IsPlain() {
			user.FsConfig.AzBlobConfig.AccountKey.SetAdditionalData(user.Username)
			err = user.FsConfig.AzBlobConfig.AccountKey.Encrypt()
			if err != nil {
				return &ValidationError{err: fmt.Sprintf("could not encrypt Azure blob account key: %v", err)}
			}
		}
		user.FsConfig.S3Config = vfs.S3FsConfig{}
		user.FsConfig.GCSConfig = vfs.GCSFsConfig{}
		user.FsConfig.CryptConfig = vfs.CryptFsConfig{}
		return nil
	} else if user.FsConfig.Provider == CryptedFilesystemProvider {
		err := vfs.ValidateCryptFsConfig(&user.FsConfig.CryptConfig)
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not validate Crypt fs config: %v", err)}
		}
		if user.FsConfig.CryptConfig.Passphrase.IsPlain() {
			user.FsConfig.CryptConfig.Passphrase.SetAdditionalData(user.Username)
			err = user.FsConfig.CryptConfig.Passphrase.Encrypt()
			if err != nil {
				return &ValidationError{err: fmt.Sprintf("could not encrypt Crypt fs passphrase: %v", err)}
			}
		}
		user.FsConfig.S3Config = vfs.S3FsConfig{}
		user.FsConfig.GCSConfig = vfs.GCSFsConfig{}
		user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
		return nil
	}
	user.FsConfig.Provider = LocalFilesystemProvider
	user.FsConfig.S3Config = vfs.S3FsConfig{}
	user.FsConfig.GCSConfig = vfs.GCSFsConfig{}
	user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
	user.FsConfig.CryptConfig = vfs.CryptFsConfig{}
	return nil
}

func validateBaseParams(user *User) error {
	if user.Username == "" {
		return &ValidationError{err: "username is mandatory"}
	}
	if user.HomeDir == "" {
		return &ValidationError{err: "home_dir is mandatory"}
	}
	if user.Password == "" && len(user.PublicKeys) == 0 {
		return &ValidationError{err: "please set a password or at least a public_key"}
	}
	if !filepath.IsAbs(user.HomeDir) {
		return &ValidationError{err: fmt.Sprintf("home_dir must be an absolute path, actual value: %v", user.HomeDir)}
	}
	return nil
}

func createUserPasswordHash(user *User) error {
	if len(user.Password) > 0 && !utils.IsStringPrefixInSlice(user.Password, hashPwdPrefixes) {
		pwd, err := argon2id.CreateHash(user.Password, argon2Params)
		if err != nil {
			return err
		}
		user.Password = pwd
	}
	return nil
}

func validateFolder(folder *vfs.BaseVirtualFolder) error {
	cleanedMPath := filepath.Clean(folder.MappedPath)
	if !filepath.IsAbs(cleanedMPath) {
		return &ValidationError{err: fmt.Sprintf("invalid mapped folder %#v", folder.MappedPath)}
	}
	folder.MappedPath = cleanedMPath
	return nil
}

func validateUser(user *User) error {
	user.SetEmptySecretsIfNil()
	buildUserHomeDir(user)
	if err := validateBaseParams(user); err != nil {
		return err
	}
	if err := validatePermissions(user); err != nil {
		return err
	}
	if err := validateFilesystemConfig(user); err != nil {
		return err
	}
	if err := validateUserVirtualFolders(user); err != nil {
		return err
	}
	if user.Status < 0 || user.Status > 1 {
		return &ValidationError{err: fmt.Sprintf("invalid user status: %v", user.Status)}
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
	if err := saveGCSCredentials(user); err != nil {
		return err
	}
	return nil
}

func checkLoginConditions(user User) error {
	if user.Status < 1 {
		return fmt.Errorf("user %#v is disabled", user.Username)
	}
	if user.ExpirationDate > 0 && user.ExpirationDate < utils.GetTimeAsMsSinceEpoch(time.Now()) {
		return fmt.Errorf("user %#v is expired, expiration timestamp: %v current timestamp: %v", user.Username,
			user.ExpirationDate, utils.GetTimeAsMsSinceEpoch(time.Now()))
	}
	return nil
}

func isPasswordOK(user *User, password string) (bool, error) {
	match := false
	var err error
	if strings.HasPrefix(user.Password, argonPwdPrefix) {
		match, err = argon2id.ComparePasswordAndHash(password, user.Password)
		if err != nil {
			providerLog(logger.LevelWarn, "error comparing password with argon hash: %v", err)
			return match, err
		}
	} else if strings.HasPrefix(user.Password, bcryptPwdPrefix) {
		if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			providerLog(logger.LevelWarn, "error comparing password with bcrypt hash: %v", err)
			return match, err
		}
		match = true
	} else if utils.IsStringPrefixInSlice(user.Password, pbkdfPwdPrefixes) {
		match, err = comparePbkdf2PasswordAndHash(password, user.Password)
		if err != nil {
			return match, err
		}
	} else if utils.IsStringPrefixInSlice(user.Password, unixPwdPrefixes) {
		match, err = compareUnixPasswordAndHash(user, password)
		if err != nil {
			return match, err
		}
	}
	return match, err
}

func checkUserAndPass(user User, password, ip, protocol string) (User, error) {
	err := checkLoginConditions(user)
	if err != nil {
		return user, err
	}
	if len(user.Password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	hookResponse, err := executeCheckPasswordHook(user.Username, password, ip, protocol)
	if err != nil {
		providerLog(logger.LevelDebug, "error executing check password hook: %v", err)
		return user, errors.New("Unable to check credentials")
	}
	switch hookResponse.Status {
	case -1:
		// no hook configured
	case 1:
		providerLog(logger.LevelDebug, "password accepted by check password hook")
		return user, nil
	case 2:
		providerLog(logger.LevelDebug, "partial success from check password hook")
		password = hookResponse.ToVerify
	default:
		providerLog(logger.LevelDebug, "password rejected by check password hook, status: %v", hookResponse.Status)
		return user, ErrInvalidCredentials
	}

	match, err := isPasswordOK(&user, password)
	if !match {
		err = ErrInvalidCredentials
	}
	return user, err
}

func checkUserAndPubKey(user User, pubKey []byte) (User, string, error) {
	err := checkLoginConditions(user)
	if err != nil {
		return user, "", err
	}
	if len(user.PublicKeys) == 0 {
		return user, "", ErrInvalidCredentials
	}
	for i, k := range user.PublicKeys {
		storedPubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			providerLog(logger.LevelWarn, "error parsing stored public key %d for user %v: %v", i, user.Username, err)
			return user, "", err
		}
		if bytes.Equal(storedPubKey.Marshal(), pubKey) {
			certInfo := ""
			cert, ok := storedPubKey.(*ssh.Certificate)
			if ok {
				certInfo = fmt.Sprintf(" %v ID: %v Serial: %v CA: %v", cert.Type(), cert.KeyId, cert.Serial,
					ssh.FingerprintSHA256(cert.SignatureKey))
			}
			return user, fmt.Sprintf("%v:%v%v", ssh.FingerprintSHA256(storedPubKey), comment, certInfo), nil
		}
	}
	return user, "", ErrInvalidCredentials
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
	if utils.IsStringPrefixInSlice(hashedPassword, pbkdfPwdB64SaltPrefixes) {
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
	if user.FsConfig.Provider != GCSFilesystemProvider {
		return nil
	}
	if user.FsConfig.GCSConfig.AutomaticCredentials > 0 {
		return nil
	}

	// Don't read from file if credentials have already been set
	if user.FsConfig.GCSConfig.Credentials.IsValid() {
		return nil
	}

	cred, err := ioutil.ReadFile(user.getGCSCredentialsFilePath())
	if err != nil {
		return err
	}
	return json.Unmarshal(cred, &user.FsConfig.GCSConfig.Credentials)
}

func getSSLMode() string {
	if config.Driver == PGSQLDataProviderName {
		if config.SSLMode == 0 {
			return "disable"
		} else if config.SSLMode == 1 {
			return "require"
		} else if config.SSLMode == 2 {
			return "verify-ca"
		} else if config.SSLMode == 3 {
			return "verify-full"
		}
	} else if config.Driver == MySQLDataProviderName {
		if config.SSLMode == 0 {
			return "false"
		} else if config.SSLMode == 1 {
			return "true"
		} else if config.SSLMode == 2 {
			return "skip-verify"
		} else if config.SSLMode == 3 {
			return "preferred"
		}
	}
	return ""
}

func startAvailabilityTimer() {
	availabilityTicker = time.NewTicker(30 * time.Second)
	availabilityTickerDone = make(chan bool)
	checkDataprovider()
	go func() {
		for {
			select {
			case <-availabilityTickerDone:
				return
			case <-availabilityTicker.C:
				checkDataprovider()
			}
		}
	}()
}

func checkDataprovider() {
	err := provider.checkAvailability()
	if err != nil {
		providerLog(logger.LevelWarn, "check availability error: %v", err)
	}
	metrics.UpdateDataProviderAvailability(err)
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

func validateKeyboardAuthResponse(response keyboardAuthHookResponse) error {
	if len(response.Questions) == 0 {
		err := errors.New("interactive auth error: hook response does not contain questions")
		providerLog(logger.LevelInfo, "%v", err)
		return err
	}
	if len(response.Questions) != len(response.Echos) {
		err := fmt.Errorf("interactive auth error, http hook response questions don't match echos: %v %v",
			len(response.Questions), len(response.Echos))
		providerLog(logger.LevelInfo, "%v", err)
		return err
	}
	return nil
}

func sendKeyboardAuthHTTPReq(url *url.URL, request keyboardAuthHookRequest) (keyboardAuthHookResponse, error) {
	var response keyboardAuthHookResponse
	httpClient := httpclient.GetHTTPClient()
	reqAsJSON, err := json.Marshal(request)
	if err != nil {
		providerLog(logger.LevelWarn, "error serializing keyboard interactive auth request: %v", err)
		return response, err
	}
	resp, err := httpClient.Post(url.String(), "application/json", bytes.NewBuffer(reqAsJSON))
	if err != nil {
		providerLog(logger.LevelWarn, "error getting keyboard interactive auth hook HTTP response: %v", err)
		return response, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return response, fmt.Errorf("wrong keyboard interactive auth http status code: %v, expected 200", resp.StatusCode)
	}
	err = render.DecodeJSON(resp.Body, &response)
	return response, err
}

func executeKeyboardInteractiveHTTPHook(user User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	authResult := 0
	var url *url.URL
	url, err := url.Parse(authHook)
	if err != nil {
		providerLog(logger.LevelWarn, "invalid url for keyboard interactive hook %#v, error: %v", authHook, err)
		return authResult, err
	}
	requestID := xid.New().String()
	req := keyboardAuthHookRequest{
		Username:  user.Username,
		IP:        ip,
		Password:  user.Password,
		RequestID: requestID,
	}
	var response keyboardAuthHookResponse
	for {
		response, err = sendKeyboardAuthHTTPReq(url, req)
		if err != nil {
			return authResult, err
		}
		if response.AuthResult != 0 {
			return response.AuthResult, err
		}
		if err = validateKeyboardAuthResponse(response); err != nil {
			return authResult, err
		}
		answers, err := getKeyboardInteractiveAnswers(client, response, user, ip, protocol)
		if err != nil {
			return authResult, err
		}
		req = keyboardAuthHookRequest{
			RequestID: requestID,
			Username:  user.Username,
			Password:  user.Password,
			Answers:   answers,
			Questions: response.Questions,
		}
	}
}

func getKeyboardInteractiveAnswers(client ssh.KeyboardInteractiveChallenge, response keyboardAuthHookResponse,
	user User, ip, protocol string) ([]string, error) {
	questions := response.Questions
	answers, err := client(user.Username, response.Instruction, questions, response.Echos)
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
		_, err = checkUserAndPass(user, answers[0], ip, protocol)
		providerLog(logger.LevelInfo, "interactive auth hook requested password validation for user %#v, validation error: %v",
			user.Username, err)
		if err != nil {
			return answers, err
		}
		answers[0] = "OK"
	}
	return answers, err
}

func handleProgramInteractiveQuestions(client ssh.KeyboardInteractiveChallenge, response keyboardAuthHookResponse,
	user User, stdin io.WriteCloser, ip, protocol string) error {
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

func executeKeyboardInteractiveProgram(user User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
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
		var response keyboardAuthHookResponse
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
		if err = validateKeyboardAuthResponse(response); err != nil {
			once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
			break
		}
		go func() {
			err := handleProgramInteractiveQuestions(client, response, user, stdin, ip, protocol)
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

func doKeyboardInteractiveAuth(user User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (User, error) {
	var authResult int
	var err error
	if strings.HasPrefix(authHook, "http") {
		authResult, err = executeKeyboardInteractiveHTTPHook(user, authHook, client, ip, protocol)
	} else {
		authResult, err = executeKeyboardInteractiveProgram(user, authHook, client, ip, protocol)
	}
	if err != nil {
		return user, err
	}
	if authResult != 1 {
		return user, fmt.Errorf("keyboard interactive auth failed, result: %v", authResult)
	}
	err = checkLoginConditions(user)
	if err != nil {
		return user, err
	}
	return user, nil
}

func isCheckPasswordHookDefined(protocol string) bool {
	if len(config.CheckPasswordHook) == 0 {
		return false
	}
	if config.CheckPasswordScope == 0 {
		return true
	}
	switch protocol {
	case "SSH":
		return config.CheckPasswordScope&1 != 0
	case "FTP":
		return config.CheckPasswordScope&2 != 0
	case "DAV":
		return config.CheckPasswordScope&4 != 0
	default:
		return false
	}
}

func getPasswordHookResponse(username, password, ip, protocol string) ([]byte, error) {
	if strings.HasPrefix(config.CheckPasswordHook, "http") {
		var result []byte
		var url *url.URL
		url, err := url.Parse(config.CheckPasswordHook)
		if err != nil {
			providerLog(logger.LevelWarn, "invalid url for check password hook %#v, error: %v", config.CheckPasswordHook, err)
			return result, err
		}
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
		httpClient := httpclient.GetHTTPClient()
		resp, err := httpClient.Post(url.String(), "application/json", bytes.NewBuffer(reqAsJSON))
		if err != nil {
			providerLog(logger.LevelWarn, "error getting check password hook response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong http status code from chek password hook: %v, expected 200", resp.StatusCode)
		}
		return ioutil.ReadAll(resp.Body)
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

	out, err := getPasswordHookResponse(username, password, ip, protocol)
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
			providerLog(logger.LevelWarn, "invalid url for pre-login hook %#v, error: %v", config.PreLoginHook, err)
			return result, err
		}
		q := url.Query()
		q.Add("login_method", loginMethod)
		q.Add("ip", ip)
		q.Add("protocol", protocol)
		url.RawQuery = q.Encode()
		httpClient := httpclient.GetHTTPClient()
		resp, err := httpClient.Post(url.String(), "application/json", bytes.NewBuffer(userAsJSON))
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
		return ioutil.ReadAll(resp.Body)
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
	u, err := provider.userExists(username)
	if err != nil {
		if _, ok := err.(*RecordNotFoundError); !ok {
			return u, err
		}
		u = User{
			ID:       0,
			Username: username,
		}
	}
	userAsJSON, err := json.Marshal(u)
	if err != nil {
		return u, err
	}
	out, err := getPreLoginHookResponse(loginMethod, ip, protocol, userAsJSON)
	if err != nil {
		return u, fmt.Errorf("Pre-login hook error: %v", err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		providerLog(logger.LevelDebug, "empty response from pre-login hook, no modification requested for user %#v id: %v",
			username, u.ID)
		if u.ID == 0 {
			return u, &RecordNotFoundError{err: fmt.Sprintf("username %v does not exist", username)}
		}
		return u, nil
	}

	userID := u.ID
	userUsedQuotaSize := u.UsedQuotaSize
	userUsedQuotaFiles := u.UsedQuotaFiles
	userLastQuotaUpdate := u.LastQuotaUpdate
	userLastLogin := u.LastLogin
	err = json.Unmarshal(out, &u)
	if err != nil {
		return u, fmt.Errorf("Invalid pre-login hook response %#v, error: %v", string(out), err)
	}
	u.ID = userID
	u.UsedQuotaSize = userUsedQuotaSize
	u.UsedQuotaFiles = userUsedQuotaFiles
	u.LastQuotaUpdate = userLastQuotaUpdate
	u.LastLogin = userLastLogin
	if userID == 0 {
		err = provider.addUser(u)
	} else {
		err = provider.updateUser(u)
	}
	if err != nil {
		return u, err
	}
	providerLog(logger.LevelDebug, "user %#v added/updated from pre-login hook response, id: %v", username, userID)
	return provider.userExists(username)
}

// ExecutePostLoginHook executes the post login hook if defined
func ExecutePostLoginHook(username, loginMethod, ip, protocol string, err error) {
	if len(config.PostLoginHook) == 0 {
		return
	}
	if config.PostLoginScope == 1 && err == nil {
		return
	}
	if config.PostLoginScope == 2 && err != nil {
		return
	}

	go func(username, loginMethod, ip, protocol string, err error) {
		status := 0
		if err == nil {
			status = 1
		}
		if strings.HasPrefix(config.PostLoginHook, "http") {
			var url *url.URL
			url, err := url.Parse(config.PostLoginHook)
			if err != nil {
				providerLog(logger.LevelDebug, "Invalid post-login hook %#v", config.PostLoginHook)
				return
			}
			postReq := make(map[string]interface{})
			postReq["username"] = username
			postReq["login_method"] = loginMethod
			postReq["ip"] = ip
			postReq["protocol"] = protocol
			postReq["status"] = status

			postAsJSON, err := json.Marshal(postReq)
			if err != nil {
				providerLog(logger.LevelWarn, "error serializing post login request: %v", err)
				return
			}
			startTime := time.Now()
			respCode := 0
			httpClient := httpclient.GetHTTPClient()
			resp, err := httpClient.Post(url.String(), "application/json", bytes.NewBuffer(postAsJSON))
			if err == nil {
				respCode = resp.StatusCode
				resp.Body.Close()
			}
			providerLog(logger.LevelDebug, "post login hook executed, response code: %v, elapsed: %v err: %v",
				respCode, time.Since(startTime), err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, config.PostLoginHook)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("SFTPGO_LOGIND_USER=%v", username),
			fmt.Sprintf("SFTPGO_LOGIND_IP=%v", ip),
			fmt.Sprintf("SFTPGO_LOGIND_METHOD=%v", loginMethod),
			fmt.Sprintf("SFTPGO_LOGIND_STATUS=%v", status),
			fmt.Sprintf("SFTPGO_LOGIND_PROTOCOL=%v", protocol))
		startTime := time.Now()
		err = cmd.Run()
		providerLog(logger.LevelDebug, "post login hook executed, elapsed %v err: %v", time.Since(startTime), err)
	}(username, loginMethod, ip, protocol, err)
}

func getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol string) ([]byte, error) {
	if strings.HasPrefix(config.ExternalAuthHook, "http") {
		var url *url.URL
		var result []byte
		url, err := url.Parse(config.ExternalAuthHook)
		if err != nil {
			providerLog(logger.LevelWarn, "invalid url for external auth hook %#v, error: %v", config.ExternalAuthHook, err)
			return result, err
		}
		httpClient := httpclient.GetHTTPClient()
		authRequest := make(map[string]string)
		authRequest["username"] = username
		authRequest["ip"] = ip
		authRequest["password"] = password
		authRequest["public_key"] = pkey
		authRequest["protocol"] = protocol
		authRequest["keyboard_interactive"] = keyboardInteractive
		authRequestAsJSON, err := json.Marshal(authRequest)
		if err != nil {
			providerLog(logger.LevelWarn, "error serializing external auth request: %v", err)
			return result, err
		}
		resp, err := httpClient.Post(url.String(), "application/json", bytes.NewBuffer(authRequestAsJSON))
		if err != nil {
			providerLog(logger.LevelWarn, "error getting external auth hook HTTP response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong external auth http status code: %v, expected 200", resp.StatusCode)
		}
		return ioutil.ReadAll(resp.Body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, config.ExternalAuthHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_AUTHD_USERNAME=%v", username),
		fmt.Sprintf("SFTPGO_AUTHD_IP=%v", ip),
		fmt.Sprintf("SFTPGO_AUTHD_PASSWORD=%v", password),
		fmt.Sprintf("SFTPGO_AUTHD_PUBLIC_KEY=%v", pkey),
		fmt.Sprintf("SFTPGO_AUTHD_PROTOCOL=%v", protocol),
		fmt.Sprintf("SFTPGO_AUTHD_KEYBOARD_INTERACTIVE=%v", keyboardInteractive))
	return cmd.Output()
}

func doExternalAuth(username, password string, pubKey []byte, keyboardInteractive, ip, protocol string) (User, error) {
	var user User
	pkey := ""
	if len(pubKey) > 0 {
		k, err := ssh.ParsePublicKey(pubKey)
		if err != nil {
			return user, err
		}
		pkey = string(ssh.MarshalAuthorizedKey(k))
	}
	out, err := getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol)
	if err != nil {
		return user, fmt.Errorf("External auth error: %v", err)
	}
	err = json.Unmarshal(out, &user)
	if err != nil {
		return user, fmt.Errorf("Invalid external auth response: %v", err)
	}
	if len(user.Username) == 0 {
		return user, ErrInvalidCredentials
	}
	if len(password) > 0 {
		user.Password = password
	}
	if len(pkey) > 0 && !utils.IsStringPrefixInSlice(pkey, user.PublicKeys) {
		user.PublicKeys = append(user.PublicKeys, pkey)
	}
	// some users want to map multiple login usernames with a single SGTPGo account
	// for example an SFTP user logins using "user1" or "user2" and the external auth
	// returns "user" in both cases, so we use the username returned from
	// external auth and not the one used to login
	u, err := provider.userExists(user.Username)
	if err == nil {
		user.ID = u.ID
		user.UsedQuotaSize = u.UsedQuotaSize
		user.UsedQuotaFiles = u.UsedQuotaFiles
		user.LastQuotaUpdate = u.LastQuotaUpdate
		user.LastLogin = u.LastLogin
		err = provider.updateUser(user)
	} else {
		err = provider.addUser(user)
	}
	if err != nil {
		return user, err
	}
	return provider.userExists(user.Username)
}

func providerLog(level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, logSender, "", format, v...)
}

func executeNotificationCommand(operation string, user User) error {
	if !filepath.IsAbs(config.Actions.Hook) {
		err := fmt.Errorf("invalid notification command %#v", config.Actions.Hook)
		logger.Warn(logSender, "", "unable to execute notification command: %v", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	commandArgs := user.getNotificationFieldsAsSlice(operation)
	cmd := exec.CommandContext(ctx, config.Actions.Hook, commandArgs...)
	cmd.Env = append(os.Environ(), user.getNotificationFieldsAsEnvVars(operation)...)
	startTime := time.Now()
	err := cmd.Run()
	providerLog(logger.LevelDebug, "executed command %#v with arguments: %+v, elapsed: %v, error: %v",
		config.Actions.Hook, commandArgs, time.Since(startTime), err)
	return err
}

// executed in a goroutine
func executeAction(operation string, user User) {
	if !utils.IsStringInSlice(operation, config.Actions.ExecuteOn) {
		return
	}
	if len(config.Actions.Hook) == 0 {
		return
	}
	if operation != operationDelete {
		var err error
		user, err = provider.userExists(user.Username)
		if err != nil {
			providerLog(logger.LevelWarn, "unable to get the user to notify for operation %#v: %v", operation, err)
			return
		}
	}
	if strings.HasPrefix(config.Actions.Hook, "http") {
		var url *url.URL
		url, err := url.Parse(config.Actions.Hook)
		if err != nil {
			providerLog(logger.LevelWarn, "Invalid http_notification_url %#v for operation %#v: %v", config.Actions.Hook, operation, err)
			return
		}
		q := url.Query()
		q.Add("action", operation)
		url.RawQuery = q.Encode()
		user.HideConfidentialData()
		userAsJSON, err := json.Marshal(user)
		if err != nil {
			return
		}
		startTime := time.Now()
		httpClient := httpclient.GetHTTPClient()
		resp, err := httpClient.Post(url.String(), "application/json", bytes.NewBuffer(userAsJSON))
		respCode := 0
		if err == nil {
			respCode = resp.StatusCode
			resp.Body.Close()
		}
		providerLog(logger.LevelDebug, "notified operation %#v to URL: %v status code: %v, elapsed: %v err: %v",
			operation, url.String(), respCode, time.Since(startTime), err)
	} else {
		executeNotificationCommand(operation, user) //nolint:errcheck // the error is used in test cases only
	}
}

// after migrating database to v4 we have to update the quota for the imported folders
func updateVFoldersQuotaAfterRestore(foldersToScan []string) {
	fs := vfs.NewOsFs("", "", nil).(*vfs.OsFs)
	for _, folder := range foldersToScan {
		providerLog(logger.LevelDebug, "starting quota scan after migration for folder %#v", folder)
		vfolder, err := provider.getFolderByPath(folder)
		if err != nil {
			providerLog(logger.LevelWarn, "error getting folder to scan %#v: %v", folder, err)
			continue
		}
		numFiles, size, err := fs.GetDirSize(folder)
		if err != nil {
			providerLog(logger.LevelWarn, "error scanning folder %#v: %v", folder, err)
			continue
		}
		err = UpdateVirtualFolderQuota(vfolder, numFiles, size, true)
		providerLog(logger.LevelDebug, "quota updated for virtual folder %#v, error: %v", vfolder.MappedPath, err)
	}
}

func updateWebDavCachedUserLastLogin(username string) {
	result, ok := webDAVUsersCache.Load(username)
	if ok {
		cachedUser := result.(*CachedUser)
		cachedUser.User.LastLogin = utils.GetTimeAsMsSinceEpoch(time.Now())
		webDAVUsersCache.Store(cachedUser.User.Username, cachedUser)
	}
}

// CacheWebDAVUser add a user to the WebDAV cache
func CacheWebDAVUser(cachedUser *CachedUser, maxSize int) {
	if maxSize > 0 {
		var cacheSize int
		var userToRemove string
		var expirationTime time.Time

		webDAVUsersCache.Range(func(k, v interface{}) bool {
			cacheSize++
			if len(userToRemove) == 0 {
				userToRemove = k.(string)
				expirationTime = v.(*CachedUser).Expiration
				return true
			}
			expireTime := v.(*CachedUser).Expiration
			if !expireTime.IsZero() && expireTime.Before(expirationTime) {
				userToRemove = k.(string)
				expirationTime = expireTime
			}
			return true
		})

		if cacheSize >= maxSize {
			RemoveCachedWebDAVUser(userToRemove)
		}
	}

	if cachedUser.User.Username != "" {
		webDAVUsersCache.Store(cachedUser.User.Username, cachedUser)
	}
}

// GetCachedWebDAVUser returns a previously cached WebDAV user
func GetCachedWebDAVUser(username string) (interface{}, bool) {
	return webDAVUsersCache.Load(username)
}

// RemoveCachedWebDAVUser removes a cached WebDAV user
func RemoveCachedWebDAVUser(username string) {
	if username != "" {
		webDAVUsersCache.Delete(username)
	}
}
