// Package dataprovider provides data access.
// It abstract different data providers and exposes a common API.
// Currently the supported data providers are: PostreSQL (9+), MySQL (4.1+) and SQLite 3.x
package dataprovider

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	// SQLiteDataProviderName name for SQLite database provider
	SQLiteDataProviderName = "sqlite"
	// PGSSQLDataProviderName name for PostgreSQL database provider
	PGSSQLDataProviderName = "postgresql"
	// MySQLDataProviderName name for MySQL database provider
	MySQLDataProviderName = "mysql"
	// BoltDataProviderName name for bbolt key/value store provider
	BoltDataProviderName = "bolt"

	logSender                = "dataProvider"
	argonPwdPrefix           = "$argon2id$"
	bcryptPwdPrefix          = "$2a$"
	manageUsersDisabledError = "please set manage_users to 1 in sftpgo.conf to enable this method"
	trackQuotaDisabledError  = "please enable track_quota in sftpgo.conf to use this method"
)

var (
	// SupportedProviders data provider configured in the sftpgo.conf file must match of these strings
	SupportedProviders = []string{SQLiteDataProviderName, PGSSQLDataProviderName, MySQLDataProviderName, BoltDataProviderName}
	config             Config
	provider           Provider
	sqlPlaceholders    []string
	validPerms         = []string{PermAny, PermListItems, PermDownload, PermUpload, PermDelete, PermRename,
		PermCreateDirs, PermCreateSymlinks}
)

// Config provider configuration
type Config struct {
	// Driver name, must be one of the SupportedProviders
	Driver string `json:"driver" mapstructure:"driver"`
	// Database name
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
	// Database table for SFTP users
	UsersTable string `json:"users_table" mapstructure:"users_table"`
	// Set to 0 to disable users management, 1 to enable
	ManageUsers int `json:"manage_users" mapstructure:"manage_users"`
	// Set the preferred way to track users quota between the following choices:
	// 0, disable quota tracking. REST API to scan user dir and update quota will do nothing
	// 1, quota is updated each time a user upload or delete a file even if the user has no quota restrictions
	// 2, quota is updated each time a user upload or delete a file but only for users with quota restrictions.
	//    With this configuration the "quota scan" REST API can still be used to periodically update space usage
	//    for users without quota restrictions
	TrackQuota int `json:"track_quota" mapstructure:"track_quota"`
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
// every time an user operation is done using the REST API
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

// GetProvider returns the configured provider
func GetProvider() Provider {
	return provider
}

// Provider interface that data providers must implement.
type Provider interface {
	validateUserAndPass(username string, password string) (User, error)
	validateUserAndPubKey(username string, pubKey string) (User, error)
	updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error
	getUsedQuota(username string) (int, int64, error)
	userExists(username string) (User, error)
	addUser(user User) error
	updateUser(user User) error
	deleteUser(user User) error
	getUsers(limit int, offset int, order string, username string) ([]User, error)
	getUserByID(ID int64) (User, error)
}

// Initialize the data provider.
// An error is returned if the configured driver is invalid or if the data provider cannot be initialized
func Initialize(cnf Config, basePath string) error {
	config = cnf
	sqlPlaceholders = getSQLPlaceholders()
	if config.Driver == SQLiteDataProviderName {
		return initializeSQLiteProvider(basePath)
	} else if config.Driver == PGSSQLDataProviderName {
		return initializePGSQLProvider()
	} else if config.Driver == MySQLDataProviderName {
		return initializeMySQLProvider()
	} else if config.Driver == BoltDataProviderName {
		return initializeBoltProvider(basePath)
	}
	return fmt.Errorf("Unsupported data provider: %v", config.Driver)
}

// CheckUserAndPass retrieves the SFTP user with the given username and password if a match is found or an error
func CheckUserAndPass(p Provider, username string, password string) (User, error) {
	return p.validateUserAndPass(username, password)
}

// CheckUserAndPubKey retrieves the SFTP user with the given username and public key if a match is found or an error
func CheckUserAndPubKey(p Provider, username string, pubKey string) (User, error) {
	return p.validateUserAndPubKey(username, pubKey)
}

// UpdateUserQuota updates the quota for the given SFTP user adding filesAdd and sizeAdd.
// If reset is true filesAdd and sizeAdd indicates the total files and the total size instead of the difference.
func UpdateUserQuota(p Provider, user User, filesAdd int, sizeAdd int64, reset bool) error {
	if config.TrackQuota == 0 {
		return &MethodDisabledError{err: trackQuotaDisabledError}
	} else if config.TrackQuota == 2 && !reset && !user.HasQuotaRestrictions() {
		return nil
	}
	return p.updateQuota(user.Username, filesAdd, sizeAdd, reset)
}

// GetUsedQuota returns the used quota for the given SFTP user.
// TrackQuota must be >=1 to enable this method
func GetUsedQuota(p Provider, username string) (int, int64, error) {
	if config.TrackQuota == 0 {
		return 0, 0, &MethodDisabledError{err: trackQuotaDisabledError}
	}
	return p.getUsedQuota(username)
}

// UserExists checks if the given SFTP username exists, returns an error if no match is found
func UserExists(p Provider, username string) (User, error) {
	return p.userExists(username)
}

// AddUser adds a new SFTP user.
// ManageUsers configuration must be set to 1 to enable this method
func AddUser(p Provider, user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return p.addUser(user)
}

// UpdateUser updates an existing SFTP user.
// ManageUsers configuration must be set to 1 to enable this method
func UpdateUser(p Provider, user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return p.updateUser(user)
}

// DeleteUser deletes an existing SFTP user.
// ManageUsers configuration must be set to 1 to enable this method
func DeleteUser(p Provider, user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return p.deleteUser(user)
}

// GetUsers returns an array of users respecting limit and offset and filtered by username exact match if not empty
func GetUsers(p Provider, limit int, offset int, order string, username string) ([]User, error) {
	return p.getUsers(limit, offset, order, username)
}

// GetUserByID returns the user with the given database ID if a match is found or an error
func GetUserByID(p Provider, ID int64) (User, error) {
	return p.getUserByID(ID)
}

func validateUser(user *User) error {
	if len(user.Username) == 0 || len(user.HomeDir) == 0 {
		return &ValidationError{err: "Mandatory parameters missing"}
	}
	if len(user.Password) == 0 && len(user.PublicKeys) == 0 {
		return &ValidationError{err: "Please set password or at least a public_key"}
	}
	if len(user.Permissions) == 0 {
		return &ValidationError{err: "Please grant some permissions to this user"}
	}
	if !filepath.IsAbs(user.HomeDir) {
		return &ValidationError{err: fmt.Sprintf("home_dir must be an absolute path, actual value: %v", user.HomeDir)}
	}
	for _, p := range user.Permissions {
		if !utils.IsStringInSlice(p, validPerms) {
			return &ValidationError{err: fmt.Sprintf("Invalid permission: %v", p)}
		}
	}
	if len(user.Password) > 0 && !strings.HasPrefix(user.Password, argonPwdPrefix) &&
		!strings.HasPrefix(user.Password, bcryptPwdPrefix) {
		pwd, err := argon2id.CreateHash(user.Password, argon2id.DefaultParams)
		if err != nil {
			return err
		}
		user.Password = pwd
	}
	for i, k := range user.PublicKeys {
		_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("Could not parse key nr. %d: %s", i, err)}
		}
	}
	return nil
}

func checkUserAndPass(user User, password string) (User, error) {
	var err error
	if len(user.Password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	var match bool
	if strings.HasPrefix(user.Password, argonPwdPrefix) {
		match, err = argon2id.ComparePasswordAndHash(password, user.Password)
		if err != nil {
			logger.Warn(logSender, "error comparing password with argon hash: %v", err)
			return user, err
		}
	} else if strings.HasPrefix(user.Password, bcryptPwdPrefix) {
		if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			logger.Warn(logSender, "error comparing password with bcrypt hash: %v", err)
			return user, err
		}
		match = true
	} else {
		// clear text password match
		match = (user.Password == password)
	}
	if !match {
		err = errors.New("Invalid credentials")
	}
	return user, err
}

func checkUserAndPubKey(user User, pubKey string) (User, error) {
	if len(user.PublicKeys) == 0 {
		return user, errors.New("Invalid credentials")
	}
	for i, k := range user.PublicKeys {
		storedPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			logger.Warn(logSender, "error parsing stored public key %d for user %v: %v", i, user.Username, err)
			return user, err
		}
		if string(storedPubKey.Marshal()) == pubKey {
			return user, nil
		}
	}
	return user, errors.New("Invalid credentials")
}

func getSSLMode() string {
	if config.Driver == PGSSQLDataProviderName {
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
