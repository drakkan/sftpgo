package dataprovider

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/utils"
)

const (
	// SQLiteDataProviderName name for sqlite db provider
	SQLiteDataProviderName = "sqlite"
	// PGSSQLDataProviderName name for postgresql db provider
	PGSSQLDataProviderName = "postgresql"
	// MySQLDataProviderName name for mysql db provider
	MySQLDataProviderName = "mysql"

	logSender                = "dataProvider"
	argonPwdPrefix           = "$argon2id$"
	manageUsersDisabledError = "please set manage_users to 1 in sftpgo.conf to enable this method"
	trackQuotaDisabledError  = "please enable track_quota in sftpgo.conf to use this method"
)

var (
	// SupportedProviders data provider in config file must be one of these strings
	SupportedProviders = []string{SQLiteDataProviderName, PGSSQLDataProviderName, MySQLDataProviderName}
	dbHandle           *sql.DB
	config             Config
	provider           Provider
	sqlPlaceholders    []string
	validPerms         = []string{PermAny, PermListItems, PermDownload, PermUpload, PermDelete, PermRename,
		PermCreateDirs, PermCreateSymlinks}
)

// Config provider configuration
type Config struct {
	Driver           string `json:"driver"`
	Name             string `json:"name"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	ConnectionString string `json:"connection_string"`
	UsersTable       string `json:"users_table"`
	ManageUsers      int    `json:"manage_users"`
	SSLMode          int    `json:"sslmode"`
	TrackQuota       int    `json:"track_quota"`
}

// ValidationError raised if input data is not valid
type ValidationError struct {
	err string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("Validation error: %s", e.err)
}

// MethodDisabledError raised if a method is disable in config file
type MethodDisabledError struct {
	err string
}

func (e *MethodDisabledError) Error() string {
	return fmt.Sprintf("Method disabled error: %s", e.err)
}

// GetProvider get the configured provider
func GetProvider() Provider {
	return provider
}

// Provider interface for data providers
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

// Initialize auth provider
func Initialize(cnf Config, basePath string) error {
	config = cnf
	sqlPlaceholders = getSQLPlaceholders()
	if config.Driver == SQLiteDataProviderName {
		provider = SQLiteProvider{}
		return initializeSQLiteProvider(basePath)
	} else if config.Driver == PGSSQLDataProviderName {
		provider = PGSQLProvider{}
		return initializePGSQLProvider()
	} else if config.Driver == MySQLDataProviderName {
		provider = SQLiteProvider{}
		return initializeMySQLProvider()
	}
	return fmt.Errorf("Unsupported data provider: %v", config.Driver)
}

// CheckUserAndPass returns the user with the given username and password if exists
func CheckUserAndPass(p Provider, username string, password string) (User, error) {
	return p.validateUserAndPass(username, password)
}

// CheckUserAndPubKey returns the user with the given username and public key if exists
func CheckUserAndPubKey(p Provider, username string, pubKey string) (User, error) {
	return p.validateUserAndPubKey(username, pubKey)
}

// UpdateUserQuota update the quota for the given user
func UpdateUserQuota(p Provider, user User, filesAdd int, sizeAdd int64, reset bool) error {
	if config.TrackQuota == 0 {
		return &MethodDisabledError{err: trackQuotaDisabledError}
	} else if config.TrackQuota == 2 && !reset && !user.HasQuotaRestrictions() {
		return nil
	}
	return p.updateQuota(user.Username, filesAdd, sizeAdd, reset)
}

// GetUsedQuota returns the used quota for the given user
func GetUsedQuota(p Provider, username string) (int, int64, error) {
	if config.TrackQuota == 0 {
		return 0, 0, &MethodDisabledError{err: trackQuotaDisabledError}
	}
	return p.getUsedQuota(username)
}

// UserExists checks if the given username exists
func UserExists(p Provider, username string) (User, error) {
	return p.userExists(username)
}

// AddUser adds a new user, ManageUsers configuration must be set to 1 to enable this method
func AddUser(p Provider, user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return p.addUser(user)
}

// UpdateUser updates an existing user, ManageUsers configuration must be set to 1 to enable this method
func UpdateUser(p Provider, user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return p.updateUser(user)
}

// DeleteUser deletes an existing user, ManageUsers configuration must be set to 1 to enable this method
func DeleteUser(p Provider, user User) error {
	if config.ManageUsers == 0 {
		return &MethodDisabledError{err: manageUsersDisabledError}
	}
	return p.deleteUser(user)
}

// GetUsers returns an array of users respecting limit and offset
func GetUsers(p Provider, limit int, offset int, order string, username string) ([]User, error) {
	return p.getUsers(limit, offset, order, username)
}

// GetUserByID returns the user with the given ID
func GetUserByID(p Provider, ID int64) (User, error) {
	return p.getUserByID(ID)
}

func validateUser(user *User) error {
	if len(user.Username) == 0 || len(user.HomeDir) == 0 {
		return &ValidationError{err: "Mandatory parameters missing"}
	}
	if len(user.Password) == 0 && len(user.PublicKey) == 0 {
		return &ValidationError{err: "Please set password or public_key"}
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
	if !strings.HasPrefix(user.Password, argonPwdPrefix) {
		pwd, err := argon2id.CreateHash(user.Password, argon2id.DefaultParams)
		if err != nil {
			return err
		}
		user.Password = pwd
	}
	if len(user.PublicKey) > 0 {
		_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.PublicKey))
		if err != nil {
			return err
		}
	}
	return nil
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
