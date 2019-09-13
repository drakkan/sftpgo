// Package dataprovider provides data access.
// It abstract different data providers and exposes a common API.
// Currently the supported data providers are: PostreSQL (9+), MySQL (4.1+) and SQLite 3.x
package dataprovider

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
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

	argonPwdPrefix           = "$argon2id$"
	bcryptPwdPrefix          = "$2a$"
	pbkdf2SHA1Prefix         = "$pbkdf2-sha1$"
	pbkdf2SHA256Prefix       = "$pbkdf2-sha256$"
	pbkdf2SHA512Prefix       = "$pbkdf2-sha512$"
	manageUsersDisabledError = "please set manage_users to 1 in sftpgo.conf to enable this method"
	trackQuotaDisabledError  = "please enable track_quota in sftpgo.conf to use this method"
)

var (
	// SupportedProviders data provider configured in the sftpgo.conf file must match of these strings
	SupportedProviders = []string{SQLiteDataProviderName, PGSQLDataProviderName, MySQLDataProviderName, BoltDataProviderName}
	config             Config
	provider           Provider
	sqlPlaceholders    []string
	validPerms         = []string{PermAny, PermListItems, PermDownload, PermUpload, PermDelete, PermRename,
		PermCreateDirs, PermCreateSymlinks}
	hashPwdPrefixes    = []string{argonPwdPrefix, bcryptPwdPrefix, pbkdf2SHA1Prefix, pbkdf2SHA256Prefix, pbkdf2SHA512Prefix}
	pbkdfPwdPrefixes   = []string{pbkdf2SHA1Prefix, pbkdf2SHA256Prefix, pbkdf2SHA512Prefix}
	logSender          = "dataProvider"
	availabilityTicker *time.Ticker
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
	// Sets the maximum number of open connections for mysql and postgresql driver.
	// Default 0 (unlimited)
	PoolSize int `json:"pool_size" mapstructure:"pool_size"`
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
	validateUserAndPubKey(username string, pubKey string) (User, string, error)
	updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error
	getUsedQuota(username string) (int, int64, error)
	userExists(username string) (User, error)
	addUser(user User) error
	updateUser(user User) error
	deleteUser(user User) error
	getUsers(limit int, offset int, order string, username string) ([]User, error)
	getUserByID(ID int64) (User, error)
	checkAvailability() error
}

func init() {
	availabilityTicker = time.NewTicker(30 * time.Second)
}

// Initialize the data provider.
// An error is returned if the configured driver is invalid or if the data provider cannot be initialized
func Initialize(cnf Config, basePath string) error {
	var err error
	config = cnf
	sqlPlaceholders = getSQLPlaceholders()
	if config.Driver == SQLiteDataProviderName {
		err = initializeSQLiteProvider(basePath)
	} else if config.Driver == PGSQLDataProviderName {
		err = initializePGSQLProvider()
	} else if config.Driver == MySQLDataProviderName {
		err = initializeMySQLProvider()
	} else if config.Driver == BoltDataProviderName {
		err = initializeBoltProvider(basePath)
	} else {
		err = fmt.Errorf("Unsupported data provider: %v", config.Driver)
	}
	if err == nil {
		startAvailabilityTimer()
	}
	return err
}

// CheckUserAndPass retrieves the SFTP user with the given username and password if a match is found or an error
func CheckUserAndPass(p Provider, username string, password string) (User, error) {
	return p.validateUserAndPass(username, password)
}

// CheckUserAndPubKey retrieves the SFTP user with the given username and public key if a match is found or an error
func CheckUserAndPubKey(p Provider, username string, pubKey string) (User, string, error) {
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
	if len(user.Password) > 0 && !utils.IsStringPrefixInSlice(user.Password, hashPwdPrefixes) {
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
			providerLog(logger.LevelWarn, "error comparing password with argon hash: %v", err)
			return user, err
		}
	} else if strings.HasPrefix(user.Password, bcryptPwdPrefix) {
		if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			providerLog(logger.LevelWarn, "error comparing password with bcrypt hash: %v", err)
			return user, err
		}
		match = true
	} else if utils.IsStringPrefixInSlice(user.Password, pbkdfPwdPrefixes) {
		match, err = comparePbkdf2PasswordAndHash(password, user.Password)
		if err != nil {
			providerLog(logger.LevelWarn, "error comparing password with pbkdf2 sha256 hash: %v", err)
			return user, err
		}
	}
	if !match {
		err = errors.New("Invalid credentials")
	}
	return user, err
}

func checkUserAndPubKey(user User, pubKey string) (User, string, error) {
	if len(user.PublicKeys) == 0 {
		return user, "", errors.New("Invalid credentials")
	}
	for i, k := range user.PublicKeys {
		storedPubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil {
			providerLog(logger.LevelWarn, "error parsing stored public key %d for user %v: %v", i, user.Username, err)
			return user, "", err
		}
		if string(storedPubKey.Marshal()) == pubKey {
			fp := ssh.FingerprintSHA256(storedPubKey)
			return user, fp + ":" + comment, nil
		}
	}
	return user, "", errors.New("Invalid credentials")
}

func comparePbkdf2PasswordAndHash(password, hashedPassword string) (bool, error) {
	vals := strings.Split(hashedPassword, "$")
	if len(vals) != 5 {
		return false, fmt.Errorf("pbkdf2: hash is not in the correct format")
	}
	var hashFunc func() hash.Hash
	var hashSize int
	if strings.HasPrefix(hashedPassword, pbkdf2SHA256Prefix) {
		hashSize = sha256.Size
		hashFunc = sha256.New
	} else if strings.HasPrefix(hashedPassword, pbkdf2SHA512Prefix) {
		hashSize = sha512.Size
		hashFunc = sha512.New
	} else if strings.HasPrefix(hashedPassword, pbkdf2SHA1Prefix) {
		hashSize = sha1.Size
		hashFunc = sha1.New
	} else {
		return false, fmt.Errorf("pbkdf2: invalid or unsupported hash format %v", vals[1])
	}
	iterations, err := strconv.Atoi(vals[2])
	if err != nil {
		return false, err
	}
	salt := vals[3]
	expected := vals[4]
	df := pbkdf2.Key([]byte(password), []byte(salt), iterations, hashSize, hashFunc)
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(df)))
	base64.StdEncoding.Encode(buf, df)
	return subtle.ConstantTimeCompare(buf, []byte(expected)) == 1, nil
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
	checkDataprovider()
	go func() {
		for range availabilityTicker.C {
			checkDataprovider()
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

func providerLog(level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, logSender, "", format, v...)
}
