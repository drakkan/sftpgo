// +build !nomysql

package dataprovider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	// we import go-sql-driver/mysql here to be able to disable MySQL support using a build tag
	_ "github.com/go-sql-driver/mysql"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	mysqlInitialSQL = "CREATE TABLE `{{schema_version}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `version` integer NOT NULL);" +
		"CREATE TABLE `{{admins}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `username` varchar(255) NOT NULL UNIQUE, " +
		"`description` varchar(512) NULL, `password` varchar(255) NOT NULL, `email` varchar(255) NULL, `status` integer NOT NULL, " +
		"`permissions` longtext NOT NULL, `filters` longtext NULL, `additional_info` longtext NULL);" +
		"CREATE TABLE `{{folders}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `name` varchar(255) NOT NULL UNIQUE, " +
		"`description` varchar(512) NULL, `path` varchar(512) NULL, `used_quota_size` bigint NOT NULL, " +
		"`used_quota_files` integer NOT NULL, `last_quota_update` bigint NOT NULL, `filesystem` longtext NULL);" +
		"CREATE TABLE `{{users}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `username` varchar(255) NOT NULL UNIQUE, " +
		"`status` integer NOT NULL, `expiration_date` bigint NOT NULL, `description` varchar(512) NULL, `password` longtext NULL, " +
		"`public_keys` longtext NULL, `home_dir` varchar(512) NOT NULL, `uid` integer NOT NULL, `gid` integer NOT NULL, " +
		"`max_sessions` integer NOT NULL, `quota_size` bigint NOT NULL, `quota_files` integer NOT NULL, " +
		"`permissions` longtext NOT NULL, `used_quota_size` bigint NOT NULL, `used_quota_files` integer NOT NULL, " +
		"`last_quota_update` bigint NOT NULL, `upload_bandwidth` integer NOT NULL, `download_bandwidth` integer NOT NULL, " +
		"`last_login` bigint NOT NULL, `filters` longtext NULL, `filesystem` longtext NULL, `additional_info` longtext NULL);" +
		"CREATE TABLE `{{folders_mapping}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `virtual_path` varchar(512) NOT NULL, " +
		"`quota_size` bigint NOT NULL, `quota_files` integer NOT NULL, `folder_id` integer NOT NULL, `user_id` integer NOT NULL);" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `{{prefix}}unique_mapping` UNIQUE (`user_id`, `folder_id`);" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `{{prefix}}folders_mapping_folder_id_fk_folders_id` FOREIGN KEY (`folder_id`) REFERENCES `{{folders}}` (`id`) ON DELETE CASCADE;" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `{{prefix}}folders_mapping_user_id_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `{{users}}` (`id`) ON DELETE CASCADE;" +
		"INSERT INTO {{schema_version}} (version) VALUES (10);"
	mysqlV11SQL = "CREATE TABLE `{{api_keys}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `name` varchar(255) NOT NULL, `key_id` varchar(50) NOT NULL UNIQUE," +
		"`api_key` varchar(255) NOT NULL UNIQUE, `scope` integer NOT NULL, `created_at` bigint NOT NULL, `updated_at` bigint NOT NULL, `last_use_at` bigint NOT NULL, " +
		"`expires_at` bigint NOT NULL, `description` longtext NULL, `admin_id` integer NULL, `user_id` integer NULL);" +
		"ALTER TABLE `{{api_keys}}` ADD CONSTRAINT `{{prefix}}api_keys_admin_id_fk_admins_id` FOREIGN KEY (`admin_id`) REFERENCES `{{admins}}` (`id`) ON DELETE CASCADE;" +
		"ALTER TABLE `{{api_keys}}` ADD CONSTRAINT `{{prefix}}api_keys_user_id_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `{{users}}` (`id`) ON DELETE CASCADE;"
	mysqlV11DownSQL = "DROP TABLE `{{api_keys}}` CASCADE;"
)

// MySQLProvider auth provider for MySQL/MariaDB database
type MySQLProvider struct {
	dbHandle *sql.DB
}

func init() {
	version.AddFeature("+mysql")
}

func initializeMySQLProvider() error {
	var err error

	dbHandle, err := sql.Open("mysql", getMySQLConnectionString(false))
	if err == nil {
		providerLog(logger.LevelDebug, "mysql database handle created, connection string: %#v, pool size: %v",
			getMySQLConnectionString(true), config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		if config.PoolSize > 0 {
			dbHandle.SetMaxIdleConns(config.PoolSize)
		} else {
			dbHandle.SetMaxIdleConns(2)
		}
		dbHandle.SetConnMaxLifetime(240 * time.Second)
		provider = &MySQLProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating mysql database handler, connection string: %#v, error: %v",
			getMySQLConnectionString(true), err)
	}
	return err
}
func getMySQLConnectionString(redactedPwd bool) string {
	var connectionString string
	if config.ConnectionString == "" {
		password := config.Password
		if redactedPwd {
			password = "[redacted]"
		}
		connectionString = fmt.Sprintf("%v:%v@tcp([%v]:%v)/%v?charset=utf8&interpolateParams=true&timeout=10s&tls=%v&writeTimeout=10s&readTimeout=10s",
			config.Username, password, config.Host, config.Port, config.Name, getSSLMode())
	} else {
		connectionString = config.ConnectionString
	}
	return connectionString
}

func (p *MySQLProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p *MySQLProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, ip, protocol, p.dbHandle)
}

func (p *MySQLProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	return sqlCommonValidateUserAndTLSCertificate(username, protocol, tlsCert, p.dbHandle)
}

func (p *MySQLProvider) validateUserAndPubKey(username string, publicKey []byte) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p *MySQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *MySQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p *MySQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p *MySQLProvider) userExists(username string) (User, error) {
	return sqlCommonGetUserByUsername(username, p.dbHandle)
}

func (p *MySQLProvider) addUser(user *User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p *MySQLProvider) updateUser(user *User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p *MySQLProvider) deleteUser(user *User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p *MySQLProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p *MySQLProvider) getUsers(limit int, offset int, order string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p *MySQLProvider) getFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonGetFolderByName(ctx, name, p.dbHandle)
}

func (p *MySQLProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonAddFolder(folder, p.dbHandle)
}

func (p *MySQLProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonUpdateFolder(folder, p.dbHandle)
}

func (p *MySQLProvider) deleteFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p *MySQLProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *MySQLProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, p.dbHandle)
}

func (p *MySQLProvider) adminExists(username string) (Admin, error) {
	return sqlCommonGetAdminByUsername(username, p.dbHandle)
}

func (p *MySQLProvider) addAdmin(admin *Admin) error {
	return sqlCommonAddAdmin(admin, p.dbHandle)
}

func (p *MySQLProvider) updateAdmin(admin *Admin) error {
	return sqlCommonUpdateAdmin(admin, p.dbHandle)
}

func (p *MySQLProvider) deleteAdmin(admin *Admin) error {
	return sqlCommonDeleteAdmin(admin, p.dbHandle)
}

func (p *MySQLProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	return sqlCommonGetAdmins(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) dumpAdmins() ([]Admin, error) {
	return sqlCommonDumpAdmins(p.dbHandle)
}

func (p *MySQLProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	return sqlCommonValidateAdminAndPass(username, password, ip, p.dbHandle)
}

func (p *MySQLProvider) apiKeyExists(keyID string) (APIKey, error) {
	return sqlCommonGetAPIKeyByID(keyID, p.dbHandle)
}

func (p *MySQLProvider) addAPIKey(apiKey *APIKey) error {
	return sqlCommonAddAPIKey(apiKey, p.dbHandle)
}

func (p *MySQLProvider) updateAPIKey(apiKey *APIKey) error {
	return sqlCommonUpdateAPIKey(apiKey, p.dbHandle)
}

func (p *MySQLProvider) deleteAPIKeys(apiKey *APIKey) error {
	return sqlCommonDeleteAPIKey(apiKey, p.dbHandle)
}

func (p *MySQLProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	return sqlCommonGetAPIKeys(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) dumpAPIKeys() ([]APIKey, error) {
	return sqlCommonDumpAPIKeys(p.dbHandle)
}

func (p *MySQLProvider) updateAPIKeyLastUse(keyID string) error {
	return sqlCommonUpdateAPIKeyLastUse(keyID, p.dbHandle)
}

func (p *MySQLProvider) close() error {
	return p.dbHandle.Close()
}

func (p *MySQLProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (p *MySQLProvider) initializeDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, false)
	if err == nil && dbVersion.Version > 0 {
		return ErrNoInitRequired
	}
	initialSQL := strings.ReplaceAll(mysqlInitialSQL, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(initialSQL, ";"), 10)
}

func (p *MySQLProvider) migrateDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}

	switch version := dbVersion.Version; {
	case version == sqlDatabaseVersion:
		providerLog(logger.LevelDebug, "sql database is up to date, current version: %v", version)
		return ErrNoInitRequired
	case version < 10:
		err = fmt.Errorf("database version %v is too old, please see the upgrading docs", version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 10:
		return updateMySQLDatabaseFromV10(p.dbHandle)
	default:
		if version > sqlDatabaseVersion {
			providerLog(logger.LevelWarn, "database version %v is newer than the supported one: %v", version,
				sqlDatabaseVersion)
			logger.WarnToConsole("database version %v is newer than the supported one: %v", version,
				sqlDatabaseVersion)
			return nil
		}
		return fmt.Errorf("database version not handled: %v", version)
	}
}

func (p *MySQLProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}

	switch dbVersion.Version {
	case 11:
		return downgradeMySQLDatabaseFromV11(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func updateMySQLDatabaseFromV10(dbHandle *sql.DB) error {
	return updateMySQLDatabaseFrom10To11(dbHandle)
}

func downgradeMySQLDatabaseFromV11(dbHandle *sql.DB) error {
	return downgradeMySQLDatabaseFrom11To10(dbHandle)
}

func updateMySQLDatabaseFrom10To11(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 10 -> 11")
	providerLog(logger.LevelInfo, "updating database version: 10 -> 11")
	sql := strings.ReplaceAll(mysqlV11SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 11)
}

func downgradeMySQLDatabaseFrom11To10(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 11 -> 10")
	providerLog(logger.LevelInfo, "downgrading database version: 11 -> 10")
	sql := strings.ReplaceAll(mysqlV11DownSQL, "{{api_keys}}", sqlTableAPIKeys)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 10)
}
