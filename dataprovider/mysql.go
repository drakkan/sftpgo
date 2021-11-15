//go:build !nomysql
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
	mysqlResetSQL = "DROP TABLE IF EXISTS `{{api_keys}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{folders_mapping}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{admins}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{folders}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{shares}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{users}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{schema_version}}` CASCADE;"
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
	mysqlV12SQL     = "ALTER TABLE `{{admins}}` ADD COLUMN `created_at` bigint DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{admins}}` ALTER COLUMN `created_at` DROP DEFAULT;" +
		"ALTER TABLE `{{admins}}` ADD COLUMN `updated_at` bigint DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{admins}}` ALTER COLUMN `updated_at` DROP DEFAULT;" +
		"ALTER TABLE `{{admins}}` ADD COLUMN `last_login` bigint DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{admins}}` ALTER COLUMN `last_login` DROP DEFAULT;" +
		"ALTER TABLE `{{users}}` ADD COLUMN `created_at` bigint DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{users}}` ALTER COLUMN `created_at` DROP DEFAULT;" +
		"ALTER TABLE `{{users}}` ADD COLUMN `updated_at` bigint DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{users}}` ALTER COLUMN `updated_at` DROP DEFAULT;" +
		"CREATE INDEX `{{prefix}}users_updated_at_idx` ON `{{users}}` (`updated_at`);"
	mysqlV12DownSQL = "ALTER TABLE `{{admins}}` DROP COLUMN `updated_at`;" +
		"ALTER TABLE `{{admins}}` DROP COLUMN `created_at`;" +
		"ALTER TABLE `{{admins}}` DROP COLUMN `last_login`;" +
		"ALTER TABLE `{{users}}` DROP COLUMN `created_at`;" +
		"ALTER TABLE `{{users}}` DROP COLUMN `updated_at`;"

	mysqlV13SQL     = "ALTER TABLE `{{users}}` ADD COLUMN `email` varchar(255) NULL;"
	mysqlV13DownSQL = "ALTER TABLE `{{users}}` DROP COLUMN `email`;"
	mysqlV14SQL     = "CREATE TABLE `{{shares}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, " +
		"`share_id` varchar(60) NOT NULL UNIQUE, `name` varchar(255) NOT NULL, `description` varchar(512) NULL, " +
		"`scope` integer NOT NULL, `paths` longtext NOT NULL, `created_at` bigint NOT NULL, " +
		"`updated_at` bigint NOT NULL, `last_use_at` bigint NOT NULL, `expires_at` bigint NOT NULL, " +
		"`password` longtext NULL, `max_tokens` integer NOT NULL, `used_tokens` integer NOT NULL, " +
		"`allow_from` longtext NULL, `user_id` integer NOT NULL);" +
		"ALTER TABLE `{{shares}}` ADD CONSTRAINT `{{prefix}}shares_user_id_fk_users_id` " +
		"FOREIGN KEY (`user_id`) REFERENCES `{{users}}` (`id`) ON DELETE CASCADE;"
	mysqlV14DownSQL = "DROP TABLE `{{shares}}` CASCADE;"
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
		connectionString = fmt.Sprintf("%v:%v@tcp([%v]:%v)/%v?charset=utf8mb4&interpolateParams=true&timeout=10s&parseTime=true&tls=%v&writeTimeout=10s&readTimeout=10s",
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

func (p *MySQLProvider) setUpdatedAt(username string) {
	sqlCommonSetUpdatedAt(username, p.dbHandle)
}

func (p *MySQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p *MySQLProvider) updateAdminLastLogin(username string) error {
	return sqlCommonUpdateAdminLastLogin(username, p.dbHandle)
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

func (p *MySQLProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return sqlCommonGetRecentlyUpdatedUsers(after, p.dbHandle)
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

func (p *MySQLProvider) deleteAPIKey(apiKey *APIKey) error {
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

func (p *MySQLProvider) shareExists(shareID, username string) (Share, error) {
	return sqlCommonGetShareByID(shareID, username, p.dbHandle)
}

func (p *MySQLProvider) addShare(share *Share) error {
	return sqlCommonAddShare(share, p.dbHandle)
}

func (p *MySQLProvider) updateShare(share *Share) error {
	return sqlCommonUpdateShare(share, p.dbHandle)
}

func (p *MySQLProvider) deleteShare(share *Share) error {
	return sqlCommonDeleteShare(share, p.dbHandle)
}

func (p *MySQLProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	return sqlCommonGetShares(limit, offset, order, username, p.dbHandle)
}

func (p *MySQLProvider) dumpShares() ([]Share, error) {
	return sqlCommonDumpShares(p.dbHandle)
}

func (p *MySQLProvider) updateShareLastUse(shareID string, numTokens int) error {
	return sqlCommonUpdateShareLastUse(shareID, numTokens, p.dbHandle)
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
	if errors.Is(err, sql.ErrNoRows) {
		return errSchemaVersionEmpty
	}
	initialSQL := strings.ReplaceAll(mysqlInitialSQL, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(initialSQL, ";"), 10)
}

//nolint:dupl
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
	case version == 11:
		return updateMySQLDatabaseFromV11(p.dbHandle)
	case version == 12:
		return updateMySQLDatabaseFromV12(p.dbHandle)
	case version == 13:
		return updateMySQLDatabaseFromV13(p.dbHandle)
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
	case 14:
		return downgradeMySQLDatabaseFromV14(p.dbHandle)
	case 13:
		return downgradeMySQLDatabaseFromV13(p.dbHandle)
	case 12:
		return downgradeMySQLDatabaseFromV12(p.dbHandle)
	case 11:
		return downgradeMySQLDatabaseFromV11(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func (p *MySQLProvider) resetDatabase() error {
	sql := strings.ReplaceAll(mysqlResetSQL, "{{schema_version}}", sqlTableSchemaVersion)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(sql, ";"), 0)
}

func updateMySQLDatabaseFromV10(dbHandle *sql.DB) error {
	if err := updateMySQLDatabaseFrom10To11(dbHandle); err != nil {
		return err
	}
	return updateMySQLDatabaseFromV11(dbHandle)
}

func updateMySQLDatabaseFromV11(dbHandle *sql.DB) error {
	if err := updateMySQLDatabaseFrom11To12(dbHandle); err != nil {
		return err
	}
	return updateMySQLDatabaseFromV12(dbHandle)
}

func updateMySQLDatabaseFromV12(dbHandle *sql.DB) error {
	if err := updateMySQLDatabaseFrom12To13(dbHandle); err != nil {
		return err
	}
	return updateMySQLDatabaseFromV13(dbHandle)
}

func updateMySQLDatabaseFromV13(dbHandle *sql.DB) error {
	return updateMySQLDatabaseFrom13To14(dbHandle)
}

func downgradeMySQLDatabaseFromV14(dbHandle *sql.DB) error {
	if err := downgradeMySQLDatabaseFrom14To13(dbHandle); err != nil {
		return err
	}
	return downgradeMySQLDatabaseFromV13(dbHandle)
}

func downgradeMySQLDatabaseFromV13(dbHandle *sql.DB) error {
	if err := downgradeMySQLDatabaseFrom13To12(dbHandle); err != nil {
		return err
	}
	return downgradeMySQLDatabaseFromV12(dbHandle)
}

func downgradeMySQLDatabaseFromV12(dbHandle *sql.DB) error {
	if err := downgradeMySQLDatabaseFrom12To11(dbHandle); err != nil {
		return err
	}
	return downgradeMySQLDatabaseFromV11(dbHandle)
}

func downgradeMySQLDatabaseFromV11(dbHandle *sql.DB) error {
	return downgradeMySQLDatabaseFrom11To10(dbHandle)
}

func updateMySQLDatabaseFrom13To14(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 13 -> 14")
	providerLog(logger.LevelInfo, "updating database version: 13 -> 14")
	sql := strings.ReplaceAll(mysqlV14SQL, "{{shares}}", sqlTableShares)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 14)
}

func downgradeMySQLDatabaseFrom14To13(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 14 -> 13")
	providerLog(logger.LevelInfo, "downgrading database version: 14 -> 13")
	sql := strings.ReplaceAll(mysqlV14DownSQL, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 13)
}

func updateMySQLDatabaseFrom12To13(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 12 -> 13")
	providerLog(logger.LevelInfo, "updating database version: 12 -> 13")
	sql := strings.ReplaceAll(mysqlV13SQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 13)
}

func downgradeMySQLDatabaseFrom13To12(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 13 -> 12")
	providerLog(logger.LevelInfo, "downgrading database version: 13 -> 12")
	sql := strings.ReplaceAll(mysqlV13DownSQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 12)
}

func updateMySQLDatabaseFrom11To12(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 11 -> 12")
	providerLog(logger.LevelInfo, "updating database version: 11 -> 12")
	sql := strings.ReplaceAll(mysqlV12SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 12)
}

func downgradeMySQLDatabaseFrom12To11(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 12 -> 11")
	providerLog(logger.LevelInfo, "downgrading database version: 12 -> 11")
	sql := strings.ReplaceAll(mysqlV12DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 11)
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
