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

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	mysqlInitialSQL = "CREATE TABLE `{{schema_version}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `version` integer NOT NULL);" +
		"CREATE TABLE `{{admins}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `username` varchar(255) NOT NULL UNIQUE, " +
		"`password` varchar(255) NOT NULL, `email` varchar(255) NULL, `status` integer NOT NULL, `permissions` longtext NOT NULL, " +
		"`filters` longtext NULL, `additional_info` longtext NULL);" +
		"CREATE TABLE `{{folders}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `name` varchar(255) NOT NULL UNIQUE, " +
		"`path` varchar(512) NULL, `used_quota_size` bigint NOT NULL, `used_quota_files` integer NOT NULL, " +
		"`last_quota_update` bigint NOT NULL);" +
		"CREATE TABLE `{{users}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `status` integer NOT NULL, " +
		"`expiration_date` bigint NOT NULL, `username` varchar(255) NOT NULL UNIQUE, `password` longtext NULL, " +
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
		"INSERT INTO {{schema_version}} (version) VALUES (8);"
	mysqlV9SQL = "ALTER TABLE `{{admins}}` ADD COLUMN `description` varchar(512) NULL;" +
		"ALTER TABLE `{{folders}}` ADD COLUMN `description` varchar(512) NULL;" +
		"ALTER TABLE `{{folders}}` ADD COLUMN `filesystem` longtext NULL;" +
		"ALTER TABLE `{{users}}` ADD COLUMN `description` varchar(512) NULL;"
	mysqlV9DownSQL = "ALTER TABLE `{{users}}` DROP COLUMN `description`;" +
		"ALTER TABLE `{{folders}}` DROP COLUMN `filesystem`;" +
		"ALTER TABLE `{{folders}}` DROP COLUMN `description`;" +
		"ALTER TABLE `{{admins}}` DROP COLUMN `description`;"
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

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(initialSQL, ";"), 8)
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
	case version < 8:
		err = fmt.Errorf("database version %v is too old, please see the upgrading docs", version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 8:
		return updateMySQLDatabaseFromV8(p.dbHandle)
	case version == 9:
		return updateMySQLDatabaseFromV9(p.dbHandle)
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
	case 9:
		return downgradeMySQLDatabaseFromV9(p.dbHandle)
	case 10:
		return downgradeMySQLDatabaseFromV10(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func updateMySQLDatabaseFromV8(dbHandle *sql.DB) error {
	if err := updateMySQLDatabaseFrom8To9(dbHandle); err != nil {
		return err
	}
	return updateMySQLDatabaseFromV9(dbHandle)
}

func updateMySQLDatabaseFromV9(dbHandle *sql.DB) error {
	return updateMySQLDatabaseFrom9To10(dbHandle)
}

func downgradeMySQLDatabaseFromV9(dbHandle *sql.DB) error {
	return downgradeMySQLDatabaseFrom9To8(dbHandle)
}

func downgradeMySQLDatabaseFromV10(dbHandle *sql.DB) error {
	if err := downgradeMySQLDatabaseFrom10To9(dbHandle); err != nil {
		return err
	}
	return downgradeMySQLDatabaseFromV9(dbHandle)
}

func updateMySQLDatabaseFrom8To9(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 8 -> 9")
	providerLog(logger.LevelInfo, "updating database version: 8 -> 9")
	sql := strings.ReplaceAll(mysqlV9SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 9)
}

func downgradeMySQLDatabaseFrom9To8(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 9 -> 8")
	providerLog(logger.LevelInfo, "downgrading database version: 9 -> 8")
	sql := strings.ReplaceAll(mysqlV9DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 8)
}

func updateMySQLDatabaseFrom9To10(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom9To10(dbHandle)
}

func downgradeMySQLDatabaseFrom10To9(dbHandle *sql.DB) error {
	return sqlCommonDowngradeDatabaseFrom10To9(dbHandle)
}
