// +build !nomysql

package dataprovider

import (
	"context"
	"database/sql"
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
	mysqlUsersTableSQL = "CREATE TABLE `{{users}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, " +
		"`username` varchar(255) NOT NULL UNIQUE, `password` varchar(255) NULL, `public_keys` longtext NULL, " +
		"`home_dir` varchar(255) NOT NULL, `uid` integer NOT NULL, `gid` integer NOT NULL, `max_sessions` integer NOT NULL, " +
		" `quota_size` bigint NOT NULL, `quota_files` integer NOT NULL, `permissions` longtext NOT NULL, " +
		"`used_quota_size` bigint NOT NULL, `used_quota_files` integer NOT NULL, `last_quota_update` bigint NOT NULL, " +
		"`upload_bandwidth` integer NOT NULL, `download_bandwidth` integer NOT NULL, `expiration_date` bigint(20) NOT NULL, " +
		"`last_login` bigint(20) NOT NULL, `status` int(11) NOT NULL, `filters` longtext DEFAULT NULL, " +
		"`filesystem` longtext DEFAULT NULL);"
	mysqlSchemaTableSQL = "CREATE TABLE `{{schema_version}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `version` integer NOT NULL);"
	mysqlV2SQL          = "ALTER TABLE `{{users}}` ADD COLUMN `virtual_folders` longtext NULL;"
	mysqlV3SQL          = "ALTER TABLE `{{users}}` MODIFY `password` longtext NULL;"
	mysqlV4SQL          = "CREATE TABLE `{{folders}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `path` varchar(512) NOT NULL UNIQUE," +
		"`used_quota_size` bigint NOT NULL, `used_quota_files` integer NOT NULL, `last_quota_update` bigint NOT NULL);" +
		"ALTER TABLE `{{users}}` MODIFY `home_dir` varchar(512) NOT NULL;" +
		"ALTER TABLE `{{users}}` DROP COLUMN `virtual_folders`;" +
		"CREATE TABLE `{{folders_mapping}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `virtual_path` varchar(512) NOT NULL, " +
		"`quota_size` bigint NOT NULL, `quota_files` integer NOT NULL, `folder_id` integer NOT NULL, `user_id` integer NOT NULL);" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `unique_mapping` UNIQUE (`user_id`, `folder_id`);" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `folders_mapping_folder_id_fk_folders_id` FOREIGN KEY (`folder_id`) REFERENCES `{{folders}}` (`id`) ON DELETE CASCADE;" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `folders_mapping_user_id_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `{{users}}` (`id`) ON DELETE CASCADE;"
	mysqlV6SQL     = "ALTER TABLE `{{users}}` ADD COLUMN `additional_info` longtext NULL;"
	mysqlV6DownSQL = "ALTER TABLE `{{users}}` DROP COLUMN `additional_info`;"
	mysqlV7SQL     = "CREATE TABLE `{{admins}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `username` varchar(255) NOT NULL UNIQUE, " +
		"`password` varchar(255) NOT NULL, `email` varchar(255) NULL, `status` integer NOT NULL, `permissions` longtext NOT NULL, " +
		"`filters` longtext NULL, `additional_info` longtext NULL);"
	mysqlV7DownSQL = "DROP TABLE `{{admins}}` CASCADE;"
	mysqlV8SQL     = "ALTER TABLE `{{folders}}` ADD COLUMN `name` varchar(255) NULL;" +
		"ALTER TABLE `{{folders}}` MODIFY `path` varchar(512) NULL;" +
		"ALTER TABLE `{{folders}}` DROP INDEX `path`;" +
		"UPDATE `{{folders}}` f1 SET name = (SELECT CONCAT('folder',f2.id) FROM `{{folders}}` f2 WHERE f2.id = f1.id);" +
		"ALTER TABLE `{{folders}}` MODIFY `name` varchar(255) NOT NULL;" +
		"ALTER TABLE `folders` ADD CONSTRAINT `name` UNIQUE (`name`);"
	mysqlV8DownSQL = "ALTER TABLE `{{folders}}` DROP COLUMN `name`;" +
		"ALTER TABLE `{{folders}}` MODIFY `path` varchar(512) NOT NULL;" +
		"ALTER TABLE `{{folders}}` ADD CONSTRAINT `path` UNIQUE (`path`);"
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
	logSender = fmt.Sprintf("dataprovider_%v", MySQLDataProviderName)
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
	sqlUsers := strings.Replace(mysqlUsersTableSQL, "{{users}}", sqlTableUsers, 1)
	tx, err := p.dbHandle.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(sqlUsers)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = tx.Exec(strings.Replace(mysqlSchemaTableSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = tx.Exec(strings.Replace(initialDBVersionSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	return tx.Commit()
}

func (p *MySQLProvider) migrateDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == sqlDatabaseVersion {
		providerLog(logger.LevelDebug, "sql database is up to date, current version: %v", dbVersion.Version)
		return ErrNoInitRequired
	}
	switch dbVersion.Version {
	case 1:
		return updateMySQLDatabaseFromV1(p.dbHandle)
	case 2:
		return updateMySQLDatabaseFromV2(p.dbHandle)
	case 3:
		return updateMySQLDatabaseFromV3(p.dbHandle)
	case 4:
		return updateMySQLDatabaseFromV4(p.dbHandle)
	case 5:
		return updateMySQLDatabaseFromV5(p.dbHandle)
	case 6:
		return updateMySQLDatabaseFromV6(p.dbHandle)
	case 7:
		return updateMySQLDatabaseFromV7(p.dbHandle)
	default:
		if dbVersion.Version > sqlDatabaseVersion {
			providerLog(logger.LevelWarn, "database version %v is newer than the supported: %v", dbVersion.Version,
				sqlDatabaseVersion)
			logger.WarnToConsole("database version %v is newer than the supported: %v", dbVersion.Version,
				sqlDatabaseVersion)
			return nil
		}
		return fmt.Errorf("Database version not handled: %v", dbVersion.Version)
	}
}

//nolint:dupl
func (p *MySQLProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return fmt.Errorf("current version match target version, nothing to do")
	}
	switch dbVersion.Version {
	case 8:
		err = downgradeMySQLDatabaseFrom8To7(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradeMySQLDatabaseFrom7To6(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradeMySQLDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradeMySQLDatabaseFrom5To4(p.dbHandle)
	case 7:
		err = downgradeMySQLDatabaseFrom7To6(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradeMySQLDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradeMySQLDatabaseFrom5To4(p.dbHandle)
	case 6:
		err = downgradeMySQLDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradeMySQLDatabaseFrom5To4(p.dbHandle)
	case 5:
		return downgradeMySQLDatabaseFrom5To4(p.dbHandle)
	default:
		return fmt.Errorf("Database version not handled: %v", dbVersion.Version)
	}
}

func updateMySQLDatabaseFromV1(dbHandle *sql.DB) error {
	err := updateMySQLDatabaseFrom1To2(dbHandle)
	if err != nil {
		return err
	}
	return updateMySQLDatabaseFromV2(dbHandle)
}

func updateMySQLDatabaseFromV2(dbHandle *sql.DB) error {
	err := updateMySQLDatabaseFrom2To3(dbHandle)
	if err != nil {
		return err
	}
	return updateMySQLDatabaseFromV3(dbHandle)
}

func updateMySQLDatabaseFromV3(dbHandle *sql.DB) error {
	err := updateMySQLDatabaseFrom3To4(dbHandle)
	if err != nil {
		return err
	}
	return updateMySQLDatabaseFromV4(dbHandle)
}

func updateMySQLDatabaseFromV4(dbHandle *sql.DB) error {
	err := updateMySQLDatabaseFrom4To5(dbHandle)
	if err != nil {
		return err
	}
	return updateMySQLDatabaseFromV5(dbHandle)
}

func updateMySQLDatabaseFromV5(dbHandle *sql.DB) error {
	err := updateMySQLDatabaseFrom5To6(dbHandle)
	if err != nil {
		return err
	}
	return updateMySQLDatabaseFromV6(dbHandle)
}

func updateMySQLDatabaseFromV6(dbHandle *sql.DB) error {
	err := updateMySQLDatabaseFrom6To7(dbHandle)
	if err != nil {
		return err
	}
	return updateMySQLDatabaseFromV7(dbHandle)
}

func updateMySQLDatabaseFromV7(dbHandle *sql.DB) error {
	return updateMySQLDatabaseFrom7To8(dbHandle)
}

func updateMySQLDatabaseFrom1To2(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 1 -> 2")
	providerLog(logger.LevelInfo, "updating database version: 1 -> 2")
	sql := strings.Replace(mysqlV2SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 2)
}

func updateMySQLDatabaseFrom2To3(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 2 -> 3")
	providerLog(logger.LevelInfo, "updating database version: 2 -> 3")
	sql := strings.Replace(mysqlV3SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 3)
}

func updateMySQLDatabaseFrom3To4(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom3To4(mysqlV4SQL, dbHandle)
}

func updateMySQLDatabaseFrom4To5(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom4To5(dbHandle)
}

func updateMySQLDatabaseFrom5To6(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 5 -> 6")
	providerLog(logger.LevelInfo, "updating database version: 5 -> 6")
	sql := strings.Replace(mysqlV6SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 6)
}

func updateMySQLDatabaseFrom6To7(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 6 -> 7")
	providerLog(logger.LevelInfo, "updating database version: 6 -> 7")
	sql := strings.Replace(mysqlV7SQL, "{{admins}}", sqlTableAdmins, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 7)
}

func updateMySQLDatabaseFrom7To8(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 7 -> 8")
	providerLog(logger.LevelInfo, "updating database version: 7 -> 8")
	sql := strings.ReplaceAll(mysqlV8SQL, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 8)
}

func downgradeMySQLDatabaseFrom8To7(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 8 -> 7")
	providerLog(logger.LevelInfo, "downgrading database version: 8 -> 7")
	sql := strings.ReplaceAll(mysqlV8DownSQL, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 7)
}

func downgradeMySQLDatabaseFrom7To6(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 7 -> 6")
	providerLog(logger.LevelInfo, "downgrading database version: 7 -> 6")
	sql := strings.Replace(mysqlV7DownSQL, "{{admins}}", sqlTableAdmins, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 6)
}

func downgradeMySQLDatabaseFrom6To5(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 6 -> 5")
	providerLog(logger.LevelInfo, "downgrading database version: 6 -> 5")
	sql := strings.Replace(mysqlV6DownSQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 5)
}

func downgradeMySQLDatabaseFrom5To4(dbHandle *sql.DB) error {
	return sqlCommonDowngradeDatabaseFrom5To4(dbHandle)
}
