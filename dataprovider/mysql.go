package dataprovider

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/logger"
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
	mysqlSchemaTableSQL = "CREATE TABLE `schema_version` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `version` integer NOT NULL);"
	mysqlUsersV2SQL     = "ALTER TABLE `{{users}}` ADD COLUMN `virtual_folders` longtext NULL;"
	mysqlUsersV3SQL     = "ALTER TABLE `{{users}}` MODIFY `password` longtext NULL;"
)

// MySQLProvider auth provider for MySQL/MariaDB database
type MySQLProvider struct {
	dbHandle *sql.DB
}

func initializeMySQLProvider() error {
	var err error
	logSender = fmt.Sprintf("dataprovider_%v", MySQLDataProviderName)
	dbHandle, err := sql.Open("mysql", getMySQLConnectionString(false))
	if err == nil {
		providerLog(logger.LevelDebug, "mysql database handle created, connection string: %#v, pool size: %v",
			getMySQLConnectionString(true), config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		dbHandle.SetConnMaxLifetime(1800 * time.Second)
		provider = MySQLProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating mysql database handler, connection string: %#v, error: %v",
			getMySQLConnectionString(true), err)
	}
	return err
}
func getMySQLConnectionString(redactedPwd bool) string {
	var connectionString string
	if len(config.ConnectionString) == 0 {
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

func (p MySQLProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p MySQLProvider) validateUserAndPass(username string, password string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, p.dbHandle)
}

func (p MySQLProvider) validateUserAndPubKey(username string, publicKey []byte) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p MySQLProvider) getUserByID(ID int64) (User, error) {
	return sqlCommonGetUserByID(ID, p.dbHandle)
}

func (p MySQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p MySQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p MySQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p MySQLProvider) userExists(username string) (User, error) {
	return sqlCommonCheckUserExists(username, p.dbHandle)
}

func (p MySQLProvider) addUser(user User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p MySQLProvider) updateUser(user User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p MySQLProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p MySQLProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p MySQLProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, username, p.dbHandle)
}

func (p MySQLProvider) close() error {
	return p.dbHandle.Close()
}

func (p MySQLProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (p MySQLProvider) initializeDatabase() error {
	sqlUsers := strings.Replace(mysqlUsersTableSQL, "{{users}}", config.UsersTable, 1)
	tx, err := p.dbHandle.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(sqlUsers)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(mysqlSchemaTableSQL)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(initialDBVersionSQL)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (p MySQLProvider) migrateDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle)
	if err != nil {
		return err
	}
	if dbVersion.Version == sqlDatabaseVersion {
		providerLog(logger.LevelDebug, "sql database is updated, current version: %v", dbVersion.Version)
		return nil
	}
	switch dbVersion.Version {
	case 1:
		err = updateMySQLDatabaseFrom1To2(p.dbHandle)
		if err != nil {
			return err
		}
		return updateMySQLDatabaseFrom2To3(p.dbHandle)
	case 2:
		return updateMySQLDatabaseFrom2To3(p.dbHandle)
	default:
		return fmt.Errorf("Database version not handled: %v", dbVersion.Version)
	}
}

func updateMySQLDatabaseFrom1To2(dbHandle *sql.DB) error {
	providerLog(logger.LevelInfo, "updating database version: 1 -> 2")
	sql := strings.Replace(mysqlUsersV2SQL, "{{users}}", config.UsersTable, 1)
	return updateMySQLDatabase(dbHandle, sql, 2)
}

func updateMySQLDatabaseFrom2To3(dbHandle *sql.DB) error {
	providerLog(logger.LevelInfo, "updating database version: 2 -> 3")
	sql := strings.Replace(mysqlUsersV3SQL, "{{users}}", config.UsersTable, 1)
	return updateMySQLDatabase(dbHandle, sql, 3)
}

func updateMySQLDatabase(dbHandle *sql.DB, sql string, newVersion int) error {
	tx, err := dbHandle.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(sql)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = sqlCommonUpdateDatabaseVersionWithTX(tx, newVersion)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
