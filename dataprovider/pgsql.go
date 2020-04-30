package dataprovider

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/drakkan/sftpgo/logger"
)

const (
	pgsqlUsersTableSQL = `CREATE TABLE "{{users}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"password" varchar(255) NULL, "public_keys" text NULL, "home_dir" varchar(255) NOT NULL, "uid" integer NOT NULL,
"gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL,
"permissions" text NOT NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL,
"expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL, "status" integer NOT NULL, "filters" text NULL,
"filesystem" text NULL);`
	pgsqlSchemaTableSQL = `CREATE TABLE "schema_version" ("id" serial NOT NULL PRIMARY KEY, "version" integer NOT NULL);`
	pgsqlUsersV2SQL     = `ALTER TABLE "{{users}}" ADD COLUMN "virtual_folders" text NULL;`
	pgsqlUsersV3SQL     = `ALTER TABLE "{{users}}" ALTER COLUMN "password" TYPE text USING "password"::text;`
)

// PGSQLProvider auth provider for PostgreSQL database
type PGSQLProvider struct {
	dbHandle *sql.DB
}

func initializePGSQLProvider() error {
	var err error
	logSender = fmt.Sprintf("dataprovider_%v", PGSQLDataProviderName)
	dbHandle, err := sql.Open("postgres", getPGSQLConnectionString(false))
	if err == nil {
		providerLog(logger.LevelDebug, "postgres database handle created, connection string: %#v, pool size: %v",
			getPGSQLConnectionString(true), config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		provider = PGSQLProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating postgres database handler, connection string: %#v, error: %v",
			getPGSQLConnectionString(true), err)
	}
	return err
}

func getPGSQLConnectionString(redactedPwd bool) string {
	var connectionString string
	if len(config.ConnectionString) == 0 {
		password := config.Password
		if redactedPwd {
			password = "[redacted]"
		}
		connectionString = fmt.Sprintf("host='%v' port=%v dbname='%v' user='%v' password='%v' sslmode=%v connect_timeout=10",
			config.Host, config.Port, config.Name, config.Username, password, getSSLMode())
	} else {
		connectionString = config.ConnectionString
	}
	return connectionString
}

func (p PGSQLProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p PGSQLProvider) validateUserAndPass(username string, password string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, p.dbHandle)
}

func (p PGSQLProvider) validateUserAndPubKey(username string, publicKey []byte) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p PGSQLProvider) getUserByID(ID int64) (User, error) {
	return sqlCommonGetUserByID(ID, p.dbHandle)
}

func (p PGSQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p PGSQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p PGSQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p PGSQLProvider) userExists(username string) (User, error) {
	return sqlCommonCheckUserExists(username, p.dbHandle)
}

func (p PGSQLProvider) addUser(user User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p PGSQLProvider) updateUser(user User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p PGSQLProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p PGSQLProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p PGSQLProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, username, p.dbHandle)
}

func (p PGSQLProvider) close() error {
	return p.dbHandle.Close()
}

func (p PGSQLProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (p PGSQLProvider) initializeDatabase() error {
	sqlUsers := strings.Replace(pgsqlUsersTableSQL, "{{users}}", config.UsersTable, 1)
	tx, err := p.dbHandle.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(sqlUsers)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = tx.Exec(pgsqlSchemaTableSQL)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = tx.Exec(initialDBVersionSQL)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	return tx.Commit()
}

func (p PGSQLProvider) migrateDatabase() error {
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
		err = updatePGSQLDatabaseFrom1To2(p.dbHandle)
		if err != nil {
			return err
		}
		return updatePGSQLDatabaseFrom2To3(p.dbHandle)
	case 2:
		return updatePGSQLDatabaseFrom2To3(p.dbHandle)
	default:
		return fmt.Errorf("Database version not handled: %v", dbVersion.Version)
	}
}

func updatePGSQLDatabaseFrom1To2(dbHandle *sql.DB) error {
	providerLog(logger.LevelInfo, "updating database version: 1 -> 2")
	sql := strings.Replace(pgsqlUsersV2SQL, "{{users}}", config.UsersTable, 1)
	return updatePGSQLDatabase(dbHandle, sql, 2)
}

func updatePGSQLDatabaseFrom2To3(dbHandle *sql.DB) error {
	providerLog(logger.LevelInfo, "updating database version: 2 -> 3")
	sql := strings.Replace(pgsqlUsersV3SQL, "{{users}}", config.UsersTable, 1)
	return updatePGSQLDatabase(dbHandle, sql, 3)
}

func updatePGSQLDatabase(dbHandle *sql.DB, sql string, newVersion int) error {
	tx, err := dbHandle.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(sql)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	err = sqlCommonUpdateDatabaseVersionWithTX(tx, newVersion)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	return tx.Commit()
}
