//go:build !nosqlite
// +build !nosqlite

package dataprovider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	// we import go-sqlite3 here to be able to disable SQLite support using a build tag
	_ "github.com/mattn/go-sqlite3"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	sqliteResetSQL = `DROP TABLE IF EXISTS "{{api_keys}}";
DROP TABLE IF EXISTS "{{folders_mapping}}";
DROP TABLE IF EXISTS "{{admins}}";
DROP TABLE IF EXISTS "{{folders}}";
DROP TABLE IF EXISTS "{{shares}}";
DROP TABLE IF EXISTS "{{users}}";
DROP TABLE IF EXISTS "{{schema_version}}";
`
	sqliteInitialSQL = `CREATE TABLE "{{schema_version}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "version" integer NOT NULL);
CREATE TABLE "{{admins}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL,
"permissions" text NOT NULL, "filters" text NULL, "additional_info" text NULL);
CREATE TABLE "{{folders}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "path" varchar(512) NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL, "filesystem" text NULL);
CREATE TABLE "{{users}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
"status" integer NOT NULL, "expiration_date" bigint NOT NULL, "description" varchar(512) NULL, "password" text NULL,
"public_keys" text NULL, "home_dir" varchar(512) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL,
"max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL,
"used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL,
"upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL, "last_login" bigint NOT NULL, "filters" text NULL,
"filesystem" text NULL, "additional_info" text NULL);
CREATE TABLE "{{folders_mapping}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "virtual_path" varchar(512) NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "folder_id" integer NOT NULL REFERENCES "{{folders}}" ("id")
ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, "user_id" integer NOT NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
CONSTRAINT "{{prefix}}unique_mapping" UNIQUE ("user_id", "folder_id"));
CREATE INDEX "{{prefix}}folders_mapping_folder_id_idx" ON "{{folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}folders_mapping_user_id_idx" ON "{{folders_mapping}}" ("user_id");
INSERT INTO {{schema_version}} (version) VALUES (10);
`
	sqliteV11SQL = `CREATE TABLE "{{api_keys}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(255) NOT NULL,
"key_id" varchar(50) NOT NULL UNIQUE, "api_key" varchar(255) NOT NULL UNIQUE, "scope" integer NOT NULL, "created_at" bigint NOT NULL,
"updated_at" bigint NOT NULL, "last_use_at" bigint NOT NULL, "expires_at" bigint NOT NULL, "description" text NULL,
"admin_id" integer NULL REFERENCES "{{admins}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"user_id" integer NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED);
CREATE INDEX "{{prefix}}api_keys_admin_id_idx" ON "api_keys" ("admin_id");
CREATE INDEX "{{prefix}}api_keys_user_id_idx" ON "api_keys" ("user_id");
`
	sqliteV11DownSQL = `DROP TABLE "{{api_keys}}";`
	sqliteV12SQL     = `ALTER TABLE "{{admins}}" ADD COLUMN "created_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{admins}}" ADD COLUMN "updated_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{admins}}" ADD COLUMN "last_login" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ADD COLUMN "created_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ADD COLUMN "updated_at" bigint DEFAULT 0 NOT NULL;
CREATE INDEX "{{prefix}}users_updated_at_idx" ON "{{users}}" ("updated_at");
`
	sqliteV12DownSQL = `DROP INDEX "{{prefix}}users_updated_at_idx";
ALTER TABLE "{{users}}" DROP COLUMN "updated_at";
ALTER TABLE "{{users}}" DROP COLUMN "created_at";
ALTER TABLE "{{admins}}" DROP COLUMN "created_at";
ALTER TABLE "{{admins}}" DROP COLUMN "updated_at";
ALTER TABLE "{{admins}}" DROP COLUMN "last_login";
`
	sqliteV13SQL     = `ALTER TABLE "{{users}}" ADD COLUMN "email" varchar(255) NULL;`
	sqliteV13DownSQL = `ALTER TABLE "{{users}}" DROP COLUMN "email";`
	sqliteV14SQL     = `CREATE TABLE "{{shares}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"share_id" varchar(60) NOT NULL UNIQUE, "name" varchar(255) NOT NULL, "description" varchar(512) NULL,
"scope" integer NOT NULL, "paths" text NOT NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL,
"last_use_at" bigint NOT NULL, "expires_at" bigint NOT NULL, "password" text NULL, "max_tokens" integer NOT NULL,
"used_tokens" integer NOT NULL, "allow_from" text NULL,
"user_id" integer NOT NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED);
CREATE INDEX "{{prefix}}shares_user_id_idx" ON "{{shares}}" ("user_id");
`
	sqliteV14DownSQL = `DROP TABLE "{{shares}}";`
)

// SQLiteProvider auth provider for SQLite database
type SQLiteProvider struct {
	dbHandle *sql.DB
}

func init() {
	version.AddFeature("+sqlite")
}

func initializeSQLiteProvider(basePath string) error {
	var err error
	var connectionString string

	if config.ConnectionString == "" {
		dbPath := config.Name
		if !util.IsFileInputValid(dbPath) {
			return fmt.Errorf("invalid database path: %#v", dbPath)
		}
		if !filepath.IsAbs(dbPath) {
			dbPath = filepath.Join(basePath, dbPath)
		}
		connectionString = fmt.Sprintf("file:%v?cache=shared&_foreign_keys=1", dbPath)
	} else {
		connectionString = config.ConnectionString
	}
	dbHandle, err := sql.Open("sqlite3", connectionString)
	if err == nil {
		providerLog(logger.LevelDebug, "sqlite database handle created, connection string: %#v", connectionString)
		dbHandle.SetMaxOpenConns(1)
		provider = &SQLiteProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating sqlite database handler, connection string: %#v, error: %v",
			connectionString, err)
	}
	return err
}

func (p *SQLiteProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p *SQLiteProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, ip, protocol, p.dbHandle)
}

func (p *SQLiteProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	return sqlCommonValidateUserAndTLSCertificate(username, protocol, tlsCert, p.dbHandle)
}

func (p *SQLiteProvider) validateUserAndPubKey(username string, publicKey []byte) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p *SQLiteProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *SQLiteProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p *SQLiteProvider) setUpdatedAt(username string) {
	sqlCommonSetUpdatedAt(username, p.dbHandle)
}

func (p *SQLiteProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p *SQLiteProvider) updateAdminLastLogin(username string) error {
	return sqlCommonUpdateAdminLastLogin(username, p.dbHandle)
}

func (p *SQLiteProvider) userExists(username string) (User, error) {
	return sqlCommonGetUserByUsername(username, p.dbHandle)
}

func (p *SQLiteProvider) addUser(user *User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p *SQLiteProvider) updateUser(user *User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p *SQLiteProvider) deleteUser(user *User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p *SQLiteProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

// SQLite provider cannot be shared, so we always return no recently updated users
func (p *SQLiteProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return nil, nil
}

func (p *SQLiteProvider) getUsers(limit int, offset int, order string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, p.dbHandle)
}

func (p *SQLiteProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p *SQLiteProvider) getFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, p.dbHandle)
}

func (p *SQLiteProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonGetFolderByName(ctx, name, p.dbHandle)
}

func (p *SQLiteProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonAddFolder(folder, p.dbHandle)
}

func (p *SQLiteProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonUpdateFolder(folder, p.dbHandle)
}

func (p *SQLiteProvider) deleteFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p *SQLiteProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *SQLiteProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, p.dbHandle)
}

func (p *SQLiteProvider) adminExists(username string) (Admin, error) {
	return sqlCommonGetAdminByUsername(username, p.dbHandle)
}

func (p *SQLiteProvider) addAdmin(admin *Admin) error {
	return sqlCommonAddAdmin(admin, p.dbHandle)
}

func (p *SQLiteProvider) updateAdmin(admin *Admin) error {
	return sqlCommonUpdateAdmin(admin, p.dbHandle)
}

func (p *SQLiteProvider) deleteAdmin(admin *Admin) error {
	return sqlCommonDeleteAdmin(admin, p.dbHandle)
}

func (p *SQLiteProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	return sqlCommonGetAdmins(limit, offset, order, p.dbHandle)
}

func (p *SQLiteProvider) dumpAdmins() ([]Admin, error) {
	return sqlCommonDumpAdmins(p.dbHandle)
}

func (p *SQLiteProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	return sqlCommonValidateAdminAndPass(username, password, ip, p.dbHandle)
}

func (p *SQLiteProvider) apiKeyExists(keyID string) (APIKey, error) {
	return sqlCommonGetAPIKeyByID(keyID, p.dbHandle)
}

func (p *SQLiteProvider) addAPIKey(apiKey *APIKey) error {
	return sqlCommonAddAPIKey(apiKey, p.dbHandle)
}

func (p *SQLiteProvider) updateAPIKey(apiKey *APIKey) error {
	return sqlCommonUpdateAPIKey(apiKey, p.dbHandle)
}

func (p *SQLiteProvider) deleteAPIKey(apiKey *APIKey) error {
	return sqlCommonDeleteAPIKey(apiKey, p.dbHandle)
}

func (p *SQLiteProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	return sqlCommonGetAPIKeys(limit, offset, order, p.dbHandle)
}

func (p *SQLiteProvider) dumpAPIKeys() ([]APIKey, error) {
	return sqlCommonDumpAPIKeys(p.dbHandle)
}

func (p *SQLiteProvider) updateAPIKeyLastUse(keyID string) error {
	return sqlCommonUpdateAPIKeyLastUse(keyID, p.dbHandle)
}

func (p *SQLiteProvider) shareExists(shareID, username string) (Share, error) {
	return sqlCommonGetShareByID(shareID, username, p.dbHandle)
}

func (p *SQLiteProvider) addShare(share *Share) error {
	return sqlCommonAddShare(share, p.dbHandle)
}

func (p *SQLiteProvider) updateShare(share *Share) error {
	return sqlCommonUpdateShare(share, p.dbHandle)
}

func (p *SQLiteProvider) deleteShare(share *Share) error {
	return sqlCommonDeleteShare(share, p.dbHandle)
}

func (p *SQLiteProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	return sqlCommonGetShares(limit, offset, order, username, p.dbHandle)
}

func (p *SQLiteProvider) dumpShares() ([]Share, error) {
	return sqlCommonDumpShares(p.dbHandle)
}

func (p *SQLiteProvider) updateShareLastUse(shareID string, numTokens int) error {
	return sqlCommonUpdateShareLastUse(shareID, numTokens, p.dbHandle)
}

func (p *SQLiteProvider) close() error {
	return p.dbHandle.Close()
}

func (p *SQLiteProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (p *SQLiteProvider) initializeDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, false)
	if err == nil && dbVersion.Version > 0 {
		return ErrNoInitRequired
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errSchemaVersionEmpty
	}
	initialSQL := strings.ReplaceAll(sqliteInitialSQL, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{initialSQL}, 10)
}

//nolint:dupl
func (p *SQLiteProvider) migrateDatabase() error {
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
		return updateSQLiteDatabaseFromV10(p.dbHandle)
	case version == 11:
		return updateSQLiteDatabaseFromV11(p.dbHandle)
	case version == 12:
		return updateSQLiteDatabaseFromV12(p.dbHandle)
	case version == 13:
		return updateSQLiteDatabaseFromV13(p.dbHandle)
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

func (p *SQLiteProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}

	switch dbVersion.Version {
	case 14:
		return downgradeSQLiteDatabaseFromV14(p.dbHandle)
	case 13:
		return downgradeSQLiteDatabaseFromV13(p.dbHandle)
	case 12:
		return downgradeSQLiteDatabaseFromV12(p.dbHandle)
	case 11:
		return downgradeSQLiteDatabaseFromV11(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func (p *SQLiteProvider) resetDatabase() error {
	sql := strings.ReplaceAll(sqliteResetSQL, "{{schema_version}}", sqlTableSchemaVersion)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{sql}, 0)
}

func updateSQLiteDatabaseFromV10(dbHandle *sql.DB) error {
	if err := updateSQLiteDatabaseFrom10To11(dbHandle); err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV11(dbHandle)
}

func updateSQLiteDatabaseFromV11(dbHandle *sql.DB) error {
	if err := updateSQLiteDatabaseFrom11To12(dbHandle); err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV12(dbHandle)
}

func updateSQLiteDatabaseFromV12(dbHandle *sql.DB) error {
	if err := updateSQLiteDatabaseFrom12To13(dbHandle); err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV13(dbHandle)
}

func updateSQLiteDatabaseFromV13(dbHandle *sql.DB) error {
	return updateSQLiteDatabaseFrom13To14(dbHandle)
}

func downgradeSQLiteDatabaseFromV14(dbHandle *sql.DB) error {
	if err := downgradeSQLiteDatabaseFrom14To13(dbHandle); err != nil {
		return err
	}
	return downgradeSQLiteDatabaseFromV13(dbHandle)
}

func downgradeSQLiteDatabaseFromV13(dbHandle *sql.DB) error {
	if err := downgradeSQLiteDatabaseFrom13To12(dbHandle); err != nil {
		return err
	}
	return downgradeSQLiteDatabaseFromV12(dbHandle)
}

func downgradeSQLiteDatabaseFromV12(dbHandle *sql.DB) error {
	if err := downgradeSQLiteDatabaseFrom12To11(dbHandle); err != nil {
		return err
	}
	return downgradeSQLiteDatabaseFromV11(dbHandle)
}

func downgradeSQLiteDatabaseFromV11(dbHandle *sql.DB) error {
	return downgradeSQLiteDatabaseFrom11To10(dbHandle)
}

func updateSQLiteDatabaseFrom13To14(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 13 -> 14")
	providerLog(logger.LevelInfo, "updating database version: 13 -> 14")
	sql := strings.ReplaceAll(sqliteV14SQL, "{{shares}}", sqlTableShares)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 14)
}

func downgradeSQLiteDatabaseFrom14To13(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 14 -> 13")
	providerLog(logger.LevelInfo, "downgrading database version: 14 -> 13")
	sql := strings.ReplaceAll(sqliteV14DownSQL, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 13)
}

func updateSQLiteDatabaseFrom12To13(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 12 -> 13")
	providerLog(logger.LevelInfo, "updating database version: 12 -> 13")
	sql := strings.ReplaceAll(sqliteV13SQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 13)
}

func downgradeSQLiteDatabaseFrom13To12(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 13 -> 12")
	providerLog(logger.LevelInfo, "downgrading database version: 13 -> 12")
	sql := strings.ReplaceAll(sqliteV13DownSQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 12)
}

func updateSQLiteDatabaseFrom11To12(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 11 -> 12")
	providerLog(logger.LevelInfo, "updating database version: 11 -> 12")
	sql := strings.ReplaceAll(sqliteV12SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 12)
}

func downgradeSQLiteDatabaseFrom12To11(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 12 -> 11")
	providerLog(logger.LevelInfo, "downgrading database version: 12 -> 11")
	sql := strings.ReplaceAll(sqliteV12DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 11)
}

func updateSQLiteDatabaseFrom10To11(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 10 -> 11")
	providerLog(logger.LevelInfo, "updating database version: 10 -> 11")
	sql := strings.ReplaceAll(sqliteV11SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 11)
}

func downgradeSQLiteDatabaseFrom11To10(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 11 -> 10")
	providerLog(logger.LevelInfo, "downgrading database version: 11 -> 10")
	sql := strings.ReplaceAll(sqliteV11DownSQL, "{{api_keys}}", sqlTableAPIKeys)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 10)
}

/*func setPragmaFK(dbHandle *sql.DB, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	sql := fmt.Sprintf("PRAGMA foreign_keys=%v;", value)

	_, err := dbHandle.ExecContext(ctx, sql)
	return err
}*/
