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

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	sqliteInitialSQL = `CREATE TABLE "{{schema_version}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "version" integer NOT NULL);
CREATE TABLE "{{admins}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
"password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL, "permissions" text NOT NULL,
"filters" text NULL, "additional_info" text NULL);
CREATE TABLE "{{folders}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(255) NOT NULL UNIQUE,
"path" varchar(512) NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL);
CREATE TABLE "{{users}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
"password" text NULL, "public_keys" text NULL, "home_dir" varchar(512) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL,
"max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL,
"used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL,
"upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL, "expiration_date" bigint NOT NULL,
"last_login" bigint NOT NULL, "status" integer NOT NULL, "filters" text NULL, "filesystem" text NULL,
"additional_info" text NULL);
CREATE TABLE "{{folders_mapping}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "virtual_path" varchar(512) NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "folder_id" integer NOT NULL REFERENCES "{{folders}}" ("id")
ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, "user_id" integer NOT NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
CONSTRAINT "{{prefix}}unique_mapping" UNIQUE ("user_id", "folder_id"));
CREATE INDEX "{{prefix}}folders_mapping_folder_id_idx" ON "{{folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}folders_mapping_user_id_idx" ON "{{folders_mapping}}" ("user_id");
INSERT INTO {{schema_version}} (version) VALUES (8);
`
	sqliteV9SQL = `ALTER TABLE "{{admins}}" ADD COLUMN "description" varchar(512) NULL;
ALTER TABLE "{{folders}}" ADD COLUMN "description" varchar(512) NULL;
ALTER TABLE "{{folders}}" ADD COLUMN "filesystem" text NULL;
ALTER TABLE "{{users}}" ADD COLUMN "description" varchar(512) NULL;
`
	sqliteV9DownSQL = `CREATE TABLE "new__users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "status" integer NOT NULL,
"expiration_date" bigint NOT NULL, "username" varchar(255) NOT NULL UNIQUE, "password" text NULL, "public_keys" text NULL,
"home_dir" varchar(512) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL, "max_sessions" integer NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL,
"used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL,
"download_bandwidth" integer NOT NULL, "last_login" bigint NOT NULL, "filters" text NULL, "filesystem" text NULL,
"additional_info" text NULL);
INSERT INTO "new__users" ("id", "status", "expiration_date", "username", "password", "public_keys", "home_dir", "uid", "gid",
"max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update",
"upload_bandwidth", "download_bandwidth", "last_login", "filters", "filesystem", "additional_info")
SELECT "id", "status", "expiration_date", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions",
"quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth",
"download_bandwidth", "last_login", "filters", "filesystem", "additional_info" FROM "{{users}}";
DROP TABLE "{{users}}";
ALTER TABLE "new__users" RENAME TO "{{users}}";
CREATE TABLE "new__admins" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
"password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL, "permissions" text NOT NULL,
"filters" text NULL, "additional_info" text NULL);
INSERT INTO "new__admins" ("id", "username", "password", "email", "status", "permissions", "filters", "additional_info")
SELECT "id", "username", "password", "email", "status", "permissions", "filters", "additional_info" FROM "{{admins}}";
DROP TABLE "{{admins}}";
ALTER TABLE "new__admins" RENAME TO "{{admins}}";
CREATE TABLE "new__folders" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(255) NOT NULL UNIQUE,
"path" varchar(512) NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL);
INSERT INTO "new__folders" ("id", "name", "path", "used_quota_size", "used_quota_files", "last_quota_update")
SELECT "id", "name", "path", "used_quota_size", "used_quota_files", "last_quota_update" FROM "{{folders}}";
DROP TABLE "{{folders}}";
ALTER TABLE "new__folders" RENAME TO "{{folders}}";
`
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
		if !utils.IsFileInputValid(dbPath) {
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

func (p *SQLiteProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
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
	initialSQL := strings.ReplaceAll(sqliteInitialSQL, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{initialSQL}, 8)
}

func (p *SQLiteProvider) migrateDatabase() error {
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
		return updateSQLiteDatabaseFromV8(p.dbHandle)
	case version == 9:
		return updateSQLiteDatabaseFromV9(p.dbHandle)
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
	case 9:
		return downgradeSQLiteDatabaseFromV9(p.dbHandle)
	case 10:
		return downgradeSQLiteDatabaseFromV10(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func updateSQLiteDatabaseFromV8(dbHandle *sql.DB) error {
	if err := updateSQLiteDatabaseFrom8To9(dbHandle); err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV9(dbHandle)
}

func updateSQLiteDatabaseFromV9(dbHandle *sql.DB) error {
	return updateSQLiteDatabaseFrom9To10(dbHandle)
}

func downgradeSQLiteDatabaseFromV9(dbHandle *sql.DB) error {
	return downgradeSQLiteDatabaseFrom9To8(dbHandle)
}

func downgradeSQLiteDatabaseFromV10(dbHandle *sql.DB) error {
	if err := downgradeSQLiteDatabaseFrom10To9(dbHandle); err != nil {
		return err
	}
	return downgradeSQLiteDatabaseFromV9(dbHandle)
}

func updateSQLiteDatabaseFrom8To9(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 8 -> 9")
	providerLog(logger.LevelInfo, "updating database version: 8 -> 9")
	sql := strings.ReplaceAll(sqliteV9SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 9)
}

func downgradeSQLiteDatabaseFrom9To8(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 9 -> 8")
	providerLog(logger.LevelInfo, "downgrading database version: 9 -> 8")
	if err := setPragmaFK(dbHandle, "OFF"); err != nil {
		return err
	}
	sql := strings.ReplaceAll(sqliteV9DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	if err := sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 8); err != nil {
		return err
	}
	return setPragmaFK(dbHandle, "ON")
}

func updateSQLiteDatabaseFrom9To10(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom9To10(dbHandle)
}

func downgradeSQLiteDatabaseFrom10To9(dbHandle *sql.DB) error {
	return sqlCommonDowngradeDatabaseFrom10To9(dbHandle)
}

func setPragmaFK(dbHandle *sql.DB, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	sql := fmt.Sprintf("PRAGMA foreign_keys=%v;", value)

	_, err := dbHandle.ExecContext(ctx, sql)
	return err
}
