// +build !nosqlite

package dataprovider

import (
	"context"
	"database/sql"
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
	sqliteUsersTableSQL = `CREATE TABLE "{{users}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255)
NOT NULL UNIQUE, "password" varchar(255) NULL, "public_keys" text NULL, "home_dir" varchar(255) NOT NULL, "uid" integer NOT NULL,
"gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL,
"permissions" text NOT NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL,
"expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL, "status" integer NOT NULL, "filters" text NULL,
"filesystem" text NULL);`
	sqliteSchemaTableSQL = `CREATE TABLE "{{schema_version}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "version" integer NOT NULL);`
	sqliteV2SQL          = `ALTER TABLE "{{users}}" ADD COLUMN "virtual_folders" text NULL;`
	sqliteV3SQL          = `CREATE TABLE "new__users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
	"password" text NULL, "public_keys" text NULL, "home_dir" varchar(255) NOT NULL, "uid" integer NOT NULL,
"gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL,
"permissions" text NOT NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL,
"upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL, "expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL,
"status" integer NOT NULL, "filters" text NULL, "filesystem" text NULL, "virtual_folders" text NULL);
INSERT INTO "new__users" ("id", "username", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files",
"permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date",
"last_login", "status", "filters", "filesystem", "virtual_folders", "password") SELECT "id", "username", "public_keys", "home_dir",
"uid", "gid", "max_sessions", "quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update",
"upload_bandwidth", "download_bandwidth", "expiration_date", "last_login", "status", "filters", "filesystem", "virtual_folders",
"password" FROM "{{users}}";
DROP TABLE "{{users}}";
ALTER TABLE "new__users" RENAME TO "{{users}}";`
	sqliteV4SQL = `CREATE TABLE "{{folders}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "path" varchar(512) NOT NULL UNIQUE,
"used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL);
CREATE TABLE "{{folders_mapping}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "virtual_path" varchar(512) NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "folder_id" integer NOT NULL REFERENCES "{{folders}}" ("id")
ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, "user_id" integer NOT NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
CONSTRAINT "unique_mapping" UNIQUE ("user_id", "folder_id"));
CREATE TABLE "new__users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE, "password" text NULL,
"public_keys" text NULL, "home_dir" varchar(512) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL, "max_sessions" integer NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL,
"used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL,
"expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL, "status" integer NOT NULL, "filters" text NULL, "filesystem" text NULL);
INSERT INTO "new__users" ("id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files",
"permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date",
"last_login", "status", "filters", "filesystem") SELECT "id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions",
"quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth",
"expiration_date", "last_login", "status", "filters", "filesystem" FROM "{{users}}";
DROP TABLE "{{users}}";
ALTER TABLE "new__users" RENAME TO "{{users}}";
CREATE INDEX "folders_mapping_folder_id_idx" ON "{{folders_mapping}}" ("folder_id");
CREATE INDEX "folders_mapping_user_id_idx" ON "{{folders_mapping}}" ("user_id");
`
	sqliteV6SQL     = `ALTER TABLE "{{users}}" ADD COLUMN "additional_info" text NULL;`
	sqliteV6DownSQL = `CREATE TABLE "new__users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
"password" text NULL, "public_keys" text NULL, "home_dir" varchar(512) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL,
"max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL,
"used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL,
"download_bandwidth" integer NOT NULL, "expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL, "status" integer NOT NULL,
"filters" text NULL, "filesystem" text NULL);
INSERT INTO "new__users" ("id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions", "quota_size", "quota_files",
"permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth", "expiration_date",
"last_login", "status", "filters", "filesystem") SELECT "id", "username", "password", "public_keys", "home_dir", "uid", "gid", "max_sessions",
"quota_size", "quota_files", "permissions", "used_quota_size", "used_quota_files", "last_quota_update", "upload_bandwidth", "download_bandwidth",
"expiration_date", "last_login", "status", "filters", "filesystem" FROM "{{users}}";
DROP TABLE "{{users}}";
ALTER TABLE "new__users" RENAME TO "{{users}}";
`
	sqliteV7SQL = `CREATE TABLE "{{admins}}" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL UNIQUE,
"password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL, "permissions" text NOT NULL, "filters" text NULL,
"additional_info" text NULL);`
	sqliteV7DownSQL = `DROP TABLE "{{admins}}";`
	sqliteV8SQL     = `CREATE TABLE "new__folders" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"name" varchar(255) NOT NULL UNIQUE, "path" varchar(512) NULL, "used_quota_size" bigint NOT NULL,
"used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL);
INSERT INTO "new__folders" ("id", "path", "used_quota_size", "used_quota_files", "last_quota_update", "name")
SELECT "id", "path", "used_quota_size", "used_quota_files", "last_quota_update", ('folder' || "id") FROM "{{folders}}";
DROP TABLE "{{folders}}";
ALTER TABLE "new__folders" RENAME TO "{{folders}}";
`
	sqliteV8DownSQL = `CREATE TABLE "new__folders" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"path" varchar(512) NOT NULL UNIQUE, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL);
INSERT INTO "new__folders" ("id", "path", "used_quota_size", "used_quota_files", "last_quota_update")
SELECT "id", "path", "used_quota_size", "used_quota_files", "last_quota_update" FROM "{{folders}}";
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
	logSender = fmt.Sprintf("dataprovider_%v", SQLiteDataProviderName)
	if config.ConnectionString == "" {
		dbPath := config.Name
		if !utils.IsFileInputValid(dbPath) {
			return fmt.Errorf("Invalid database path: %#v", dbPath)
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
	sqlUsers := strings.Replace(sqliteUsersTableSQL, "{{users}}", sqlTableUsers, 1)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	tx, err := p.dbHandle.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	_, err = tx.Exec(sqlUsers)
	if err != nil {
		return err
	}
	_, err = tx.Exec(strings.Replace(sqliteSchemaTableSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		return err
	}
	_, err = tx.Exec(strings.Replace(initialDBVersionSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (p *SQLiteProvider) migrateDatabase() error {
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
		return updateSQLiteDatabaseFromV1(p.dbHandle)
	case 2:
		return updateSQLiteDatabaseFromV2(p.dbHandle)
	case 3:
		return updateSQLiteDatabaseFromV3(p.dbHandle)
	case 4:
		return updateSQLiteDatabaseFromV4(p.dbHandle)
	case 5:
		return updateSQLiteDatabaseFromV5(p.dbHandle)
	case 6:
		return updateSQLiteDatabaseFromV6(p.dbHandle)
	case 7:
		return updateSQLiteDatabaseFromV7(p.dbHandle)
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
func (p *SQLiteProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return fmt.Errorf("current version match target version, nothing to do")
	}
	switch dbVersion.Version {
	case 8:
		err = downgradeSQLiteDatabaseFrom8To7(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradeSQLiteDatabaseFrom7To6(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradeSQLiteDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradeSQLiteDatabaseFrom5To4(p.dbHandle)
	case 7:
		err = downgradeSQLiteDatabaseFrom7To6(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradeSQLiteDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradeSQLiteDatabaseFrom5To4(p.dbHandle)
	case 6:
		err = downgradeSQLiteDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradeSQLiteDatabaseFrom5To4(p.dbHandle)
	case 5:
		return downgradeSQLiteDatabaseFrom5To4(p.dbHandle)
	default:
		return fmt.Errorf("Database version not handled: %v", dbVersion.Version)
	}
}

func updateSQLiteDatabaseFromV1(dbHandle *sql.DB) error {
	err := updateSQLiteDatabaseFrom1To2(dbHandle)
	if err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV2(dbHandle)
}

func updateSQLiteDatabaseFromV2(dbHandle *sql.DB) error {
	err := updateSQLiteDatabaseFrom2To3(dbHandle)
	if err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV3(dbHandle)
}

func updateSQLiteDatabaseFromV3(dbHandle *sql.DB) error {
	err := updateSQLiteDatabaseFrom3To4(dbHandle)
	if err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV4(dbHandle)
}

func updateSQLiteDatabaseFromV4(dbHandle *sql.DB) error {
	err := updateSQLiteDatabaseFrom4To5(dbHandle)
	if err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV5(dbHandle)
}

func updateSQLiteDatabaseFromV5(dbHandle *sql.DB) error {
	err := updateSQLiteDatabaseFrom5To6(dbHandle)
	if err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV6(dbHandle)
}

func updateSQLiteDatabaseFromV6(dbHandle *sql.DB) error {
	err := updateSQLiteDatabaseFrom6To7(dbHandle)
	if err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV7(dbHandle)
}

func updateSQLiteDatabaseFromV7(dbHandle *sql.DB) error {
	return updateSQLiteDatabaseFrom7To8(dbHandle)
}

func updateSQLiteDatabaseFrom1To2(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 1 -> 2")
	providerLog(logger.LevelInfo, "updating database version: 1 -> 2")
	sql := strings.Replace(sqliteV2SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 2)
}

func updateSQLiteDatabaseFrom2To3(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 2 -> 3")
	providerLog(logger.LevelInfo, "updating database version: 2 -> 3")
	sql := strings.ReplaceAll(sqliteV3SQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 3)
}

func updateSQLiteDatabaseFrom3To4(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom3To4(sqliteV4SQL, dbHandle)
}

func updateSQLiteDatabaseFrom4To5(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom4To5(dbHandle)
}

func updateSQLiteDatabaseFrom5To6(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 5 -> 6")
	providerLog(logger.LevelInfo, "updating database version: 5 -> 6")
	sql := strings.Replace(sqliteV6SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 6)
}

func updateSQLiteDatabaseFrom6To7(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 6 -> 7")
	providerLog(logger.LevelInfo, "updating database version: 6 -> 7")
	sql := strings.Replace(sqliteV7SQL, "{{admins}}", sqlTableAdmins, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 7)
}

func updateSQLiteDatabaseFrom7To8(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 7 -> 8")
	providerLog(logger.LevelInfo, "updating database version: 7 -> 8")
	if err := setPragmaFK(dbHandle, "OFF"); err != nil {
		return err
	}
	sql := strings.ReplaceAll(sqliteV8SQL, "{{folders}}", sqlTableFolders)
	if err := sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 8); err != nil {
		return err
	}
	return setPragmaFK(dbHandle, "ON")
}

func setPragmaFK(dbHandle *sql.DB, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	sql := fmt.Sprintf("PRAGMA foreign_keys=%v;", value)

	_, err := dbHandle.ExecContext(ctx, sql)
	return err
}

func downgradeSQLiteDatabaseFrom8To7(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 8 -> 7")
	providerLog(logger.LevelInfo, "downgrading database version: 8 -> 7")
	if err := setPragmaFK(dbHandle, "OFF"); err != nil {
		return err
	}
	sql := strings.ReplaceAll(sqliteV8DownSQL, "{{folders}}", sqlTableFolders)
	if err := sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 7); err != nil {
		return err
	}
	return setPragmaFK(dbHandle, "ON")
}

func downgradeSQLiteDatabaseFrom7To6(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 7 -> 6")
	providerLog(logger.LevelInfo, "downgrading database version: 7 -> 6")
	sql := strings.Replace(sqliteV7DownSQL, "{{admins}}", sqlTableAdmins, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 6)
}

func downgradeSQLiteDatabaseFrom6To5(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 6 -> 5")
	providerLog(logger.LevelInfo, "downgrading database version: 6 -> 5")
	sql := strings.ReplaceAll(sqliteV6DownSQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 5)
}

func downgradeSQLiteDatabaseFrom5To4(dbHandle *sql.DB) error {
	return sqlCommonDowngradeDatabaseFrom5To4(dbHandle)
}
