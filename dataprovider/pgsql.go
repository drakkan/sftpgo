//go:build !nopgsql
// +build !nopgsql

package dataprovider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	// we import lib/pq here to be able to disable PostgreSQL support using a build tag
	_ "github.com/lib/pq"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	pgsqlResetSQL = `DROP TABLE IF EXISTS "{{api_keys}}" CASCADE;
DROP TABLE IF EXISTS "{{folders_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{admins}}" CASCADE;
DROP TABLE IF EXISTS "{{folders}}" CASCADE;
DROP TABLE IF EXISTS "{{shares}}" CASCADE;
DROP TABLE IF EXISTS "{{users}}" CASCADE;
DROP TABLE IF EXISTS "{{schema_version}}" CASCADE;
`
	pgsqlInitial = `CREATE TABLE "{{schema_version}}" ("id" serial NOT NULL PRIMARY KEY, "version" integer NOT NULL);
	CREATE TABLE "{{admins}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL,
"permissions" text NOT NULL, "filters" text NULL, "additional_info" text NULL);
CREATE TABLE "{{folders}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE, "description" varchar(512) NULL,
"path" varchar(512) NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL,
"filesystem" text NULL);
CREATE TABLE "{{users}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE, "status" integer NOT NULL,
"expiration_date" bigint NOT NULL, "description" varchar(512) NULL, "password" text NULL, "public_keys" text NULL,
"home_dir" varchar(512) NOT NULL, "uid" integer NOT NULL, "gid" integer NOT NULL, "max_sessions" integer NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL,
"used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL,
"download_bandwidth" integer NOT NULL, "last_login" bigint NOT NULL, "filters" text NULL, "filesystem" text NULL,
"additional_info" text NULL);
CREATE TABLE "{{folders_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "virtual_path" varchar(512) NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "folder_id" integer NOT NULL, "user_id" integer NOT NULL);
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "{{prefix}}unique_mapping" UNIQUE ("user_id", "folder_id");
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "{{prefix}}folders_mapping_folder_id_fk_folders_id"
FOREIGN KEY ("folder_id") REFERENCES "{{folders}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "{{prefix}}folders_mapping_user_id_fk_users_id"
FOREIGN KEY ("user_id") REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX "{{prefix}}folders_mapping_folder_id_idx" ON "{{folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}folders_mapping_user_id_idx" ON "{{folders_mapping}}" ("user_id");
INSERT INTO {{schema_version}} (version) VALUES (10);
`
	pgsqlV11SQL = `CREATE TABLE "{{api_keys}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL,
"key_id" varchar(50) NOT NULL UNIQUE, "api_key" varchar(255) NOT NULL UNIQUE, "scope" integer NOT NULL,
"created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "last_use_at" bigint NOT NULL,"expires_at" bigint NOT NULL,
"description" text NULL, "admin_id" integer NULL, "user_id" integer NULL);
ALTER TABLE "{{api_keys}}" ADD CONSTRAINT "{{prefix}}api_keys_admin_id_fk_admins_id" FOREIGN KEY ("admin_id")
REFERENCES "{{admins}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE "{{api_keys}}" ADD CONSTRAINT "{{prefix}}api_keys_user_id_fk_users_id" FOREIGN KEY ("user_id")
REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE INDEX "{{prefix}}api_keys_admin_id_idx" ON "{{api_keys}}" ("admin_id");
CREATE INDEX "{{prefix}}api_keys_user_id_idx" ON "{{api_keys}}" ("user_id");
`
	pgsqlV11DownSQL = `DROP TABLE "{{api_keys}}" CASCADE;`
	pgsqlV12SQL     = `ALTER TABLE "{{admins}}" ADD COLUMN "created_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{admins}}" ALTER COLUMN "created_at" DROP DEFAULT;
ALTER TABLE "{{admins}}" ADD COLUMN "updated_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{admins}}" ALTER COLUMN "updated_at" DROP DEFAULT;
ALTER TABLE "{{admins}}" ADD COLUMN "last_login" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{admins}}" ALTER COLUMN "last_login" DROP DEFAULT;
ALTER TABLE "{{users}}" ADD COLUMN "created_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "created_at" DROP DEFAULT;
ALTER TABLE "{{users}}" ADD COLUMN "updated_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "updated_at" DROP DEFAULT;
CREATE INDEX "{{prefix}}users_updated_at_idx" ON "{{users}}" ("updated_at");
`
	pgsqlV12DownSQL = `ALTER TABLE "{{users}}" DROP COLUMN "updated_at" CASCADE;
ALTER TABLE "{{users}}" DROP COLUMN "created_at" CASCADE;
ALTER TABLE "{{admins}}" DROP COLUMN "created_at" CASCADE;
ALTER TABLE "{{admins}}" DROP COLUMN "updated_at" CASCADE;
ALTER TABLE "{{admins}}" DROP COLUMN "last_login" CASCADE;
`
	pgsqlV13SQL     = `ALTER TABLE "{{users}}" ADD COLUMN "email" varchar(255) NULL;`
	pgsqlV13DownSQL = `ALTER TABLE "{{users}}" DROP COLUMN "email" CASCADE;`
	pgsqlV14SQL     = `CREATE TABLE "{{shares}}" ("id" serial NOT NULL PRIMARY KEY,
"share_id" varchar(60) NOT NULL UNIQUE, "name" varchar(255) NOT NULL, "description" varchar(512) NULL,
"scope" integer NOT NULL, "paths" text NOT NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL,
"last_use_at" bigint NOT NULL, "expires_at" bigint NOT NULL, "password" text NULL,
"max_tokens" integer NOT NULL, "used_tokens" integer NOT NULL, "allow_from" text NULL,
"user_id" integer NOT NULL);
ALTER TABLE "{{shares}}" ADD CONSTRAINT "{{prefix}}shares_user_id_fk_users_id" FOREIGN KEY ("user_id")
REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE INDEX "{{prefix}}shares_user_id_idx" ON "{{shares}}" ("user_id");
`
	pgsqlV14DownSQL = `DROP TABLE "{{shares}}" CASCADE;`
)

// PGSQLProvider auth provider for PostgreSQL database
type PGSQLProvider struct {
	dbHandle *sql.DB
}

func init() {
	version.AddFeature("+pgsql")
}

func initializePGSQLProvider() error {
	var err error
	dbHandle, err := sql.Open("postgres", getPGSQLConnectionString(false))
	if err == nil {
		providerLog(logger.LevelDebug, "postgres database handle created, connection string: %#v, pool size: %v",
			getPGSQLConnectionString(true), config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		if config.PoolSize > 0 {
			dbHandle.SetMaxIdleConns(config.PoolSize)
		} else {
			dbHandle.SetMaxIdleConns(2)
		}
		dbHandle.SetConnMaxLifetime(240 * time.Second)
		provider = &PGSQLProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating postgres database handler, connection string: %#v, error: %v",
			getPGSQLConnectionString(true), err)
	}
	return err
}

func getPGSQLConnectionString(redactedPwd bool) string {
	var connectionString string
	if config.ConnectionString == "" {
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

func (p *PGSQLProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p *PGSQLProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, ip, protocol, p.dbHandle)
}

func (p *PGSQLProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	return sqlCommonValidateUserAndTLSCertificate(username, protocol, tlsCert, p.dbHandle)
}

func (p *PGSQLProvider) validateUserAndPubKey(username string, publicKey []byte) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p *PGSQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *PGSQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p *PGSQLProvider) setUpdatedAt(username string) {
	sqlCommonSetUpdatedAt(username, p.dbHandle)
}

func (p *PGSQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p *PGSQLProvider) updateAdminLastLogin(username string) error {
	return sqlCommonUpdateAdminLastLogin(username, p.dbHandle)
}

func (p *PGSQLProvider) userExists(username string) (User, error) {
	return sqlCommonGetUserByUsername(username, p.dbHandle)
}

func (p *PGSQLProvider) addUser(user *User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p *PGSQLProvider) updateUser(user *User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p *PGSQLProvider) deleteUser(user *User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p *PGSQLProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p *PGSQLProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return sqlCommonGetRecentlyUpdatedUsers(after, p.dbHandle)
}

func (p *PGSQLProvider) getUsers(limit int, offset int, order string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, p.dbHandle)
}

func (p *PGSQLProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p *PGSQLProvider) getFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, p.dbHandle)
}

func (p *PGSQLProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonGetFolderByName(ctx, name, p.dbHandle)
}

func (p *PGSQLProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonAddFolder(folder, p.dbHandle)
}

func (p *PGSQLProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonUpdateFolder(folder, p.dbHandle)
}

func (p *PGSQLProvider) deleteFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p *PGSQLProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *PGSQLProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, p.dbHandle)
}

func (p *PGSQLProvider) adminExists(username string) (Admin, error) {
	return sqlCommonGetAdminByUsername(username, p.dbHandle)
}

func (p *PGSQLProvider) addAdmin(admin *Admin) error {
	return sqlCommonAddAdmin(admin, p.dbHandle)
}

func (p *PGSQLProvider) updateAdmin(admin *Admin) error {
	return sqlCommonUpdateAdmin(admin, p.dbHandle)
}

func (p *PGSQLProvider) deleteAdmin(admin *Admin) error {
	return sqlCommonDeleteAdmin(admin, p.dbHandle)
}

func (p *PGSQLProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	return sqlCommonGetAdmins(limit, offset, order, p.dbHandle)
}

func (p *PGSQLProvider) dumpAdmins() ([]Admin, error) {
	return sqlCommonDumpAdmins(p.dbHandle)
}

func (p *PGSQLProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	return sqlCommonValidateAdminAndPass(username, password, ip, p.dbHandle)
}

func (p *PGSQLProvider) apiKeyExists(keyID string) (APIKey, error) {
	return sqlCommonGetAPIKeyByID(keyID, p.dbHandle)
}

func (p *PGSQLProvider) addAPIKey(apiKey *APIKey) error {
	return sqlCommonAddAPIKey(apiKey, p.dbHandle)
}

func (p *PGSQLProvider) updateAPIKey(apiKey *APIKey) error {
	return sqlCommonUpdateAPIKey(apiKey, p.dbHandle)
}

func (p *PGSQLProvider) deleteAPIKey(apiKey *APIKey) error {
	return sqlCommonDeleteAPIKey(apiKey, p.dbHandle)
}

func (p *PGSQLProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	return sqlCommonGetAPIKeys(limit, offset, order, p.dbHandle)
}

func (p *PGSQLProvider) dumpAPIKeys() ([]APIKey, error) {
	return sqlCommonDumpAPIKeys(p.dbHandle)
}

func (p *PGSQLProvider) updateAPIKeyLastUse(keyID string) error {
	return sqlCommonUpdateAPIKeyLastUse(keyID, p.dbHandle)
}

func (p *PGSQLProvider) shareExists(shareID, username string) (Share, error) {
	return sqlCommonGetShareByID(shareID, username, p.dbHandle)
}

func (p *PGSQLProvider) addShare(share *Share) error {
	return sqlCommonAddShare(share, p.dbHandle)
}

func (p *PGSQLProvider) updateShare(share *Share) error {
	return sqlCommonUpdateShare(share, p.dbHandle)
}

func (p *PGSQLProvider) deleteShare(share *Share) error {
	return sqlCommonDeleteShare(share, p.dbHandle)
}

func (p *PGSQLProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	return sqlCommonGetShares(limit, offset, order, username, p.dbHandle)
}

func (p *PGSQLProvider) dumpShares() ([]Share, error) {
	return sqlCommonDumpShares(p.dbHandle)
}

func (p *PGSQLProvider) updateShareLastUse(shareID string, numTokens int) error {
	return sqlCommonUpdateShareLastUse(shareID, numTokens, p.dbHandle)
}

func (p *PGSQLProvider) close() error {
	return p.dbHandle.Close()
}

func (p *PGSQLProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (p *PGSQLProvider) initializeDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, false)
	if err == nil && dbVersion.Version > 0 {
		return ErrNoInitRequired
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errSchemaVersionEmpty
	}
	initialSQL := strings.ReplaceAll(pgsqlInitial, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)
	if config.Driver == CockroachDataProviderName {
		// Cockroach does not support deferrable constraint validation, we don't need them,
		// we keep these definitions for the PostgreSQL driver to avoid changes for users
		// upgrading from old SFTPGo versions
		initialSQL = strings.ReplaceAll(initialSQL, "DEFERRABLE INITIALLY DEFERRED", "")
	}

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{initialSQL}, 10)
}

//nolint:dupl
func (p *PGSQLProvider) migrateDatabase() error {
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
		return updatePGSQLDatabaseFromV10(p.dbHandle)
	case version == 11:
		return updatePGSQLDatabaseFromV11(p.dbHandle)
	case version == 12:
		return updatePGSQLDatabaseFromV12(p.dbHandle)
	case version == 13:
		return updatePGSQLDatabaseFromV13(p.dbHandle)
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

func (p *PGSQLProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}

	switch dbVersion.Version {
	case 14:
		return downgradePGSQLDatabaseFromV14(p.dbHandle)
	case 13:
		return downgradePGSQLDatabaseFromV13(p.dbHandle)
	case 12:
		return downgradePGSQLDatabaseFromV12(p.dbHandle)
	case 11:
		return downgradePGSQLDatabaseFromV11(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func (p *PGSQLProvider) resetDatabase() error {
	sql := strings.ReplaceAll(pgsqlResetSQL, "{{schema_version}}", sqlTableSchemaVersion)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{sql}, 0)
}

func updatePGSQLDatabaseFromV10(dbHandle *sql.DB) error {
	if err := updatePGSQLDatabaseFrom10To11(dbHandle); err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV11(dbHandle)
}

func updatePGSQLDatabaseFromV11(dbHandle *sql.DB) error {
	if err := updatePGSQLDatabaseFrom11To12(dbHandle); err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV12(dbHandle)
}

func updatePGSQLDatabaseFromV12(dbHandle *sql.DB) error {
	if err := updatePGSQLDatabaseFrom12To13(dbHandle); err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV13(dbHandle)
}

func updatePGSQLDatabaseFromV13(dbHandle *sql.DB) error {
	return updatePGSQLDatabaseFrom13To14(dbHandle)
}

func downgradePGSQLDatabaseFromV14(dbHandle *sql.DB) error {
	if err := downgradePGSQLDatabaseFrom14To13(dbHandle); err != nil {
		return err
	}
	return downgradePGSQLDatabaseFromV13(dbHandle)
}

func downgradePGSQLDatabaseFromV13(dbHandle *sql.DB) error {
	if err := downgradePGSQLDatabaseFrom13To12(dbHandle); err != nil {
		return err
	}
	return downgradePGSQLDatabaseFromV12(dbHandle)
}

func downgradePGSQLDatabaseFromV12(dbHandle *sql.DB) error {
	if err := downgradePGSQLDatabaseFrom12To11(dbHandle); err != nil {
		return err
	}
	return downgradePGSQLDatabaseFromV11(dbHandle)
}

func downgradePGSQLDatabaseFromV11(dbHandle *sql.DB) error {
	return downgradePGSQLDatabaseFrom11To10(dbHandle)
}

func updatePGSQLDatabaseFrom13To14(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 13 -> 14")
	providerLog(logger.LevelInfo, "updating database version: 13 -> 14")
	sql := strings.ReplaceAll(pgsqlV14SQL, "{{shares}}", sqlTableShares)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 14)
}

func downgradePGSQLDatabaseFrom14To13(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 14 -> 13")
	providerLog(logger.LevelInfo, "downgrading database version: 14 -> 13")
	sql := strings.ReplaceAll(pgsqlV14DownSQL, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 13)
}

func updatePGSQLDatabaseFrom12To13(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 12 -> 13")
	providerLog(logger.LevelInfo, "updating database version: 12 -> 13")
	sql := strings.ReplaceAll(pgsqlV13SQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 13)
}

func downgradePGSQLDatabaseFrom13To12(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 13 -> 12")
	providerLog(logger.LevelInfo, "downgrading database version: 13 -> 12")
	sql := strings.ReplaceAll(pgsqlV13DownSQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 12)
}

func updatePGSQLDatabaseFrom11To12(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 11 -> 12")
	providerLog(logger.LevelInfo, "updating database version: 11 -> 12")
	sql := strings.ReplaceAll(pgsqlV12SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 12)
}

func downgradePGSQLDatabaseFrom12To11(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 12 -> 11")
	providerLog(logger.LevelInfo, "downgrading database version: 12 -> 11")
	sql := strings.ReplaceAll(pgsqlV12DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 11)
}

func updatePGSQLDatabaseFrom10To11(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 10 -> 11")
	providerLog(logger.LevelInfo, "updating database version: 10 -> 11")
	sql := strings.ReplaceAll(pgsqlV11SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 11)
}

func downgradePGSQLDatabaseFrom11To10(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 11 -> 10")
	providerLog(logger.LevelInfo, "downgrading database version: 11 -> 10")
	sql := strings.ReplaceAll(pgsqlV11DownSQL, "{{api_keys}}", sqlTableAPIKeys)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 10)
}
