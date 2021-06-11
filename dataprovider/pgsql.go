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

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	pgsqlInitial = `CREATE TABLE "{{schema_version}}" ("id" serial NOT NULL PRIMARY KEY, "version" integer NOT NULL);
CREATE TABLE "{{admins}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL, "permissions" text NOT NULL,
"filters" text NULL, "additional_info" text NULL);
CREATE TABLE "{{folders}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"path" varchar(512) NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL);
CREATE TABLE "{{users}}" ("id" serial NOT NULL PRIMARY KEY, "status" integer NOT NULL, "expiration_date" bigint NOT NULL,
"username" varchar(255) NOT NULL UNIQUE, "password" text NULL, "public_keys" text NULL, "home_dir" varchar(512) NOT NULL,
"uid" integer NOT NULL, "gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL,
"quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL,
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
INSERT INTO {{schema_version}} (version) VALUES (8);
`
	pgsqlV9SQL = `ALTER TABLE "{{admins}}" ADD COLUMN "description" varchar(512) NULL;
ALTER TABLE "{{folders}}" ADD COLUMN "description" varchar(512) NULL;
ALTER TABLE "{{folders}}" ADD COLUMN "filesystem" text NULL;
ALTER TABLE "{{users}}" ADD COLUMN "description" varchar(512) NULL;
`
	pgsqlV9DownSQL = `ALTER TABLE "{{users}}" DROP COLUMN "description" CASCADE;
ALTER TABLE "{{folders}}" DROP COLUMN "filesystem" CASCADE;
ALTER TABLE "{{folders}}" DROP COLUMN "description" CASCADE;
ALTER TABLE "{{admins}}" DROP COLUMN "description" CASCADE;
`
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

func (p *PGSQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
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
	initialSQL := strings.ReplaceAll(pgsqlInitial, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)
	if config.Driver == CockroachDataProviderName {
		// Cockroach does not support deferrable constraint validation, we don't need it,
		// we keep these definitions for the PostgreSQL driver to avoid changes for users
		// upgrading from old SFTPGo versions
		initialSQL = strings.ReplaceAll(initialSQL, "DEFERRABLE INITIALLY DEFERRED", "")
	}

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{initialSQL}, 8)
}

func (p *PGSQLProvider) migrateDatabase() error {
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
		return updatePGSQLDatabaseFromV8(p.dbHandle)
	case version == 9:
		return updatePGSQLDatabaseFromV9(p.dbHandle)
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
	case 9:
		return downgradePGSQLDatabaseFromV9(p.dbHandle)
	case 10:
		return downgradePGSQLDatabaseFromV10(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func updatePGSQLDatabaseFromV8(dbHandle *sql.DB) error {
	if err := updatePGSQLDatabaseFrom8To9(dbHandle); err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV9(dbHandle)
}

func updatePGSQLDatabaseFromV9(dbHandle *sql.DB) error {
	return updatePGSQLDatabaseFrom9To10(dbHandle)
}

func downgradePGSQLDatabaseFromV9(dbHandle *sql.DB) error {
	return downgradePGSQLDatabaseFrom9To8(dbHandle)
}

func downgradePGSQLDatabaseFromV10(dbHandle *sql.DB) error {
	if err := downgradePGSQLDatabaseFrom10To9(dbHandle); err != nil {
		return err
	}
	return downgradePGSQLDatabaseFromV9(dbHandle)
}

func updatePGSQLDatabaseFrom8To9(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 8 -> 9")
	providerLog(logger.LevelInfo, "updating database version: 8 -> 9")
	sql := strings.ReplaceAll(pgsqlV9SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 9)
}

func downgradePGSQLDatabaseFrom9To8(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 9 -> 8")
	providerLog(logger.LevelInfo, "downgrading database version: 9 -> 8")
	sql := strings.ReplaceAll(pgsqlV9DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 8)
}

func updatePGSQLDatabaseFrom9To10(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom9To10(dbHandle)
}

func downgradePGSQLDatabaseFrom10To9(dbHandle *sql.DB) error {
	return sqlCommonDowngradeDatabaseFrom10To9(dbHandle)
}
