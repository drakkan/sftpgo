// +build !nopgsql

package dataprovider

import (
	"context"
	"database/sql"
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
	pgsqlUsersTableSQL = `CREATE TABLE "{{users}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"password" varchar(255) NULL, "public_keys" text NULL, "home_dir" varchar(255) NOT NULL, "uid" integer NOT NULL,
"gid" integer NOT NULL, "max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL,
"permissions" text NOT NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL,
"expiration_date" bigint NOT NULL, "last_login" bigint NOT NULL, "status" integer NOT NULL, "filters" text NULL,
"filesystem" text NULL);`
	pgsqlSchemaTableSQL = `CREATE TABLE "{{schema_version}}" ("id" serial NOT NULL PRIMARY KEY, "version" integer NOT NULL);`
	pgsqlV2SQL          = `ALTER TABLE "{{users}}" ADD COLUMN "virtual_folders" text NULL;`
	pgsqlV3SQL          = `ALTER TABLE "{{users}}" ALTER COLUMN "password" TYPE text USING "password"::text;`
	pgsqlV4SQL          = `CREATE TABLE "{{folders}}" ("id" serial NOT NULL PRIMARY KEY, "path" varchar(512) NOT NULL UNIQUE, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL);
ALTER TABLE "{{users}}" ALTER COLUMN "home_dir" TYPE varchar(512) USING "home_dir"::varchar(512);
ALTER TABLE "{{users}}" DROP COLUMN "virtual_folders" CASCADE;
CREATE TABLE "{{folders_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "virtual_path" varchar(512) NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "folder_id" integer NOT NULL, "user_id" integer NOT NULL);
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "unique_mapping" UNIQUE ("user_id", "folder_id");
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "folders_mapping_folder_id_fk_folders_id" FOREIGN KEY ("folder_id") REFERENCES "{{folders}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "folders_mapping_user_id_fk_users_id" FOREIGN KEY ("user_id") REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX "folders_mapping_folder_id_idx" ON "{{folders_mapping}}" ("folder_id");
CREATE INDEX "folders_mapping_user_id_idx" ON "{{folders_mapping}}" ("user_id");
`
	pgsqlV6SQL     = `ALTER TABLE "{{users}}" ADD COLUMN "additional_info" text NULL;`
	pgsqlV6DownSQL = `ALTER TABLE "{{users}}" DROP COLUMN "additional_info" CASCADE;`
	pgsqlV7SQL     = `CREATE TABLE "{{admins}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL, "permissions" text NOT NULL,
"filters" text NULL, "additional_info" text NULL);
`
	pgsqlV7DownSQL = `DROP TABLE "{{admins}}" CASCADE;`
	pgsqlV8SQL     = `ALTER TABLE "{{folders}}" ADD COLUMN "name" varchar(255) NULL;
ALTER TABLE "folders" ALTER COLUMN "path" DROP NOT NULL;
ALTER TABLE "{{folders}}" DROP CONSTRAINT IF EXISTS folders_path_key;
UPDATE "{{folders}}" f1 SET name = (SELECT CONCAT('folder',f2.id) FROM "{{folders}}" f2 WHERE f2.id = f1.id);
ALTER TABLE "{{folders}}" ALTER COLUMN "name" SET NOT NULL;
ALTER TABLE "{{folders}}" ADD CONSTRAINT "folders_name_uniq" UNIQUE ("name");
`
	pgsqlV8DownSQL = `ALTER TABLE "{{folders}}" DROP COLUMN "name" CASCADE;
ALTER TABLE "{{folders}}" ALTER COLUMN "path" SET NOT NULL;
ALTER TABLE "{{folders}}" ADD CONSTRAINT folders_path_key UNIQUE (path);
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
	logSender = fmt.Sprintf("dataprovider_%v", PGSQLDataProviderName)
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
	sqlUsers := strings.Replace(pgsqlUsersTableSQL, "{{users}}", sqlTableUsers, 1)
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
	_, err = tx.Exec(strings.Replace(pgsqlSchemaTableSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		return err
	}
	_, err = tx.Exec(strings.Replace(initialDBVersionSQL, "{{schema_version}}", sqlTableSchemaVersion, 1))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (p *PGSQLProvider) migrateDatabase() error {
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
		return updatePGSQLDatabaseFromV1(p.dbHandle)
	case 2:
		return updatePGSQLDatabaseFromV2(p.dbHandle)
	case 3:
		return updatePGSQLDatabaseFromV3(p.dbHandle)
	case 4:
		return updatePGSQLDatabaseFromV4(p.dbHandle)
	case 5:
		return updatePGSQLDatabaseFromV5(p.dbHandle)
	case 6:
		return updatePGSQLDatabaseFromV6(p.dbHandle)
	case 7:
		return updatePGSQLDatabaseFromV7(p.dbHandle)
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
func (p *PGSQLProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return fmt.Errorf("current version match target version, nothing to do")
	}
	switch dbVersion.Version {
	case 8:
		err = downgradePGSQLDatabaseFrom8To7(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradePGSQLDatabaseFrom7To6(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradePGSQLDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradePGSQLDatabaseFrom5To4(p.dbHandle)
	case 7:
		err = downgradePGSQLDatabaseFrom7To6(p.dbHandle)
		if err != nil {
			return err
		}
		err = downgradePGSQLDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradePGSQLDatabaseFrom5To4(p.dbHandle)
	case 6:
		err = downgradePGSQLDatabaseFrom6To5(p.dbHandle)
		if err != nil {
			return err
		}
		return downgradePGSQLDatabaseFrom5To4(p.dbHandle)
	case 5:
		return downgradePGSQLDatabaseFrom5To4(p.dbHandle)
	default:
		return fmt.Errorf("Database version not handled: %v", dbVersion.Version)
	}
}

func updatePGSQLDatabaseFromV1(dbHandle *sql.DB) error {
	err := updatePGSQLDatabaseFrom1To2(dbHandle)
	if err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV2(dbHandle)
}

func updatePGSQLDatabaseFromV2(dbHandle *sql.DB) error {
	err := updatePGSQLDatabaseFrom2To3(dbHandle)
	if err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV3(dbHandle)
}

func updatePGSQLDatabaseFromV3(dbHandle *sql.DB) error {
	err := updatePGSQLDatabaseFrom3To4(dbHandle)
	if err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV4(dbHandle)
}

func updatePGSQLDatabaseFromV4(dbHandle *sql.DB) error {
	err := updatePGSQLDatabaseFrom4To5(dbHandle)
	if err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV5(dbHandle)
}

func updatePGSQLDatabaseFromV5(dbHandle *sql.DB) error {
	err := updatePGSQLDatabaseFrom5To6(dbHandle)
	if err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV6(dbHandle)
}

func updatePGSQLDatabaseFromV6(dbHandle *sql.DB) error {
	err := updatePGSQLDatabaseFrom6To7(dbHandle)
	if err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV7(dbHandle)
}

func updatePGSQLDatabaseFromV7(dbHandle *sql.DB) error {
	return updatePGSQLDatabaseFrom7To8(dbHandle)
}

func updatePGSQLDatabaseFrom1To2(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 1 -> 2")
	providerLog(logger.LevelInfo, "updating database version: 1 -> 2")
	sql := strings.Replace(pgsqlV2SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 2)
}

func updatePGSQLDatabaseFrom2To3(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 2 -> 3")
	providerLog(logger.LevelInfo, "updating database version: 2 -> 3")
	sql := strings.Replace(pgsqlV3SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 3)
}

func updatePGSQLDatabaseFrom3To4(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom3To4(pgsqlV4SQL, dbHandle)
}

func updatePGSQLDatabaseFrom4To5(dbHandle *sql.DB) error {
	return sqlCommonUpdateDatabaseFrom4To5(dbHandle)
}

func updatePGSQLDatabaseFrom5To6(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 5 -> 6")
	providerLog(logger.LevelInfo, "updating database version: 5 -> 6")
	sql := strings.Replace(pgsqlV6SQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 6)
}

func updatePGSQLDatabaseFrom6To7(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 6 -> 7")
	providerLog(logger.LevelInfo, "updating database version: 6 -> 7")
	sql := strings.Replace(pgsqlV7SQL, "{{admins}}", sqlTableAdmins, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 7)
}

func updatePGSQLDatabaseFrom7To8(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 7 -> 8")
	providerLog(logger.LevelInfo, "updating database version: 7 -> 8")
	sql := strings.ReplaceAll(pgsqlV8SQL, "{{folders}}", sqlTableFolders)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 8)
}

func downgradePGSQLDatabaseFrom8To7(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 8 -> 7")
	providerLog(logger.LevelInfo, "downgrading database version: 8 -> 7")
	sql := strings.ReplaceAll(pgsqlV8DownSQL, "{{folders}}", sqlTableAdmins)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 7)
}

func downgradePGSQLDatabaseFrom7To6(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 7 -> 6")
	providerLog(logger.LevelInfo, "downgrading database version: 7 -> 6")
	sql := strings.Replace(pgsqlV7DownSQL, "{{admins}}", sqlTableAdmins, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 6)
}

func downgradePGSQLDatabaseFrom6To5(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 6 -> 5")
	providerLog(logger.LevelInfo, "downgrading database version: 6 -> 5")
	sql := strings.Replace(pgsqlV6DownSQL, "{{users}}", sqlTableUsers, 1)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 5)
}

func downgradePGSQLDatabaseFrom5To4(dbHandle *sql.DB) error {
	return sqlCommonDowngradeDatabaseFrom5To4(dbHandle)
}
