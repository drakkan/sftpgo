// Copyright (C) 2019-2022  Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
DROP TABLE IF EXISTS "{{users_folders_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{users_groups_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{groups_folders_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{admins}}" CASCADE;
DROP TABLE IF EXISTS "{{folders}}" CASCADE;
DROP TABLE IF EXISTS "{{shares}}" CASCADE;
DROP TABLE IF EXISTS "{{users}}" CASCADE;
DROP TABLE IF EXISTS "{{groups}}" CASCADE;
DROP TABLE IF EXISTS "{{defender_events}}" CASCADE;
DROP TABLE IF EXISTS "{{defender_hosts}}" CASCADE;
DROP TABLE IF EXISTS "{{active_transfers}}" CASCADE;
DROP TABLE IF EXISTS "{{shared_sessions}}" CASCADE;
DROP TABLE IF EXISTS "{{schema_version}}" CASCADE;
`
	pgsqlInitial = `CREATE TABLE "{{schema_version}}" ("id" serial NOT NULL PRIMARY KEY, "version" integer NOT NULL);
CREATE TABLE "{{admins}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL,
"permissions" text NOT NULL, "filters" text NULL, "additional_info" text NULL, "last_login" bigint NOT NULL,
"created_at" bigint NOT NULL, "updated_at" bigint NOT NULL);
CREATE TABLE "{{defender_hosts}}" ("id" bigserial NOT NULL PRIMARY KEY, "ip" varchar(50) NOT NULL UNIQUE,
"ban_time" bigint NOT NULL, "updated_at" bigint NOT NULL);
CREATE TABLE "{{defender_events}}" ("id" bigserial NOT NULL PRIMARY KEY, "date_time" bigint NOT NULL, "score" integer NOT NULL,
"host_id" bigint NOT NULL);
ALTER TABLE "{{defender_events}}" ADD CONSTRAINT "{{prefix}}defender_events_host_id_fk_defender_hosts_id" FOREIGN KEY
("host_id") REFERENCES "{{defender_hosts}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE TABLE "{{folders}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE, "description" varchar(512) NULL,
"path" text NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL,
"filesystem" text NULL);
CREATE TABLE "{{users}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE, "status" integer NOT NULL,
"expiration_date" bigint NOT NULL, "description" varchar(512) NULL, "password" text NULL, "public_keys" text NULL,
"home_dir" text NOT NULL, "uid" bigint NOT NULL, "gid" bigint NOT NULL, "max_sessions" integer NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL,
"used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL,
"download_bandwidth" integer NOT NULL, "last_login" bigint NOT NULL, "filters" text NULL, "filesystem" text NULL,
"additional_info" text NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "email" varchar(255) NULL);
CREATE TABLE "{{folders_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "virtual_path" text NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "folder_id" integer NOT NULL, "user_id" integer NOT NULL);
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "{{prefix}}unique_mapping" UNIQUE ("user_id", "folder_id");
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "{{prefix}}folders_mapping_folder_id_fk_folders_id"
FOREIGN KEY ("folder_id") REFERENCES "{{folders}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "{{prefix}}folders_mapping_user_id_fk_users_id"
FOREIGN KEY ("user_id") REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE TABLE "{{shares}}" ("id" serial NOT NULL PRIMARY KEY,
"share_id" varchar(60) NOT NULL UNIQUE, "name" varchar(255) NOT NULL, "description" varchar(512) NULL,
"scope" integer NOT NULL, "paths" text NOT NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL,
"last_use_at" bigint NOT NULL, "expires_at" bigint NOT NULL, "password" text NULL,
"max_tokens" integer NOT NULL, "used_tokens" integer NOT NULL, "allow_from" text NULL,
"user_id" integer NOT NULL);
ALTER TABLE "{{shares}}" ADD CONSTRAINT "{{prefix}}shares_user_id_fk_users_id" FOREIGN KEY ("user_id")
REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE TABLE "{{api_keys}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL,
"key_id" varchar(50) NOT NULL UNIQUE, "api_key" varchar(255) NOT NULL UNIQUE, "scope" integer NOT NULL,
"created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "last_use_at" bigint NOT NULL,"expires_at" bigint NOT NULL,
"description" text NULL, "admin_id" integer NULL, "user_id" integer NULL);
ALTER TABLE "{{api_keys}}" ADD CONSTRAINT "{{prefix}}api_keys_admin_id_fk_admins_id" FOREIGN KEY ("admin_id")
REFERENCES "{{admins}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE "{{api_keys}}" ADD CONSTRAINT "{{prefix}}api_keys_user_id_fk_users_id" FOREIGN KEY ("user_id")
REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE INDEX "{{prefix}}folders_mapping_folder_id_idx" ON "{{folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}folders_mapping_user_id_idx" ON "{{folders_mapping}}" ("user_id");
CREATE INDEX "{{prefix}}api_keys_admin_id_idx" ON "{{api_keys}}" ("admin_id");
CREATE INDEX "{{prefix}}api_keys_user_id_idx" ON "{{api_keys}}" ("user_id");
CREATE INDEX "{{prefix}}users_updated_at_idx" ON "{{users}}" ("updated_at");
CREATE INDEX "{{prefix}}shares_user_id_idx" ON "{{shares}}" ("user_id");
CREATE INDEX "{{prefix}}defender_hosts_updated_at_idx" ON "{{defender_hosts}}" ("updated_at");
CREATE INDEX "{{prefix}}defender_hosts_ban_time_idx" ON "{{defender_hosts}}" ("ban_time");
CREATE INDEX "{{prefix}}defender_events_date_time_idx" ON "{{defender_events}}" ("date_time");
CREATE INDEX "{{prefix}}defender_events_host_id_idx" ON "{{defender_events}}" ("host_id");
INSERT INTO {{schema_version}} (version) VALUES (15);
`
	pgsqlV16SQL = `ALTER TABLE "{{users}}" ADD COLUMN "download_data_transfer" integer DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "download_data_transfer" DROP DEFAULT;
ALTER TABLE "{{users}}" ADD COLUMN "total_data_transfer" integer DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "total_data_transfer" DROP DEFAULT;
ALTER TABLE "{{users}}" ADD COLUMN "upload_data_transfer" integer DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "upload_data_transfer" DROP DEFAULT;
ALTER TABLE "{{users}}" ADD COLUMN "used_download_data_transfer" integer DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "used_download_data_transfer" DROP DEFAULT;
ALTER TABLE "{{users}}" ADD COLUMN "used_upload_data_transfer" integer DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "used_upload_data_transfer" DROP DEFAULT;
CREATE TABLE "{{active_transfers}}" ("id" bigserial NOT NULL PRIMARY KEY, "connection_id" varchar(100) NOT NULL,
"transfer_id" bigint NOT NULL, "transfer_type" integer NOT NULL, "username" varchar(255) NOT NULL,
"folder_name" varchar(255) NULL, "ip" varchar(50) NOT NULL, "truncated_size" bigint NOT NULL,
"current_ul_size" bigint NOT NULL, "current_dl_size" bigint NOT NULL, "created_at" bigint NOT NULL,
"updated_at" bigint NOT NULL);
CREATE INDEX "{{prefix}}active_transfers_connection_id_idx" ON "{{active_transfers}}" ("connection_id");
CREATE INDEX "{{prefix}}active_transfers_transfer_id_idx" ON "{{active_transfers}}" ("transfer_id");
CREATE INDEX "{{prefix}}active_transfers_updated_at_idx" ON "{{active_transfers}}" ("updated_at");
`
	pgsqlV16DownSQL = `ALTER TABLE "{{users}}" DROP COLUMN "used_upload_data_transfer" CASCADE;
ALTER TABLE "{{users}}" DROP COLUMN "used_download_data_transfer" CASCADE;
ALTER TABLE "{{users}}" DROP COLUMN "upload_data_transfer" CASCADE;
ALTER TABLE "{{users}}" DROP COLUMN "total_data_transfer" CASCADE;
ALTER TABLE "{{users}}" DROP COLUMN "download_data_transfer" CASCADE;
DROP TABLE "{{active_transfers}}" CASCADE;
`
	pgsqlV17SQL = `CREATE TABLE "{{groups}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "user_settings" text NULL);
CREATE TABLE "{{groups_folders_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "group_id" integer NOT NULL,
"folder_id" integer NOT NULL, "virtual_path" text NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL);
CREATE TABLE "{{users_groups_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "user_id" integer NOT NULL,
"group_id" integer NOT NULL, "group_type" integer NOT NULL);
DROP INDEX "{{prefix}}folders_mapping_folder_id_idx";
DROP INDEX "{{prefix}}folders_mapping_user_id_idx";
ALTER TABLE "{{folders_mapping}}" DROP CONSTRAINT "{{prefix}}unique_mapping";
ALTER TABLE "{{folders_mapping}}" RENAME TO "{{users_folders_mapping}}";
ALTER TABLE "{{users_folders_mapping}}" ADD CONSTRAINT "{{prefix}}unique_user_folder_mapping" UNIQUE ("user_id", "folder_id");
CREATE INDEX "{{prefix}}users_folders_mapping_folder_id_idx" ON "{{users_folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}users_folders_mapping_user_id_idx" ON "{{users_folders_mapping}}" ("user_id");
ALTER TABLE "{{users_groups_mapping}}" ADD CONSTRAINT "{{prefix}}unique_user_group_mapping" UNIQUE ("user_id", "group_id");
ALTER TABLE "{{groups_folders_mapping}}" ADD CONSTRAINT "{{prefix}}unique_group_folder_mapping" UNIQUE ("group_id", "folder_id");
CREATE INDEX "{{prefix}}users_groups_mapping_group_id_idx" ON "{{users_groups_mapping}}" ("group_id");
ALTER TABLE "{{users_groups_mapping}}" ADD CONSTRAINT "{{prefix}}users_groups_mapping_group_id_fk_groups_id"
FOREIGN KEY ("group_id") REFERENCES "{{groups}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION;
CREATE INDEX "{{prefix}}users_groups_mapping_user_id_idx" ON "{{users_groups_mapping}}" ("user_id");
ALTER TABLE "{{users_groups_mapping}}" ADD CONSTRAINT "{{prefix}}users_groups_mapping_user_id_fk_users_id"
FOREIGN KEY ("user_id") REFERENCES "{{users}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE INDEX "{{prefix}}groups_folders_mapping_folder_id_idx" ON "{{groups_folders_mapping}}" ("folder_id");
ALTER TABLE "{{groups_folders_mapping}}" ADD CONSTRAINT "{{prefix}}groups_folders_mapping_folder_id_fk_folders_id"
FOREIGN KEY ("folder_id") REFERENCES "{{folders}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE INDEX "{{prefix}}groups_folders_mapping_group_id_idx" ON "{{groups_folders_mapping}}" ("group_id");
ALTER TABLE "{{groups_folders_mapping}}" ADD CONSTRAINT "{{prefix}}groups_folders_mapping_group_id_fk_groups_id"
FOREIGN KEY ("group_id") REFERENCES "{{groups}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE INDEX "{{prefix}}groups_updated_at_idx" ON "{{groups}}" ("updated_at");
`
	pgsqlV17DownSQL = `DROP TABLE "{{users_groups_mapping}}" CASCADE;
DROP TABLE "{{groups_folders_mapping}}" CASCADE;
DROP TABLE "{{groups}}" CASCADE;
DROP INDEX "{{prefix}}users_folders_mapping_folder_id_idx";
DROP INDEX "{{prefix}}users_folders_mapping_user_id_idx";
ALTER TABLE "{{users_folders_mapping}}" DROP CONSTRAINT "{{prefix}}unique_user_folder_mapping";
ALTER TABLE "{{users_folders_mapping}}" RENAME TO "{{folders_mapping}}";
ALTER TABLE "{{folders_mapping}}" ADD CONSTRAINT "{{prefix}}unique_mapping" UNIQUE ("user_id", "folder_id");
CREATE INDEX "{{prefix}}folders_mapping_folder_id_idx" ON "{{folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}folders_mapping_user_id_idx" ON "{{folders_mapping}}" ("user_id");
`
	pgsqlV19SQL = `CREATE TABLE "{{shared_sessions}}" ("key" varchar(128) NOT NULL PRIMARY KEY,
"data" text NOT NULL, "type" integer NOT NULL, "timestamp" bigint NOT NULL);
CREATE INDEX "{{prefix}}shared_sessions_type_idx" ON "{{shared_sessions}}" ("type");
CREATE INDEX "{{prefix}}shared_sessions_timestamp_idx" ON "{{shared_sessions}}" ("timestamp");`
	pgsqlV19DownSQL = `DROP TABLE "{{shared_sessions}}" CASCADE;`
)

// PGSQLProvider defines the auth provider for PostgreSQL database
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
		providerLog(logger.LevelError, "error creating postgres database handler, connection string: %#v, error: %v",
			getPGSQLConnectionString(true), err)
	}
	return err
}

func getPGSQLConnectionString(redactedPwd bool) string {
	var connectionString string
	if config.ConnectionString == "" {
		password := config.Password
		if redactedPwd && password != "" {
			password = "[redacted]"
		}
		connectionString = fmt.Sprintf("host='%v' port=%v dbname='%v' user='%v' password='%v' sslmode=%v connect_timeout=10",
			config.Host, config.Port, config.Name, config.Username, password, getSSLMode())
		if config.RootCert != "" {
			connectionString += fmt.Sprintf(" sslrootcert='%v'", config.RootCert)
		}
		if config.ClientCert != "" && config.ClientKey != "" {
			connectionString += fmt.Sprintf(" sslcert='%v' sslkey='%v'", config.ClientCert, config.ClientKey)
		}
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

func (p *PGSQLProvider) validateUserAndPubKey(username string, publicKey []byte, isSSHCert bool) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, isSSHCert, p.dbHandle)
}

func (p *PGSQLProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	return sqlCommonUpdateTransferQuota(username, uploadSize, downloadSize, reset, p.dbHandle)
}

func (p *PGSQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *PGSQLProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
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

func (p *PGSQLProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p *PGSQLProvider) updateUserPassword(username, password string) error {
	return sqlCommonUpdateUserPassword(username, password, p.dbHandle)
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

func (p *PGSQLProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return sqlCommonGetUsersForQuotaCheck(toFetch, p.dbHandle)
}

func (p *PGSQLProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p *PGSQLProvider) getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, minimal, p.dbHandle)
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

func (p *PGSQLProvider) deleteFolder(folder vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p *PGSQLProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *PGSQLProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, p.dbHandle)
}

func (p *PGSQLProvider) getGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	return sqlCommonGetGroups(limit, offset, order, minimal, p.dbHandle)
}

func (p *PGSQLProvider) getGroupsWithNames(names []string) ([]Group, error) {
	return sqlCommonGetGroupsWithNames(names, p.dbHandle)
}

func (p *PGSQLProvider) getUsersInGroups(names []string) ([]string, error) {
	return sqlCommonGetUsersInGroups(names, p.dbHandle)
}

func (p *PGSQLProvider) groupExists(name string) (Group, error) {
	return sqlCommonGetGroupByName(name, p.dbHandle)
}

func (p *PGSQLProvider) addGroup(group *Group) error {
	return sqlCommonAddGroup(group, p.dbHandle)
}

func (p *PGSQLProvider) updateGroup(group *Group) error {
	return sqlCommonUpdateGroup(group, p.dbHandle)
}

func (p *PGSQLProvider) deleteGroup(group Group) error {
	return sqlCommonDeleteGroup(group, p.dbHandle)
}

func (p *PGSQLProvider) dumpGroups() ([]Group, error) {
	return sqlCommonDumpGroups(p.dbHandle)
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

func (p *PGSQLProvider) deleteAdmin(admin Admin) error {
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

func (p *PGSQLProvider) deleteAPIKey(apiKey APIKey) error {
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

func (p *PGSQLProvider) deleteShare(share Share) error {
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

func (p *PGSQLProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return sqlCommonGetDefenderHosts(from, limit, p.dbHandle)
}

func (p *PGSQLProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return sqlCommonGetDefenderHostByIP(ip, from, p.dbHandle)
}

func (p *PGSQLProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
	return sqlCommonIsDefenderHostBanned(ip, p.dbHandle)
}

func (p *PGSQLProvider) updateDefenderBanTime(ip string, minutes int) error {
	return sqlCommonDefenderIncrementBanTime(ip, minutes, p.dbHandle)
}

func (p *PGSQLProvider) deleteDefenderHost(ip string) error {
	return sqlCommonDeleteDefenderHost(ip, p.dbHandle)
}

func (p *PGSQLProvider) addDefenderEvent(ip string, score int) error {
	return sqlCommonAddDefenderHostAndEvent(ip, score, p.dbHandle)
}

func (p *PGSQLProvider) setDefenderBanTime(ip string, banTime int64) error {
	return sqlCommonSetDefenderBanTime(ip, banTime, p.dbHandle)
}

func (p *PGSQLProvider) cleanupDefender(from int64) error {
	return sqlCommonDefenderCleanup(from, p.dbHandle)
}

func (p *PGSQLProvider) addActiveTransfer(transfer ActiveTransfer) error {
	return sqlCommonAddActiveTransfer(transfer, p.dbHandle)
}

func (p *PGSQLProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
	return sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID, connectionID, p.dbHandle)
}

func (p *PGSQLProvider) removeActiveTransfer(transferID int64, connectionID string) error {
	return sqlCommonRemoveActiveTransfer(transferID, connectionID, p.dbHandle)
}

func (p *PGSQLProvider) cleanupActiveTransfers(before time.Time) error {
	return sqlCommonCleanupActiveTransfers(before, p.dbHandle)
}

func (p *PGSQLProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return sqlCommonGetActiveTransfers(from, p.dbHandle)
}

func (p *PGSQLProvider) addSharedSession(session Session) error {
	return sqlCommonAddSession(session, p.dbHandle)
}

func (p *PGSQLProvider) deleteSharedSession(key string) error {
	return sqlCommonDeleteSession(key, p.dbHandle)
}

func (p *PGSQLProvider) getSharedSession(key string) (Session, error) {
	return sqlCommonGetSession(key, p.dbHandle)
}

func (p *PGSQLProvider) cleanupSharedSessions(sessionType SessionType, before int64) error {
	return sqlCommonCleanupSessions(sessionType, before, p.dbHandle)
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
	logger.InfoToConsole("creating initial database schema, version 15")
	providerLog(logger.LevelInfo, "creating initial database schema, version 15")
	initialSQL := strings.ReplaceAll(pgsqlInitial, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{api_keys}}", sqlTableAPIKeys)
	initialSQL = strings.ReplaceAll(initialSQL, "{{shares}}", sqlTableShares)
	initialSQL = strings.ReplaceAll(initialSQL, "{{defender_events}}", sqlTableDefenderEvents)
	initialSQL = strings.ReplaceAll(initialSQL, "{{defender_hosts}}", sqlTableDefenderHosts)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)
	if config.Driver == CockroachDataProviderName {
		// Cockroach does not support deferrable constraint validation, we don't need them,
		// we keep these definitions for the PostgreSQL driver to avoid changes for users
		// upgrading from old SFTPGo versions
		initialSQL = strings.ReplaceAll(initialSQL, "DEFERRABLE INITIALLY DEFERRED", "")
	}

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{initialSQL}, 15, true)
}

func (p *PGSQLProvider) migrateDatabase() error { //nolint:dupl
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}

	switch version := dbVersion.Version; {
	case version == sqlDatabaseVersion:
		providerLog(logger.LevelDebug, "sql database is up to date, current version: %v", version)
		return ErrNoInitRequired
	case version < 15:
		err = fmt.Errorf("database version %v is too old, please see the upgrading docs", version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 15:
		return updatePGSQLDatabaseFromV15(p.dbHandle)
	case version == 16:
		return updatePGSQLDatabaseFromV16(p.dbHandle)
	case version == 17:
		return updatePGSQLDatabaseFromV17(p.dbHandle)
	case version == 18:
		return updatePGSQLDatabaseFromV18(p.dbHandle)
	default:
		if version > sqlDatabaseVersion {
			providerLog(logger.LevelError, "database version %v is newer than the supported one: %v", version,
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
	case 16:
		return downgradePGSQLDatabaseFromV16(p.dbHandle)
	case 17:
		return downgradePGSQLDatabaseFromV17(p.dbHandle)
	case 18:
		return downgradePGSQLDatabaseFromV18(p.dbHandle)
	case 19:
		return downgradePGSQLDatabaseFromV19(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func (p *PGSQLProvider) resetDatabase() error {
	sql := sqlReplaceAll(pgsqlResetSQL)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{sql}, 0, false)
}

func updatePGSQLDatabaseFromV15(dbHandle *sql.DB) error {
	if err := updatePGSQLDatabaseFrom15To16(dbHandle); err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV16(dbHandle)
}

func updatePGSQLDatabaseFromV16(dbHandle *sql.DB) error {
	if err := updatePGSQLDatabaseFrom16To17(dbHandle); err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV17(dbHandle)
}

func updatePGSQLDatabaseFromV17(dbHandle *sql.DB) error {
	if err := updatePGSQLDatabaseFrom17To18(dbHandle); err != nil {
		return err
	}
	return updatePGSQLDatabaseFromV18(dbHandle)
}

func updatePGSQLDatabaseFromV18(dbHandle *sql.DB) error {
	return updatePGSQLDatabaseFrom18To19(dbHandle)
}

func downgradePGSQLDatabaseFromV16(dbHandle *sql.DB) error {
	return downgradePGSQLDatabaseFrom16To15(dbHandle)
}

func downgradePGSQLDatabaseFromV17(dbHandle *sql.DB) error {
	if err := downgradePGSQLDatabaseFrom17To16(dbHandle); err != nil {
		return err
	}
	return downgradePGSQLDatabaseFromV16(dbHandle)
}

func downgradePGSQLDatabaseFromV18(dbHandle *sql.DB) error {
	if err := downgradePGSQLDatabaseFrom18To17(dbHandle); err != nil {
		return err
	}
	return downgradePGSQLDatabaseFromV17(dbHandle)
}

func downgradePGSQLDatabaseFromV19(dbHandle *sql.DB) error {
	if err := downgradePGSQLDatabaseFrom19To18(dbHandle); err != nil {
		return err
	}
	return downgradePGSQLDatabaseFromV18(dbHandle)
}

func updatePGSQLDatabaseFrom15To16(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 15 -> 16")
	providerLog(logger.LevelInfo, "updating database version: 15 -> 16")
	sql := strings.ReplaceAll(pgsqlV16SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{active_transfers}}", sqlTableActiveTransfers)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	if config.Driver == CockroachDataProviderName {
		// Cockroach does not allow to run this schema migration within a transaction
		ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
		defer cancel()

		for _, q := range strings.Split(sql, ";") {
			if strings.TrimSpace(q) == "" {
				continue
			}
			_, err := dbHandle.ExecContext(ctx, q)
			if err != nil {
				return err
			}
		}
		return sqlCommonUpdateDatabaseVersion(ctx, dbHandle, 16)
	}
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 16, true)
}

func updatePGSQLDatabaseFrom16To17(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 16 -> 17")
	providerLog(logger.LevelInfo, "updating database version: 16 -> 17")
	sql := pgsqlV17SQL
	if config.Driver == CockroachDataProviderName {
		sql = strings.ReplaceAll(sql, `ALTER TABLE "{{folders_mapping}}" DROP CONSTRAINT "{{prefix}}unique_mapping";`,
			`DROP INDEX "{{prefix}}unique_mapping" CASCADE;`)
	}
	sql = strings.ReplaceAll(sql, "{{groups}}", sqlTableGroups)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{users_folders_mapping}}", sqlTableUsersFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{users_groups_mapping}}", sqlTableUsersGroupsMapping)
	sql = strings.ReplaceAll(sql, "{{groups_folders_mapping}}", sqlTableGroupsFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 17, true)
}

func updatePGSQLDatabaseFrom17To18(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 17 -> 18")
	providerLog(logger.LevelInfo, "updating database version: 17 -> 18")
	if err := importGCSCredentials(); err != nil {
		return err
	}
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, nil, 18, true)
}

func updatePGSQLDatabaseFrom18To19(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 18 -> 19")
	providerLog(logger.LevelInfo, "updating database version: 18 -> 19")
	sql := strings.ReplaceAll(pgsqlV19SQL, "{{shared_sessions}}", sqlTableSharedSessions)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 19, true)
}

func downgradePGSQLDatabaseFrom16To15(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 16 -> 15")
	providerLog(logger.LevelInfo, "downgrading database version: 16 -> 15")
	sql := strings.ReplaceAll(pgsqlV16DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{active_transfers}}", sqlTableActiveTransfers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 15, false)
}

func downgradePGSQLDatabaseFrom17To16(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 17 -> 16")
	providerLog(logger.LevelInfo, "downgrading database version: 17 -> 16")
	sql := pgsqlV17DownSQL
	if config.Driver == CockroachDataProviderName {
		sql = strings.ReplaceAll(sql, `ALTER TABLE "{{users_folders_mapping}}" DROP CONSTRAINT "{{prefix}}unique_user_folder_mapping";`,
			`DROP INDEX "{{prefix}}unique_user_folder_mapping" CASCADE;`)
	}
	sql = strings.ReplaceAll(sql, "{{groups}}", sqlTableGroups)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{users_folders_mapping}}", sqlTableUsersFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{users_groups_mapping}}", sqlTableUsersGroupsMapping)
	sql = strings.ReplaceAll(sql, "{{groups_folders_mapping}}", sqlTableGroupsFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 16, false)
}

func downgradePGSQLDatabaseFrom18To17(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 18 -> 17")
	providerLog(logger.LevelInfo, "downgrading database version: 18 -> 17")
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, nil, 17, false)
}

func downgradePGSQLDatabaseFrom19To18(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 19 -> 18")
	providerLog(logger.LevelInfo, "downgrading database version: 19 -> 18")
	sql := strings.ReplaceAll(pgsqlV19DownSQL, "{{shared_sessions}}", sqlTableSharedSessions)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 18, false)
}
