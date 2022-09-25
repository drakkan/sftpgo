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

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	pgsqlResetSQL = `DROP TABLE IF EXISTS "{{api_keys}}" CASCADE;
DROP TABLE IF EXISTS "{{folders_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{users_folders_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{users_groups_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{admins_groups_mapping}}" CASCADE;
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
DROP TABLE IF EXISTS "{{rules_actions_mapping}}" CASCADE;
DROP TABLE IF EXISTS "{{events_actions}}" CASCADE;
DROP TABLE IF EXISTS "{{events_rules}}" CASCADE;
DROP TABLE IF EXISTS "{{tasks}}" CASCADE;
DROP TABLE IF EXISTS "{{nodes}}" CASCADE;
DROP TABLE IF EXISTS "{{schema_version}}" CASCADE;
`
	pgsqlInitial = `CREATE TABLE "{{schema_version}}" ("id" serial NOT NULL PRIMARY KEY, "version" integer NOT NULL);
CREATE TABLE "{{admins}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL,
"permissions" text NOT NULL, "filters" text NULL, "additional_info" text NULL, "last_login" bigint NOT NULL,
"created_at" bigint NOT NULL, "updated_at" bigint NOT NULL);
CREATE TABLE "{{active_transfers}}" ("id" bigserial NOT NULL PRIMARY KEY, "connection_id" varchar(100) NOT NULL,
"transfer_id" bigint NOT NULL, "transfer_type" integer NOT NULL, "username" varchar(255) NOT NULL,
"folder_name" varchar(255) NULL, "ip" varchar(50) NOT NULL, "truncated_size" bigint NOT NULL,
"current_ul_size" bigint NOT NULL, "current_dl_size" bigint NOT NULL, "created_at" bigint NOT NULL,
"updated_at" bigint NOT NULL);
CREATE TABLE "{{defender_hosts}}" ("id" bigserial NOT NULL PRIMARY KEY, "ip" varchar(50) NOT NULL UNIQUE,
"ban_time" bigint NOT NULL, "updated_at" bigint NOT NULL);
CREATE TABLE "{{defender_events}}" ("id" bigserial NOT NULL PRIMARY KEY, "date_time" bigint NOT NULL, "score" integer NOT NULL,
"host_id" bigint NOT NULL);
ALTER TABLE "{{defender_events}}" ADD CONSTRAINT "{{prefix}}defender_events_host_id_fk_defender_hosts_id" FOREIGN KEY
("host_id") REFERENCES "{{defender_hosts}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE TABLE "{{folders}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE, "description" varchar(512) NULL,
"path" text NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL,
"filesystem" text NULL);
CREATE TABLE "{{groups}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "user_settings" text NULL);
CREATE TABLE "{{shared_sessions}}" ("key" varchar(128) NOT NULL PRIMARY KEY,
"data" text NOT NULL, "type" integer NOT NULL, "timestamp" bigint NOT NULL);
CREATE TABLE "{{users}}" ("id" serial NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE, "status" integer NOT NULL,
"expiration_date" bigint NOT NULL, "description" varchar(512) NULL, "password" text NULL, "public_keys" text NULL,
"home_dir" text NOT NULL, "uid" bigint NOT NULL, "gid" bigint NOT NULL, "max_sessions" integer NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL, "used_quota_size" bigint NOT NULL,
"used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL, "upload_bandwidth" integer NOT NULL,
"download_bandwidth" integer NOT NULL, "last_login" bigint NOT NULL, "filters" text NULL, "filesystem" text NULL,
"additional_info" text NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "email" varchar(255) NULL,
"upload_data_transfer" integer NOT NULL, "download_data_transfer" integer NOT NULL, "total_data_transfer" integer NOT NULL,
"used_upload_data_transfer" integer NOT NULL, "used_download_data_transfer" integer NOT NULL);
CREATE TABLE "{{groups_folders_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "group_id" integer NOT NULL,
"folder_id" integer NOT NULL, "virtual_path" text NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL);
CREATE TABLE "{{users_groups_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "user_id" integer NOT NULL,
"group_id" integer NOT NULL, "group_type" integer NOT NULL);
CREATE TABLE "{{users_folders_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "virtual_path" text NOT NULL,
"quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "folder_id" integer NOT NULL, "user_id" integer NOT NULL);
ALTER TABLE "{{users_folders_mapping}}" ADD CONSTRAINT "{{prefix}}unique_user_folder_mapping" UNIQUE ("user_id", "folder_id");
ALTER TABLE "{{users_folders_mapping}}" ADD CONSTRAINT "{{prefix}}users_folders_mapping_folder_id_fk_folders_id"
FOREIGN KEY ("folder_id") REFERENCES "{{folders}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE "{{users_folders_mapping}}" ADD CONSTRAINT "{{prefix}}users_folders_mapping_user_id_fk_users_id"
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
CREATE INDEX "{{prefix}}users_folders_mapping_folder_id_idx" ON "{{users_folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}users_folders_mapping_user_id_idx" ON "{{users_folders_mapping}}" ("user_id");
CREATE INDEX "{{prefix}}api_keys_admin_id_idx" ON "{{api_keys}}" ("admin_id");
CREATE INDEX "{{prefix}}api_keys_user_id_idx" ON "{{api_keys}}" ("user_id");
CREATE INDEX "{{prefix}}users_updated_at_idx" ON "{{users}}" ("updated_at");
CREATE INDEX "{{prefix}}shares_user_id_idx" ON "{{shares}}" ("user_id");
CREATE INDEX "{{prefix}}defender_hosts_updated_at_idx" ON "{{defender_hosts}}" ("updated_at");
CREATE INDEX "{{prefix}}defender_hosts_ban_time_idx" ON "{{defender_hosts}}" ("ban_time");
CREATE INDEX "{{prefix}}defender_events_date_time_idx" ON "{{defender_events}}" ("date_time");
CREATE INDEX "{{prefix}}defender_events_host_id_idx" ON "{{defender_events}}" ("host_id");
CREATE INDEX "{{prefix}}active_transfers_connection_id_idx" ON "{{active_transfers}}" ("connection_id");
CREATE INDEX "{{prefix}}active_transfers_transfer_id_idx" ON "{{active_transfers}}" ("transfer_id");
CREATE INDEX "{{prefix}}active_transfers_updated_at_idx" ON "{{active_transfers}}" ("updated_at");
CREATE INDEX "{{prefix}}shared_sessions_type_idx" ON "{{shared_sessions}}" ("type");
CREATE INDEX "{{prefix}}shared_sessions_timestamp_idx" ON "{{shared_sessions}}" ("timestamp");
INSERT INTO {{schema_version}} (version) VALUES (19);
`
	pgsqlV20SQL = `CREATE TABLE "{{events_rules}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "trigger" integer NOT NULL,
"conditions" text NOT NULL, "deleted_at" bigint NOT NULL);
CREATE TABLE "{{events_actions}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "type" integer NOT NULL, "options" text NOT NULL);
CREATE TABLE "{{rules_actions_mapping}}" ("id" serial NOT NULL PRIMARY KEY, "rule_id" integer NOT NULL,
"action_id" integer NOT NULL, "order" integer NOT NULL, "options" text NOT NULL);
CREATE TABLE "{{tasks}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE, "updated_at" bigint NOT NULL,
"version" bigint NOT NULL);
ALTER TABLE "{{rules_actions_mapping}}" ADD CONSTRAINT "{{prefix}}unique_rule_action_mapping" UNIQUE ("rule_id", "action_id");
ALTER TABLE "{{rules_actions_mapping}}" ADD CONSTRAINT "{{prefix}}rules_actions_mapping_rule_id_fk_events_rules_id"
FOREIGN KEY ("rule_id") REFERENCES "{{events_rules}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE "{{rules_actions_mapping}}" ADD CONSTRAINT "{{prefix}}rules_actions_mapping_action_id_fk_events_targets_id"
FOREIGN KEY ("action_id") REFERENCES "{{events_actions}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE "{{users}}" ADD COLUMN "deleted_at" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "deleted_at" DROP DEFAULT;
CREATE INDEX "{{prefix}}events_rules_updated_at_idx" ON "{{events_rules}}" ("updated_at");
CREATE INDEX "{{prefix}}events_rules_deleted_at_idx" ON "{{events_rules}}" ("deleted_at");
CREATE INDEX "{{prefix}}events_rules_trigger_idx" ON "{{events_rules}}" ("trigger");
CREATE INDEX "{{prefix}}rules_actions_mapping_rule_id_idx" ON "{{rules_actions_mapping}}" ("rule_id");
CREATE INDEX "{{prefix}}rules_actions_mapping_action_id_idx" ON "{{rules_actions_mapping}}" ("action_id");
CREATE INDEX "{{prefix}}rules_actions_mapping_order_idx" ON "{{rules_actions_mapping}}" ("order");
CREATE INDEX "{{prefix}}users_deleted_at_idx" ON "{{users}}" ("deleted_at");
`
	pgsqlV20DownSQL = `DROP TABLE "{{rules_actions_mapping}}" CASCADE;
DROP TABLE "{{events_rules}}" CASCADE;
DROP TABLE "{{events_actions}}" CASCADE;
DROP TABLE "{{tasks}}" CASCADE;
ALTER TABLE "{{users}}" DROP COLUMN "deleted_at" CASCADE;
`
	pgsqlV21SQL = `ALTER TABLE "{{users}}" ADD COLUMN "first_download" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "first_download" DROP DEFAULT;
ALTER TABLE "{{users}}" ADD COLUMN "first_upload" bigint DEFAULT 0 NOT NULL;
ALTER TABLE "{{users}}" ALTER COLUMN "first_upload" DROP DEFAULT;
`
	pgsqlV21DownSQL = `ALTER TABLE "{{users}}" DROP COLUMN "first_upload" CASCADE;
ALTER TABLE "{{users}}" DROP COLUMN "first_download" CASCADE;
`
	pgsqlV22SQL = `CREATE TABLE "{{admins_groups_mapping}}" ("id" serial NOT NULL PRIMARY KEY,
"admin_id" integer NOT NULL, "group_id" integer NOT NULL, "options" text NOT NULL);
ALTER TABLE "{{admins_groups_mapping}}" ADD CONSTRAINT "{{prefix}}unique_admin_group_mapping" UNIQUE ("admin_id", "group_id");
ALTER TABLE "{{admins_groups_mapping}}" ADD CONSTRAINT "{{prefix}}admins_groups_mapping_admin_id_fk_admins_id"
FOREIGN KEY ("admin_id") REFERENCES "{{admins}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE "{{admins_groups_mapping}}" ADD CONSTRAINT "{{prefix}}admins_groups_mapping_group_id_fk_groups_id"
FOREIGN KEY ("group_id") REFERENCES "{{groups}}" ("id") MATCH SIMPLE ON UPDATE NO ACTION ON DELETE CASCADE;
CREATE INDEX "{{prefix}}admins_groups_mapping_admin_id_idx" ON "{{admins_groups_mapping}}" ("admin_id");
CREATE INDEX "{{prefix}}admins_groups_mapping_group_id_idx" ON "{{admins_groups_mapping}}" ("group_id");
`
	pgsqlV22DownSQL = `ALTER TABLE "{{admins_groups_mapping}}" DROP CONSTRAINT "{{prefix}}unique_admin_group_mapping";
DROP TABLE "{{admins_groups_mapping}}" CASCADE;
`
	pgsqlV23SQL = `CREATE TABLE "{{nodes}}" ("id" serial NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"data" text NOT NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL);`
	pgsqlV23DownSQL = `DROP TABLE "{{nodes}}" CASCADE;`
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
		if config.DisableSNI {
			connectionString += " sslsni=0"
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

func (p *PGSQLProvider) deleteUser(user User, softDelete bool) error {
	return sqlCommonDeleteUser(user, softDelete, p.dbHandle)
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

func (p *PGSQLProvider) getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	return sqlCommonGetEventActions(limit, offset, order, minimal, p.dbHandle)
}

func (p *PGSQLProvider) dumpEventActions() ([]BaseEventAction, error) {
	return sqlCommonDumpEventActions(p.dbHandle)
}

func (p *PGSQLProvider) eventActionExists(name string) (BaseEventAction, error) {
	return sqlCommonGetEventActionByName(name, p.dbHandle)
}

func (p *PGSQLProvider) addEventAction(action *BaseEventAction) error {
	return sqlCommonAddEventAction(action, p.dbHandle)
}

func (p *PGSQLProvider) updateEventAction(action *BaseEventAction) error {
	return sqlCommonUpdateEventAction(action, p.dbHandle)
}

func (p *PGSQLProvider) deleteEventAction(action BaseEventAction) error {
	return sqlCommonDeleteEventAction(action, p.dbHandle)
}

func (p *PGSQLProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	return sqlCommonGetEventRules(limit, offset, order, p.dbHandle)
}

func (p *PGSQLProvider) dumpEventRules() ([]EventRule, error) {
	return sqlCommonDumpEventRules(p.dbHandle)
}

func (p *PGSQLProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	return sqlCommonGetRecentlyUpdatedRules(after, p.dbHandle)
}

func (p *PGSQLProvider) eventRuleExists(name string) (EventRule, error) {
	return sqlCommonGetEventRuleByName(name, p.dbHandle)
}

func (p *PGSQLProvider) addEventRule(rule *EventRule) error {
	return sqlCommonAddEventRule(rule, p.dbHandle)
}

func (p *PGSQLProvider) updateEventRule(rule *EventRule) error {
	return sqlCommonUpdateEventRule(rule, p.dbHandle)
}

func (p *PGSQLProvider) deleteEventRule(rule EventRule, softDelete bool) error {
	return sqlCommonDeleteEventRule(rule, softDelete, p.dbHandle)
}

func (p *PGSQLProvider) getTaskByName(name string) (Task, error) {
	return sqlCommonGetTaskByName(name, p.dbHandle)
}

func (p *PGSQLProvider) addTask(name string) error {
	return sqlCommonAddTask(name, p.dbHandle)
}

func (p *PGSQLProvider) updateTask(name string, version int64) error {
	return sqlCommonUpdateTask(name, version, p.dbHandle)
}

func (p *PGSQLProvider) updateTaskTimestamp(name string) error {
	return sqlCommonUpdateTaskTimestamp(name, p.dbHandle)
}

func (p *PGSQLProvider) addNode() error {
	return sqlCommonAddNode(p.dbHandle)
}

func (p *PGSQLProvider) getNodeByName(name string) (Node, error) {
	return sqlCommonGetNodeByName(name, p.dbHandle)
}

func (p *PGSQLProvider) getNodes() ([]Node, error) {
	return sqlCommonGetNodes(p.dbHandle)
}

func (p *PGSQLProvider) updateNodeTimestamp() error {
	return sqlCommonUpdateNodeTimestamp(p.dbHandle)
}

func (p *PGSQLProvider) cleanupNodes() error {
	return sqlCommonCleanupNodes(p.dbHandle)
}

func (p *PGSQLProvider) setFirstDownloadTimestamp(username string) error {
	return sqlCommonSetFirstDownloadTimestamp(username, p.dbHandle)
}

func (p *PGSQLProvider) setFirstUploadTimestamp(username string) error {
	return sqlCommonSetFirstUploadTimestamp(username, p.dbHandle)
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
	logger.InfoToConsole("creating initial database schema, version 19")
	providerLog(logger.LevelInfo, "creating initial database schema, version 19")
	initialSQL := sqlReplaceAll(pgsqlInitial)

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{initialSQL}, 19, true)
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
	case version < 19:
		err = fmt.Errorf("database schema version %v is too old, please see the upgrading docs", version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 19:
		return updatePgSQLDatabaseFromV19(p.dbHandle)
	case version == 20:
		return updatePgSQLDatabaseFromV20(p.dbHandle)
	case version == 21:
		return updatePgSQLDatabaseFromV21(p.dbHandle)
	case version == 22:
		return updatePgSQLDatabaseFromV21(p.dbHandle)
	default:
		if version > sqlDatabaseVersion {
			providerLog(logger.LevelError, "database schema version %v is newer than the supported one: %v", version,
				sqlDatabaseVersion)
			logger.WarnToConsole("database schema version %v is newer than the supported one: %v", version,
				sqlDatabaseVersion)
			return nil
		}
		return fmt.Errorf("database schema version not handled: %v", version)
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
	case 20:
		return downgradePgSQLDatabaseFromV20(p.dbHandle)
	case 21:
		return downgradePgSQLDatabaseFromV21(p.dbHandle)
	case 22:
		return downgradePgSQLDatabaseFromV22(p.dbHandle)
	case 23:
		return downgradePgSQLDatabaseFromV23(p.dbHandle)
	default:
		return fmt.Errorf("database schema version not handled: %v", dbVersion.Version)
	}
}

func (p *PGSQLProvider) resetDatabase() error {
	sql := sqlReplaceAll(pgsqlResetSQL)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{sql}, 0, false)
}

func updatePgSQLDatabaseFromV19(dbHandle *sql.DB) error {
	if err := updatePgSQLDatabaseFrom19To20(dbHandle); err != nil {
		return err
	}
	return updatePgSQLDatabaseFromV20(dbHandle)
}

func updatePgSQLDatabaseFromV20(dbHandle *sql.DB) error {
	if err := updatePgSQLDatabaseFrom20To21(dbHandle); err != nil {
		return err
	}
	return updatePgSQLDatabaseFromV21(dbHandle)
}

func updatePgSQLDatabaseFromV21(dbHandle *sql.DB) error {
	if err := updatePgSQLDatabaseFrom21To22(dbHandle); err != nil {
		return err
	}
	return updatePgSQLDatabaseFromV22(dbHandle)
}

func updatePgSQLDatabaseFromV22(dbHandle *sql.DB) error {
	return updatePgSQLDatabaseFrom22To23(dbHandle)
}

func downgradePgSQLDatabaseFromV20(dbHandle *sql.DB) error {
	return downgradePgSQLDatabaseFrom20To19(dbHandle)
}

func downgradePgSQLDatabaseFromV21(dbHandle *sql.DB) error {
	if err := downgradePgSQLDatabaseFrom21To20(dbHandle); err != nil {
		return err
	}
	return downgradePgSQLDatabaseFromV20(dbHandle)
}

func downgradePgSQLDatabaseFromV22(dbHandle *sql.DB) error {
	if err := downgradePgSQLDatabaseFrom22To21(dbHandle); err != nil {
		return err
	}
	return downgradePgSQLDatabaseFromV21(dbHandle)
}

func downgradePgSQLDatabaseFromV23(dbHandle *sql.DB) error {
	if err := downgradePgSQLDatabaseFrom23To22(dbHandle); err != nil {
		return err
	}
	return downgradePgSQLDatabaseFromV22(dbHandle)
}

func updatePgSQLDatabaseFrom19To20(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 19 -> 20")
	providerLog(logger.LevelInfo, "updating database schema version: 19 -> 20")
	sql := strings.ReplaceAll(pgsqlV20SQL, "{{events_actions}}", sqlTableEventsActions)
	sql = strings.ReplaceAll(sql, "{{events_rules}}", sqlTableEventsRules)
	sql = strings.ReplaceAll(sql, "{{rules_actions_mapping}}", sqlTableRulesActionsMapping)
	sql = strings.ReplaceAll(sql, "{{tasks}}", sqlTableTasks)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 20, true)
}

func updatePgSQLDatabaseFrom20To21(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 20 -> 21")
	providerLog(logger.LevelInfo, "updating database schema version: 20 -> 21")
	sql := strings.ReplaceAll(pgsqlV21SQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 21, true)
}

func updatePgSQLDatabaseFrom21To22(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 21 -> 22")
	providerLog(logger.LevelInfo, "updating database schema version: 21 -> 22")
	sql := strings.ReplaceAll(pgsqlV22SQL, "{{admins_groups_mapping}}", sqlTableAdminsGroupsMapping)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{groups}}", sqlTableGroups)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 22, true)
}

func updatePgSQLDatabaseFrom22To23(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 22 -> 23")
	providerLog(logger.LevelInfo, "updating database schema version: 22 -> 23")
	sql := strings.ReplaceAll(pgsqlV23SQL, "{{nodes}}", sqlTableNodes)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 23, true)
}

func downgradePgSQLDatabaseFrom20To19(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 20 -> 19")
	providerLog(logger.LevelInfo, "downgrading database schema version: 20 -> 19")
	sql := strings.ReplaceAll(pgsqlV20DownSQL, "{{events_actions}}", sqlTableEventsActions)
	sql = strings.ReplaceAll(sql, "{{events_rules}}", sqlTableEventsRules)
	sql = strings.ReplaceAll(sql, "{{rules_actions_mapping}}", sqlTableRulesActionsMapping)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{tasks}}", sqlTableTasks)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 19, false)
}

func downgradePgSQLDatabaseFrom21To20(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 21 -> 20")
	providerLog(logger.LevelInfo, "downgrading database schema version: 21 -> 20")
	sql := strings.ReplaceAll(pgsqlV21DownSQL, "{{users}}", sqlTableUsers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 20, false)
}

func downgradePgSQLDatabaseFrom22To21(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 22 -> 21")
	providerLog(logger.LevelInfo, "downgrading database schema version: 22 -> 21")
	sql := strings.ReplaceAll(pgsqlV22DownSQL, "{{admins_groups_mapping}}", sqlTableAdminsGroupsMapping)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 21, false)
}

func downgradePgSQLDatabaseFrom23To22(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 23 -> 22")
	providerLog(logger.LevelInfo, "downgrading database schema version: 23 -> 22")
	sql := strings.ReplaceAll(pgsqlV23DownSQL, "{{nodes}}", sqlTableNodes)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 22, false)
}
