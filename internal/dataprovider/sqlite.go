// Copyright (C) 2019 Nicola Murino
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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build !nosqlite && cgo
// +build !nosqlite,cgo

package dataprovider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	sqliteResetSQL = `DROP TABLE IF EXISTS "{{api_keys}}";
DROP TABLE IF EXISTS "{{folders_mapping}}";
DROP TABLE IF EXISTS "{{users_folders_mapping}}";
DROP TABLE IF EXISTS "{{users_groups_mapping}}";
DROP TABLE IF EXISTS "{{admins_groups_mapping}}";
DROP TABLE IF EXISTS "{{groups_folders_mapping}}";
DROP TABLE IF EXISTS "{{admins}}";
DROP TABLE IF EXISTS "{{folders}}";
DROP TABLE IF EXISTS "{{shares}}";
DROP TABLE IF EXISTS "{{users}}";
DROP TABLE IF EXISTS "{{groups}}";
DROP TABLE IF EXISTS "{{defender_events}}";
DROP TABLE IF EXISTS "{{defender_hosts}}";
DROP TABLE IF EXISTS "{{active_transfers}}";
DROP TABLE IF EXISTS "{{shared_sessions}}";
DROP TABLE IF EXISTS "{{rules_actions_mapping}}";
DROP TABLE IF EXISTS "{{events_rules}}";
DROP TABLE IF EXISTS "{{events_actions}}";
DROP TABLE IF EXISTS "{{tasks}}";
DROP TABLE IF EXISTS "{{roles}}";
DROP TABLE IF EXISTS "{{ip_lists}}";
DROP TABLE IF EXISTS "{{configs}}";
DROP TABLE IF EXISTS "{{schema_version}}";
`
	sqliteInitialSQL = `CREATE TABLE "{{schema_version}}" ("id" integer NOT NULL PRIMARY KEY, "version" integer NOT NULL);
CREATE TABLE "{{roles}}" ("id" integer NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL);
CREATE TABLE "{{admins}}" ("id" integer NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "password" varchar(255) NOT NULL, "email" varchar(255) NULL, "status" integer NOT NULL,
"permissions" text NOT NULL, "filters" text NULL, "additional_info" text NULL, "last_login" bigint NOT NULL,
"role_id" integer NULL REFERENCES "{{roles}}" ("id") ON DELETE NO ACTION, "created_at" bigint NOT NULL,
"updated_at" bigint NOT NULL);
CREATE TABLE "{{active_transfers}}" ("id" integer NOT NULL PRIMARY KEY, "connection_id" varchar(100) NOT NULL,
"transfer_id" bigint NOT NULL, "transfer_type" integer NOT NULL, "username" varchar(255) NOT NULL,
"folder_name" varchar(255) NULL, "ip" varchar(50) NOT NULL, "truncated_size" bigint NOT NULL,
"current_ul_size" bigint NOT NULL, "current_dl_size" bigint NOT NULL, "created_at" bigint NOT NULL,
"updated_at" bigint NOT NULL);
CREATE TABLE "{{defender_hosts}}" ("id" integer NOT NULL PRIMARY KEY, "ip" varchar(50) NOT NULL UNIQUE,
"ban_time" bigint NOT NULL, "updated_at" bigint NOT NULL);
CREATE TABLE "{{defender_events}}" ("id" integer NOT NULL PRIMARY KEY, "date_time" bigint NOT NULL,
"score" integer NOT NULL, "host_id" integer NOT NULL REFERENCES "{{defender_hosts}}" ("id") ON DELETE CASCADE
DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE "{{folders}}" ("id" integer NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "path" text NULL, "used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL,
"last_quota_update" bigint NOT NULL, "filesystem" text NULL);
CREATE TABLE "{{groups}}" ("id" integer NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "user_settings" text NULL);
CREATE TABLE "{{shared_sessions}}" ("key" varchar(128) NOT NULL PRIMARY KEY, "data" text NOT NULL,
"type" integer NOT NULL, "timestamp" bigint NOT NULL);
CREATE TABLE "{{users}}" ("id" integer NOT NULL PRIMARY KEY, "username" varchar(255) NOT NULL UNIQUE,
"status" integer NOT NULL, "expiration_date" bigint NOT NULL, "description" varchar(512) NULL, "password" text NULL,
"public_keys" text NULL, "home_dir" text NOT NULL, "uid" bigint NOT NULL, "gid" bigint NOT NULL,
"max_sessions" integer NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL, "permissions" text NOT NULL,
"used_quota_size" bigint NOT NULL, "used_quota_files" integer NOT NULL, "last_quota_update" bigint NOT NULL,
"upload_bandwidth" integer NOT NULL, "download_bandwidth" integer NOT NULL, "last_login" bigint NOT NULL,
"filters" text NULL, "filesystem" text NULL, "additional_info" text NULL, "created_at" bigint NOT NULL,
"updated_at" bigint NOT NULL, "email" varchar(255) NULL, "upload_data_transfer" integer NOT NULL,
"download_data_transfer" integer NOT NULL, "total_data_transfer" integer NOT NULL, "used_upload_data_transfer" bigint NOT NULL,
"used_download_data_transfer" bigint NOT NULL, "deleted_at" bigint NOT NULL, "first_download" bigint NOT NULL,
"first_upload" bigint NOT NULL, "last_password_change" bigint NOT NULL, "role_id" integer NULL REFERENCES "{{roles}}" ("id") ON DELETE SET NULL);
CREATE TABLE "{{groups_folders_mapping}}" ("id" integer NOT NULL PRIMARY KEY,
"folder_id" integer NOT NULL REFERENCES "{{folders}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"group_id" integer NOT NULL REFERENCES "{{groups}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"virtual_path" text NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL,
CONSTRAINT "{{prefix}}unique_group_folder_mapping" UNIQUE ("group_id", "folder_id"));
CREATE TABLE "{{users_groups_mapping}}" ("id" integer NOT NULL PRIMARY KEY,
"user_id" integer NOT NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"group_id" integer NOT NULL REFERENCES "{{groups}}" ("id") ON DELETE NO ACTION,
"group_type" integer NOT NULL, CONSTRAINT "{{prefix}}unique_user_group_mapping" UNIQUE ("user_id", "group_id"));
CREATE TABLE "{{users_folders_mapping}}" ("id" integer NOT NULL PRIMARY KEY,
"user_id" integer NOT NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"folder_id" integer NOT NULL REFERENCES "{{folders}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"virtual_path" text NOT NULL, "quota_size" bigint NOT NULL, "quota_files" integer NOT NULL,
CONSTRAINT "{{prefix}}unique_user_folder_mapping" UNIQUE ("user_id", "folder_id"));
CREATE TABLE "{{shares}}" ("id" integer NOT NULL PRIMARY KEY, "share_id" varchar(60) NOT NULL UNIQUE,
"name" varchar(255) NOT NULL, "description" varchar(512) NULL, "scope" integer NOT NULL, "paths" text NOT NULL,
"created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "last_use_at" bigint NOT NULL, "expires_at" bigint NOT NULL,
"password" text NULL, "max_tokens" integer NOT NULL, "used_tokens" integer NOT NULL, "allow_from" text NULL,
"user_id" integer NOT NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE "{{api_keys}}" ("id" integer NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL,
"key_id" varchar(50) NOT NULL UNIQUE, "api_key" varchar(255) NOT NULL UNIQUE, "scope" integer NOT NULL,
"created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "last_use_at" bigint NOT NULL, "expires_at" bigint NOT NULL,
"description" text NULL, "admin_id" integer NULL REFERENCES "{{admins}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"user_id" integer NULL REFERENCES "{{users}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE "{{events_rules}}" ("id" integer NOT NULL PRIMARY KEY,
"name" varchar(255) NOT NULL UNIQUE, "status" integer NOT NULL, "description" varchar(512) NULL, "created_at" bigint NOT NULL,
"updated_at" bigint NOT NULL, "trigger" integer NOT NULL, "conditions" text NOT NULL, "deleted_at" bigint NOT NULL);
CREATE TABLE "{{events_actions}}" ("id" integer NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"description" varchar(512) NULL, "type" integer NOT NULL, "options" text NOT NULL);
CREATE TABLE "{{rules_actions_mapping}}" ("id" integer NOT NULL PRIMARY KEY,
"rule_id" integer NOT NULL REFERENCES "{{events_rules}}" ("id")  ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"action_id" integer NOT NULL REFERENCES "{{events_actions}}" ("id")  ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
"order" integer NOT NULL, "options" text NOT NULL,
CONSTRAINT "{{prefix}}unique_rule_action_mapping" UNIQUE ("rule_id", "action_id"));
CREATE TABLE "{{tasks}}" ("id" integer NOT NULL PRIMARY KEY, "name" varchar(255) NOT NULL UNIQUE,
"updated_at" bigint NOT NULL, "version" bigint NOT NULL);
CREATE TABLE "{{admins_groups_mapping}}" ("id" integer NOT NULL PRIMARY KEY,
"admin_id" integer NOT NULL REFERENCES "{{admins}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"group_id" integer NOT NULL REFERENCES "{{groups}}" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
"options" text NOT NULL, CONSTRAINT "{{prefix}}unique_admin_group_mapping" UNIQUE ("admin_id", "group_id"));
CREATE TABLE "{{ip_lists}}" ("id" integer NOT NULL PRIMARY KEY,
"type" integer NOT NULL, "ipornet" varchar(50) NOT NULL, "mode" integer NOT NULL, "description" varchar(512) NULL,
"first" BLOB NOT NULL, "last" BLOB NOT NULL, "ip_type" integer NOT NULL, "protocols" integer NOT NULL,
"created_at" bigint NOT NULL, "updated_at" bigint NOT NULL, "deleted_at" bigint NOT NULL,
CONSTRAINT "{{prefix}}unique_ipornet_type_mapping" UNIQUE ("type", "ipornet"));
CREATE TABLE "{{configs}}" ("id" integer NOT NULL PRIMARY KEY, "configs" text NOT NULL);
INSERT INTO {{configs}} (configs) VALUES ('{}');
CREATE INDEX "{{prefix}}users_folders_mapping_folder_id_idx" ON "{{users_folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}users_folders_mapping_user_id_idx" ON "{{users_folders_mapping}}" ("user_id");
CREATE INDEX "{{prefix}}users_groups_mapping_group_id_idx" ON "{{users_groups_mapping}}" ("group_id");
CREATE INDEX "{{prefix}}users_groups_mapping_user_id_idx" ON "{{users_groups_mapping}}" ("user_id");
CREATE INDEX "{{prefix}}groups_folders_mapping_folder_id_idx" ON "{{groups_folders_mapping}}" ("folder_id");
CREATE INDEX "{{prefix}}groups_folders_mapping_group_id_idx" ON "{{groups_folders_mapping}}" ("group_id");
CREATE INDEX "{{prefix}}api_keys_admin_id_idx" ON "{{api_keys}}" ("admin_id");
CREATE INDEX "{{prefix}}api_keys_user_id_idx" ON "{{api_keys}}" ("user_id");
CREATE INDEX "{{prefix}}users_updated_at_idx" ON "{{users}}" ("updated_at");
CREATE INDEX "{{prefix}}users_deleted_at_idx" ON "{{users}}" ("deleted_at");
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
CREATE INDEX "{{prefix}}events_rules_updated_at_idx" ON "{{events_rules}}" ("updated_at");
CREATE INDEX "{{prefix}}events_rules_deleted_at_idx" ON "{{events_rules}}" ("deleted_at");
CREATE INDEX "{{prefix}}events_rules_trigger_idx" ON "{{events_rules}}" ("trigger");
CREATE INDEX "{{prefix}}rules_actions_mapping_rule_id_idx" ON "{{rules_actions_mapping}}" ("rule_id");
CREATE INDEX "{{prefix}}rules_actions_mapping_action_id_idx" ON "{{rules_actions_mapping}}" ("action_id");
CREATE INDEX "{{prefix}}rules_actions_mapping_order_idx" ON "{{rules_actions_mapping}}" ("order");
CREATE INDEX "{{prefix}}admins_groups_mapping_admin_id_idx" ON "{{admins_groups_mapping}}" ("admin_id");
CREATE INDEX "{{prefix}}admins_groups_mapping_group_id_idx" ON "{{admins_groups_mapping}}" ("group_id");
CREATE INDEX "{{prefix}}users_role_id_idx" ON "{{users}}" ("role_id");
CREATE INDEX "{{prefix}}admins_role_id_idx" ON "{{admins}}" ("role_id");
CREATE INDEX "{{prefix}}ip_lists_type_idx" ON "{{ip_lists}}" ("type");
CREATE INDEX "{{prefix}}ip_lists_ipornet_idx" ON "{{ip_lists}}" ("ipornet");
CREATE INDEX "{{prefix}}ip_lists_ip_type_idx" ON "{{ip_lists}}" ("ip_type");
CREATE INDEX "{{prefix}}ip_lists_ip_updated_at_idx" ON "{{ip_lists}}" ("updated_at");
CREATE INDEX "{{prefix}}ip_lists_ip_deleted_at_idx" ON "{{ip_lists}}" ("deleted_at");
CREATE INDEX "{{prefix}}ip_lists_first_last_idx" ON "{{ip_lists}}" ("first", "last");
INSERT INTO {{schema_version}} (version) VALUES (29);
`
	sqliteV30SQL     = `ALTER TABLE "{{shares}}" ADD COLUMN "options" text NULL;`
	sqliteV30DownSQL = `ALTER TABLE "{{shares}}" DROP COLUMN "options";`
	sqliteV31SQL     = `DROP TABLE "{{shared_sessions}}";
CREATE TABLE "{{shared_sessions}}" ("key" varchar(128) NOT NULL, "type" integer NOT NULL,
"data" text NOT NULL, "timestamp" bigint NOT NULL, PRIMARY KEY ("key", "type"));
CREATE INDEX "{{prefix}}shared_sessions_type_idx" ON "{{shared_sessions}}" ("type");
CREATE INDEX "{{prefix}}shared_sessions_timestamp_idx" ON "{{shared_sessions}}" ("timestamp");
`
	sqliteV31DownSQL = `DROP TABLE "{{shared_sessions}}";
CREATE TABLE "{{shared_sessions}}" ("key" varchar(128) NOT NULL PRIMARY KEY, "data" text NOT NULL,
"type" integer NOT NULL, "timestamp" bigint NOT NULL);
CREATE INDEX "{{prefix}}shared_sessions_type_idx" ON "{{shared_sessions}}" ("type");
CREATE INDEX "{{prefix}}shared_sessions_timestamp_idx" ON "{{shared_sessions}}" ("timestamp");
`
)

// SQLiteProvider defines the auth provider for SQLite database
type SQLiteProvider struct {
	dbHandle *sql.DB
}

func init() {
	version.AddFeature("+sqlite")
}

func initializeSQLiteProvider(basePath string) error {
	var connectionString string

	if config.ConnectionString == "" {
		dbPath := config.Name
		if !util.IsFileInputValid(dbPath) {
			return fmt.Errorf("invalid database path: %q", dbPath)
		}
		if !filepath.IsAbs(dbPath) {
			dbPath = filepath.Join(basePath, dbPath)
		}
		connectionString = fmt.Sprintf("file:%s?cache=shared&_foreign_keys=1", dbPath)
	} else {
		connectionString = config.ConnectionString
	}
	dbHandle, err := sql.Open("sqlite3", connectionString)
	if err != nil {
		providerLog(logger.LevelError, "error creating sqlite database handler, connection string: %q, error: %v",
			connectionString, err)
		return err
	}
	providerLog(logger.LevelDebug, "sqlite database handle created, connection string: %q", connectionString)
	dbHandle.SetMaxOpenConns(1)
	provider = &SQLiteProvider{dbHandle: dbHandle}
	return executePragmaOptimize(dbHandle)
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

func (p *SQLiteProvider) validateUserAndPubKey(username string, publicKey []byte, isSSHCert bool) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, isSSHCert, p.dbHandle)
}

func (p *SQLiteProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	return sqlCommonUpdateTransferQuota(username, uploadSize, downloadSize, reset, p.dbHandle)
}

func (p *SQLiteProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *SQLiteProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p *SQLiteProvider) getAdminSignature(username string) (string, error) {
	return sqlCommonGetAdminSignature(username, p.dbHandle)
}

func (p *SQLiteProvider) getUserSignature(username string) (string, error) {
	return sqlCommonGetUserSignature(username, p.dbHandle)
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

func (p *SQLiteProvider) userExists(username, role string) (User, error) {
	return sqlCommonGetUserByUsername(username, role, p.dbHandle)
}

func (p *SQLiteProvider) addUser(user *User) error {
	return p.normalizeError(sqlCommonAddUser(user, p.dbHandle), fieldUsername)
}

func (p *SQLiteProvider) updateUser(user *User) error {
	return p.normalizeError(sqlCommonUpdateUser(user, p.dbHandle), -1)
}

func (p *SQLiteProvider) deleteUser(user User, softDelete bool) error {
	return sqlCommonDeleteUser(user, softDelete, p.dbHandle)
}

func (p *SQLiteProvider) updateUserPassword(username, password string) error {
	return sqlCommonUpdateUserPassword(username, password, p.dbHandle)
}

func (p *SQLiteProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p *SQLiteProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return sqlCommonGetRecentlyUpdatedUsers(after, p.dbHandle)
}

func (p *SQLiteProvider) getUsers(limit int, offset int, order, role string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, role, p.dbHandle)
}

func (p *SQLiteProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return sqlCommonGetUsersForQuotaCheck(toFetch, p.dbHandle)
}

func (p *SQLiteProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p *SQLiteProvider) getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, minimal, p.dbHandle)
}

func (p *SQLiteProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonGetFolderByName(ctx, name, p.dbHandle)
}

func (p *SQLiteProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	return p.normalizeError(sqlCommonAddFolder(folder, p.dbHandle), fieldName)
}

func (p *SQLiteProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonUpdateFolder(folder, p.dbHandle)
}

func (p *SQLiteProvider) deleteFolder(folder vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p *SQLiteProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *SQLiteProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, p.dbHandle)
}

func (p *SQLiteProvider) getGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	return sqlCommonGetGroups(limit, offset, order, minimal, p.dbHandle)
}

func (p *SQLiteProvider) getGroupsWithNames(names []string) ([]Group, error) {
	return sqlCommonGetGroupsWithNames(names, p.dbHandle)
}

func (p *SQLiteProvider) getUsersInGroups(names []string) ([]string, error) {
	return sqlCommonGetUsersInGroups(names, p.dbHandle)
}

func (p *SQLiteProvider) groupExists(name string) (Group, error) {
	return sqlCommonGetGroupByName(name, p.dbHandle)
}

func (p *SQLiteProvider) addGroup(group *Group) error {
	return p.normalizeError(sqlCommonAddGroup(group, p.dbHandle), fieldName)
}

func (p *SQLiteProvider) updateGroup(group *Group) error {
	return sqlCommonUpdateGroup(group, p.dbHandle)
}

func (p *SQLiteProvider) deleteGroup(group Group) error {
	return sqlCommonDeleteGroup(group, p.dbHandle)
}

func (p *SQLiteProvider) dumpGroups() ([]Group, error) {
	return sqlCommonDumpGroups(p.dbHandle)
}

func (p *SQLiteProvider) adminExists(username string) (Admin, error) {
	return sqlCommonGetAdminByUsername(username, p.dbHandle)
}

func (p *SQLiteProvider) addAdmin(admin *Admin) error {
	return p.normalizeError(sqlCommonAddAdmin(admin, p.dbHandle), fieldUsername)
}

func (p *SQLiteProvider) updateAdmin(admin *Admin) error {
	return p.normalizeError(sqlCommonUpdateAdmin(admin, p.dbHandle), -1)
}

func (p *SQLiteProvider) deleteAdmin(admin Admin) error {
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
	return p.normalizeError(sqlCommonAddAPIKey(apiKey, p.dbHandle), -1)
}

func (p *SQLiteProvider) updateAPIKey(apiKey *APIKey) error {
	return p.normalizeError(sqlCommonUpdateAPIKey(apiKey, p.dbHandle), -1)
}

func (p *SQLiteProvider) deleteAPIKey(apiKey APIKey) error {
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
	return p.normalizeError(sqlCommonAddShare(share, p.dbHandle), fieldName)
}

func (p *SQLiteProvider) updateShare(share *Share) error {
	return p.normalizeError(sqlCommonUpdateShare(share, p.dbHandle), -1)
}

func (p *SQLiteProvider) deleteShare(share Share) error {
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

func (p *SQLiteProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return sqlCommonGetDefenderHosts(from, limit, p.dbHandle)
}

func (p *SQLiteProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return sqlCommonGetDefenderHostByIP(ip, from, p.dbHandle)
}

func (p *SQLiteProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
	return sqlCommonIsDefenderHostBanned(ip, p.dbHandle)
}

func (p *SQLiteProvider) updateDefenderBanTime(ip string, minutes int) error {
	return sqlCommonDefenderIncrementBanTime(ip, minutes, p.dbHandle)
}

func (p *SQLiteProvider) deleteDefenderHost(ip string) error {
	return sqlCommonDeleteDefenderHost(ip, p.dbHandle)
}

func (p *SQLiteProvider) addDefenderEvent(ip string, score int) error {
	return sqlCommonAddDefenderHostAndEvent(ip, score, p.dbHandle)
}

func (p *SQLiteProvider) setDefenderBanTime(ip string, banTime int64) error {
	return sqlCommonSetDefenderBanTime(ip, banTime, p.dbHandle)
}

func (p *SQLiteProvider) cleanupDefender(from int64) error {
	return sqlCommonDefenderCleanup(from, p.dbHandle)
}

func (p *SQLiteProvider) addActiveTransfer(transfer ActiveTransfer) error {
	return sqlCommonAddActiveTransfer(transfer, p.dbHandle)
}

func (p *SQLiteProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
	return sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID, connectionID, p.dbHandle)
}

func (p *SQLiteProvider) removeActiveTransfer(transferID int64, connectionID string) error {
	return sqlCommonRemoveActiveTransfer(transferID, connectionID, p.dbHandle)
}

func (p *SQLiteProvider) cleanupActiveTransfers(before time.Time) error {
	return sqlCommonCleanupActiveTransfers(before, p.dbHandle)
}

func (p *SQLiteProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return sqlCommonGetActiveTransfers(from, p.dbHandle)
}

func (p *SQLiteProvider) addSharedSession(session Session) error {
	return sqlCommonAddSession(session, p.dbHandle)
}

func (p *SQLiteProvider) deleteSharedSession(key string, sessionType SessionType) error {
	return sqlCommonDeleteSession(key, sessionType, p.dbHandle)
}

func (p *SQLiteProvider) getSharedSession(key string, sessionType SessionType) (Session, error) {
	return sqlCommonGetSession(key, sessionType, p.dbHandle)
}

func (p *SQLiteProvider) cleanupSharedSessions(sessionType SessionType, before int64) error {
	return sqlCommonCleanupSessions(sessionType, before, p.dbHandle)
}

func (p *SQLiteProvider) getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	return sqlCommonGetEventActions(limit, offset, order, minimal, p.dbHandle)
}

func (p *SQLiteProvider) dumpEventActions() ([]BaseEventAction, error) {
	return sqlCommonDumpEventActions(p.dbHandle)
}

func (p *SQLiteProvider) eventActionExists(name string) (BaseEventAction, error) {
	return sqlCommonGetEventActionByName(name, p.dbHandle)
}

func (p *SQLiteProvider) addEventAction(action *BaseEventAction) error {
	return p.normalizeError(sqlCommonAddEventAction(action, p.dbHandle), fieldName)
}

func (p *SQLiteProvider) updateEventAction(action *BaseEventAction) error {
	return sqlCommonUpdateEventAction(action, p.dbHandle)
}

func (p *SQLiteProvider) deleteEventAction(action BaseEventAction) error {
	return sqlCommonDeleteEventAction(action, p.dbHandle)
}

func (p *SQLiteProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	return sqlCommonGetEventRules(limit, offset, order, p.dbHandle)
}

func (p *SQLiteProvider) dumpEventRules() ([]EventRule, error) {
	return sqlCommonDumpEventRules(p.dbHandle)
}

func (p *SQLiteProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	return sqlCommonGetRecentlyUpdatedRules(after, p.dbHandle)
}

func (p *SQLiteProvider) eventRuleExists(name string) (EventRule, error) {
	return sqlCommonGetEventRuleByName(name, p.dbHandle)
}

func (p *SQLiteProvider) addEventRule(rule *EventRule) error {
	return p.normalizeError(sqlCommonAddEventRule(rule, p.dbHandle), fieldName)
}

func (p *SQLiteProvider) updateEventRule(rule *EventRule) error {
	return sqlCommonUpdateEventRule(rule, p.dbHandle)
}

func (p *SQLiteProvider) deleteEventRule(rule EventRule, softDelete bool) error {
	return sqlCommonDeleteEventRule(rule, softDelete, p.dbHandle)
}

func (p *SQLiteProvider) getTaskByName(name string) (Task, error) {
	return sqlCommonGetTaskByName(name, p.dbHandle)
}

func (p *SQLiteProvider) addTask(name string) error {
	return sqlCommonAddTask(name, p.dbHandle)
}

func (p *SQLiteProvider) updateTask(name string, version int64) error {
	return sqlCommonUpdateTask(name, version, p.dbHandle)
}

func (p *SQLiteProvider) updateTaskTimestamp(name string) error {
	return sqlCommonUpdateTaskTimestamp(name, p.dbHandle)
}

func (*SQLiteProvider) addNode() error {
	return ErrNotImplemented
}

func (*SQLiteProvider) getNodeByName(_ string) (Node, error) {
	return Node{}, ErrNotImplemented
}

func (*SQLiteProvider) getNodes() ([]Node, error) {
	return nil, ErrNotImplemented
}

func (*SQLiteProvider) updateNodeTimestamp() error {
	return ErrNotImplemented
}

func (*SQLiteProvider) cleanupNodes() error {
	return ErrNotImplemented
}

func (p *SQLiteProvider) roleExists(name string) (Role, error) {
	return sqlCommonGetRoleByName(name, p.dbHandle)
}

func (p *SQLiteProvider) addRole(role *Role) error {
	return p.normalizeError(sqlCommonAddRole(role, p.dbHandle), fieldName)
}

func (p *SQLiteProvider) updateRole(role *Role) error {
	return sqlCommonUpdateRole(role, p.dbHandle)
}

func (p *SQLiteProvider) deleteRole(role Role) error {
	return sqlCommonDeleteRole(role, p.dbHandle)
}

func (p *SQLiteProvider) getRoles(limit int, offset int, order string, minimal bool) ([]Role, error) {
	return sqlCommonGetRoles(limit, offset, order, minimal, p.dbHandle)
}

func (p *SQLiteProvider) dumpRoles() ([]Role, error) {
	return sqlCommonDumpRoles(p.dbHandle)
}

func (p *SQLiteProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	return sqlCommonGetIPListEntry(ipOrNet, listType, p.dbHandle)
}

func (p *SQLiteProvider) addIPListEntry(entry *IPListEntry) error {
	return p.normalizeError(sqlCommonAddIPListEntry(entry, p.dbHandle), fieldIPNet)
}

func (p *SQLiteProvider) updateIPListEntry(entry *IPListEntry) error {
	return sqlCommonUpdateIPListEntry(entry, p.dbHandle)
}

func (p *SQLiteProvider) deleteIPListEntry(entry IPListEntry, softDelete bool) error {
	return sqlCommonDeleteIPListEntry(entry, softDelete, p.dbHandle)
}

func (p *SQLiteProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	return sqlCommonGetIPListEntries(listType, filter, from, order, limit, p.dbHandle)
}

func (p *SQLiteProvider) getRecentlyUpdatedIPListEntries(after int64) ([]IPListEntry, error) {
	return sqlCommonGetRecentlyUpdatedIPListEntries(after, p.dbHandle)
}

func (p *SQLiteProvider) dumpIPListEntries() ([]IPListEntry, error) {
	return sqlCommonDumpIPListEntries(p.dbHandle)
}

func (p *SQLiteProvider) countIPListEntries(listType IPListType) (int64, error) {
	return sqlCommonCountIPListEntries(listType, p.dbHandle)
}

func (p *SQLiteProvider) getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error) {
	return sqlCommonGetListEntriesForIP(ip, listType, p.dbHandle)
}

func (p *SQLiteProvider) getConfigs() (Configs, error) {
	return sqlCommonGetConfigs(p.dbHandle)
}

func (p *SQLiteProvider) setConfigs(configs *Configs) error {
	return sqlCommonSetConfigs(configs, p.dbHandle)
}

func (p *SQLiteProvider) setFirstDownloadTimestamp(username string) error {
	return sqlCommonSetFirstDownloadTimestamp(username, p.dbHandle)
}

func (p *SQLiteProvider) setFirstUploadTimestamp(username string) error {
	return sqlCommonSetFirstUploadTimestamp(username, p.dbHandle)
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
	logger.InfoToConsole("creating initial database schema, version 29")
	providerLog(logger.LevelInfo, "creating initial database schema, version 29")
	sql := sqlReplaceAll(sqliteInitialSQL)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{sql}, 29, true)
}

func (p *SQLiteProvider) migrateDatabase() error { //nolint:dupl
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}

	switch version := dbVersion.Version; {
	case version == sqlDatabaseVersion:
		providerLog(logger.LevelDebug, "sql database is up to date, current version: %d", version)
		return ErrNoInitRequired
	case version < 29:
		err = errSchemaVersionTooOld(version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 29:
		return updateSQLiteDatabaseFromV29(p.dbHandle)
	case version == 30:
		return updateSQLiteDatabaseFromV30(p.dbHandle)
	default:
		if version > sqlDatabaseVersion {
			providerLog(logger.LevelError, "database schema version %d is newer than the supported one: %d", version,
				sqlDatabaseVersion)
			logger.WarnToConsole("database schema version %d is newer than the supported one: %d", version,
				sqlDatabaseVersion)
			return nil
		}
		return fmt.Errorf("database schema version not handled: %d", version)
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
	case 30:
		return downgradeSQLiteDatabaseFromV30(p.dbHandle)
	case 31:
		return downgradeSQLiteDatabaseFromV31(p.dbHandle)
	default:
		return fmt.Errorf("database schema version not handled: %d", dbVersion.Version)
	}
}

func (p *SQLiteProvider) resetDatabase() error {
	sql := sqlReplaceAll(sqliteResetSQL)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, []string{sql}, 0, false)
}

func (p *SQLiteProvider) normalizeError(err error, fieldType int) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(sqlite3.Error); ok {
		switch e.ExtendedCode {
		case 1555, 2067:
			var message string
			switch fieldType {
			case fieldUsername:
				message = util.I18nErrorDuplicatedUsername
			case fieldIPNet:
				message = util.I18nErrorDuplicatedIPNet
			default:
				message = util.I18nErrorDuplicatedName
			}
			return util.NewI18nError(
				fmt.Errorf("%w: %s", ErrDuplicatedKey, err.Error()),
				message,
			)
		case 787:
			return fmt.Errorf("%w: %s", ErrForeignKeyViolated, err.Error())
		}
	}
	return err
}

func executePragmaOptimize(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	_, err := dbHandle.ExecContext(ctx, "PRAGMA optimize;")
	return err
}

func updateSQLiteDatabaseFromV29(dbHandle *sql.DB) error {
	if err := updateSQLiteDatabaseFrom29To30(dbHandle); err != nil {
		return err
	}
	return updateSQLiteDatabaseFromV30(dbHandle)
}

func updateSQLiteDatabaseFromV30(dbHandle *sql.DB) error {
	return updateSQLiteDatabaseFrom30To31(dbHandle)
}

func downgradeSQLiteDatabaseFromV30(dbHandle *sql.DB) error {
	return downgradeSQLiteDatabaseFrom30To29(dbHandle)
}

func downgradeSQLiteDatabaseFromV31(dbHandle *sql.DB) error {
	if err := downgradeSQLiteDatabaseFrom31To30(dbHandle); err != nil {
		return err
	}
	return downgradeSQLiteDatabaseFromV30(dbHandle)
}

func updateSQLiteDatabaseFrom29To30(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 29 -> 30")
	providerLog(logger.LevelInfo, "updating database schema version: 29 -> 30")

	sql := strings.ReplaceAll(sqliteV30SQL, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 30, true)
}

func downgradeSQLiteDatabaseFrom30To29(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 30 -> 29")
	providerLog(logger.LevelInfo, "downgrading database schema version: 30 -> 29")

	sql := strings.ReplaceAll(sqliteV30DownSQL, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 29, false)
}

func updateSQLiteDatabaseFrom30To31(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 30 -> 31")
	providerLog(logger.LevelInfo, "updating database schema version: 30 -> 31")

	sql := strings.ReplaceAll(sqliteV31SQL, "{{shared_sessions}}", sqlTableSharedSessions)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 31, true)
}

func downgradeSQLiteDatabaseFrom31To30(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 31 -> 30")
	providerLog(logger.LevelInfo, "downgrading database schema version: 31 -> 30")

	sql := strings.ReplaceAll(sqliteV31DownSQL, "{{shared_sessions}}", sqlTableSharedSessions)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, []string{sql}, 30, false)
}

/*func setPragmaFK(dbHandle *sql.DB, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	sql := fmt.Sprintf("PRAGMA foreign_keys=%v;", value)

	_, err := dbHandle.ExecContext(ctx, sql)
	return err
}*/
