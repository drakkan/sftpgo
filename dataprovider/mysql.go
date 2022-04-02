//go:build !nomysql
// +build !nomysql

package dataprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	mysqlResetSQL = "DROP TABLE IF EXISTS `{{api_keys}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{folders_mapping}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{admins}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{folders}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{shares}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{users}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{defender_events}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{defender_hosts}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{active_transfers}}` CASCADE;" +
		"DROP TABLE IF EXISTS `{{schema_version}}` CASCADE;"
	mysqlInitialSQL = "CREATE TABLE `{{schema_version}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `version` integer NOT NULL);" +
		"CREATE TABLE `{{admins}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `username` varchar(255) NOT NULL UNIQUE, " +
		"`description` varchar(512) NULL, `password` varchar(255) NOT NULL, `email` varchar(255) NULL, `status` integer NOT NULL, " +
		"`permissions` longtext NOT NULL, `filters` longtext NULL, `additional_info` longtext NULL, `last_login` bigint NOT NULL, " +
		"`created_at` bigint NOT NULL, `updated_at` bigint NOT NULL);" +
		"CREATE TABLE `{{defender_hosts}}` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, " +
		"`ip` varchar(50) NOT NULL UNIQUE, `ban_time` bigint NOT NULL, `updated_at` bigint NOT NULL);" +
		"CREATE TABLE `{{defender_events}}` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, " +
		"`date_time` bigint NOT NULL, `score` integer NOT NULL, `host_id` bigint NOT NULL);" +
		"ALTER TABLE `{{defender_events}}` ADD CONSTRAINT `{{prefix}}defender_events_host_id_fk_defender_hosts_id` " +
		"FOREIGN KEY (`host_id`) REFERENCES `{{defender_hosts}}` (`id`) ON DELETE CASCADE;" +
		"CREATE TABLE `{{folders}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `name` varchar(255) NOT NULL UNIQUE, " +
		"`description` varchar(512) NULL, `path` longtext NULL, `used_quota_size` bigint NOT NULL, " +
		"`used_quota_files` integer NOT NULL, `last_quota_update` bigint NOT NULL, `filesystem` longtext NULL);" +
		"CREATE TABLE `{{users}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `username` varchar(255) NOT NULL UNIQUE, " +
		"`status` integer NOT NULL, `expiration_date` bigint NOT NULL, `description` varchar(512) NULL, `password` longtext NULL, " +
		"`public_keys` longtext NULL, `home_dir` longtext NOT NULL, `uid` bigint NOT NULL, `gid` bigint NOT NULL, " +
		"`max_sessions` integer NOT NULL, `quota_size` bigint NOT NULL, `quota_files` integer NOT NULL, " +
		"`permissions` longtext NOT NULL, `used_quota_size` bigint NOT NULL, `used_quota_files` integer NOT NULL, " +
		"`last_quota_update` bigint NOT NULL, `upload_bandwidth` integer NOT NULL, `download_bandwidth` integer NOT NULL, " +
		"`last_login` bigint NOT NULL, `filters` longtext NULL, `filesystem` longtext NULL, `additional_info` longtext NULL, " +
		"`created_at` bigint NOT NULL, `updated_at` bigint NOT NULL, `email` varchar(255) NULL);" +
		"CREATE TABLE `{{folders_mapping}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `virtual_path` longtext NOT NULL, " +
		"`quota_size` bigint NOT NULL, `quota_files` integer NOT NULL, `folder_id` integer NOT NULL, `user_id` integer NOT NULL);" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `{{prefix}}unique_mapping` UNIQUE (`user_id`, `folder_id`);" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `{{prefix}}folders_mapping_folder_id_fk_folders_id` FOREIGN KEY (`folder_id`) REFERENCES `{{folders}}` (`id`) ON DELETE CASCADE;" +
		"ALTER TABLE `{{folders_mapping}}` ADD CONSTRAINT `{{prefix}}folders_mapping_user_id_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `{{users}}` (`id`) ON DELETE CASCADE;" +
		"CREATE TABLE `{{shares}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, " +
		"`share_id` varchar(60) NOT NULL UNIQUE, `name` varchar(255) NOT NULL, `description` varchar(512) NULL, " +
		"`scope` integer NOT NULL, `paths` longtext NOT NULL, `created_at` bigint NOT NULL, " +
		"`updated_at` bigint NOT NULL, `last_use_at` bigint NOT NULL, `expires_at` bigint NOT NULL, " +
		"`password` longtext NULL, `max_tokens` integer NOT NULL, `used_tokens` integer NOT NULL, " +
		"`allow_from` longtext NULL, `user_id` integer NOT NULL);" +
		"ALTER TABLE `{{shares}}` ADD CONSTRAINT `{{prefix}}shares_user_id_fk_users_id` " +
		"FOREIGN KEY (`user_id`) REFERENCES `{{users}}` (`id`) ON DELETE CASCADE;" +
		"CREATE TABLE `{{api_keys}}` (`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, `name` varchar(255) NOT NULL, `key_id` varchar(50) NOT NULL UNIQUE," +
		"`api_key` varchar(255) NOT NULL UNIQUE, `scope` integer NOT NULL, `created_at` bigint NOT NULL, `updated_at` bigint NOT NULL, `last_use_at` bigint NOT NULL, " +
		"`expires_at` bigint NOT NULL, `description` longtext NULL, `admin_id` integer NULL, `user_id` integer NULL);" +
		"ALTER TABLE `{{api_keys}}` ADD CONSTRAINT `{{prefix}}api_keys_admin_id_fk_admins_id` FOREIGN KEY (`admin_id`) REFERENCES `{{admins}}` (`id`) ON DELETE CASCADE;" +
		"ALTER TABLE `{{api_keys}}` ADD CONSTRAINT `{{prefix}}api_keys_user_id_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `{{users}}` (`id`) ON DELETE CASCADE;" +
		"CREATE INDEX `{{prefix}}users_updated_at_idx` ON `{{users}}` (`updated_at`);" +
		"CREATE INDEX `{{prefix}}defender_hosts_updated_at_idx` ON `{{defender_hosts}}` (`updated_at`);" +
		"CREATE INDEX `{{prefix}}defender_hosts_ban_time_idx` ON `{{defender_hosts}}` (`ban_time`);" +
		"CREATE INDEX `{{prefix}}defender_events_date_time_idx` ON `{{defender_events}}` (`date_time`);" +
		"INSERT INTO {{schema_version}} (version) VALUES (15);"
	mysqlV16SQL = "ALTER TABLE `{{users}}` ADD COLUMN `download_data_transfer` integer DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{users}}` ALTER COLUMN `download_data_transfer` DROP DEFAULT;" +
		"ALTER TABLE `{{users}}` ADD COLUMN `total_data_transfer` integer DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{users}}` ALTER COLUMN `total_data_transfer` DROP DEFAULT;" +
		"ALTER TABLE `{{users}}` ADD COLUMN `upload_data_transfer` integer DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{users}}` ALTER COLUMN `upload_data_transfer` DROP DEFAULT;" +
		"ALTER TABLE `{{users}}` ADD COLUMN `used_download_data_transfer` integer DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{users}}` ALTER COLUMN `used_download_data_transfer` DROP DEFAULT;" +
		"ALTER TABLE `{{users}}` ADD COLUMN `used_upload_data_transfer` integer DEFAULT 0 NOT NULL;" +
		"ALTER TABLE `{{users}}` ALTER COLUMN `used_upload_data_transfer` DROP DEFAULT;" +
		"CREATE TABLE `{{active_transfers}}` (`id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, " +
		"`connection_id` varchar(100) NOT NULL, `transfer_id` bigint NOT NULL, `transfer_type` integer NOT NULL, " +
		"`username` varchar(255) NOT NULL, `folder_name` varchar(255) NULL, `ip` varchar(50) NOT NULL, " +
		"`truncated_size` bigint NOT NULL, `current_ul_size` bigint NOT NULL, `current_dl_size` bigint NOT NULL, " +
		"`created_at` bigint NOT NULL, `updated_at` bigint NOT NULL);" +
		"CREATE INDEX `{{prefix}}active_transfers_connection_id_idx` ON `{{active_transfers}}` (`connection_id`);" +
		"CREATE INDEX `{{prefix}}active_transfers_transfer_id_idx` ON `{{active_transfers}}` (`transfer_id`);" +
		"CREATE INDEX `{{prefix}}active_transfers_updated_at_idx` ON `{{active_transfers}}` (`updated_at`);"
	mysqlV16DownSQL = "ALTER TABLE `{{users}}` DROP COLUMN `used_upload_data_transfer`;" +
		"ALTER TABLE `{{users}}` DROP COLUMN `used_download_data_transfer`;" +
		"ALTER TABLE `{{users}}` DROP COLUMN `upload_data_transfer`;" +
		"ALTER TABLE `{{users}}` DROP COLUMN `total_data_transfer`;" +
		"ALTER TABLE `{{users}}` DROP COLUMN `download_data_transfer`;" +
		"DROP TABLE `{{active_transfers}}` CASCADE;"
)

// MySQLProvider defines the auth provider for MySQL/MariaDB database
type MySQLProvider struct {
	dbHandle *sql.DB
}

func init() {
	version.AddFeature("+mysql")
}

func initializeMySQLProvider() error {
	var err error

	connString, err := getMySQLConnectionString(false)
	if err != nil {
		return err
	}
	redactedConnString, err := getMySQLConnectionString(true)
	if err != nil {
		return err
	}
	dbHandle, err := sql.Open("mysql", connString)
	if err == nil {
		providerLog(logger.LevelDebug, "mysql database handle created, connection string: %#v, pool size: %v",
			redactedConnString, config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		if config.PoolSize > 0 {
			dbHandle.SetMaxIdleConns(config.PoolSize)
		} else {
			dbHandle.SetMaxIdleConns(2)
		}
		dbHandle.SetConnMaxLifetime(240 * time.Second)
		provider = &MySQLProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelError, "error creating mysql database handler, connection string: %#v, error: %v",
			redactedConnString, err)
	}
	return err
}
func getMySQLConnectionString(redactedPwd bool) (string, error) {
	var connectionString string
	if config.ConnectionString == "" {
		password := config.Password
		if redactedPwd && password != "" {
			password = "[redacted]"
		}
		sslMode := getSSLMode()
		if sslMode == "custom" && !redactedPwd {
			tlsConfig := &tls.Config{}
			if config.RootCert != "" {
				rootCAs, err := x509.SystemCertPool()
				if err != nil {
					rootCAs = x509.NewCertPool()
				}
				rootCrt, err := os.ReadFile(config.RootCert)
				if err != nil {
					return "", fmt.Errorf("unable to load root certificate %#v: %v", config.RootCert, err)
				}
				if !rootCAs.AppendCertsFromPEM(rootCrt) {
					return "", fmt.Errorf("unable to parse root certificate %#v", config.RootCert)
				}
				tlsConfig.RootCAs = rootCAs
			}
			if config.ClientCert != "" && config.ClientKey != "" {
				clientCert := make([]tls.Certificate, 0, 1)
				tlsCert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
				if err != nil {
					return "", fmt.Errorf("unable to load key pair %#v, %#v: %v", config.ClientCert, config.ClientKey, err)
				}
				clientCert = append(clientCert, tlsCert)
				tlsConfig.Certificates = clientCert
			}
			if config.SSLMode == 2 {
				tlsConfig.InsecureSkipVerify = true
			}
			providerLog(logger.LevelInfo, "registering custom TLS config, root cert %#v, client cert %#v, client key %#v",
				config.RootCert, config.ClientCert, config.ClientKey)
			if err := mysql.RegisterTLSConfig("custom", tlsConfig); err != nil {
				return "", fmt.Errorf("unable to register tls config: %v", err)
			}
		}
		connectionString = fmt.Sprintf("%v:%v@tcp([%v]:%v)/%v?charset=utf8mb4&interpolateParams=true&timeout=10s&parseTime=true&tls=%v&writeTimeout=10s&readTimeout=10s",
			config.Username, password, config.Host, config.Port, config.Name, sslMode)
	} else {
		connectionString = config.ConnectionString
	}
	return connectionString, nil
}

func (p *MySQLProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p *MySQLProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, ip, protocol, p.dbHandle)
}

func (p *MySQLProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	return sqlCommonValidateUserAndTLSCertificate(username, protocol, tlsCert, p.dbHandle)
}

func (p *MySQLProvider) validateUserAndPubKey(username string, publicKey []byte, isSSHCert bool) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, isSSHCert, p.dbHandle)
}

func (p *MySQLProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	return sqlCommonUpdateTransferQuota(username, uploadSize, downloadSize, reset, p.dbHandle)
}

func (p *MySQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *MySQLProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p *MySQLProvider) setUpdatedAt(username string) {
	sqlCommonSetUpdatedAt(username, p.dbHandle)
}

func (p *MySQLProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p *MySQLProvider) updateAdminLastLogin(username string) error {
	return sqlCommonUpdateAdminLastLogin(username, p.dbHandle)
}

func (p *MySQLProvider) userExists(username string) (User, error) {
	return sqlCommonGetUserByUsername(username, p.dbHandle)
}

func (p *MySQLProvider) addUser(user *User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p *MySQLProvider) updateUser(user *User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p *MySQLProvider) deleteUser(user *User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p *MySQLProvider) updateUserPassword(username, password string) error {
	return sqlCommonUpdateUserPassword(username, password, p.dbHandle)
}

func (p *MySQLProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p *MySQLProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return sqlCommonGetRecentlyUpdatedUsers(after, p.dbHandle)
}

func (p *MySQLProvider) getUsers(limit int, offset int, order string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return sqlCommonGetUsersForQuotaCheck(toFetch, p.dbHandle)
}

func (p *MySQLProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p *MySQLProvider) getFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonGetFolderByName(ctx, name, p.dbHandle)
}

func (p *MySQLProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonAddFolder(folder, p.dbHandle)
}

func (p *MySQLProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonUpdateFolder(folder, p.dbHandle)
}

func (p *MySQLProvider) deleteFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p *MySQLProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *MySQLProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, p.dbHandle)
}

func (p *MySQLProvider) adminExists(username string) (Admin, error) {
	return sqlCommonGetAdminByUsername(username, p.dbHandle)
}

func (p *MySQLProvider) addAdmin(admin *Admin) error {
	return sqlCommonAddAdmin(admin, p.dbHandle)
}

func (p *MySQLProvider) updateAdmin(admin *Admin) error {
	return sqlCommonUpdateAdmin(admin, p.dbHandle)
}

func (p *MySQLProvider) deleteAdmin(admin *Admin) error {
	return sqlCommonDeleteAdmin(admin, p.dbHandle)
}

func (p *MySQLProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	return sqlCommonGetAdmins(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) dumpAdmins() ([]Admin, error) {
	return sqlCommonDumpAdmins(p.dbHandle)
}

func (p *MySQLProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	return sqlCommonValidateAdminAndPass(username, password, ip, p.dbHandle)
}

func (p *MySQLProvider) apiKeyExists(keyID string) (APIKey, error) {
	return sqlCommonGetAPIKeyByID(keyID, p.dbHandle)
}

func (p *MySQLProvider) addAPIKey(apiKey *APIKey) error {
	return sqlCommonAddAPIKey(apiKey, p.dbHandle)
}

func (p *MySQLProvider) updateAPIKey(apiKey *APIKey) error {
	return sqlCommonUpdateAPIKey(apiKey, p.dbHandle)
}

func (p *MySQLProvider) deleteAPIKey(apiKey *APIKey) error {
	return sqlCommonDeleteAPIKey(apiKey, p.dbHandle)
}

func (p *MySQLProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	return sqlCommonGetAPIKeys(limit, offset, order, p.dbHandle)
}

func (p *MySQLProvider) dumpAPIKeys() ([]APIKey, error) {
	return sqlCommonDumpAPIKeys(p.dbHandle)
}

func (p *MySQLProvider) updateAPIKeyLastUse(keyID string) error {
	return sqlCommonUpdateAPIKeyLastUse(keyID, p.dbHandle)
}

func (p *MySQLProvider) shareExists(shareID, username string) (Share, error) {
	return sqlCommonGetShareByID(shareID, username, p.dbHandle)
}

func (p *MySQLProvider) addShare(share *Share) error {
	return sqlCommonAddShare(share, p.dbHandle)
}

func (p *MySQLProvider) updateShare(share *Share) error {
	return sqlCommonUpdateShare(share, p.dbHandle)
}

func (p *MySQLProvider) deleteShare(share *Share) error {
	return sqlCommonDeleteShare(share, p.dbHandle)
}

func (p *MySQLProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	return sqlCommonGetShares(limit, offset, order, username, p.dbHandle)
}

func (p *MySQLProvider) dumpShares() ([]Share, error) {
	return sqlCommonDumpShares(p.dbHandle)
}

func (p *MySQLProvider) updateShareLastUse(shareID string, numTokens int) error {
	return sqlCommonUpdateShareLastUse(shareID, numTokens, p.dbHandle)
}

func (p *MySQLProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return sqlCommonGetDefenderHosts(from, limit, p.dbHandle)
}

func (p *MySQLProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return sqlCommonGetDefenderHostByIP(ip, from, p.dbHandle)
}

func (p *MySQLProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
	return sqlCommonIsDefenderHostBanned(ip, p.dbHandle)
}

func (p *MySQLProvider) updateDefenderBanTime(ip string, minutes int) error {
	return sqlCommonDefenderIncrementBanTime(ip, minutes, p.dbHandle)
}

func (p *MySQLProvider) deleteDefenderHost(ip string) error {
	return sqlCommonDeleteDefenderHost(ip, p.dbHandle)
}

func (p *MySQLProvider) addDefenderEvent(ip string, score int) error {
	return sqlCommonAddDefenderHostAndEvent(ip, score, p.dbHandle)
}

func (p *MySQLProvider) setDefenderBanTime(ip string, banTime int64) error {
	return sqlCommonSetDefenderBanTime(ip, banTime, p.dbHandle)
}

func (p *MySQLProvider) cleanupDefender(from int64) error {
	return sqlCommonDefenderCleanup(from, p.dbHandle)
}

func (p *MySQLProvider) addActiveTransfer(transfer ActiveTransfer) error {
	return sqlCommonAddActiveTransfer(transfer, p.dbHandle)
}

func (p *MySQLProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
	return sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID, connectionID, p.dbHandle)
}

func (p *MySQLProvider) removeActiveTransfer(transferID int64, connectionID string) error {
	return sqlCommonRemoveActiveTransfer(transferID, connectionID, p.dbHandle)
}

func (p *MySQLProvider) cleanupActiveTransfers(before time.Time) error {
	return sqlCommonCleanupActiveTransfers(before, p.dbHandle)
}

func (p *MySQLProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return sqlCommonGetActiveTransfers(from, p.dbHandle)
}

func (p *MySQLProvider) close() error {
	return p.dbHandle.Close()
}

func (p *MySQLProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (p *MySQLProvider) initializeDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, false)
	if err == nil && dbVersion.Version > 0 {
		return ErrNoInitRequired
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errSchemaVersionEmpty
	}
	logger.InfoToConsole("creating initial database schema, version 15")
	providerLog(logger.LevelInfo, "creating initial database schema, version 15")
	initialSQL := strings.ReplaceAll(mysqlInitialSQL, "{{schema_version}}", sqlTableSchemaVersion)
	initialSQL = strings.ReplaceAll(initialSQL, "{{admins}}", sqlTableAdmins)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders}}", sqlTableFolders)
	initialSQL = strings.ReplaceAll(initialSQL, "{{users}}", sqlTableUsers)
	initialSQL = strings.ReplaceAll(initialSQL, "{{folders_mapping}}", sqlTableFoldersMapping)
	initialSQL = strings.ReplaceAll(initialSQL, "{{api_keys}}", sqlTableAPIKeys)
	initialSQL = strings.ReplaceAll(initialSQL, "{{shares}}", sqlTableShares)
	initialSQL = strings.ReplaceAll(initialSQL, "{{defender_events}}", sqlTableDefenderEvents)
	initialSQL = strings.ReplaceAll(initialSQL, "{{defender_hosts}}", sqlTableDefenderHosts)
	initialSQL = strings.ReplaceAll(initialSQL, "{{prefix}}", config.SQLTablesPrefix)

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(initialSQL, ";"), 15)
}

func (p *MySQLProvider) migrateDatabase() error {
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
		return updateMySQLDatabaseFromV15(p.dbHandle)
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

func (p *MySQLProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}

	switch dbVersion.Version {
	case 16:
		return downgradeMySQLDatabaseFromV16(p.dbHandle)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func (p *MySQLProvider) resetDatabase() error {
	sql := strings.ReplaceAll(mysqlResetSQL, "{{schema_version}}", sqlTableSchemaVersion)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{shares}}", sqlTableShares)
	sql = strings.ReplaceAll(sql, "{{defender_events}}", sqlTableDefenderEvents)
	sql = strings.ReplaceAll(sql, "{{defender_hosts}}", sqlTableDefenderHosts)
	sql = strings.ReplaceAll(sql, "{{active_transfers}}", sqlTableActiveTransfers)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(sql, ";"), 0)
}

func updateMySQLDatabaseFromV15(dbHandle *sql.DB) error {
	return updateMySQLDatabaseFrom15To16(dbHandle)
}

func downgradeMySQLDatabaseFromV16(dbHandle *sql.DB) error {
	return downgradeMySQLDatabaseFrom16To15(dbHandle)
}

func updateMySQLDatabaseFrom15To16(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 15 -> 16")
	providerLog(logger.LevelInfo, "updating database version: 15 -> 16")
	sql := strings.ReplaceAll(mysqlV16SQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{active_transfers}}", sqlTableActiveTransfers)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 16)
}

func downgradeMySQLDatabaseFrom16To15(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 16 -> 15")
	providerLog(logger.LevelInfo, "downgrading database version: 16 -> 15")
	sql := strings.ReplaceAll(mysqlV16DownSQL, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{active_transfers}}", sqlTableActiveTransfers)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 15)
}
