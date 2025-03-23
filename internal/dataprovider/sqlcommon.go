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

package dataprovider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/cockroach-go/v2/crdb"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	sqlDatabaseVersion     = 31
	defaultSQLQueryTimeout = 10 * time.Second
	longSQLQueryTimeout    = 60 * time.Second
)

var (
	errSQLFoldersAssociation = errors.New("unable to associate virtual folders to user")
	errSQLGroupsAssociation  = errors.New("unable to associate groups to user")
	errSQLUsersAssociation   = errors.New("unable to associate users to group")
	errSchemaVersionEmpty    = errors.New("we can't determine schema version because the schema_migration table is empty. The SFTPGo database might be corrupted. Consider using the \"resetprovider\" sub-command")
)

type sqlQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

type sqlScanner interface {
	Scan(dest ...any) error
}

func sqlReplaceAll(sql string) string {
	sql = strings.ReplaceAll(sql, "{{schema_version}}", sqlTableSchemaVersion)
	sql = strings.ReplaceAll(sql, "{{admins}}", sqlTableAdmins)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{groups}}", sqlTableGroups)
	sql = strings.ReplaceAll(sql, "{{users_folders_mapping}}", sqlTableUsersFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{users_groups_mapping}}", sqlTableUsersGroupsMapping)
	sql = strings.ReplaceAll(sql, "{{admins_groups_mapping}}", sqlTableAdminsGroupsMapping)
	sql = strings.ReplaceAll(sql, "{{groups_folders_mapping}}", sqlTableGroupsFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{shares}}", sqlTableShares)
	sql = strings.ReplaceAll(sql, "{{defender_events}}", sqlTableDefenderEvents)
	sql = strings.ReplaceAll(sql, "{{defender_hosts}}", sqlTableDefenderHosts)
	sql = strings.ReplaceAll(sql, "{{active_transfers}}", sqlTableActiveTransfers)
	sql = strings.ReplaceAll(sql, "{{shared_sessions}}", sqlTableSharedSessions)
	sql = strings.ReplaceAll(sql, "{{events_actions}}", sqlTableEventsActions)
	sql = strings.ReplaceAll(sql, "{{events_rules}}", sqlTableEventsRules)
	sql = strings.ReplaceAll(sql, "{{rules_actions_mapping}}", sqlTableRulesActionsMapping)
	sql = strings.ReplaceAll(sql, "{{tasks}}", sqlTableTasks)
	sql = strings.ReplaceAll(sql, "{{nodes}}", sqlTableNodes)
	sql = strings.ReplaceAll(sql, "{{roles}}", sqlTableRoles)
	sql = strings.ReplaceAll(sql, "{{ip_lists}}", sqlTableIPLists)
	sql = strings.ReplaceAll(sql, "{{configs}}", sqlTableConfigs)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sql
}

func sqlCommonGetShareByID(shareID, username string, dbHandle sqlQuerier) (Share, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	filterUser := username != ""
	q := getShareByIDQuery(filterUser)

	var row *sql.Row
	if filterUser {
		row = dbHandle.QueryRowContext(ctx, q, shareID, username)
	} else {
		row = dbHandle.QueryRowContext(ctx, q, shareID)
	}

	return getShareFromDbRow(row)
}

func sqlCommonAddShare(share *Share, dbHandle *sql.DB) error {
	err := share.validate()
	if err != nil {
		return err
	}

	user, err := provider.userExists(share.Username, "")
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("unable to validate user %q", share.Username))
	}

	paths, err := json.Marshal(share.Paths)
	if err != nil {
		return err
	}
	var allowFrom []byte
	if len(share.AllowFrom) > 0 {
		res, err := json.Marshal(share.AllowFrom)
		if err == nil {
			allowFrom = res
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddShareQuery()
	usedTokens := 0
	createdAt := util.GetTimeAsMsSinceEpoch(time.Now())
	updatedAt := createdAt
	lastUseAt := int64(0)
	if share.IsRestore {
		usedTokens = share.UsedTokens
		if share.CreatedAt > 0 {
			createdAt = share.CreatedAt
		}
		if share.UpdatedAt > 0 {
			updatedAt = share.UpdatedAt
		}
		lastUseAt = share.LastUseAt
	}
	_, err = dbHandle.ExecContext(ctx, q, share.ShareID, share.Name, share.Description, share.Scope,
		paths, createdAt, updatedAt, lastUseAt, share.ExpiresAt, share.Password,
		share.MaxTokens, usedTokens, allowFrom, user.ID)
	return err
}

func sqlCommonUpdateShare(share *Share, dbHandle *sql.DB) error {
	err := share.validate()
	if err != nil {
		return err
	}

	paths, err := json.Marshal(share.Paths)
	if err != nil {
		return err
	}

	var allowFrom []byte
	if len(share.AllowFrom) > 0 {
		res, err := json.Marshal(share.AllowFrom)
		if err == nil {
			allowFrom = res
		}
	}

	user, err := provider.userExists(share.Username, "")
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("unable to validate user %q", share.Username))
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	var q string
	if share.IsRestore {
		q = getUpdateShareRestoreQuery()
	} else {
		q = getUpdateShareQuery()
	}

	var res sql.Result
	if share.IsRestore {
		if share.CreatedAt == 0 {
			share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		}
		if share.UpdatedAt == 0 {
			share.UpdatedAt = share.CreatedAt
		}
		res, err = dbHandle.ExecContext(ctx, q, share.Name, share.Description, share.Scope, paths,
			share.CreatedAt, share.UpdatedAt, share.LastUseAt, share.ExpiresAt, share.Password, share.MaxTokens,
			share.UsedTokens, allowFrom, user.ID, share.ShareID)
	} else {
		res, err = dbHandle.ExecContext(ctx, q, share.Name, share.Description, share.Scope, paths,
			util.GetTimeAsMsSinceEpoch(time.Now()), share.ExpiresAt, share.Password, share.MaxTokens,
			allowFrom, user.ID, share.ShareID)
	}
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDeleteShare(share Share, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteShareQuery()
	res, err := dbHandle.ExecContext(ctx, q, share.ShareID)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetShares(limit, offset int, order, username string, dbHandle sqlQuerier) ([]Share, error) {
	shares := make([]Share, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getSharesQuery(order)
	rows, err := dbHandle.QueryContext(ctx, q, username, limit, offset)
	if err != nil {
		return shares, err
	}
	defer rows.Close()

	for rows.Next() {
		s, err := getShareFromDbRow(rows)
		if err != nil {
			return shares, err
		}
		s.HideConfidentialData()
		shares = append(shares, s)
	}

	return shares, rows.Err()
}

func sqlCommonDumpShares(dbHandle sqlQuerier) ([]Share, error) {
	shares := make([]Share, 0, 30)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDumpSharesQuery()
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return shares, err
	}
	defer rows.Close()

	for rows.Next() {
		s, err := getShareFromDbRow(rows)
		if err != nil {
			return shares, err
		}
		shares = append(shares, s)
	}

	return shares, rows.Err()
}

func sqlCommonGetAPIKeyByID(keyID string, dbHandle sqlQuerier) (APIKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAPIKeyByIDQuery()
	row := dbHandle.QueryRowContext(ctx, q, keyID)

	apiKey, err := getAPIKeyFromDbRow(row)
	if err != nil {
		return apiKey, err
	}
	return getAPIKeyWithRelatedFields(ctx, apiKey, dbHandle)
}

func sqlCommonAddAPIKey(apiKey *APIKey, dbHandle *sql.DB) error {
	err := apiKey.validate()
	if err != nil {
		return err
	}

	userID, adminID, err := sqlCommonGetAPIKeyRelatedIDs(apiKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddAPIKeyQuery()
	_, err = dbHandle.ExecContext(ctx, q, apiKey.KeyID, apiKey.Name, apiKey.Key, apiKey.Scope,
		util.GetTimeAsMsSinceEpoch(time.Now()), util.GetTimeAsMsSinceEpoch(time.Now()), apiKey.LastUseAt,
		apiKey.ExpiresAt, apiKey.Description, userID, adminID)
	return err
}

func sqlCommonUpdateAPIKey(apiKey *APIKey, dbHandle *sql.DB) error {
	err := apiKey.validate()
	if err != nil {
		return err
	}

	userID, adminID, err := sqlCommonGetAPIKeyRelatedIDs(apiKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateAPIKeyQuery()
	res, err := dbHandle.ExecContext(ctx, q, apiKey.Name, apiKey.Scope, apiKey.ExpiresAt, userID, adminID,
		apiKey.Description, util.GetTimeAsMsSinceEpoch(time.Now()), apiKey.KeyID)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDeleteAPIKey(apiKey APIKey, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteAPIKeyQuery()
	res, err := dbHandle.ExecContext(ctx, q, apiKey.KeyID)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetAPIKeys(limit, offset int, order string, dbHandle sqlQuerier) ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAPIKeysQuery(order)
	rows, err := dbHandle.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return apiKeys, err
	}
	defer rows.Close()

	for rows.Next() {
		k, err := getAPIKeyFromDbRow(rows)
		if err != nil {
			return apiKeys, err
		}
		k.HideConfidentialData()
		apiKeys = append(apiKeys, k)
	}
	err = rows.Err()
	if err != nil {
		return apiKeys, err
	}
	apiKeys, err = getRelatedValuesForAPIKeys(ctx, apiKeys, dbHandle, APIKeyScopeAdmin)
	if err != nil {
		return apiKeys, err
	}

	return getRelatedValuesForAPIKeys(ctx, apiKeys, dbHandle, APIKeyScopeUser)
}

func sqlCommonDumpAPIKeys(dbHandle sqlQuerier) ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, 30)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDumpAPIKeysQuery()
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return apiKeys, err
	}
	defer rows.Close()

	for rows.Next() {
		k, err := getAPIKeyFromDbRow(rows)
		if err != nil {
			return apiKeys, err
		}
		apiKeys = append(apiKeys, k)
	}
	err = rows.Err()
	if err != nil {
		return apiKeys, err
	}
	apiKeys, err = getRelatedValuesForAPIKeys(ctx, apiKeys, dbHandle, APIKeyScopeAdmin)
	if err != nil {
		return apiKeys, err
	}

	return getRelatedValuesForAPIKeys(ctx, apiKeys, dbHandle, APIKeyScopeUser)
}

func sqlCommonGetAdminByUsername(username string, dbHandle sqlQuerier) (Admin, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAdminByUsernameQuery()
	row := dbHandle.QueryRowContext(ctx, q, username)

	admin, err := getAdminFromDbRow(row)
	if err != nil {
		return admin, err
	}
	return getAdminWithGroups(ctx, admin, dbHandle)
}

func sqlCommonValidateAdminAndPass(username, password, ip string, dbHandle *sql.DB) (Admin, error) {
	admin, err := sqlCommonGetAdminByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating admin %q: %v", username, err)
		return admin, err
	}
	err = admin.checkUserAndPass(password, ip)
	return admin, err
}

func sqlCommonAddAdmin(admin *Admin, dbHandle *sql.DB) error {
	err := admin.validate()
	if err != nil {
		return err
	}

	perms, err := json.Marshal(admin.Permissions)
	if err != nil {
		return err
	}

	filters, err := json.Marshal(admin.Filters)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getAddAdminQuery(admin.Role)
		_, err = tx.ExecContext(ctx, q, admin.Username, admin.Password, admin.Status, admin.Email, perms,
			filters, admin.AdditionalInfo, admin.Description, util.GetTimeAsMsSinceEpoch(time.Now()),
			util.GetTimeAsMsSinceEpoch(time.Now()), admin.Role)
		if err != nil {
			return err
		}
		return generateAdminGroupMapping(ctx, admin, tx)
	})
}

func sqlCommonUpdateAdmin(admin *Admin, dbHandle *sql.DB) error {
	err := admin.validate()
	if err != nil {
		return err
	}

	perms, err := json.Marshal(admin.Permissions)
	if err != nil {
		return err
	}

	filters, err := json.Marshal(admin.Filters)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getUpdateAdminQuery(admin.Role)
		_, err = tx.ExecContext(ctx, q, admin.Password, admin.Status, admin.Email, perms, filters,
			admin.AdditionalInfo, admin.Description, util.GetTimeAsMsSinceEpoch(time.Now()), admin.Role, admin.Username)
		if err != nil {
			return err
		}
		return generateAdminGroupMapping(ctx, admin, tx)
	})
}

func sqlCommonDeleteAdmin(admin Admin, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteAdminQuery()
	res, err := dbHandle.ExecContext(ctx, q, admin.Username)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetAdmins(limit, offset int, order string, dbHandle sqlQuerier) ([]Admin, error) {
	admins := make([]Admin, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAdminsQuery(order)
	rows, err := dbHandle.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return admins, err
	}
	defer rows.Close()

	for rows.Next() {
		a, err := getAdminFromDbRow(rows)
		if err != nil {
			return admins, err
		}
		a.HideConfidentialData()
		admins = append(admins, a)
	}
	err = rows.Err()
	if err != nil {
		return admins, err
	}
	return getAdminsWithGroups(ctx, admins, dbHandle)
}

func sqlCommonDumpAdmins(dbHandle sqlQuerier) ([]Admin, error) {
	admins := make([]Admin, 0, 30)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDumpAdminsQuery()
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return admins, err
	}
	defer rows.Close()

	for rows.Next() {
		a, err := getAdminFromDbRow(rows)
		if err != nil {
			return admins, err
		}
		admins = append(admins, a)
	}
	err = rows.Err()
	if err != nil {
		return admins, err
	}
	return getAdminsWithGroups(ctx, admins, dbHandle)
}

func sqlCommonGetIPListEntry(ipOrNet string, listType IPListType, dbHandle sqlQuerier) (IPListEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getIPListEntryQuery()
	row := dbHandle.QueryRowContext(ctx, q, listType, ipOrNet)
	return getIPListEntryFromDbRow(row)
}

func sqlCommonDumpIPListEntries(dbHandle *sql.DB) ([]IPListEntry, error) {
	count, err := sqlCommonCountIPListEntries(0, dbHandle)
	if err != nil {
		return nil, err
	}
	if count > ipListMemoryLimit {
		providerLog(logger.LevelInfo, "IP lists excluded from dump, too many entries: %d", count)
		return nil, nil
	}
	entries := make([]IPListEntry, 0, 100)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpListEntriesQuery()

	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	for rows.Next() {
		entry, err := getIPListEntryFromDbRow(rows)
		if err != nil {
			return entries, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func sqlCommonCountIPListEntries(listType IPListType, dbHandle *sql.DB) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	var q string
	var args []any
	if listType == 0 {
		q = getCountAllIPListEntriesQuery()
	} else {
		q = getCountIPListEntriesQuery()
		args = append(args, listType)
	}
	var count int64
	err := dbHandle.QueryRowContext(ctx, q, args...).Scan(&count)
	return count, err
}

func sqlCommonGetIPListEntries(listType IPListType, filter, from, order string, limit int, dbHandle sqlQuerier) ([]IPListEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getIPListEntriesQuery(filter, from, order, limit)
	args := []any{listType}
	if from != "" {
		args = append(args, from)
	}
	if filter != "" {
		args = append(args, filter+"%")
	}
	if limit > 0 {
		args = append(args, limit)
	}
	entries := make([]IPListEntry, 0, limit)
	rows, err := dbHandle.QueryContext(ctx, q, args...)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	for rows.Next() {
		entry, err := getIPListEntryFromDbRow(rows)
		if err != nil {
			return entries, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func sqlCommonGetRecentlyUpdatedIPListEntries(after int64, dbHandle sqlQuerier) ([]IPListEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getRecentlyUpdatedIPListQuery()
	entries := make([]IPListEntry, 0, 5)
	rows, err := dbHandle.QueryContext(ctx, q, after)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	for rows.Next() {
		entry, err := getIPListEntryFromDbRow(rows)
		if err != nil {
			return entries, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func sqlCommonGetListEntriesForIP(ip string, listType IPListType, dbHandle sqlQuerier) ([]IPListEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	var rows *sql.Rows
	var err error

	entries := make([]IPListEntry, 0, 2)
	if config.Driver == PGSQLDataProviderName || config.Driver == CockroachDataProviderName {
		rows, err = dbHandle.QueryContext(ctx, getIPListEntriesForIPQueryPg(), listType, ip)
		if err != nil {
			return entries, err
		}
	} else {
		ipAddr, err := netip.ParseAddr(ip)
		if err != nil {
			return entries, fmt.Errorf("invalid ip address %s", ip)
		}
		var netType int
		var ipBytes []byte
		if ipAddr.Is4() || ipAddr.Is4In6() {
			netType = ipTypeV4
			as4 := ipAddr.As4()
			ipBytes = as4[:]
		} else {
			netType = ipTypeV6
			as16 := ipAddr.As16()
			ipBytes = as16[:]
		}
		rows, err = dbHandle.QueryContext(ctx, getIPListEntriesForIPQueryNoPg(), listType, netType, ipBytes)
		if err != nil {
			return entries, err
		}
	}
	defer rows.Close()

	for rows.Next() {
		entry, err := getIPListEntryFromDbRow(rows)
		if err != nil {
			return entries, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func sqlCommonAddIPListEntry(entry *IPListEntry, dbHandle *sql.DB) error {
	if err := entry.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	var err error
	q := getAddIPListEntryQuery()
	first := entry.getFirst()
	last := entry.getLast()
	var netType int
	if first.Is4() {
		netType = ipTypeV4
	} else {
		netType = ipTypeV6
	}
	if config.IsShared == 1 {
		return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, getRemoveSoftDeletedIPListEntryQuery(), entry.Type, entry.IPOrNet)
			if err != nil {
				return err
			}
			if config.Driver == PGSQLDataProviderName || config.Driver == CockroachDataProviderName {
				_, err = tx.ExecContext(ctx, q, entry.Type, entry.IPOrNet, first.String(), last.String(),
					netType, entry.Protocols, entry.Description, entry.Mode, util.GetTimeAsMsSinceEpoch(time.Now()),
					util.GetTimeAsMsSinceEpoch(time.Now()))
			} else {
				_, err = tx.ExecContext(ctx, q, entry.Type, entry.IPOrNet, entry.First, entry.Last,
					netType, entry.Protocols, entry.Description, entry.Mode, util.GetTimeAsMsSinceEpoch(time.Now()),
					util.GetTimeAsMsSinceEpoch(time.Now()))
			}
			return err
		})
	}
	if config.Driver == PGSQLDataProviderName || config.Driver == CockroachDataProviderName {
		_, err = dbHandle.ExecContext(ctx, q, entry.Type, entry.IPOrNet, first.String(), last.String(),
			netType, entry.Protocols, entry.Description, entry.Mode, util.GetTimeAsMsSinceEpoch(time.Now()),
			util.GetTimeAsMsSinceEpoch(time.Now()))
	} else {
		_, err = dbHandle.ExecContext(ctx, q, entry.Type, entry.IPOrNet, entry.First, entry.Last,
			netType, entry.Protocols, entry.Description, entry.Mode, util.GetTimeAsMsSinceEpoch(time.Now()),
			util.GetTimeAsMsSinceEpoch(time.Now()))
	}
	return err
}

func sqlCommonUpdateIPListEntry(entry *IPListEntry, dbHandle *sql.DB) error {
	if err := entry.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateIPListEntryQuery()
	res, err := dbHandle.ExecContext(ctx, q, entry.Mode, entry.Protocols, entry.Description,
		util.GetTimeAsMsSinceEpoch(time.Now()), entry.Type, entry.IPOrNet)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDeleteIPListEntry(entry IPListEntry, softDelete bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteIPListEntryQuery(softDelete)
	var args []any
	if softDelete {
		ts := util.GetTimeAsMsSinceEpoch(time.Now())
		args = append(args, ts, ts)
	}
	args = append(args, entry.Type, entry.IPOrNet)
	res, err := dbHandle.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetRoleByName(name string, dbHandle sqlQuerier) (Role, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getRoleByNameQuery()
	row := dbHandle.QueryRowContext(ctx, q, name)
	role, err := getRoleFromDbRow(row)
	if err != nil {
		return role, err
	}
	role, err = getRoleWithUsers(ctx, role, dbHandle)
	if err != nil {
		return role, err
	}
	return getRoleWithAdmins(ctx, role, dbHandle)
}

func sqlCommonDumpRoles(dbHandle sqlQuerier) ([]Role, error) {
	roles := make([]Role, 0, 10)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpRolesQuery()

	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return roles, err
	}
	defer rows.Close()

	for rows.Next() {
		role, err := getRoleFromDbRow(rows)
		if err != nil {
			return roles, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func sqlCommonGetRoles(limit int, offset int, order string, minimal bool, dbHandle sqlQuerier) ([]Role, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getRolesQuery(order, minimal)

	roles := make([]Role, 0, limit)
	rows, err := dbHandle.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return roles, err
	}
	defer rows.Close()

	for rows.Next() {
		var role Role
		if minimal {
			err = rows.Scan(&role.ID, &role.Name)
		} else {
			role, err = getRoleFromDbRow(rows)
		}
		if err != nil {
			return roles, err
		}
		roles = append(roles, role)
	}
	err = rows.Err()
	if err != nil {
		return roles, err
	}
	if minimal {
		return roles, nil
	}
	roles, err = getRolesWithUsers(ctx, roles, dbHandle)
	if err != nil {
		return roles, err
	}
	return getRolesWithAdmins(ctx, roles, dbHandle)
}

func sqlCommonAddRole(role *Role, dbHandle *sql.DB) error {
	if err := role.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddRoleQuery()
	_, err := dbHandle.ExecContext(ctx, q, role.Name, role.Description, util.GetTimeAsMsSinceEpoch(time.Now()),
		util.GetTimeAsMsSinceEpoch(time.Now()))
	return err
}

func sqlCommonUpdateRole(role *Role, dbHandle *sql.DB) error {
	if err := role.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateRoleQuery()
	res, err := dbHandle.ExecContext(ctx, q, role.Description, util.GetTimeAsMsSinceEpoch(time.Now()), role.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDeleteRole(role Role, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteRoleQuery()
	res, err := dbHandle.ExecContext(ctx, q, role.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetGroupByName(name string, dbHandle sqlQuerier) (Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getGroupByNameQuery()

	row := dbHandle.QueryRowContext(ctx, q, name)
	group, err := getGroupFromDbRow(row)
	if err != nil {
		return group, err
	}
	group, err = getGroupWithVirtualFolders(ctx, group, dbHandle)
	if err != nil {
		return group, err
	}
	group, err = getGroupWithUsers(ctx, group, dbHandle)
	if err != nil {
		return group, err
	}
	return getGroupWithAdmins(ctx, group, dbHandle)
}

func sqlCommonDumpGroups(dbHandle sqlQuerier) ([]Group, error) {
	groups := make([]Group, 0, 50)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpGroupsQuery()

	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return groups, err
	}
	defer rows.Close()

	for rows.Next() {
		group, err := getGroupFromDbRow(rows)
		if err != nil {
			return groups, err
		}
		groups = append(groups, group)
	}
	err = rows.Err()
	if err != nil {
		return groups, err
	}
	return getGroupsWithVirtualFolders(ctx, groups, dbHandle)
}

func sqlCommonGetUsersInGroups(names []string, dbHandle sqlQuerier) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	maxNames := len(sqlPlaceholders)
	usernames := make([]string, 0, len(names))

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	for len(names) > 0 {
		if maxNames > len(names) {
			maxNames = len(names)
		}

		q := getUsersInGroupsQuery(maxNames)
		args := make([]any, 0, maxNames)
		for _, name := range names[:maxNames] {
			args = append(args, name)
		}

		rows, err := dbHandle.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var username string
			err = rows.Scan(&username)
			if err != nil {
				return usernames, err
			}
			usernames = append(usernames, username)
		}
		err = rows.Err()
		if err != nil {
			return usernames, err
		}
		names = names[maxNames:]
	}
	return usernames, nil
}

func sqlCommonGetGroupsWithNames(names []string, dbHandle sqlQuerier) ([]Group, error) {
	if len(names) == 0 {
		return nil, nil
	}
	maxNames := len(sqlPlaceholders)
	groups := make([]Group, 0, len(names))
	for len(names) > 0 {
		if maxNames > len(names) {
			maxNames = len(names)
		}
		ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
		defer cancel()

		q := getGroupsWithNamesQuery(maxNames)
		args := make([]any, 0, maxNames)
		for _, name := range names[:maxNames] {
			args = append(args, name)
		}
		rows, err := dbHandle.QueryContext(ctx, q, args...)
		if err != nil {
			return groups, err
		}
		defer rows.Close()

		for rows.Next() {
			group, err := getGroupFromDbRow(rows)
			if err != nil {
				return groups, err
			}
			groups = append(groups, group)
		}
		err = rows.Err()
		if err != nil {
			return groups, err
		}
		names = names[maxNames:]
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return getGroupsWithVirtualFolders(ctx, groups, dbHandle)
}

func sqlCommonGetGroups(limit int, offset int, order string, minimal bool, dbHandle sqlQuerier) ([]Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getGroupsQuery(order, minimal)

	groups := make([]Group, 0, limit)
	rows, err := dbHandle.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return groups, err
	}
	defer rows.Close()

	for rows.Next() {
		var group Group
		if minimal {
			err = rows.Scan(&group.ID, &group.Name)
		} else {
			group, err = getGroupFromDbRow(rows)
		}
		if err != nil {
			return groups, err
		}
		groups = append(groups, group)
	}
	err = rows.Err()
	if err != nil {
		return groups, err
	}
	if minimal {
		return groups, nil
	}
	groups, err = getGroupsWithVirtualFolders(ctx, groups, dbHandle)
	if err != nil {
		return groups, err
	}
	groups, err = getGroupsWithUsers(ctx, groups, dbHandle)
	if err != nil {
		return groups, err
	}
	groups, err = getGroupsWithAdmins(ctx, groups, dbHandle)
	if err != nil {
		return groups, err
	}
	for idx := range groups {
		groups[idx].PrepareForRendering()
	}
	return groups, nil
}

func sqlCommonAddGroup(group *Group, dbHandle *sql.DB) error {
	if err := group.validate(); err != nil {
		return err
	}
	settings, err := json.Marshal(group.UserSettings)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getAddGroupQuery()
		_, err := tx.ExecContext(ctx, q, group.Name, group.Description, util.GetTimeAsMsSinceEpoch(time.Now()),
			util.GetTimeAsMsSinceEpoch(time.Now()), settings)
		if err != nil {
			return err
		}
		return generateGroupVirtualFoldersMapping(ctx, group, tx)
	})
}

func sqlCommonUpdateGroup(group *Group, dbHandle *sql.DB) error {
	if err := group.validate(); err != nil {
		return err
	}

	settings, err := json.Marshal(group.UserSettings)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getUpdateGroupQuery()
		_, err := tx.ExecContext(ctx, q, group.Description, settings, util.GetTimeAsMsSinceEpoch(time.Now()), group.Name)
		if err != nil {
			return err
		}
		return generateGroupVirtualFoldersMapping(ctx, group, tx)
	})
}

func sqlCommonDeleteGroup(group Group, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteGroupQuery()
	res, err := dbHandle.ExecContext(ctx, q, group.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetUserByUsername(username, role string, dbHandle sqlQuerier) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUserByUsernameQuery(role)
	args := []any{username}
	if role != "" {
		args = append(args, role)
	}
	row := dbHandle.QueryRowContext(ctx, q, args...)
	user, err := getUserFromDbRow(row)
	if err != nil {
		return user, err
	}
	user, err = getUserWithVirtualFolders(ctx, user, dbHandle)
	if err != nil {
		return user, err
	}
	return getUserWithGroups(ctx, user, dbHandle)
}

func sqlCommonValidateUserAndPass(username, password, ip, protocol string, dbHandle *sql.DB) (User, error) {
	user, err := sqlCommonGetUserByUsername(username, "", dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}
	return checkUserAndPass(&user, password, ip, protocol)
}

func sqlCommonValidateUserAndTLSCertificate(username, protocol string, tlsCert *x509.Certificate, dbHandle *sql.DB) (User, error) {
	var user User
	if tlsCert == nil {
		return user, errors.New("TLS certificate cannot be null or empty")
	}
	user, err := sqlCommonGetUserByUsername(username, "", dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}
	return checkUserAndTLSCertificate(&user, protocol, tlsCert)
}

func sqlCommonValidateUserAndPubKey(username string, pubKey []byte, isSSHCert bool, dbHandle *sql.DB) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}
	user, err := sqlCommonGetUserByUsername(username, "", dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey, isSSHCert)
}

func sqlCommonCheckAvailability(dbHandle *sql.DB) (err error) {
	defer func() {
		if r := recover(); r != nil {
			providerLog(logger.LevelError, "panic in check provider availability, stack trace: %s", string(debug.Stack()))
			err = errors.New("unable to check provider status")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	err = dbHandle.PingContext(ctx)
	return
}

func sqlCommonUpdateTransferQuota(username string, uploadSize, downloadSize int64, reset bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateTransferQuotaQuery(reset)
	_, err := dbHandle.ExecContext(ctx, q, uploadSize, downloadSize, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "transfer quota updated for user %q, ul increment: %d dl increment: %d is reset? %t",
			username, uploadSize, downloadSize, reset)
	} else {
		providerLog(logger.LevelError, "error updating quota for user %q: %v", username, err)
	}
	return err
}

func sqlCommonUpdateQuota(username string, filesAdd int, sizeAdd int64, reset bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateQuotaQuery(reset)
	_, err := dbHandle.ExecContext(ctx, q, sizeAdd, filesAdd, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "quota updated for user %q, files increment: %d size increment: %d is reset? %t",
			username, filesAdd, sizeAdd, reset)
	} else {
		providerLog(logger.LevelError, "error updating quota for user %q: %v", username, err)
	}
	return err
}

func sqlCommonGetAdminSignature(username string, dbHandle *sql.DB) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAdminSignatureQuery()
	var updatedAt int64
	err := dbHandle.QueryRowContext(ctx, q, username).Scan(&updatedAt)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(updatedAt, 10), nil
}

func sqlCommonGetUserSignature(username string, dbHandle *sql.DB) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUserSignatureQuery()
	var updatedAt int64
	err := dbHandle.QueryRowContext(ctx, q, username).Scan(&updatedAt)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(updatedAt, 10), nil
}

func sqlCommonGetUsedQuota(username string, dbHandle *sql.DB) (int, int64, int64, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getQuotaQuery()
	var usedFiles int
	var usedSize, usedUploadSize, usedDownloadSize int64
	err := dbHandle.QueryRowContext(ctx, q, username).Scan(&usedSize, &usedFiles, &usedUploadSize, &usedDownloadSize)
	if err != nil {
		providerLog(logger.LevelError, "error getting quota for user: %v, error: %v", username, err)
		return 0, 0, 0, 0, err
	}
	return usedFiles, usedSize, usedUploadSize, usedDownloadSize, err
}

func sqlCommonUpdateShareLastUse(shareID string, numTokens int, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateShareLastUseQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), numTokens, shareID)
	if err == nil {
		providerLog(logger.LevelDebug, "last use updated for shared object %q", shareID)
	} else {
		providerLog(logger.LevelWarn, "error updating last use for shared object %q: %v", shareID, err)
	}
	return err
}

func sqlCommonUpdateAPIKeyLastUse(keyID string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateAPIKeyLastUseQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), keyID)
	if err == nil {
		providerLog(logger.LevelDebug, "last use updated for key %q", keyID)
	} else {
		providerLog(logger.LevelWarn, "error updating last use for key %q: %v", keyID, err)
	}
	return err
}

func sqlCommonUpdateAdminLastLogin(username string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateAdminLastLoginQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "last login updated for admin %q", username)
	} else {
		providerLog(logger.LevelWarn, "error updating last login for admin %q: %v", username, err)
	}
	return err
}

func sqlCommonSetUpdatedAt(username string, dbHandle *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getSetUpdateAtQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "updated_at set for user %q", username)
	} else {
		providerLog(logger.LevelWarn, "error setting updated_at for user %q: %v", username, err)
	}
}

func sqlCommonSetFirstDownloadTimestamp(username string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getSetFirstDownloadQuery()
	res, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonSetFirstUploadTimestamp(username string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getSetFirstUploadQuery()
	res, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonUpdateLastLogin(username string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateLastLoginQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "last login updated for user %q", username)
	} else {
		providerLog(logger.LevelWarn, "error updating last login for user %q: %v", username, err)
	}
	return err
}

func sqlCommonAddUser(user *User, dbHandle *sql.DB) error {
	err := ValidateUser(user)
	if err != nil {
		return err
	}

	permissions, err := user.GetPermissionsAsJSON()
	if err != nil {
		return err
	}
	publicKeys, err := user.GetPublicKeysAsJSON()
	if err != nil {
		return err
	}
	filters, err := user.GetFiltersAsJSON()
	if err != nil {
		return err
	}
	fsConfig, err := user.GetFsConfigAsJSON()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		if config.IsShared == 1 {
			_, err := tx.ExecContext(ctx, getRemoveSoftDeletedUserQuery(), user.Username)
			if err != nil {
				return err
			}
		}
		q := getAddUserQuery(user.Role)
		_, err := tx.ExecContext(ctx, q, user.Username, user.Password, publicKeys, user.HomeDir, user.UID, user.GID,
			user.MaxSessions, user.QuotaSize, user.QuotaFiles, permissions, user.UploadBandwidth,
			user.DownloadBandwidth, user.Status, user.ExpirationDate, filters, fsConfig, user.AdditionalInfo,
			user.Description, user.Email, util.GetTimeAsMsSinceEpoch(time.Now()), util.GetTimeAsMsSinceEpoch(time.Now()),
			user.UploadDataTransfer, user.DownloadDataTransfer, user.TotalDataTransfer, user.Role, user.LastPasswordChange)
		if err != nil {
			return err
		}
		if err := generateUserVirtualFoldersMapping(ctx, user, tx); err != nil {
			return err
		}
		return generateUserGroupMapping(ctx, user, tx)
	})
}

func sqlCommonUpdateUserPassword(username, password string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateUserPasswordQuery()
	res, err := dbHandle.ExecContext(ctx, q, password, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonUpdateUser(user *User, dbHandle *sql.DB) error {
	err := ValidateUser(user)
	if err != nil {
		return err
	}

	permissions, err := user.GetPermissionsAsJSON()
	if err != nil {
		return err
	}
	publicKeys, err := user.GetPublicKeysAsJSON()
	if err != nil {
		return err
	}
	filters, err := user.GetFiltersAsJSON()
	if err != nil {
		return err
	}
	fsConfig, err := user.GetFsConfigAsJSON()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getUpdateUserQuery(user.Role)
		res, err := tx.ExecContext(ctx, q, user.Password, publicKeys, user.HomeDir, user.UID, user.GID, user.MaxSessions,
			user.QuotaSize, user.QuotaFiles, permissions, user.UploadBandwidth, user.DownloadBandwidth, user.Status,
			user.ExpirationDate, filters, fsConfig, user.AdditionalInfo, user.Description, user.Email,
			util.GetTimeAsMsSinceEpoch(time.Now()), user.UploadDataTransfer, user.DownloadDataTransfer, user.TotalDataTransfer,
			user.Role, user.LastPasswordChange, user.Username)
		if err != nil {
			return err
		}
		if err := sqlCommonRequireRowAffected(res); err != nil {
			return err
		}
		if err := generateUserVirtualFoldersMapping(ctx, user, tx); err != nil {
			return err
		}
		return generateUserGroupMapping(ctx, user, tx)
	})
}

func sqlCommonDeleteUser(user User, softDelete bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteUserQuery(softDelete)
	if softDelete {
		return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
			if err := sqlCommonClearUserFolderMapping(ctx, &user, tx); err != nil {
				return err
			}
			if err := sqlCommonClearUserGroupMapping(ctx, &user, tx); err != nil {
				return err
			}
			ts := util.GetTimeAsMsSinceEpoch(time.Now())
			res, err := tx.ExecContext(ctx, q, ts, ts, user.Username)
			if err != nil {
				return err
			}
			return sqlCommonRequireRowAffected(res)
		})
	}
	res, err := dbHandle.ExecContext(ctx, q, user.Username)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDumpUsers(dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, 100)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpUsersQuery()
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return users, err
	}

	defer rows.Close()
	for rows.Next() {
		u, err := getUserFromDbRow(rows)
		if err != nil {
			return users, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	users, err = getUsersWithVirtualFolders(ctx, users, dbHandle)
	if err != nil {
		return users, err
	}
	return getUsersWithGroups(ctx, users, dbHandle)
}

func sqlCommonGetRecentlyUpdatedUsers(after int64, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, 10)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getRecentlyUpdatedUsersQuery()

	rows, err := dbHandle.QueryContext(ctx, q, after)
	if err != nil {
		return users, err
	}
	defer rows.Close()

	for rows.Next() {
		u, err := getUserFromDbRow(rows)
		if err != nil {
			return users, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	users, err = getUsersWithVirtualFolders(ctx, users, dbHandle)
	if err != nil {
		return users, err
	}
	users, err = getUsersWithGroups(ctx, users, dbHandle)
	if err != nil {
		return users, err
	}
	var groupNames []string
	for _, u := range users {
		for _, g := range u.Groups {
			groupNames = append(groupNames, g.Name)
		}
	}
	groupNames = util.RemoveDuplicates(groupNames, false)
	if len(groupNames) == 0 {
		return users, nil
	}
	groups, err := sqlCommonGetGroupsWithNames(groupNames, dbHandle)
	if err != nil {
		return users, err
	}
	if len(groups) == 0 {
		return users, nil
	}
	groupsMapping := make(map[string]Group)
	for idx := range groups {
		groupsMapping[groups[idx].Name] = groups[idx]
	}
	for idx := range users {
		ref := &users[idx]
		ref.applyGroupSettings(groupsMapping)
	}
	return users, nil
}

func sqlGetMaxUsersForQuotaCheckRange() int {
	maxUsers := 50
	if maxUsers > len(sqlPlaceholders) {
		maxUsers = len(sqlPlaceholders)
	}
	return maxUsers
}

func sqlCommonGetUsersForQuotaCheck(toFetch map[string]bool, dbHandle sqlQuerier) ([]User, error) {
	maxUsers := sqlGetMaxUsersForQuotaCheckRange()
	users := make([]User, 0, maxUsers)

	usernames := make([]string, 0, len(toFetch))
	for k := range toFetch {
		usernames = append(usernames, k)
	}

	for len(usernames) > 0 {
		if maxUsers > len(usernames) {
			maxUsers = len(usernames)
		}
		usersRange, err := sqlCommonGetUsersRangeForQuotaCheck(usernames[:maxUsers], dbHandle)
		if err != nil {
			return users, err
		}
		users = append(users, usersRange...)
		usernames = usernames[maxUsers:]
	}

	var usersWithFolders []User

	validIdx := 0
	for _, user := range users {
		if toFetch[user.Username] {
			usersWithFolders = append(usersWithFolders, user)
		} else {
			users[validIdx] = user
			validIdx++
		}
	}
	users = users[:validIdx]
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	usersWithFolders, err := getUsersWithVirtualFolders(ctx, usersWithFolders, dbHandle)
	if err != nil {
		return users, err
	}
	users = append(users, usersWithFolders...)
	users, err = getUsersWithGroups(ctx, users, dbHandle)
	if err != nil {
		return users, err
	}
	var groupNames []string
	for _, u := range users {
		for _, g := range u.Groups {
			groupNames = append(groupNames, g.Name)
		}
	}
	groupNames = util.RemoveDuplicates(groupNames, false)
	if len(groupNames) == 0 {
		return users, nil
	}
	groups, err := sqlCommonGetGroupsWithNames(groupNames, dbHandle)
	if err != nil {
		return users, err
	}
	groupsMapping := make(map[string]Group)
	for idx := range groups {
		groupsMapping[groups[idx].Name] = groups[idx]
	}
	for idx := range users {
		ref := &users[idx]
		ref.applyGroupSettings(groupsMapping)
	}
	return users, nil
}

func sqlCommonGetUsersRangeForQuotaCheck(usernames []string, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, len(usernames))
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUsersForQuotaCheckQuery(len(usernames))
	queryArgs := make([]any, 0, len(usernames))
	for idx := range usernames {
		queryArgs = append(queryArgs, usernames[idx])
	}

	rows, err := dbHandle.QueryContext(ctx, q, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		var filters []byte
		err = rows.Scan(&user.ID, &user.Username, &user.QuotaSize, &user.UsedQuotaSize, &user.TotalDataTransfer,
			&user.UploadDataTransfer, &user.DownloadDataTransfer, &user.UsedUploadDataTransfer,
			&user.UsedDownloadDataTransfer, &filters)
		if err != nil {
			return users, err
		}
		var userFilters UserFilters
		err = json.Unmarshal(filters, &userFilters)
		if err == nil {
			user.Filters = userFilters
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

func sqlCommonAddActiveTransfer(transfer ActiveTransfer, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddActiveTransferQuery()
	now := util.GetTimeAsMsSinceEpoch(time.Now())
	_, err := dbHandle.ExecContext(ctx, q, transfer.ID, transfer.ConnID, transfer.Type, transfer.Username,
		transfer.FolderName, transfer.IP, transfer.TruncatedSize, transfer.CurrentULSize, transfer.CurrentDLSize,
		now, now)
	return err
}

func sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateActiveTransferSizesQuery()
	_, err := dbHandle.ExecContext(ctx, q, ulSize, dlSize, util.GetTimeAsMsSinceEpoch(time.Now()), connectionID, transferID)
	return err
}

func sqlCommonRemoveActiveTransfer(transferID int64, connectionID string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getRemoveActiveTransferQuery()
	_, err := dbHandle.ExecContext(ctx, q, connectionID, transferID)
	return err
}

func sqlCommonCleanupActiveTransfers(before time.Time, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getCleanupActiveTransfersQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(before))
	return err
}

func sqlCommonGetActiveTransfers(from time.Time, dbHandle sqlQuerier) ([]ActiveTransfer, error) {
	transfers := make([]ActiveTransfer, 0, 30)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getActiveTransfersQuery()
	rows, err := dbHandle.QueryContext(ctx, q, util.GetTimeAsMsSinceEpoch(from))
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var transfer ActiveTransfer
		var folderName sql.NullString
		err = rows.Scan(&transfer.ID, &transfer.ConnID, &transfer.Type, &transfer.Username, &folderName, &transfer.IP,
			&transfer.TruncatedSize, &transfer.CurrentULSize, &transfer.CurrentDLSize, &transfer.CreatedAt,
			&transfer.UpdatedAt)
		if err != nil {
			return transfers, err
		}
		if folderName.Valid {
			transfer.FolderName = folderName.String
		}
		transfers = append(transfers, transfer)
	}

	return transfers, rows.Err()
}

func sqlCommonGetUsers(limit int, offset int, order, role string, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUsersQuery(order, role)
	var args []any
	if role == "" {
		args = append(args, limit, offset)
	} else {
		args = append(args, role, limit, offset)
	}
	rows, err := dbHandle.QueryContext(ctx, q, args...)
	if err != nil {
		return users, err
	}
	defer rows.Close()

	for rows.Next() {
		u, err := getUserFromDbRow(rows)
		if err != nil {
			return users, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	users, err = getUsersWithVirtualFolders(ctx, users, dbHandle)
	if err != nil {
		return users, err
	}
	users, err = getUsersWithGroups(ctx, users, dbHandle)
	if err != nil {
		return users, err
	}
	for idx := range users {
		users[idx].PrepareForRendering()
	}
	return users, nil
}

func sqlCommonGetDefenderHosts(from int64, limit int, dbHandle sqlQuerier) ([]DefenderEntry, error) {
	hosts := make([]DefenderEntry, 0, 100)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderHostsQuery()
	rows, err := dbHandle.QueryContext(ctx, q, from, limit)
	if err != nil {
		providerLog(logger.LevelError, "unable to get defender hosts: %v", err)
		return hosts, err
	}
	defer rows.Close()

	var idForScores []int64

	for rows.Next() {
		var banTime sql.NullInt64
		host := DefenderEntry{}
		err = rows.Scan(&host.ID, &host.IP, &banTime)
		if err != nil {
			providerLog(logger.LevelError, "unable to scan defender host row: %v", err)
			return hosts, err
		}
		var hostBanTime time.Time
		if banTime.Valid && banTime.Int64 > 0 {
			hostBanTime = util.GetTimeFromMsecSinceEpoch(banTime.Int64)
		}
		if hostBanTime.IsZero() || hostBanTime.Before(time.Now()) {
			idForScores = append(idForScores, host.ID)
		} else {
			host.BanTime = hostBanTime
		}
		hosts = append(hosts, host)
	}
	err = rows.Err()
	if err != nil {
		providerLog(logger.LevelError, "unable to iterate over defender host rows: %v", err)
		return hosts, err
	}

	return getDefenderHostsWithScores(ctx, hosts, from, idForScores, dbHandle)
}

func sqlCommonIsDefenderHostBanned(ip string, dbHandle sqlQuerier) (DefenderEntry, error) {
	var host DefenderEntry

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderIsHostBannedQuery()
	row := dbHandle.QueryRowContext(ctx, q, ip, util.GetTimeAsMsSinceEpoch(time.Now()))
	err := row.Scan(&host.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return host, util.NewRecordNotFoundError("host not found")
		}
		providerLog(logger.LevelError, "unable to check ban status for host %q: %v", ip, err)
		return host, err
	}

	return host, nil
}

func sqlCommonGetDefenderHostByIP(ip string, from int64, dbHandle sqlQuerier) (DefenderEntry, error) {
	var host DefenderEntry
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderHostQuery()
	row := dbHandle.QueryRowContext(ctx, q, ip, from)
	var banTime sql.NullInt64
	err := row.Scan(&host.ID, &host.IP, &banTime)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return host, util.NewRecordNotFoundError("host not found")
		}
		providerLog(logger.LevelError, "unable to get host for ip %q: %v", ip, err)
		return host, err
	}
	if banTime.Valid && banTime.Int64 > 0 {
		hostBanTime := util.GetTimeFromMsecSinceEpoch(banTime.Int64)
		if !hostBanTime.IsZero() && hostBanTime.After(time.Now()) {
			host.BanTime = hostBanTime
			return host, nil
		}
	}

	hosts, err := getDefenderHostsWithScores(ctx, []DefenderEntry{host}, from, []int64{host.ID}, dbHandle)
	if err != nil {
		return host, err
	}
	if len(hosts) == 0 {
		return host, util.NewRecordNotFoundError("host not found")
	}

	return hosts[0], nil
}

func sqlCommonDefenderIncrementBanTime(ip string, minutesToAdd int, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderIncrementBanTimeQuery()
	_, err := dbHandle.ExecContext(ctx, q, minutesToAdd*60000, ip)
	if err == nil {
		providerLog(logger.LevelDebug, "ban time updated for ip %q, increment (minutes): %v",
			ip, minutesToAdd)
	} else {
		providerLog(logger.LevelError, "error updating ban time for ip %q: %v", ip, err)
	}
	return err
}

func sqlCommonSetDefenderBanTime(ip string, banTime int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderSetBanTimeQuery()
	_, err := dbHandle.ExecContext(ctx, q, banTime, ip)
	if err == nil {
		providerLog(logger.LevelDebug, "ip %q banned until %v", ip, util.GetTimeFromMsecSinceEpoch(banTime))
	} else {
		providerLog(logger.LevelError, "error setting ban time for ip %q: %v", ip, err)
	}
	return err
}

func sqlCommonDeleteDefenderHost(ip string, dbHandle sqlQuerier) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteDefenderHostQuery()
	res, err := dbHandle.ExecContext(ctx, q, ip)
	if err != nil {
		providerLog(logger.LevelError, "unable to delete defender host %q: %v", ip, err)
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonAddDefenderHostAndEvent(ip string, score int, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		if err := sqlCommonAddDefenderHost(ctx, ip, tx); err != nil {
			return err
		}
		return sqlCommonAddDefenderEvent(ctx, ip, score, tx)
	})
}

func sqlCommonDefenderCleanup(from int64, dbHandler *sql.DB) error {
	if err := sqlCommonCleanupDefenderEvents(from, dbHandler); err != nil {
		return err
	}
	return sqlCommonCleanupDefenderHosts(from, dbHandler)
}

func sqlCommonAddDefenderHost(ctx context.Context, ip string, tx *sql.Tx) error {
	q := getAddDefenderHostQuery()
	_, err := tx.ExecContext(ctx, q, ip, util.GetTimeAsMsSinceEpoch(time.Now()))
	if err != nil {
		providerLog(logger.LevelError, "unable to add defender host %q: %v", ip, err)
	}
	return err
}

func sqlCommonAddDefenderEvent(ctx context.Context, ip string, score int, tx *sql.Tx) error {
	q := getAddDefenderEventQuery()
	_, err := tx.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), score, ip)
	if err != nil {
		providerLog(logger.LevelError, "unable to add defender event for %q: %v", ip, err)
	}
	return err
}

func sqlCommonCleanupDefenderHosts(from int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderHostsCleanupQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), from)
	if err != nil {
		providerLog(logger.LevelError, "unable to cleanup defender hosts: %v", err)
	}
	return err
}

func sqlCommonCleanupDefenderEvents(from int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderEventsCleanupQuery()
	_, err := dbHandle.ExecContext(ctx, q, from)
	if err != nil {
		providerLog(logger.LevelError, "unable to cleanup defender events: %v", err)
	}
	return err
}

func getShareFromDbRow(row sqlScanner) (Share, error) {
	var share Share
	var description, password sql.NullString
	var allowFrom, paths []byte

	err := row.Scan(&share.ShareID, &share.Name, &description, &share.Scope,
		&paths, &share.Username, &share.CreatedAt, &share.UpdatedAt,
		&share.LastUseAt, &share.ExpiresAt, &password, &share.MaxTokens,
		&share.UsedTokens, &allowFrom)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return share, util.NewRecordNotFoundError(err.Error())
		}
		return share, err
	}
	var list []string
	err = json.Unmarshal(paths, &list)
	if err != nil {
		return share, err
	}
	share.Paths = list
	if description.Valid {
		share.Description = description.String
	}
	if password.Valid {
		share.Password = password.String
	}
	list = nil
	err = json.Unmarshal(allowFrom, &list)
	if err == nil {
		share.AllowFrom = list
	}
	return share, nil
}

func getAPIKeyFromDbRow(row sqlScanner) (APIKey, error) {
	var apiKey APIKey
	var userID, adminID sql.NullInt64
	var description sql.NullString

	err := row.Scan(&apiKey.KeyID, &apiKey.Name, &apiKey.Key, &apiKey.Scope, &apiKey.CreatedAt, &apiKey.UpdatedAt,
		&apiKey.LastUseAt, &apiKey.ExpiresAt, &description, &userID, &adminID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apiKey, util.NewRecordNotFoundError(err.Error())
		}
		return apiKey, err
	}

	if userID.Valid {
		apiKey.userID = userID.Int64
	}
	if adminID.Valid {
		apiKey.adminID = adminID.Int64
	}
	if description.Valid {
		apiKey.Description = description.String
	}

	return apiKey, nil
}

func getAdminFromDbRow(row sqlScanner) (Admin, error) {
	var admin Admin
	var email, additionalInfo, description, role sql.NullString
	var permissions, filters []byte

	err := row.Scan(&admin.ID, &admin.Username, &admin.Password, &admin.Status, &email, &permissions,
		&filters, &additionalInfo, &description, &admin.CreatedAt, &admin.UpdatedAt, &admin.LastLogin, &role)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return admin, util.NewRecordNotFoundError(err.Error())
		}
		return admin, err
	}

	var perms []string
	err = json.Unmarshal(permissions, &perms)
	if err != nil {
		return admin, err
	}
	admin.Permissions = perms

	if email.Valid {
		admin.Email = email.String
	}

	var adminFilters AdminFilters
	err = json.Unmarshal(filters, &adminFilters)
	if err == nil {
		admin.Filters = adminFilters
	}
	if additionalInfo.Valid {
		admin.AdditionalInfo = additionalInfo.String
	}
	if description.Valid {
		admin.Description = description.String
	}
	if role.Valid {
		admin.Role = role.String
	}

	admin.SetEmptySecretsIfNil()
	return admin, nil
}

func getEventActionFromDbRow(row sqlScanner) (BaseEventAction, error) {
	var action BaseEventAction
	var description sql.NullString
	var options []byte

	err := row.Scan(&action.ID, &action.Name, &description, &action.Type, &options)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return action, util.NewRecordNotFoundError(err.Error())
		}
		return action, err
	}
	if description.Valid {
		action.Description = description.String
	}
	var actionOptions BaseEventActionOptions
	err = json.Unmarshal(options, &actionOptions)
	if err == nil {
		action.Options = actionOptions
	}
	return action, nil
}

func getEventRuleFromDbRow(row sqlScanner) (EventRule, error) {
	var rule EventRule
	var description sql.NullString
	var conditions []byte

	err := row.Scan(&rule.ID, &rule.Name, &description, &rule.CreatedAt, &rule.UpdatedAt, &rule.Trigger,
		&conditions, &rule.DeletedAt, &rule.Status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rule, util.NewRecordNotFoundError(err.Error())
		}
		return rule, err
	}
	var ruleConditions EventConditions
	err = json.Unmarshal(conditions, &ruleConditions)
	if err == nil {
		rule.Conditions = ruleConditions
	}

	if description.Valid {
		rule.Description = description.String
	}
	return rule, nil
}

func getIPListEntryFromDbRow(row sqlScanner) (IPListEntry, error) {
	var entry IPListEntry
	var description sql.NullString

	err := row.Scan(&entry.Type, &entry.IPOrNet, &entry.Mode, &entry.Protocols, &description,
		&entry.CreatedAt, &entry.UpdatedAt, &entry.DeletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entry, util.NewRecordNotFoundError(err.Error())
		}
		return entry, err
	}
	if description.Valid {
		entry.Description = description.String
	}
	return entry, err
}

func getRoleFromDbRow(row sqlScanner) (Role, error) {
	var role Role
	var description sql.NullString

	err := row.Scan(&role.ID, &role.Name, &description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return role, util.NewRecordNotFoundError(err.Error())
		}
		return role, err
	}
	if description.Valid {
		role.Description = description.String
	}

	return role, nil
}

func getGroupFromDbRow(row sqlScanner) (Group, error) {
	var group Group
	var description sql.NullString
	var userSettings []byte

	err := row.Scan(&group.ID, &group.Name, &description, &group.CreatedAt, &group.UpdatedAt, &userSettings)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return group, util.NewRecordNotFoundError(err.Error())
		}
		return group, err
	}
	if description.Valid {
		group.Description = description.String
	}

	var settings GroupUserSettings
	err = json.Unmarshal(userSettings, &settings)
	if err == nil {
		group.UserSettings = settings
	}

	return group, nil
}

func getUserFromDbRow(row sqlScanner) (User, error) {
	var user User
	var password sql.NullString
	var permissions, publicKey, filters, fsConfig []byte
	var additionalInfo, description, email, role sql.NullString

	err := row.Scan(&user.ID, &user.Username, &password, &publicKey, &user.HomeDir, &user.UID, &user.GID, &user.MaxSessions,
		&user.QuotaSize, &user.QuotaFiles, &permissions, &user.UsedQuotaSize, &user.UsedQuotaFiles, &user.LastQuotaUpdate,
		&user.UploadBandwidth, &user.DownloadBandwidth, &user.ExpirationDate, &user.LastLogin, &user.Status, &filters, &fsConfig,
		&additionalInfo, &description, &email, &user.CreatedAt, &user.UpdatedAt, &user.UploadDataTransfer, &user.DownloadDataTransfer,
		&user.TotalDataTransfer, &user.UsedUploadDataTransfer, &user.UsedDownloadDataTransfer, &user.DeletedAt, &user.FirstDownload,
		&user.FirstUpload, &role, &user.LastPasswordChange)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, util.NewRecordNotFoundError(err.Error())
		}
		return user, err
	}
	if password.Valid {
		user.Password = password.String
	}
	perms := make(map[string][]string)
	err = json.Unmarshal(permissions, &perms)
	if err != nil {
		providerLog(logger.LevelError, "unable to deserialize permissions for user %q: %v", user.Username, err)
		return user, fmt.Errorf("unable to deserialize permissions for user %q: %v", user.Username, err)
	}
	user.Permissions = perms
	// we can have a empty string or an invalid json in null string
	// so we do a relaxed test if the field is optional, for example we
	// populate public keys only if unmarshal does not return an error
	var pKeys []string
	err = json.Unmarshal(publicKey, &pKeys)
	if err == nil {
		user.PublicKeys = pKeys
	}
	var userFilters UserFilters
	err = json.Unmarshal(filters, &userFilters)
	if err == nil {
		user.Filters = userFilters
	}
	var fs vfs.Filesystem
	err = json.Unmarshal(fsConfig, &fs)
	if err == nil {
		user.FsConfig = fs
	}
	if additionalInfo.Valid {
		user.AdditionalInfo = additionalInfo.String
	}
	if description.Valid {
		user.Description = description.String
	}
	if email.Valid {
		user.Email = email.String
	}
	if role.Valid {
		user.Role = role.String
	}
	user.SetEmptySecretsIfNil()
	return user, nil
}

func sqlCommonGetFolder(ctx context.Context, name string, dbHandle sqlQuerier) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	q := getFolderByNameQuery()
	row := dbHandle.QueryRowContext(ctx, q, name)
	var mappedPath, description sql.NullString
	var fsConfig []byte
	err := row.Scan(&folder.ID, &mappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles, &folder.LastQuotaUpdate,
		&folder.Name, &description, &fsConfig)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return folder, util.NewRecordNotFoundError(err.Error())
		}
		return folder, err
	}
	if mappedPath.Valid {
		folder.MappedPath = mappedPath.String
	}
	if description.Valid {
		folder.Description = description.String
	}
	var fs vfs.Filesystem
	err = json.Unmarshal(fsConfig, &fs)
	if err == nil {
		folder.FsConfig = fs
	}
	return folder, err
}

func sqlCommonGetFolderByName(ctx context.Context, name string, dbHandle sqlQuerier) (vfs.BaseVirtualFolder, error) {
	folder, err := sqlCommonGetFolder(ctx, name, dbHandle)
	if err != nil {
		return folder, err
	}
	folders, err := getVirtualFoldersWithUsers([]vfs.BaseVirtualFolder{folder}, dbHandle)
	if err != nil {
		return folder, err
	}
	if len(folders) != 1 {
		return folder, fmt.Errorf("unable to associate users with folder %q", name)
	}
	folders, err = getVirtualFoldersWithGroups([]vfs.BaseVirtualFolder{folders[0]}, dbHandle)
	if err != nil {
		return folder, err
	}
	if len(folders) != 1 {
		return folder, fmt.Errorf("unable to associate groups with folder %q", name)
	}
	return folders[0], nil
}

func sqlCommonAddFolder(folder *vfs.BaseVirtualFolder, dbHandle sqlQuerier) error {
	err := ValidateFolder(folder)
	if err != nil {
		return err
	}
	fsConfig, err := json.Marshal(folder.FsConfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddFolderQuery()
	_, err = dbHandle.ExecContext(ctx, q, folder.MappedPath, folder.UsedQuotaSize, folder.UsedQuotaFiles,
		folder.LastQuotaUpdate, folder.Name, folder.Description, fsConfig)
	return err
}

func sqlCommonUpdateFolder(folder *vfs.BaseVirtualFolder, dbHandle sqlQuerier) error {
	err := ValidateFolder(folder)
	if err != nil {
		return err
	}
	fsConfig, err := json.Marshal(folder.FsConfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateFolderQuery()
	res, err := dbHandle.ExecContext(ctx, q, folder.MappedPath, folder.Description, fsConfig, folder.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDeleteFolder(folder vfs.BaseVirtualFolder, dbHandle sqlQuerier) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteFolderQuery()
	res, err := dbHandle.ExecContext(ctx, q, folder.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDumpFolders(dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, 50)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpFoldersQuery()
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return folders, err
	}
	defer rows.Close()
	for rows.Next() {
		var folder vfs.BaseVirtualFolder
		var mappedPath, description sql.NullString
		var fsConfig []byte
		err = rows.Scan(&folder.ID, &mappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles,
			&folder.LastQuotaUpdate, &folder.Name, &description, &fsConfig)
		if err != nil {
			return folders, err
		}
		if mappedPath.Valid {
			folder.MappedPath = mappedPath.String
		}
		if description.Valid {
			folder.Description = description.String
		}
		var fs vfs.Filesystem
		err = json.Unmarshal(fsConfig, &fs)
		if err == nil {
			folder.FsConfig = fs
		}
		folders = append(folders, folder)
	}
	return folders, rows.Err()
}

func sqlCommonGetFolders(limit, offset int, order string, minimal bool, dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getFoldersQuery(order, minimal)
	rows, err := dbHandle.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return folders, err
	}
	defer rows.Close()
	for rows.Next() {
		var folder vfs.BaseVirtualFolder
		if minimal {
			err = rows.Scan(&folder.ID, &folder.Name)
			if err != nil {
				return folders, err
			}
		} else {
			var mappedPath, description sql.NullString
			var fsConfig []byte
			err = rows.Scan(&folder.ID, &mappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles,
				&folder.LastQuotaUpdate, &folder.Name, &description, &fsConfig)
			if err != nil {
				return folders, err
			}
			if mappedPath.Valid {
				folder.MappedPath = mappedPath.String
			}
			if description.Valid {
				folder.Description = description.String
			}
			var fs vfs.Filesystem
			err = json.Unmarshal(fsConfig, &fs)
			if err == nil {
				folder.FsConfig = fs
			}
		}
		folder.PrepareForRendering()
		folders = append(folders, folder)
	}

	err = rows.Err()
	if err != nil {
		return folders, err
	}
	if minimal {
		return folders, nil
	}
	folders, err = getVirtualFoldersWithUsers(folders, dbHandle)
	if err != nil {
		return folders, err
	}
	return getVirtualFoldersWithGroups(folders, dbHandle)
}

func sqlCommonClearUserFolderMapping(ctx context.Context, user *User, dbHandle sqlQuerier) error {
	q := getClearUserFolderMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, user.Username)
	return err
}

func sqlCommonClearGroupFolderMapping(ctx context.Context, group *Group, dbHandle sqlQuerier) error {
	q := getClearGroupFolderMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, group.Name)
	return err
}

func sqlCommonClearUserGroupMapping(ctx context.Context, user *User, dbHandle sqlQuerier) error {
	q := getClearUserGroupMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, user.Username)
	return err
}

func sqlCommonAddUserFolderMapping(ctx context.Context, user *User, folder *vfs.VirtualFolder, dbHandle sqlQuerier) error {
	q := getAddUserFolderMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, folder.VirtualPath, folder.QuotaSize, folder.QuotaFiles, folder.Name, user.Username)
	return err
}

func sqlCommonClearAdminGroupMapping(ctx context.Context, admin *Admin, dbHandle sqlQuerier) error {
	q := getClearAdminGroupMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, admin.Username)
	return err
}

func sqlCommonAddGroupFolderMapping(ctx context.Context, group *Group, folder *vfs.VirtualFolder, dbHandle sqlQuerier) error {
	q := getAddGroupFolderMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, folder.VirtualPath, folder.QuotaSize, folder.QuotaFiles, folder.Name, group.Name)
	return err
}

func sqlCommonAddUserGroupMapping(ctx context.Context, username, groupName string, groupType int, dbHandle sqlQuerier) error {
	q := getAddUserGroupMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, username, groupName, groupType)
	return err
}

func sqlCommonAddAdminGroupMapping(ctx context.Context, username, groupName string, mappingOptions AdminGroupMappingOptions,
	dbHandle sqlQuerier,
) error {
	options, err := json.Marshal(mappingOptions)
	if err != nil {
		return err
	}
	q := getAddAdminGroupMappingQuery()
	_, err = dbHandle.ExecContext(ctx, q, username, groupName, options)
	return err
}

func generateGroupVirtualFoldersMapping(ctx context.Context, group *Group, dbHandle sqlQuerier) error {
	err := sqlCommonClearGroupFolderMapping(ctx, group, dbHandle)
	if err != nil {
		return err
	}
	for idx := range group.VirtualFolders {
		vfolder := &group.VirtualFolders[idx]
		err = sqlCommonAddGroupFolderMapping(ctx, group, vfolder, dbHandle)
		if err != nil {
			return err
		}
	}
	return err
}

func generateUserVirtualFoldersMapping(ctx context.Context, user *User, dbHandle sqlQuerier) error {
	err := sqlCommonClearUserFolderMapping(ctx, user, dbHandle)
	if err != nil {
		return err
	}
	for idx := range user.VirtualFolders {
		vfolder := &user.VirtualFolders[idx]
		err = sqlCommonAddUserFolderMapping(ctx, user, vfolder, dbHandle)
		if err != nil {
			return err
		}
	}
	return err
}

func generateUserGroupMapping(ctx context.Context, user *User, dbHandle sqlQuerier) error {
	err := sqlCommonClearUserGroupMapping(ctx, user, dbHandle)
	if err != nil {
		return err
	}
	for _, group := range user.Groups {
		err = sqlCommonAddUserGroupMapping(ctx, user.Username, group.Name, group.Type, dbHandle)
		if err != nil {
			return err
		}
	}
	return err
}

func generateAdminGroupMapping(ctx context.Context, admin *Admin, dbHandle sqlQuerier) error {
	err := sqlCommonClearAdminGroupMapping(ctx, admin, dbHandle)
	if err != nil {
		return err
	}
	for _, group := range admin.Groups {
		err = sqlCommonAddAdminGroupMapping(ctx, admin.Username, group.Name, group.Options, dbHandle)
		if err != nil {
			return err
		}
	}
	return err
}

func getDefenderHostsWithScores(ctx context.Context, hosts []DefenderEntry, from int64, idForScores []int64,
	dbHandle sqlQuerier) (
	[]DefenderEntry,
	error,
) {
	if len(idForScores) == 0 {
		return hosts, nil
	}

	hostsWithScores := make(map[int64]int)
	q := getDefenderEventsQuery(idForScores)
	rows, err := dbHandle.QueryContext(ctx, q, from)
	if err != nil {
		providerLog(logger.LevelError, "unable to get score for hosts with id %+v: %v", idForScores, err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var hostID int64
		var score int
		err = rows.Scan(&hostID, &score)
		if err != nil {
			providerLog(logger.LevelError, "error scanning host score row: %v", err)
			return hosts, err
		}
		if score > 0 {
			hostsWithScores[hostID] = score
		}
	}

	err = rows.Err()
	if err != nil {
		return hosts, err
	}

	result := make([]DefenderEntry, 0, len(hosts))

	for idx := range hosts {
		hosts[idx].Score = hostsWithScores[hosts[idx].ID]
		if hosts[idx].Score > 0 || !hosts[idx].BanTime.IsZero() {
			result = append(result, hosts[idx])
		}
	}

	return result, nil
}

func getAdminWithGroups(ctx context.Context, admin Admin, dbHandle sqlQuerier) (Admin, error) {
	admins, err := getAdminsWithGroups(ctx, []Admin{admin}, dbHandle)
	if err != nil {
		return admin, err
	}
	if len(admins) == 0 {
		return admin, errSQLGroupsAssociation
	}
	return admins[0], err
}

func getAdminsWithGroups(ctx context.Context, admins []Admin, dbHandle sqlQuerier) ([]Admin, error) {
	if len(admins) == 0 {
		return admins, nil
	}
	adminsGroups := make(map[int64][]AdminGroupMapping)
	q := getRelatedGroupsForAdminsQuery(admins)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var group AdminGroupMapping
		var adminID int64
		var options []byte
		err = rows.Scan(&group.Name, &options, &adminID)
		if err != nil {
			return admins, err
		}
		err = json.Unmarshal(options, &group.Options)
		if err != nil {
			return admins, err
		}
		adminsGroups[adminID] = append(adminsGroups[adminID], group)
	}
	err = rows.Err()
	if err != nil {
		return admins, err
	}
	if len(adminsGroups) == 0 {
		return admins, err
	}
	for idx := range admins {
		ref := &admins[idx]
		ref.Groups = adminsGroups[ref.ID]
	}
	return admins, err
}

func getUserWithVirtualFolders(ctx context.Context, user User, dbHandle sqlQuerier) (User, error) {
	users, err := getUsersWithVirtualFolders(ctx, []User{user}, dbHandle)
	if err != nil {
		return user, err
	}
	if len(users) == 0 {
		return user, errSQLFoldersAssociation
	}
	return users[0], err
}

func getUsersWithVirtualFolders(ctx context.Context, users []User, dbHandle sqlQuerier) ([]User, error) {
	if len(users) == 0 {
		return users, nil
	}

	usersVirtualFolders := make(map[int64][]vfs.VirtualFolder)
	q := getRelatedFoldersForUsersQuery(users)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var folder vfs.VirtualFolder
		var userID int64
		var mappedPath, description sql.NullString
		var fsConfig []byte
		err = rows.Scan(&folder.ID, &folder.Name, &mappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles,
			&folder.LastQuotaUpdate, &folder.VirtualPath, &folder.QuotaSize, &folder.QuotaFiles, &userID, &fsConfig,
			&description)
		if err != nil {
			return users, err
		}
		if mappedPath.Valid {
			folder.MappedPath = mappedPath.String
		}
		if description.Valid {
			folder.Description = description.String
		}
		var fs vfs.Filesystem
		err = json.Unmarshal(fsConfig, &fs)
		if err == nil {
			folder.FsConfig = fs
		}
		usersVirtualFolders[userID] = append(usersVirtualFolders[userID], folder)
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	if len(usersVirtualFolders) == 0 {
		return users, err
	}
	for idx := range users {
		ref := &users[idx]
		ref.VirtualFolders = usersVirtualFolders[ref.ID]
	}
	return users, err
}

func getUserWithGroups(ctx context.Context, user User, dbHandle sqlQuerier) (User, error) {
	users, err := getUsersWithGroups(ctx, []User{user}, dbHandle)
	if err != nil {
		return user, err
	}
	if len(users) == 0 {
		return user, errSQLGroupsAssociation
	}
	return users[0], err
}

func getUsersWithGroups(ctx context.Context, users []User, dbHandle sqlQuerier) ([]User, error) {
	if len(users) == 0 {
		return users, nil
	}
	usersGroups := make(map[int64][]sdk.GroupMapping)
	q := getRelatedGroupsForUsersQuery(users)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var group sdk.GroupMapping
		var userID int64
		err = rows.Scan(&group.Name, &group.Type, &userID)
		if err != nil {
			return users, err
		}
		usersGroups[userID] = append(usersGroups[userID], group)
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	if len(usersGroups) == 0 {
		return users, err
	}
	for idx := range users {
		ref := &users[idx]
		ref.Groups = usersGroups[ref.ID]
	}
	return users, err
}

func getGroupWithUsers(ctx context.Context, group Group, dbHandle sqlQuerier) (Group, error) {
	groups, err := getGroupsWithUsers(ctx, []Group{group}, dbHandle)
	if err != nil {
		return group, err
	}
	if len(groups) == 0 {
		return group, errSQLUsersAssociation
	}
	return groups[0], err
}

func getRoleWithUsers(ctx context.Context, role Role, dbHandle sqlQuerier) (Role, error) {
	roles, err := getRolesWithUsers(ctx, []Role{role}, dbHandle)
	if err != nil {
		return role, err
	}
	if len(roles) == 0 {
		return role, errors.New("unable to associate users with role")
	}
	return roles[0], err
}

func getRoleWithAdmins(ctx context.Context, role Role, dbHandle sqlQuerier) (Role, error) {
	roles, err := getRolesWithAdmins(ctx, []Role{role}, dbHandle)
	if err != nil {
		return role, err
	}
	if len(roles) == 0 {
		return role, errors.New("unable to associate admins with role")
	}
	return roles[0], err
}

func getGroupWithAdmins(ctx context.Context, group Group, dbHandle sqlQuerier) (Group, error) {
	groups, err := getGroupsWithAdmins(ctx, []Group{group}, dbHandle)
	if err != nil {
		return group, err
	}
	if len(groups) == 0 {
		return group, errSQLUsersAssociation
	}
	return groups[0], err
}

func getGroupWithVirtualFolders(ctx context.Context, group Group, dbHandle sqlQuerier) (Group, error) {
	groups, err := getGroupsWithVirtualFolders(ctx, []Group{group}, dbHandle)
	if err != nil {
		return group, err
	}
	if len(groups) == 0 {
		return group, errSQLFoldersAssociation
	}
	return groups[0], err
}

func getGroupsWithVirtualFolders(ctx context.Context, groups []Group, dbHandle sqlQuerier) ([]Group, error) {
	if len(groups) == 0 {
		return groups, nil
	}
	q := getRelatedFoldersForGroupsQuery(groups)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groupsVirtualFolders := make(map[int64][]vfs.VirtualFolder)

	for rows.Next() {
		var groupID int64
		var folder vfs.VirtualFolder
		var mappedPath, description sql.NullString
		var fsConfig []byte
		err = rows.Scan(&folder.ID, &folder.Name, &mappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles,
			&folder.LastQuotaUpdate, &folder.VirtualPath, &folder.QuotaSize, &folder.QuotaFiles, &groupID, &fsConfig,
			&description)
		if err != nil {
			return groups, err
		}
		if mappedPath.Valid {
			folder.MappedPath = mappedPath.String
		}
		if description.Valid {
			folder.Description = description.String
		}
		var fs vfs.Filesystem
		err = json.Unmarshal(fsConfig, &fs)
		if err == nil {
			folder.FsConfig = fs
		}
		groupsVirtualFolders[groupID] = append(groupsVirtualFolders[groupID], folder)
	}
	err = rows.Err()
	if err != nil {
		return groups, err
	}
	if len(groupsVirtualFolders) == 0 {
		return groups, err
	}
	for idx := range groups {
		ref := &groups[idx]
		ref.VirtualFolders = groupsVirtualFolders[ref.ID]
	}
	return groups, err
}

func getGroupsWithUsers(ctx context.Context, groups []Group, dbHandle sqlQuerier) ([]Group, error) {
	if len(groups) == 0 {
		return groups, nil
	}
	q := getRelatedUsersForGroupsQuery(groups)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groupsUsers := make(map[int64][]string)

	for rows.Next() {
		var username string
		var groupID int64
		err = rows.Scan(&groupID, &username)
		if err != nil {
			return groups, err
		}
		groupsUsers[groupID] = append(groupsUsers[groupID], username)
	}
	err = rows.Err()
	if err != nil {
		return groups, err
	}
	if len(groupsUsers) == 0 {
		return groups, err
	}
	for idx := range groups {
		ref := &groups[idx]
		ref.Users = groupsUsers[ref.ID]
	}
	return groups, err
}

func getRolesWithUsers(ctx context.Context, roles []Role, dbHandle sqlQuerier) ([]Role, error) {
	if len(roles) == 0 {
		return roles, nil
	}
	rows, err := dbHandle.QueryContext(ctx, getUsersWithRolesQuery(roles))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rolesUsers := make(map[int64][]string)
	for rows.Next() {
		var roleID int64
		var username string
		err = rows.Scan(&roleID, &username)
		if err != nil {
			return roles, err
		}
		rolesUsers[roleID] = append(rolesUsers[roleID], username)
	}
	err = rows.Err()
	if err != nil {
		return roles, err
	}
	if len(rolesUsers) > 0 {
		for idx := range roles {
			ref := &roles[idx]
			ref.Users = rolesUsers[ref.ID]
		}
	}
	return roles, nil
}

func getRolesWithAdmins(ctx context.Context, roles []Role, dbHandle sqlQuerier) ([]Role, error) {
	if len(roles) == 0 {
		return roles, nil
	}
	rows, err := dbHandle.QueryContext(ctx, getAdminsWithRolesQuery(roles))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rolesAdmins := make(map[int64][]string)
	for rows.Next() {
		var roleID int64
		var username string
		err = rows.Scan(&roleID, &username)
		if err != nil {
			return roles, err
		}
		rolesAdmins[roleID] = append(rolesAdmins[roleID], username)
	}
	if err = rows.Err(); err != nil {
		return roles, err
	}
	if len(rolesAdmins) > 0 {
		for idx := range roles {
			ref := &roles[idx]
			ref.Admins = rolesAdmins[ref.ID]
		}
	}
	return roles, nil
}

func getGroupsWithAdmins(ctx context.Context, groups []Group, dbHandle sqlQuerier) ([]Group, error) {
	if len(groups) == 0 {
		return groups, nil
	}
	q := getRelatedAdminsForGroupsQuery(groups)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groupsAdmins := make(map[int64][]string)
	for rows.Next() {
		var groupID int64
		var username string
		err = rows.Scan(&groupID, &username)
		if err != nil {
			return groups, err
		}
		groupsAdmins[groupID] = append(groupsAdmins[groupID], username)
	}
	err = rows.Err()
	if err != nil {
		return groups, err
	}
	if len(groupsAdmins) > 0 {
		for idx := range groups {
			ref := &groups[idx]
			ref.Admins = groupsAdmins[ref.ID]
		}
	}
	return groups, nil
}

func getVirtualFoldersWithGroups(folders []vfs.BaseVirtualFolder, dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	if len(folders) == 0 {
		return folders, nil
	}
	vFoldersGroups := make(map[int64][]string)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getRelatedGroupsForFoldersQuery(folders)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var folderID int64
		err = rows.Scan(&folderID, &name)
		if err != nil {
			return folders, err
		}
		vFoldersGroups[folderID] = append(vFoldersGroups[folderID], name)
	}
	err = rows.Err()
	if err != nil {
		return folders, err
	}
	if len(vFoldersGroups) == 0 {
		return folders, err
	}
	for idx := range folders {
		ref := &folders[idx]
		ref.Groups = vFoldersGroups[ref.ID]
	}
	return folders, err
}

func getVirtualFoldersWithUsers(folders []vfs.BaseVirtualFolder, dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	if len(folders) == 0 {
		return folders, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getRelatedUsersForFoldersQuery(folders)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vFoldersUsers := make(map[int64][]string)
	for rows.Next() {
		var username string
		var folderID int64
		err = rows.Scan(&folderID, &username)
		if err != nil {
			return folders, err
		}
		vFoldersUsers[folderID] = append(vFoldersUsers[folderID], username)
	}
	err = rows.Err()
	if err != nil {
		return folders, err
	}
	if len(vFoldersUsers) == 0 {
		return folders, err
	}
	for idx := range folders {
		ref := &folders[idx]
		ref.Users = vFoldersUsers[ref.ID]
	}
	return folders, err
}

func sqlCommonUpdateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateFolderQuotaQuery(reset)
	_, err := dbHandle.ExecContext(ctx, q, sizeAdd, filesAdd, util.GetTimeAsMsSinceEpoch(time.Now()), name)
	if err == nil {
		providerLog(logger.LevelDebug, "quota updated for folder %q, files increment: %d size increment: %d is reset? %t",
			name, filesAdd, sizeAdd, reset)
	} else {
		providerLog(logger.LevelWarn, "error updating quota for folder %q: %v", name, err)
	}
	return err
}

func sqlCommonGetFolderUsedQuota(mappedPath string, dbHandle *sql.DB) (int, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getQuotaFolderQuery()
	var usedFiles int
	var usedSize int64
	err := dbHandle.QueryRowContext(ctx, q, mappedPath).Scan(&usedSize, &usedFiles)
	if err != nil {
		providerLog(logger.LevelError, "error getting quota for folder: %v, error: %v", mappedPath, err)
		return 0, 0, err
	}
	return usedFiles, usedSize, err
}

func getAPIKeyWithRelatedFields(ctx context.Context, apiKey APIKey, dbHandle sqlQuerier) (APIKey, error) {
	var apiKeys []APIKey
	var err error

	scope := APIKeyScopeAdmin
	if apiKey.userID > 0 {
		scope = APIKeyScopeUser
	}
	apiKeys, err = getRelatedValuesForAPIKeys(ctx, []APIKey{apiKey}, dbHandle, scope)
	if err != nil {
		return apiKey, err
	}
	if len(apiKeys) > 0 {
		apiKey = apiKeys[0]
	}
	return apiKey, nil
}

func getRelatedValuesForAPIKeys(ctx context.Context, apiKeys []APIKey, dbHandle sqlQuerier, scope APIKeyScope) ([]APIKey, error) {
	if len(apiKeys) == 0 {
		return apiKeys, nil
	}
	values := make(map[int64]string)
	var q string
	if scope == APIKeyScopeUser {
		q = getRelatedUsersForAPIKeysQuery(apiKeys)
	} else {
		q = getRelatedAdminsForAPIKeysQuery(apiKeys)
	}
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var valueID int64
		var valueName string
		err = rows.Scan(&valueID, &valueName)
		if err != nil {
			return apiKeys, err
		}
		values[valueID] = valueName
	}
	err = rows.Err()
	if err != nil {
		return apiKeys, err
	}
	if len(values) == 0 {
		return apiKeys, nil
	}
	for idx := range apiKeys {
		ref := &apiKeys[idx]
		if scope == APIKeyScopeUser {
			ref.User = values[ref.userID]
		} else {
			ref.Admin = values[ref.adminID]
		}
	}
	return apiKeys, nil
}

func sqlCommonGetAPIKeyRelatedIDs(apiKey *APIKey) (sql.NullInt64, sql.NullInt64, error) {
	var userID, adminID sql.NullInt64
	if apiKey.User != "" {
		u, err := provider.userExists(apiKey.User, "")
		if err != nil {
			return userID, adminID, util.NewGenericError(fmt.Sprintf("unable to validate user %v", apiKey.User))
		}
		userID.Valid = true
		userID.Int64 = u.ID
	}
	if apiKey.Admin != "" {
		a, err := provider.adminExists(apiKey.Admin)
		if err != nil {
			return userID, adminID, util.NewValidationError(fmt.Sprintf("unable to validate admin %v", apiKey.Admin))
		}
		adminID.Valid = true
		adminID.Int64 = a.ID
	}
	return userID, adminID, nil
}

func sqlCommonAddSession(session Session, dbHandle *sql.DB) error {
	if err := session.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(session.Data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddSessionQuery()
	_, err = dbHandle.ExecContext(ctx, q, session.Key, data, session.Type, session.Timestamp)
	return err
}

func sqlCommonGetSession(key string, sessionType SessionType, dbHandle sqlQuerier) (Session, error) {
	var session Session
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getSessionQuery()
	var data []byte // type hint, some driver will use string instead of []byte if the type is any
	err := dbHandle.QueryRowContext(ctx, q, key, sessionType).Scan(&session.Key, &data, &session.Type, &session.Timestamp)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return session, util.NewRecordNotFoundError(err.Error())
		}
		return session, err
	}
	session.Data = data
	return session, nil
}

func sqlCommonDeleteSession(key string, sessionType SessionType, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteSessionQuery()
	res, err := dbHandle.ExecContext(ctx, q, key, sessionType)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonCleanupSessions(sessionType SessionType, before int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getCleanupSessionsQuery()
	_, err := dbHandle.ExecContext(ctx, q, sessionType, before)
	return err
}

func getActionsWithRuleNames(ctx context.Context, actions []BaseEventAction, dbHandle sqlQuerier,
) ([]BaseEventAction, error) {
	if len(actions) == 0 {
		return actions, nil
	}
	q := getRelatedRulesForActionsQuery(actions)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	actionsRules := make(map[int64][]string)
	for rows.Next() {
		var name string
		var actionID int64
		if err = rows.Scan(&actionID, &name); err != nil {
			return nil, err
		}
		actionsRules[actionID] = append(actionsRules[actionID], name)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	if len(actionsRules) == 0 {
		return actions, nil
	}
	for idx := range actions {
		ref := &actions[idx]
		ref.Rules = actionsRules[ref.ID]
	}
	return actions, nil
}

func getRulesWithActions(ctx context.Context, rules []EventRule, dbHandle sqlQuerier) ([]EventRule, error) {
	if len(rules) == 0 {
		return rules, nil
	}
	rulesActions := make(map[int64][]EventAction)
	q := getRelatedActionsForRulesQuery(rules)
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var action EventAction
		var ruleID int64
		var description sql.NullString
		var baseOptions, options []byte
		err = rows.Scan(&action.ID, &action.Name, &description, &action.Type, &baseOptions, &options,
			&action.Order, &ruleID)
		if err != nil {
			return rules, err
		}
		if len(baseOptions) > 0 {
			err = json.Unmarshal(baseOptions, &action.BaseEventAction.Options)
			if err != nil {
				return rules, err
			}
		}
		if len(options) > 0 {
			err = json.Unmarshal(options, &action.Options)
			if err != nil {
				return rules, err
			}
		}
		action.BaseEventAction.Options.SetEmptySecretsIfNil()
		rulesActions[ruleID] = append(rulesActions[ruleID], action)
	}
	err = rows.Err()
	if err != nil {
		return rules, err
	}
	if len(rulesActions) == 0 {
		return rules, nil
	}
	for idx := range rules {
		ref := &rules[idx]
		ref.Actions = rulesActions[ref.ID]
	}
	return rules, nil
}

func generateEventRuleActionsMapping(ctx context.Context, rule *EventRule, dbHandle sqlQuerier) error {
	q := getClearRuleActionMappingQuery()
	_, err := dbHandle.ExecContext(ctx, q, rule.Name)
	if err != nil {
		return err
	}
	for _, action := range rule.Actions {
		options, err := json.Marshal(action.Options)
		if err != nil {
			return err
		}
		q = getAddRuleActionMappingQuery()
		_, err = dbHandle.ExecContext(ctx, q, rule.Name, action.Name, action.Order, options)
		if err != nil {
			return err
		}
	}
	return nil
}

func sqlCommonGetEventActionByName(name string, dbHandle sqlQuerier) (BaseEventAction, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getEventActionByNameQuery()
	row := dbHandle.QueryRowContext(ctx, q, name)

	action, err := getEventActionFromDbRow(row)
	if err != nil {
		return action, err
	}
	actions, err := getActionsWithRuleNames(ctx, []BaseEventAction{action}, dbHandle)
	if err != nil {
		return action, err
	}
	if len(actions) != 1 {
		return action, fmt.Errorf("unable to associate rules with action %q", name)
	}
	return actions[0], nil
}

func sqlCommonDumpEventActions(dbHandle sqlQuerier) ([]BaseEventAction, error) {
	actions := make([]BaseEventAction, 0, 10)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpEventActionsQuery()
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return actions, err
	}
	defer rows.Close()

	for rows.Next() {
		action, err := getEventActionFromDbRow(rows)
		if err != nil {
			return actions, err
		}
		actions = append(actions, action)
	}
	return actions, rows.Err()
}

func sqlCommonGetEventActions(limit int, offset int, order string, minimal bool,
	dbHandle sqlQuerier,
) ([]BaseEventAction, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getEventsActionsQuery(order, minimal)

	actions := make([]BaseEventAction, 0, limit)
	rows, err := dbHandle.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return actions, err
	}
	defer rows.Close()

	for rows.Next() {
		var action BaseEventAction
		if minimal {
			err = rows.Scan(&action.ID, &action.Name)
		} else {
			action, err = getEventActionFromDbRow(rows)
		}
		if err != nil {
			return actions, err
		}
		actions = append(actions, action)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	if minimal {
		return actions, nil
	}
	actions, err = getActionsWithRuleNames(ctx, actions, dbHandle)
	if err != nil {
		return nil, err
	}
	for idx := range actions {
		actions[idx].PrepareForRendering()
	}
	return actions, nil
}

func sqlCommonAddEventAction(action *BaseEventAction, dbHandle *sql.DB) error {
	if err := action.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddEventActionQuery()
	options, err := json.Marshal(action.Options)
	if err != nil {
		return err
	}
	_, err = dbHandle.ExecContext(ctx, q, action.Name, action.Description, action.Type, options)
	return err
}

func sqlCommonUpdateEventAction(action *BaseEventAction, dbHandle *sql.DB) error {
	if err := action.validate(); err != nil {
		return err
	}
	options, err := json.Marshal(action.Options)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getUpdateEventActionQuery()
		res, err := tx.ExecContext(ctx, q, action.Description, action.Type, options, action.Name)
		if err != nil {
			return err
		}
		if err := sqlCommonRequireRowAffected(res); err != nil {
			return err
		}
		q = getUpdateRulesTimestampQuery()
		_, err = tx.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), action.Name)
		return err
	})
}

func sqlCommonDeleteEventAction(action BaseEventAction, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteEventActionQuery()
	res, err := dbHandle.ExecContext(ctx, q, action.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetEventRuleByName(name string, dbHandle sqlQuerier) (EventRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getEventRulesByNameQuery()
	row := dbHandle.QueryRowContext(ctx, q, name)
	rule, err := getEventRuleFromDbRow(row)
	if err != nil {
		return rule, err
	}
	rules, err := getRulesWithActions(ctx, []EventRule{rule}, dbHandle)
	if err != nil {
		return rule, err
	}
	if len(rules) != 1 {
		return rule, fmt.Errorf("unable to associate rule %q with actions", name)
	}
	return rules[0], nil
}

func sqlCommonDumpEventRules(dbHandle sqlQuerier) ([]EventRule, error) {
	rules := make([]EventRule, 0, 10)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpEventRulesQuery()
	rows, err := dbHandle.QueryContext(ctx, q)
	if err != nil {
		return rules, err
	}
	defer rows.Close()

	for rows.Next() {
		rule, err := getEventRuleFromDbRow(rows)
		if err != nil {
			return rules, err
		}
		rules = append(rules, rule)
	}
	err = rows.Err()
	if err != nil {
		return rules, err
	}
	return getRulesWithActions(ctx, rules, dbHandle)
}

func sqlCommonGetRecentlyUpdatedRules(after int64, dbHandle sqlQuerier) ([]EventRule, error) {
	rules := make([]EventRule, 0, 10)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getRecentlyUpdatedRulesQuery()
	rows, err := dbHandle.QueryContext(ctx, q, after)
	if err != nil {
		return rules, err
	}
	defer rows.Close()

	for rows.Next() {
		rule, err := getEventRuleFromDbRow(rows)
		if err != nil {
			return rules, err
		}
		rules = append(rules, rule)
	}
	err = rows.Err()
	if err != nil {
		return rules, err
	}
	return getRulesWithActions(ctx, rules, dbHandle)
}

func sqlCommonGetEventRules(limit int, offset int, order string, dbHandle sqlQuerier) ([]EventRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getEventRulesQuery(order)

	rules := make([]EventRule, 0, limit)
	rows, err := dbHandle.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return rules, err
	}
	defer rows.Close()

	for rows.Next() {
		rule, err := getEventRuleFromDbRow(rows)
		if err != nil {
			return rules, err
		}
		rules = append(rules, rule)
	}
	err = rows.Err()
	if err != nil {
		return rules, err
	}
	rules, err = getRulesWithActions(ctx, rules, dbHandle)
	if err != nil {
		return rules, err
	}
	for idx := range rules {
		rules[idx].PrepareForRendering()
	}
	return rules, nil
}

func sqlCommonAddEventRule(rule *EventRule, dbHandle *sql.DB) error {
	if err := rule.validate(); err != nil {
		return err
	}
	conditions, err := json.Marshal(rule.Conditions)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		if config.IsShared == 1 {
			_, err := tx.ExecContext(ctx, getRemoveSoftDeletedRuleQuery(), rule.Name)
			if err != nil {
				return err
			}
		}
		q := getAddEventRuleQuery()
		_, err := tx.ExecContext(ctx, q, rule.Name, rule.Description, util.GetTimeAsMsSinceEpoch(time.Now()),
			util.GetTimeAsMsSinceEpoch(time.Now()), rule.Trigger, conditions, rule.Status)
		if err != nil {
			return err
		}
		return generateEventRuleActionsMapping(ctx, rule, tx)
	})
}

func sqlCommonUpdateEventRule(rule *EventRule, dbHandle *sql.DB) error {
	if err := rule.validate(); err != nil {
		return err
	}
	conditions, err := json.Marshal(rule.Conditions)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getUpdateEventRuleQuery()
		_, err := tx.ExecContext(ctx, q, rule.Description, util.GetTimeAsMsSinceEpoch(time.Now()),
			rule.Trigger, conditions, rule.Status, rule.Name)
		if err != nil {
			return err
		}
		return generateEventRuleActionsMapping(ctx, rule, tx)
	})
}

func sqlCommonDeleteEventRule(rule EventRule, softDelete bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		if softDelete {
			q := getClearRuleActionMappingQuery()
			_, err := tx.ExecContext(ctx, q, rule.Name)
			if err != nil {
				return err
			}
		}
		q := getDeleteEventRuleQuery(softDelete)
		if softDelete {
			ts := util.GetTimeAsMsSinceEpoch(time.Now())
			res, err := tx.ExecContext(ctx, q, ts, ts, rule.Name)
			if err != nil {
				return err
			}
			return sqlCommonRequireRowAffected(res)
		}
		res, err := tx.ExecContext(ctx, q, rule.Name)
		if err != nil {
			return err
		}
		if err = sqlCommonRequireRowAffected(res); err != nil {
			return err
		}
		return sqlCommonDeleteTask(rule.Name, tx)
	})
}

func sqlCommonGetTaskByName(name string, dbHandle sqlQuerier) (Task, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	task := Task{
		Name: name,
	}
	q := getTaskByNameQuery()
	row := dbHandle.QueryRowContext(ctx, q, name)
	err := row.Scan(&task.UpdateAt, &task.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return task, util.NewRecordNotFoundError(err.Error())
		}
	}
	return task, err
}

func sqlCommonAddTask(name string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddTaskQuery()
	_, err := dbHandle.ExecContext(ctx, q, name, util.GetTimeAsMsSinceEpoch(time.Now()))
	return err
}

func sqlCommonUpdateTask(name string, version int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateTaskQuery()
	res, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), name, version)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonUpdateTaskTimestamp(name string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateTaskTimestampQuery()
	res, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonDeleteTask(name string, dbHandle sqlQuerier) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteTaskQuery()
	_, err := dbHandle.ExecContext(ctx, q, name)
	return err
}

func sqlCommonAddNode(dbHandle *sql.DB) error {
	if err := currentNode.validate(); err != nil {
		return fmt.Errorf("unable to register cluster node: %w", err)
	}
	data, err := json.Marshal(currentNode.Data)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAddNodeQuery()
	_, err = dbHandle.ExecContext(ctx, q, currentNode.Name, data, util.GetTimeAsMsSinceEpoch(time.Now()),
		util.GetTimeAsMsSinceEpoch(time.Now()))
	if err != nil {
		return fmt.Errorf("unable to register cluster node: %w", err)
	}
	providerLog(logger.LevelInfo, "registered as cluster node %q, port: %d, proto: %s",
		currentNode.Name, currentNode.Data.Port, currentNode.Data.Proto)

	return nil
}

func sqlCommonGetNodeByName(name string, dbHandle *sql.DB) (Node, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	var data []byte
	var node Node

	q := getNodeByNameQuery()
	row := dbHandle.QueryRowContext(ctx, q, name, util.GetTimeAsMsSinceEpoch(time.Now().Add(activeNodeTimeDiff)))
	err := row.Scan(&node.Name, &data, &node.CreatedAt, &node.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node, util.NewRecordNotFoundError(err.Error())
		}
		return node, err
	}
	err = json.Unmarshal(data, &node.Data)
	return node, err
}

func sqlCommonGetNodes(dbHandle *sql.DB) ([]Node, error) {
	var nodes []Node
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getNodesQuery()
	rows, err := dbHandle.QueryContext(ctx, q, currentNode.Name,
		util.GetTimeAsMsSinceEpoch(time.Now().Add(activeNodeTimeDiff)))
	if err != nil {
		return nodes, err
	}
	defer rows.Close()
	for rows.Next() {
		var node Node
		var data []byte

		err = rows.Scan(&node.Name, &data, &node.CreatedAt, &node.UpdatedAt)
		if err != nil {
			return nodes, err
		}
		err = json.Unmarshal(data, &node.Data)
		if err != nil {
			return nodes, err
		}
		nodes = append(nodes, node)
	}

	return nodes, rows.Err()
}

func sqlCommonUpdateNodeTimestamp(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateNodeTimestampQuery()
	res, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now()), currentNode.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonCleanupNodes(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getCleanupNodesQuery()
	_, err := dbHandle.ExecContext(ctx, q, util.GetTimeAsMsSinceEpoch(time.Now().Add(10*activeNodeTimeDiff)))
	return err
}

func sqlCommonGetConfigs(dbHandle sqlQuerier) (Configs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	var result Configs
	var configs []byte
	q := getConfigsQuery()
	err := dbHandle.QueryRowContext(ctx, q).Scan(&configs)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(configs, &result)
	return result, err
}

func sqlCommonSetConfigs(configs *Configs, dbHandle *sql.DB) error {
	if err := configs.validate(); err != nil {
		return err
	}
	asJSON, err := json.Marshal(configs)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUpdateConfigsQuery()
	res, err := dbHandle.ExecContext(ctx, q, asJSON)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetDatabaseVersion(dbHandle sqlQuerier, showInitWarn bool) (schemaVersion, error) {
	var result schemaVersion
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDatabaseVersionQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %q: %v", q, err)
		if showInitWarn && strings.Contains(err.Error(), sqlTableSchemaVersion) {
			logger.WarnToConsole("database query error, did you forgot to run the \"initprovider\" command?")
		}
		return result, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx)
	err = row.Scan(&result.Version)
	return result, err
}

func sqlCommonRequireRowAffected(res sql.Result) error {
	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return util.NewRecordNotFoundError(sql.ErrNoRows.Error())
	}
	return nil
}

func sqlCommonUpdateDatabaseVersion(ctx context.Context, dbHandle sqlQuerier, version int) error {
	q := getUpdateDBVersionQuery()
	_, err := dbHandle.ExecContext(ctx, q, version)
	return err
}

func sqlCommonExecSQLAndUpdateDBVersion(dbHandle *sql.DB, sqlQueries []string, newVersion int, isUp bool) error {
	if err := sqlAcquireLock(dbHandle); err != nil {
		return err
	}
	defer sqlReleaseLock(dbHandle)

	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	if newVersion > 0 {
		currentVersion, err := sqlCommonGetDatabaseVersion(dbHandle, false)
		if err == nil {
			if (isUp && currentVersion.Version >= newVersion) || (!isUp && currentVersion.Version <= newVersion) {
				providerLog(logger.LevelInfo, "current schema version: %v, requested: %v, did you execute simultaneous migrations?",
					currentVersion.Version, newVersion)
				return nil
			}
		}
	}

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		for _, q := range sqlQueries {
			if strings.TrimSpace(q) == "" {
				continue
			}
			_, err := tx.ExecContext(ctx, q)
			if err != nil {
				return err
			}
		}
		if newVersion == 0 {
			return nil
		}
		return sqlCommonUpdateDatabaseVersion(ctx, tx, newVersion)
	})
}

func sqlAcquireLock(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	switch config.Driver {
	case PGSQLDataProviderName:
		_, err := dbHandle.ExecContext(ctx, `SELECT pg_advisory_lock(101,1)`)
		if err != nil {
			return fmt.Errorf("unable to get advisory lock: %w", err)
		}
		providerLog(logger.LevelInfo, "acquired database lock")
	case MySQLDataProviderName:
		var lockResult sql.NullInt64
		err := dbHandle.QueryRowContext(ctx, `SELECT GET_LOCK('sftpgo.migration',30)`).Scan(&lockResult)
		if err != nil {
			return fmt.Errorf("unable to get lock: %w", err)
		}
		if !lockResult.Valid {
			return errors.New("unable to get lock: null value returned")
		}
		if lockResult.Int64 != 1 {
			return fmt.Errorf("unable to get lock, result: %d", lockResult.Int64)
		}
		providerLog(logger.LevelInfo, "acquired database lock")
	}

	return nil
}

func sqlReleaseLock(dbHandle *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	switch config.Driver {
	case PGSQLDataProviderName:
		_, err := dbHandle.ExecContext(ctx, `SELECT pg_advisory_unlock(101,1)`)
		if err != nil {
			providerLog(logger.LevelWarn, "unable to release lock: %v", err)
		} else {
			providerLog(logger.LevelInfo, "released database lock")
		}
	case MySQLDataProviderName:
		_, err := dbHandle.ExecContext(ctx, `SELECT RELEASE_LOCK('sftpgo.migration')`)
		if err != nil {
			providerLog(logger.LevelWarn, "unable to release lock: %v", err)
		} else {
			providerLog(logger.LevelInfo, "released database lock")
		}
	}
}

func sqlCommonExecuteTx(ctx context.Context, dbHandle *sql.DB, txFn func(*sql.Tx) error) error {
	if config.Driver == CockroachDataProviderName {
		return crdb.ExecuteTx(ctx, dbHandle, nil, txFn)
	}

	tx, err := dbHandle.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	err = txFn(tx)
	if err != nil {
		// we don't change the returned error
		tx.Rollback() //nolint:errcheck
		return err
	}
	return tx.Commit()
}
