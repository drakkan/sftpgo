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

package dataprovider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/cockroachdb/cockroach-go/v2/crdb"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	sqlDatabaseVersion     = 19
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
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{users_folders_mapping}}", sqlTableUsersFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{users_groups_mapping}}", sqlTableUsersGroupsMapping)
	sql = strings.ReplaceAll(sql, "{{groups_folders_mapping}}", sqlTableGroupsFoldersMapping)
	sql = strings.ReplaceAll(sql, "{{api_keys}}", sqlTableAPIKeys)
	sql = strings.ReplaceAll(sql, "{{shares}}", sqlTableShares)
	sql = strings.ReplaceAll(sql, "{{defender_events}}", sqlTableDefenderEvents)
	sql = strings.ReplaceAll(sql, "{{defender_hosts}}", sqlTableDefenderHosts)
	sql = strings.ReplaceAll(sql, "{{active_transfers}}", sqlTableActiveTransfers)
	sql = strings.ReplaceAll(sql, "{{shared_sessions}}", sqlTableSharedSessions)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sql
}

func sqlCommonGetShareByID(shareID, username string, dbHandle sqlQuerier) (Share, error) {
	var share Share
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	filterUser := username != ""
	q := getShareByIDQuery(filterUser)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return share, err
	}
	defer stmt.Close()
	var row *sql.Row
	if filterUser {
		row = stmt.QueryRowContext(ctx, shareID, username)
	} else {
		row = stmt.QueryRowContext(ctx, shareID)
	}

	return getShareFromDbRow(row)
}

func sqlCommonAddShare(share *Share, dbHandle *sql.DB) error {
	err := share.validate()
	if err != nil {
		return err
	}

	user, err := provider.userExists(share.Username)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("unable to validate user %#v", share.Username))
	}

	paths, err := json.Marshal(share.Paths)
	if err != nil {
		return err
	}
	allowFrom := ""
	if len(share.AllowFrom) > 0 {
		res, err := json.Marshal(share.AllowFrom)
		if err == nil {
			allowFrom = string(res)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAddShareQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

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
	_, err = stmt.ExecContext(ctx, share.ShareID, share.Name, share.Description, share.Scope,
		string(paths), createdAt, updatedAt, lastUseAt, share.ExpiresAt, share.Password,
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

	allowFrom := ""
	if len(share.AllowFrom) > 0 {
		res, err := json.Marshal(share.AllowFrom)
		if err == nil {
			allowFrom = string(res)
		}
	}

	user, err := provider.userExists(share.Username)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("unable to validate user %#v", share.Username))
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	var q string
	if share.IsRestore {
		q = getUpdateShareRestoreQuery()
	} else {
		q = getUpdateShareQuery()
	}
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	if share.IsRestore {
		if share.CreatedAt == 0 {
			share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		}
		if share.UpdatedAt == 0 {
			share.UpdatedAt = share.CreatedAt
		}
		_, err = stmt.ExecContext(ctx, share.Name, share.Description, share.Scope, string(paths),
			share.CreatedAt, share.UpdatedAt, share.LastUseAt, share.ExpiresAt, share.Password, share.MaxTokens,
			share.UsedTokens, allowFrom, user.ID, share.ShareID)
	} else {
		_, err = stmt.ExecContext(ctx, share.Name, share.Description, share.Scope, string(paths),
			util.GetTimeAsMsSinceEpoch(time.Now()), share.ExpiresAt, share.Password, share.MaxTokens,
			allowFrom, user.ID, share.ShareID)
	}
	return err
}

func sqlCommonDeleteShare(share Share, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteShareQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, share.ShareID)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, username, limit, offset)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx)
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
	var apiKey APIKey
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getAPIKeyByIDQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return apiKey, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx, keyID)

	apiKey, err = getAPIKeyFromDbRow(row)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, apiKey.KeyID, apiKey.Name, apiKey.Key, apiKey.Scope, util.GetTimeAsMsSinceEpoch(time.Now()),
		util.GetTimeAsMsSinceEpoch(time.Now()), apiKey.LastUseAt, apiKey.ExpiresAt, apiKey.Description,
		userID, adminID)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, apiKey.Name, apiKey.Scope, apiKey.ExpiresAt, userID, adminID,
		apiKey.Description, util.GetTimeAsMsSinceEpoch(time.Now()), apiKey.KeyID)
	return err
}

func sqlCommonDeleteAPIKey(apiKey APIKey, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteAPIKeyQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, apiKey.KeyID)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, limit, offset)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx)
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
	var admin Admin
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAdminByUsernameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return admin, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx, username)

	return getAdminFromDbRow(row)
}

func sqlCommonValidateAdminAndPass(username, password, ip string, dbHandle *sql.DB) (Admin, error) {
	admin, err := sqlCommonGetAdminByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating admin %#v: %v", username, err)
		return admin, ErrInvalidCredentials
	}
	err = admin.checkUserAndPass(password, ip)
	return admin, err
}

func sqlCommonAddAdmin(admin *Admin, dbHandle *sql.DB) error {
	err := admin.validate()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAddAdminQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	perms, err := json.Marshal(admin.Permissions)
	if err != nil {
		return err
	}

	filters, err := json.Marshal(admin.Filters)
	if err != nil {
		return err
	}

	_, err = stmt.ExecContext(ctx, admin.Username, admin.Password, admin.Status, admin.Email, string(perms),
		string(filters), admin.AdditionalInfo, admin.Description, util.GetTimeAsMsSinceEpoch(time.Now()),
		util.GetTimeAsMsSinceEpoch(time.Now()))
	return err
}

func sqlCommonUpdateAdmin(admin *Admin, dbHandle *sql.DB) error {
	err := admin.validate()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateAdminQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	perms, err := json.Marshal(admin.Permissions)
	if err != nil {
		return err
	}

	filters, err := json.Marshal(admin.Filters)
	if err != nil {
		return err
	}

	_, err = stmt.ExecContext(ctx, admin.Password, admin.Status, admin.Email, string(perms), string(filters),
		admin.AdditionalInfo, admin.Description, util.GetTimeAsMsSinceEpoch(time.Now()), admin.Username)
	return err
}

func sqlCommonDeleteAdmin(admin Admin, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteAdminQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, admin.Username)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, limit, offset)
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

	return admins, rows.Err()
}

func sqlCommonDumpAdmins(dbHandle sqlQuerier) ([]Admin, error) {
	admins := make([]Admin, 0, 30)

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDumpAdminsQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx)
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

	return admins, rows.Err()
}

func sqlCommonGetGroupByName(name string, dbHandle sqlQuerier) (Group, error) {
	var group Group
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getGroupByNameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return group, err
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, name)
	group, err = getGroupFromDbRow(row)
	if err != nil {
		return group, err
	}
	group, err = getGroupWithVirtualFolders(ctx, group, dbHandle)
	if err != nil {
		return group, err
	}
	return getGroupWithUsers(ctx, group, dbHandle)
}

func sqlCommonDumpGroups(dbHandle sqlQuerier) ([]Group, error) {
	groups := make([]Group, 0, 50)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getDumpGroupsQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx)
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUsersInGroupsQuery(len(names))
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	args := make([]any, 0, len(names))
	for _, name := range names {
		args = append(args, name)
	}

	usernames := make([]string, 0, len(names))
	rows, err := stmt.QueryContext(ctx, args...)
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
	return usernames, rows.Err()
}

func sqlCommonGetGroupsWithNames(names []string, dbHandle sqlQuerier) ([]Group, error) {
	if len(names) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getGroupsWithNamesQuery(len(names))
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	args := make([]any, 0, len(names))
	for _, name := range names {
		args = append(args, name)
	}

	groups := make([]Group, 0, len(names))
	rows, err := stmt.QueryContext(ctx, args...)
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

func sqlCommonGetGroups(limit int, offset int, order string, minimal bool, dbHandle sqlQuerier) ([]Group, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getGroupsQuery(order, minimal)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	groups := make([]Group, 0, limit)
	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err == nil {
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
	for idx := range groups {
		groups[idx].PrepareForRendering()
	}
	return groups, nil
}

func sqlCommonAddGroup(group *Group, dbHandle *sql.DB) error {
	if err := group.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getAddGroupQuery()
		stmt, err := tx.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()

		settings, err := json.Marshal(group.UserSettings)
		if err != nil {
			return err
		}
		_, err = stmt.ExecContext(ctx, group.Name, group.Description, util.GetTimeAsMsSinceEpoch(time.Now()),
			util.GetTimeAsMsSinceEpoch(time.Now()), string(settings))
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getUpdateGroupQuery()
		stmt, err := tx.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()

		settings, err := json.Marshal(group.UserSettings)
		if err != nil {
			return err
		}
		_, err = stmt.ExecContext(ctx, group.Description, settings, util.GetTimeAsMsSinceEpoch(time.Now()), group.Name)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, group.Name)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonGetUserByUsername(username string, dbHandle sqlQuerier) (User, error) {
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getUserByUsernameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return user, err
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, username)
	user, err = getUserFromDbRow(row)
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
	var user User
	if password == "" {
		return user, errors.New("credentials cannot be null or empty")
	}
	user, err := sqlCommonGetUserByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, err
	}
	return checkUserAndPass(&user, password, ip, protocol)
}

func sqlCommonValidateUserAndTLSCertificate(username, protocol string, tlsCert *x509.Certificate, dbHandle *sql.DB) (User, error) {
	var user User
	if tlsCert == nil {
		return user, errors.New("TLS certificate cannot be null or empty")
	}
	user, err := sqlCommonGetUserByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, err
	}
	return checkUserAndTLSCertificate(&user, protocol, tlsCert)
}

func sqlCommonValidateUserAndPubKey(username string, pubKey []byte, isSSHCert bool, dbHandle *sql.DB) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}
	user, err := sqlCommonGetUserByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey, isSSHCert)
}

func sqlCommonCheckAvailability(dbHandle *sql.DB) (err error) {
	defer func() {
		if r := recover(); r != nil {
			providerLog(logger.LevelError, "panic in check provider availability, stack trace: %v", string(debug.Stack()))
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, uploadSize, downloadSize, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "transfer quota updated for user %#v, ul increment: %v dl increment: %v is reset? %v",
			username, uploadSize, downloadSize, reset)
	} else {
		providerLog(logger.LevelError, "error updating quota for user %#v: %v", username, err)
	}
	return err
}

func sqlCommonUpdateQuota(username string, filesAdd int, sizeAdd int64, reset bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateQuotaQuery(reset)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, sizeAdd, filesAdd, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "quota updated for user %#v, files increment: %v size increment: %v is reset? %v",
			username, filesAdd, sizeAdd, reset)
	} else {
		providerLog(logger.LevelError, "error updating quota for user %#v: %v", username, err)
	}
	return err
}

func sqlCommonGetUsedQuota(username string, dbHandle *sql.DB) (int, int64, int64, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getQuotaQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return 0, 0, 0, 0, err
	}
	defer stmt.Close()

	var usedFiles int
	var usedSize, usedUploadSize, usedDownloadSize int64
	err = stmt.QueryRowContext(ctx, username).Scan(&usedSize, &usedFiles, &usedUploadSize, &usedDownloadSize)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(time.Now()), numTokens, shareID)
	if err == nil {
		providerLog(logger.LevelDebug, "last use updated for shared object %#v", shareID)
	} else {
		providerLog(logger.LevelWarn, "error updating last use for shared object %#v: %v", shareID, err)
	}
	return err
}

func sqlCommonUpdateAPIKeyLastUse(keyID string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateAPIKeyLastUseQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(time.Now()), keyID)
	if err == nil {
		providerLog(logger.LevelDebug, "last use updated for key %#v", keyID)
	} else {
		providerLog(logger.LevelWarn, "error updating last use for key %#v: %v", keyID, err)
	}
	return err
}

func sqlCommonUpdateAdminLastLogin(username string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateAdminLastLoginQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "last login updated for admin %#v", username)
	} else {
		providerLog(logger.LevelWarn, "error updating last login for admin %#v: %v", username, err)
	}
	return err
}

func sqlCommonSetUpdatedAt(username string, dbHandle *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getSetUpdateAtQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "updated_at set for user %#v", username)
	} else {
		providerLog(logger.LevelWarn, "error setting updated_at for user %#v: %v", username, err)
	}
}

func sqlCommonUpdateLastLogin(username string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateLastLoginQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "last login updated for user %#v", username)
	} else {
		providerLog(logger.LevelWarn, "error updating last login for user %#v: %v", username, err)
	}
	return err
}

func sqlCommonAddUser(user *User, dbHandle *sql.DB) error {
	err := ValidateUser(user)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getAddUserQuery()
		stmt, err := tx.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()
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
		_, err = stmt.ExecContext(ctx, user.Username, user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID,
			user.MaxSessions, user.QuotaSize, user.QuotaFiles, string(permissions), user.UploadBandwidth,
			user.DownloadBandwidth, user.Status, user.ExpirationDate, string(filters), string(fsConfig), user.AdditionalInfo,
			user.Description, user.Email, util.GetTimeAsMsSinceEpoch(time.Now()), util.GetTimeAsMsSinceEpoch(time.Now()),
			user.UploadDataTransfer, user.DownloadDataTransfer, user.TotalDataTransfer)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, password, username)
	return err
}

func sqlCommonUpdateUser(user *User, dbHandle *sql.DB) error {
	err := ValidateUser(user)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonExecuteTx(ctx, dbHandle, func(tx *sql.Tx) error {
		q := getUpdateUserQuery()
		stmt, err := tx.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()
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
		_, err = stmt.ExecContext(ctx, user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID, user.MaxSessions,
			user.QuotaSize, user.QuotaFiles, string(permissions), user.UploadBandwidth, user.DownloadBandwidth, user.Status,
			user.ExpirationDate, string(filters), string(fsConfig), user.AdditionalInfo, user.Description, user.Email,
			util.GetTimeAsMsSinceEpoch(time.Now()), user.UploadDataTransfer, user.DownloadDataTransfer, user.TotalDataTransfer,
			user.ID)
		if err != nil {
			return err
		}
		if err := generateUserVirtualFoldersMapping(ctx, user, tx); err != nil {
			return err
		}
		return generateUserGroupMapping(ctx, user, tx)
	})
}

func sqlCommonDeleteUser(user User, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteUserQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, user.ID)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, after)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			u, err := getUserFromDbRow(rows)
			if err != nil {
				return users, err
			}
			users = append(users, u)
		}
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

func sqlCommonGetUsersForQuotaCheck(toFetch map[string]bool, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, 30)

	usernames := make([]string, 0, len(toFetch))
	for k := range toFetch {
		usernames = append(usernames, k)
	}

	maxUsers := 30
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return users, err
	}
	defer stmt.Close()

	queryArgs := make([]any, 0, len(usernames))
	for idx := range usernames {
		queryArgs = append(queryArgs, usernames[idx])
	}

	rows, err := stmt.QueryContext(ctx, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		var filters sql.NullString
		err = rows.Scan(&user.ID, &user.Username, &user.QuotaSize, &user.UsedQuotaSize, &user.TotalDataTransfer,
			&user.UploadDataTransfer, &user.DownloadDataTransfer, &user.UsedUploadDataTransfer,
			&user.UsedDownloadDataTransfer, &filters)
		if err != nil {
			return users, err
		}
		if filters.Valid {
			var userFilters UserFilters
			err = json.Unmarshal([]byte(filters.String), &userFilters)
			if err == nil {
				user.Filters = userFilters
			}
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

func sqlCommonAddActiveTransfer(transfer ActiveTransfer, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAddActiveTransferQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	now := util.GetTimeAsMsSinceEpoch(time.Now())
	_, err = stmt.ExecContext(ctx, transfer.ID, transfer.ConnID, transfer.Type, transfer.Username,
		transfer.FolderName, transfer.IP, transfer.TruncatedSize, transfer.CurrentULSize, transfer.CurrentDLSize,
		now, now)
	return err
}

func sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateActiveTransferSizesQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, ulSize, dlSize, util.GetTimeAsMsSinceEpoch(time.Now()), connectionID, transferID)
	return err
}

func sqlCommonRemoveActiveTransfer(transferID int64, connectionID string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getRemoveActiveTransferQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, connectionID, transferID)
	return err
}

func sqlCommonCleanupActiveTransfers(before time.Time, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getCleanupActiveTransfersQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(before))
	return err
}

func sqlCommonGetActiveTransfers(from time.Time, dbHandle sqlQuerier) ([]ActiveTransfer, error) {
	transfers := make([]ActiveTransfer, 0, 30)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getActiveTransfersQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, util.GetTimeAsMsSinceEpoch(from))
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

func sqlCommonGetUsers(limit int, offset int, order string, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUsersQuery(order)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			u, err := getUserFromDbRow(rows)
			if err != nil {
				return users, err
			}
			users = append(users, u)
		}
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, from, limit)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return host, err
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, ip, util.GetTimeAsMsSinceEpoch(time.Now()))
	err = row.Scan(&host.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return host, util.NewRecordNotFoundError("host not found")
		}
		providerLog(logger.LevelError, "unable to check ban status for host %#v: %v", ip, err)
		return host, err
	}

	return host, nil
}

func sqlCommonGetDefenderHostByIP(ip string, from int64, dbHandle sqlQuerier) (DefenderEntry, error) {
	var host DefenderEntry

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderHostQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return host, err
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, ip, from)
	var banTime sql.NullInt64
	err = row.Scan(&host.ID, &host.IP, &banTime)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return host, util.NewRecordNotFoundError("host not found")
		}
		providerLog(logger.LevelError, "unable to get host for ip %#v: %v", ip, err)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, minutesToAdd*60000, ip)
	if err == nil {
		providerLog(logger.LevelDebug, "ban time updated for ip %#v, increment (minutes): %v",
			ip, minutesToAdd)
	} else {
		providerLog(logger.LevelError, "error updating ban time for ip %#v: %v", ip, err)
	}
	return err
}

func sqlCommonSetDefenderBanTime(ip string, banTime int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDefenderSetBanTimeQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, banTime, ip)
	if err == nil {
		providerLog(logger.LevelDebug, "ip %#v banned until %v", ip, util.GetTimeFromMsecSinceEpoch(banTime))
	} else {
		providerLog(logger.LevelError, "error setting ban time for ip %#v: %v", ip, err)
	}
	return err
}

func sqlCommonDeleteDefenderHost(ip string, dbHandle sqlQuerier) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteDefenderHostQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, ip)
	if err != nil {
		providerLog(logger.LevelError, "unable to delete defender host %#v: %v", ip, err)
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
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, ip, util.GetTimeAsMsSinceEpoch(time.Now()))
	if err != nil {
		providerLog(logger.LevelError, "unable to add defender host %#v: %v", ip, err)
	}
	return err
}

func sqlCommonAddDefenderEvent(ctx context.Context, ip string, score int, tx *sql.Tx) error {
	q := getAddDefenderEventQuery()
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(time.Now()), score, ip)
	if err != nil {
		providerLog(logger.LevelError, "unable to add defender event for %#v: %v", ip, err)
	}
	return err
}

func sqlCommonCleanupDefenderHosts(from int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderHostsCleanupQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, util.GetTimeAsMsSinceEpoch(time.Now()), from)
	if err != nil {
		providerLog(logger.LevelError, "unable to cleanup defender hosts: %v", err)
	}
	return err
}

func sqlCommonCleanupDefenderEvents(from int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDefenderEventsCleanupQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, from)
	if err != nil {
		providerLog(logger.LevelError, "unable to cleanup defender events: %v", err)
	}
	return err
}

func getShareFromDbRow(row sqlScanner) (Share, error) {
	var share Share
	var description, password, allowFrom, paths sql.NullString

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
	if paths.Valid {
		var list []string
		err = json.Unmarshal([]byte(paths.String), &list)
		if err != nil {
			return share, err
		}
		share.Paths = list
	} else {
		return share, errors.New("unable to decode shared paths")
	}
	if description.Valid {
		share.Description = description.String
	}
	if password.Valid {
		share.Password = password.String
	}
	if allowFrom.Valid {
		var list []string
		err = json.Unmarshal([]byte(allowFrom.String), &list)
		if err == nil {
			share.AllowFrom = list
		}
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
	var email, filters, additionalInfo, permissions, description sql.NullString

	err := row.Scan(&admin.ID, &admin.Username, &admin.Password, &admin.Status, &email, &permissions,
		&filters, &additionalInfo, &description, &admin.CreatedAt, &admin.UpdatedAt, &admin.LastLogin)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return admin, util.NewRecordNotFoundError(err.Error())
		}
		return admin, err
	}

	if permissions.Valid {
		var perms []string
		err = json.Unmarshal([]byte(permissions.String), &perms)
		if err != nil {
			return admin, err
		}
		admin.Permissions = perms
	}

	if email.Valid {
		admin.Email = email.String
	}
	if filters.Valid {
		var adminFilters AdminFilters
		err = json.Unmarshal([]byte(filters.String), &adminFilters)
		if err == nil {
			admin.Filters = adminFilters
		}
	}
	if additionalInfo.Valid {
		admin.AdditionalInfo = additionalInfo.String
	}
	if description.Valid {
		admin.Description = description.String
	}

	admin.SetEmptySecretsIfNil()
	return admin, nil
}

func getGroupFromDbRow(row sqlScanner) (Group, error) {
	var group Group
	var userSettings, description sql.NullString

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
	if userSettings.Valid {
		var settings GroupUserSettings
		err = json.Unmarshal([]byte(userSettings.String), &settings)
		if err == nil {
			group.UserSettings = settings
		}
	}

	return group, nil
}

func getUserFromDbRow(row sqlScanner) (User, error) {
	var user User
	var permissions sql.NullString
	var password sql.NullString
	var publicKey sql.NullString
	var filters sql.NullString
	var fsConfig sql.NullString
	var additionalInfo, description, email sql.NullString

	err := row.Scan(&user.ID, &user.Username, &password, &publicKey, &user.HomeDir, &user.UID, &user.GID, &user.MaxSessions,
		&user.QuotaSize, &user.QuotaFiles, &permissions, &user.UsedQuotaSize, &user.UsedQuotaFiles, &user.LastQuotaUpdate,
		&user.UploadBandwidth, &user.DownloadBandwidth, &user.ExpirationDate, &user.LastLogin, &user.Status, &filters, &fsConfig,
		&additionalInfo, &description, &email, &user.CreatedAt, &user.UpdatedAt, &user.UploadDataTransfer, &user.DownloadDataTransfer,
		&user.TotalDataTransfer, &user.UsedUploadDataTransfer, &user.UsedDownloadDataTransfer)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, util.NewRecordNotFoundError(err.Error())
		}
		return user, err
	}
	if password.Valid {
		user.Password = password.String
	}
	// we can have a empty string or an invalid json in null string
	// so we do a relaxed test if the field is optional, for example we
	// populate public keys only if unmarshal does not return an error
	if publicKey.Valid {
		var list []string
		err = json.Unmarshal([]byte(publicKey.String), &list)
		if err == nil {
			user.PublicKeys = list
		}
	}
	if permissions.Valid {
		perms := make(map[string][]string)
		err = json.Unmarshal([]byte(permissions.String), &perms)
		if err != nil {
			providerLog(logger.LevelError, "unable to deserialize permissions for user %#v: %v", user.Username, err)
			return user, fmt.Errorf("unable to deserialize permissions for user %#v: %v", user.Username, err)
		}
		user.Permissions = perms
	}
	if filters.Valid {
		var userFilters UserFilters
		err = json.Unmarshal([]byte(filters.String), &userFilters)
		if err == nil {
			user.Filters = userFilters
		}
	}
	if fsConfig.Valid {
		var fs vfs.Filesystem
		err = json.Unmarshal([]byte(fsConfig.String), &fs)
		if err == nil {
			user.FsConfig = fs
		}
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
	user.SetEmptySecretsIfNil()
	return user, nil
}

func sqlCommonGetFolder(ctx context.Context, name string, dbHandle sqlQuerier) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	q := getFolderByNameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return folder, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx, name)
	var mappedPath, description, fsConfig sql.NullString
	err = row.Scan(&folder.ID, &mappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles, &folder.LastQuotaUpdate,
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
	if fsConfig.Valid {
		var fs vfs.Filesystem
		err = json.Unmarshal([]byte(fsConfig.String), &fs)
		if err == nil {
			folder.FsConfig = fs
		}
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
		return folder, fmt.Errorf("unable to associate users with folder %#v", name)
	}
	folders, err = getVirtualFoldersWithGroups([]vfs.BaseVirtualFolder{folders[0]}, dbHandle)
	if err != nil {
		return folder, err
	}
	if len(folders) != 1 {
		return folder, fmt.Errorf("unable to associate groups with folder %#v", name)
	}
	return folders[0], nil
}

func sqlCommonAddOrUpdateFolder(ctx context.Context, baseFolder *vfs.BaseVirtualFolder, usedQuotaSize int64,
	usedQuotaFiles int, lastQuotaUpdate int64, dbHandle sqlQuerier,
) error {
	fsConfig, err := json.Marshal(baseFolder.FsConfig)
	if err != nil {
		return err
	}
	q := getUpsertFolderQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, baseFolder.MappedPath, usedQuotaSize, usedQuotaFiles,
		lastQuotaUpdate, baseFolder.Name, baseFolder.Description, string(fsConfig))
	return err
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.MappedPath, folder.UsedQuotaSize, folder.UsedQuotaFiles,
		folder.LastQuotaUpdate, folder.Name, folder.Description, string(fsConfig))
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.MappedPath, folder.Description, string(fsConfig), folder.Name)
	return err
}

func sqlCommonDeleteFolder(folder vfs.BaseVirtualFolder, dbHandle sqlQuerier) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteFolderQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, folder.ID)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return folders, err
	}
	defer rows.Close()
	for rows.Next() {
		var folder vfs.BaseVirtualFolder
		var mappedPath, description, fsConfig sql.NullString
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
		if fsConfig.Valid {
			var fs vfs.Filesystem
			err = json.Unmarshal([]byte(fsConfig.String), &fs)
			if err == nil {
				folder.FsConfig = fs
			}
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, limit, offset)
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
			var mappedPath, description, fsConfig sql.NullString
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
			if fsConfig.Valid {
				var fs vfs.Filesystem
				err = json.Unmarshal([]byte(fsConfig.String), &fs)
				if err == nil {
					folder.FsConfig = fs
				}
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, user.Username)
	return err
}

func sqlCommonClearGroupFolderMapping(ctx context.Context, group *Group, dbHandle sqlQuerier) error {
	q := getClearGroupFolderMappingQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, group.Name)
	return err
}

func sqlCommonClearUserGroupMapping(ctx context.Context, user *User, dbHandle sqlQuerier) error {
	q := getClearUserGroupMappingQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, user.Username)
	return err
}

func sqlCommonAddUserFolderMapping(ctx context.Context, user *User, folder *vfs.VirtualFolder, dbHandle sqlQuerier) error {
	q := getAddUserFolderMappingQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.VirtualPath, folder.QuotaSize, folder.QuotaFiles, folder.Name, user.Username)
	return err
}

func sqlCommonAddGroupFolderMapping(ctx context.Context, group *Group, folder *vfs.VirtualFolder, dbHandle sqlQuerier) error {
	q := getAddGroupFolderMappingQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.VirtualPath, folder.QuotaSize, folder.QuotaFiles, folder.Name, group.Name)
	return err
}

func sqlCommonAddUserGroupMapping(ctx context.Context, username, groupName string, groupType int, dbHandle sqlQuerier) error {
	q := getAddUserGroupMappingQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, username, groupName, groupType)
	return err
}

func generateGroupVirtualFoldersMapping(ctx context.Context, group *Group, dbHandle sqlQuerier) error {
	err := sqlCommonClearGroupFolderMapping(ctx, group, dbHandle)
	if err != nil {
		return err
	}
	for idx := range group.VirtualFolders {
		vfolder := &group.VirtualFolders[idx]
		err = sqlCommonAddOrUpdateFolder(ctx, &vfolder.BaseVirtualFolder, 0, 0, 0, dbHandle)
		if err != nil {
			return err
		}
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
		err := sqlCommonAddOrUpdateFolder(ctx, &vfolder.BaseVirtualFolder, 0, 0, 0, dbHandle)
		if err != nil {
			return err
		}
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, from)
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

	var err error
	usersVirtualFolders := make(map[int64][]vfs.VirtualFolder)
	q := getRelatedFoldersForUsersQuery(users)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var folder vfs.VirtualFolder
		var userID int64
		var mappedPath, fsConfig, description sql.NullString
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
		if fsConfig.Valid {
			var fs vfs.Filesystem
			err = json.Unmarshal([]byte(fsConfig.String), &fs)
			if err == nil {
				folder.FsConfig = fs
			}
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
	var err error
	usersGroups := make(map[int64][]sdk.GroupMapping)
	q := getRelatedGroupsForUsersQuery(users)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
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

	var err error
	q := getRelatedFoldersForGroupsQuery(groups)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groupsVirtualFolders := make(map[int64][]vfs.VirtualFolder)

	for rows.Next() {
		var groupID int64
		var folder vfs.VirtualFolder
		var mappedPath, fsConfig, description sql.NullString
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
		if fsConfig.Valid {
			var fs vfs.Filesystem
			err = json.Unmarshal([]byte(fsConfig.String), &fs)
			if err == nil {
				folder.FsConfig = fs
			}
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

	var err error
	q := getRelatedUsersForGroupsQuery(groups)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
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

func getVirtualFoldersWithGroups(folders []vfs.BaseVirtualFolder, dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	if len(folders) == 0 {
		return folders, nil
	}
	var err error
	vFoldersGroups := make(map[int64][]string)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getRelatedGroupsForFoldersQuery(folders)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
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

	var err error
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getRelatedUsersForFoldersQuery(folders)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, sizeAdd, filesAdd, util.GetTimeAsMsSinceEpoch(time.Now()), name)
	if err == nil {
		providerLog(logger.LevelDebug, "quota updated for folder %#v, files increment: %v size increment: %v is reset? %v",
			name, filesAdd, sizeAdd, reset)
	} else {
		providerLog(logger.LevelWarn, "error updating quota for folder %#v: %v", name, err)
	}
	return err
}

func sqlCommonGetFolderUsedQuota(mappedPath string, dbHandle *sql.DB) (int, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getQuotaFolderQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return 0, 0, err
	}
	defer stmt.Close()

	var usedFiles int
	var usedSize int64
	err = stmt.QueryRowContext(ctx, mappedPath).Scan(&usedSize, &usedFiles)
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
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
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
		u, err := provider.userExists(apiKey.User)
		if err != nil {
			return userID, adminID, util.NewValidationError(fmt.Sprintf("unable to validate user %v", apiKey.User))
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

	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, session.Key, data, session.Type, session.Timestamp)
	return err
}

func sqlCommonGetSession(key string, dbHandle sqlQuerier) (Session, error) {
	var session Session

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getSessionQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return session, err
	}
	defer stmt.Close()

	var data []byte // type hint, some driver will use string instead of []byte if the type is any
	err = stmt.QueryRowContext(ctx, key).Scan(&session.Key, &data, &session.Type, &session.Timestamp)
	if err != nil {
		return session, err
	}
	session.Data = data
	return session, nil
}

func sqlCommonDeleteSession(key string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteSessionQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, key)
	if err != nil {
		return err
	}
	return sqlCommonRequireRowAffected(res)
}

func sqlCommonCleanupSessions(sessionType SessionType, before int64, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getCleanupSessionsQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, sessionType, before)
	return err
}

func sqlCommonGetDatabaseVersion(dbHandle sqlQuerier, showInitWarn bool) (schemaVersion, error) {
	var result schemaVersion
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDatabaseVersionQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
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
	// MariaDB/MySQL returns 0 rows affected for updates that don't change anything
	// so we don't check rows affected for updates
	affected, err := res.RowsAffected()
	if err == nil && affected == 0 {
		return util.NewRecordNotFoundError(sql.ErrNoRows.Error())
	}
	return nil
}

func sqlCommonUpdateDatabaseVersion(ctx context.Context, dbHandle sqlQuerier, version int) error {
	q := getUpdateDBVersionQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelError, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, version)
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
		stmt, err := dbHandle.PrepareContext(ctx, `SELECT GET_LOCK('sftpgo.migration',30)`)
		if err != nil {
			return fmt.Errorf("unable to get lock: %w", err)
		}
		defer stmt.Close()

		var lockResult sql.NullInt64
		err = stmt.QueryRowContext(ctx).Scan(&lockResult)
		if err != nil {
			return fmt.Errorf("unable to get lock: %w", err)
		}
		if !lockResult.Valid {
			return errors.New("unable to get lock: null value returned")
		}
		if lockResult.Int64 != 1 {
			return fmt.Errorf("unable to get lock, result: %v", lockResult.Int64)
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
