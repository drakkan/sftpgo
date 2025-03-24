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
	"fmt"
	"strconv"
	"strings"

	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	selectUserFields = "u.id,u.username,u.password,u.public_keys,u.home_dir,u.uid,u.gid,u.max_sessions,u.quota_size,u.quota_files," +
		"u.permissions,u.used_quota_size,u.used_quota_files,u.last_quota_update,u.upload_bandwidth,u.download_bandwidth," +
		"u.expiration_date,u.last_login,u.status,u.filters,u.filesystem,u.additional_info,u.description,u.email,u.created_at," +
		"u.updated_at,u.upload_data_transfer,u.download_data_transfer,u.total_data_transfer," +
		"u.used_upload_data_transfer,u.used_download_data_transfer,u.deleted_at,u.first_download,u.first_upload,r.name,u.last_password_change"
	selectFolderFields = "id,path,used_quota_size,used_quota_files,last_quota_update,name,description,filesystem"
	selectAdminFields  = "a.id,a.username,a.password,a.status,a.email,a.permissions,a.filters,a.additional_info,a.description,a.created_at,a.updated_at,a.last_login,r.name"
	selectAPIKeyFields = "key_id,name,api_key,scope,created_at,updated_at,last_use_at,expires_at,description,user_id,admin_id"
	selectShareFields  = "s.share_id,s.name,s.description,s.scope,s.paths,u.username,s.created_at,s.updated_at,s.last_use_at," +
		"s.expires_at,s.password,s.max_tokens,s.used_tokens,s.allow_from"
	selectGroupFields       = "id,name,description,created_at,updated_at,user_settings"
	selectEventActionFields = "id,name,description,type,options"
	selectRoleFields        = "id,name,description,created_at,updated_at"
	selectIPListEntryFields = "type,ipornet,mode,protocols,description,created_at,updated_at,deleted_at"
	selectMinimalFields     = "id,name"
)

func getSQLPlaceholders() []string {
	var placeholders []string
	for i := 1; i <= 100; i++ {
		if config.Driver == PGSQLDataProviderName || config.Driver == CockroachDataProviderName {
			placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		} else {
			placeholders = append(placeholders, "?")
		}
	}
	return placeholders
}

func getSQLQuotedName(name string) string {
	if config.Driver == MySQLDataProviderName {
		return fmt.Sprintf("`%s`", name)
	}

	return fmt.Sprintf(`"%s"`, name)
}

func getSelectEventRuleFields() string {
	if config.Driver == MySQLDataProviderName {
		return "id,name,description,created_at,updated_at,`trigger`,conditions,deleted_at,status"
	}

	return `id,name,description,created_at,updated_at,"trigger",conditions,deleted_at,status`
}

func getCoalesceDefaultForRole(role string) string {
	if role != "" {
		return "0"
	}
	return "NULL"
}

func getAddSessionQuery() string {
	if config.Driver == MySQLDataProviderName {
		return fmt.Sprintf("INSERT INTO %s (`key`,`data`,`type`,`timestamp`) VALUES (%s,%s,%s,%s) "+
			"ON DUPLICATE KEY UPDATE `data`=VALUES(`data`), `timestamp`=VALUES(`timestamp`)",
			sqlTableSharedSessions, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
	}
	return fmt.Sprintf(`INSERT INTO %s (key,data,type,timestamp) VALUES (%s,%s,%s,%s) ON CONFLICT(key,type) DO UPDATE SET data=
		EXCLUDED.data, timestamp=EXCLUDED.timestamp`,
		sqlTableSharedSessions, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getDeleteSessionQuery() string {
	if config.Driver == MySQLDataProviderName {
		return fmt.Sprintf("DELETE FROM %s WHERE `key` = %s AND `type` = %s",
			sqlTableSharedSessions, sqlPlaceholders[0], sqlPlaceholders[1])
	}
	return fmt.Sprintf(`DELETE FROM %s WHERE key = %s AND type = %s`,
		sqlTableSharedSessions, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getSessionQuery() string {
	if config.Driver == MySQLDataProviderName {
		return fmt.Sprintf("SELECT `key`,`data`,`type`,`timestamp` FROM %s WHERE `key` = %s AND `type` = %s",
			sqlTableSharedSessions, sqlPlaceholders[0], sqlPlaceholders[1])
	}
	return fmt.Sprintf(`SELECT key,data,type,timestamp FROM %s WHERE key = %s AND type = %s`,
		sqlTableSharedSessions, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getCleanupSessionsQuery() string {
	return fmt.Sprintf(`DELETE from %s WHERE type = %s AND timestamp < %s`,
		sqlTableSharedSessions, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getAddDefenderHostQuery() string {
	if config.Driver == MySQLDataProviderName {
		return fmt.Sprintf("INSERT INTO %s (`ip`,`updated_at`,`ban_time`) VALUES (%s,%s,0) ON DUPLICATE KEY UPDATE `updated_at`=VALUES(`updated_at`)",
			sqlTableDefenderHosts, sqlPlaceholders[0], sqlPlaceholders[1])
	}
	return fmt.Sprintf(`INSERT INTO %s (ip,updated_at,ban_time) VALUES (%s,%s,0) ON CONFLICT (ip) DO UPDATE SET updated_at = EXCLUDED.updated_at RETURNING id`,
		sqlTableDefenderHosts, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getAddDefenderEventQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (date_time,score,host_id) VALUES (%s,%s,(SELECT id from %s WHERE ip = %s))`,
		sqlTableDefenderEvents, sqlPlaceholders[0], sqlPlaceholders[1], sqlTableDefenderHosts, sqlPlaceholders[2])
}

func getDefenderHostsQuery() string {
	return fmt.Sprintf(`SELECT id,ip,ban_time FROM %s WHERE updated_at >= %s OR ban_time > 0 ORDER BY updated_at DESC LIMIT %s`,
		sqlTableDefenderHosts, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDefenderHostQuery() string {
	return fmt.Sprintf(`SELECT id,ip,ban_time FROM %s WHERE ip = %s AND (updated_at >= %s OR ban_time > 0)`,
		sqlTableDefenderHosts, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDefenderEventsQuery(hostIDs []int64) string {
	var sb strings.Builder
	for _, hID := range hostIDs {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(hID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	} else {
		sb.WriteString("(0)")
	}
	return fmt.Sprintf(`SELECT host_id,SUM(score) FROM %s WHERE date_time >= %s AND host_id IN %s GROUP BY host_id`,
		sqlTableDefenderEvents, sqlPlaceholders[0], sb.String())
}

func getDefenderIsHostBannedQuery() string {
	return fmt.Sprintf(`SELECT id FROM %s WHERE ip = %s AND ban_time >= %s`,
		sqlTableDefenderHosts, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDefenderIncrementBanTimeQuery() string {
	return fmt.Sprintf(`UPDATE %s SET ban_time = ban_time + %s WHERE ip = %s`,
		sqlTableDefenderHosts, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDefenderSetBanTimeQuery() string {
	return fmt.Sprintf(`UPDATE %s SET ban_time = %s WHERE ip = %s`,
		sqlTableDefenderHosts, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDeleteDefenderHostQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE ip = %s`, sqlTableDefenderHosts, sqlPlaceholders[0])
}

func getDefenderHostsCleanupQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE ban_time < %s AND NOT EXISTS (
		SELECT id FROM %s WHERE %s.host_id = %s.id AND %s.date_time > %s)`,
		sqlTableDefenderHosts, sqlPlaceholders[0], sqlTableDefenderEvents, sqlTableDefenderEvents, sqlTableDefenderHosts,
		sqlTableDefenderEvents, sqlPlaceholders[1])
}

func getDefenderEventsCleanupQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE date_time < %s`, sqlTableDefenderEvents, sqlPlaceholders[0])
}

func getIPListEntryQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE type = %s AND ipornet = %s AND deleted_at = 0`,
		selectIPListEntryFields, sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getIPListEntriesQuery(filter, from, order string, limit int) string {
	var sb strings.Builder
	var idx int

	sb.WriteString("SELECT ")
	sb.WriteString(selectIPListEntryFields)
	sb.WriteString(" FROM ")
	sb.WriteString(sqlTableIPLists)
	sb.WriteString(" WHERE type = ")
	sb.WriteString(sqlPlaceholders[idx])
	idx++
	if from != "" {
		if order == OrderASC {
			sb.WriteString(" AND ipornet > ")
		} else {
			sb.WriteString(" AND ipornet < ")
		}
		sb.WriteString(sqlPlaceholders[idx])
		idx++
	}
	if filter != "" {
		sb.WriteString(" AND ipornet LIKE ")
		sb.WriteString(sqlPlaceholders[idx])
		idx++
	}
	sb.WriteString(" AND deleted_at = 0 ")
	sb.WriteString(" ORDER BY ipornet ")
	sb.WriteString(order)
	if limit > 0 {
		sb.WriteString(" LIMIT ")
		sb.WriteString(sqlPlaceholders[idx])
	}
	return sb.String()
}

func getCountIPListEntriesQuery() string {
	return fmt.Sprintf(`SELECT count(ipornet) FROM %s WHERE type = %s AND deleted_at = 0`, sqlTableIPLists, sqlPlaceholders[0])
}

func getCountAllIPListEntriesQuery() string {
	return fmt.Sprintf(`SELECT count(ipornet) FROM %s WHERE deleted_at = 0`, sqlTableIPLists)
}

func getIPListEntriesForIPQueryPg() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE type = %s AND deleted_at = 0 AND %s::inet BETWEEN first AND last`,
		selectIPListEntryFields, sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getIPListEntriesForIPQueryNoPg() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE type = %s AND deleted_at = 0 AND ip_type = %s AND %s BETWEEN first AND last`,
		selectIPListEntryFields, sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2])
}

func getRecentlyUpdatedIPListQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE updated_at >= %s OR deleted_at > 0`,
		selectIPListEntryFields, sqlTableIPLists, sqlPlaceholders[0])
}

func getDumpListEntriesQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE deleted_at = 0`, selectIPListEntryFields, sqlTableIPLists)
}

func getAddIPListEntryQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (type,ipornet,first,last,ip_type,protocols,description,mode,created_at,updated_at,deleted_at)
		VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)`, sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1],
		sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5],
		sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9])
}

func getUpdateIPListEntryQuery() string {
	return fmt.Sprintf(`UPDATE %s SET mode=%s,protocols=%s,description=%s,updated_at=%s WHERE type = %s AND ipornet = %s`,
		sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3],
		sqlPlaceholders[4], sqlPlaceholders[5])
}

func getDeleteIPListEntryQuery(softDelete bool) string {
	if softDelete {
		return fmt.Sprintf(`UPDATE %s SET updated_at=%s,deleted_at=%s WHERE type = %s AND ipornet = %s`,
			sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
	}
	return fmt.Sprintf(`DELETE FROM %s WHERE type = %s AND ipornet = %s`,
		sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getRemoveSoftDeletedIPListEntryQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE type = %s AND ipornet = %s AND deleted_at > 0`,
		sqlTableIPLists, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getConfigsQuery() string {
	return fmt.Sprintf(`SELECT configs FROM %s LIMIT 1`, sqlTableConfigs)
}

func getUpdateConfigsQuery() string {
	return fmt.Sprintf(`UPDATE %s SET configs = %s`, sqlTableConfigs, sqlPlaceholders[0])
}

func getRoleByNameQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE name = %s`, selectRoleFields, sqlTableRoles,
		sqlPlaceholders[0])
}

func getRolesQuery(order string, minimal bool) string {
	var fieldSelection string
	if minimal {
		fieldSelection = selectMinimalFields
	} else {
		fieldSelection = selectRoleFields
	}
	return fmt.Sprintf(`SELECT %s FROM %s ORDER BY name %s LIMIT %s OFFSET %s`, fieldSelection,
		sqlTableRoles, order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUsersWithRolesQuery(roles []Role) string {
	var sb strings.Builder
	for _, r := range roles {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(r.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT r.id, u.username FROM %s u INNER JOIN %s r ON u.role_id = r.id WHERE u.role_id IN %s`,
		sqlTableUsers, sqlTableRoles, sb.String())
}

func getAdminsWithRolesQuery(roles []Role) string {
	var sb strings.Builder
	for _, r := range roles {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(r.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT r.id, a.username FROM %s a INNER JOIN %s r ON a.role_id = r.id WHERE a.role_id IN %s`,
		sqlTableAdmins, sqlTableRoles, sb.String())
}

func getDumpRolesQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s`, selectRoleFields, sqlTableRoles)
}

func getAddRoleQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (name,description,created_at,updated_at)
		VALUES (%s,%s,%s,%s)`, sqlTableRoles, sqlPlaceholders[0], sqlPlaceholders[1],
		sqlPlaceholders[2], sqlPlaceholders[3])
}

func getUpdateRoleQuery() string {
	return fmt.Sprintf(`UPDATE %s SET description=%s,updated_at=%s
		WHERE name = %s`, sqlTableRoles, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2])
}

func getDeleteRoleQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE name = %s`, sqlTableRoles, sqlPlaceholders[0])
}

func getGroupByNameQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE name = %s`, selectGroupFields, getSQLQuotedName(sqlTableGroups),
		sqlPlaceholders[0])
}

func getGroupsQuery(order string, minimal bool) string {
	var fieldSelection string
	if minimal {
		fieldSelection = selectMinimalFields
	} else {
		fieldSelection = selectGroupFields
	}
	return fmt.Sprintf(`SELECT %s FROM %s ORDER BY name %s LIMIT %s OFFSET %s`, fieldSelection,
		getSQLQuotedName(sqlTableGroups), order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getGroupsWithNamesQuery(numArgs int) string {
	var sb strings.Builder
	for idx := 0; idx < numArgs; idx++ {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(sqlPlaceholders[idx])
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	} else {
		sb.WriteString("('')")
	}
	return fmt.Sprintf(`SELECT %s FROM %s WHERE name in %s`, selectGroupFields, getSQLQuotedName(sqlTableGroups), sb.String())
}

func getUsersInGroupsQuery(numArgs int) string {
	var sb strings.Builder
	for idx := 0; idx < numArgs; idx++ {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(sqlPlaceholders[idx])
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	} else {
		sb.WriteString("('')")
	}
	return fmt.Sprintf(`SELECT username FROM %s WHERE id IN (SELECT user_id from %s WHERE group_id IN (SELECT id FROM %s WHERE name IN %s))`,
		sqlTableUsers, sqlTableUsersGroupsMapping, getSQLQuotedName(sqlTableGroups), sb.String())
}

func getDumpGroupsQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s`, selectGroupFields, getSQLQuotedName(sqlTableGroups))
}

func getAddGroupQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (name,description,created_at,updated_at,user_settings)
		VALUES (%s,%s,%s,%s,%s)`, getSQLQuotedName(sqlTableGroups), sqlPlaceholders[0], sqlPlaceholders[1],
		sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4])
}

func getUpdateGroupQuery() string {
	return fmt.Sprintf(`UPDATE %s SET description=%s,user_settings=%s,updated_at=%s
		WHERE name = %s`, getSQLQuotedName(sqlTableGroups), sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2],
		sqlPlaceholders[3])
}

func getDeleteGroupQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE name = %s`, getSQLQuotedName(sqlTableGroups), sqlPlaceholders[0])
}

func getAdminByUsernameQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s a LEFT JOIN %s r on r.id = a.role_id WHERE a.username = %s`,
		selectAdminFields, sqlTableAdmins, sqlTableRoles, sqlPlaceholders[0])
}

func getAdminsQuery(order string) string {
	return fmt.Sprintf(`SELECT %s FROM %s a LEFT JOIN %s r on r.id = a.role_id ORDER BY a.username %s LIMIT %s OFFSET %s`,
		selectAdminFields, sqlTableAdmins, sqlTableRoles, order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDumpAdminsQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s a LEFT JOIN %s r on r.id = a.role_id`,
		selectAdminFields, sqlTableAdmins, sqlTableRoles)
}

func getAddAdminQuery(role string) string {
	return fmt.Sprintf(`INSERT INTO %s (username,password,status,email,permissions,filters,additional_info,description,created_at,updated_at,last_login,role_id)
		VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,COALESCE((SELECT id from %s WHERE name = %s),%s))`,
		sqlTableAdmins, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4],
		sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9],
		sqlTableRoles, sqlPlaceholders[10], getCoalesceDefaultForRole(role))
}

func getUpdateAdminQuery(role string) string {
	return fmt.Sprintf(`UPDATE %s SET password=%s,status=%s,email=%s,permissions=%s,filters=%s,additional_info=%s,description=%s,updated_at=%s,
		role_id=COALESCE((SELECT id from %s WHERE name = %s),%s) WHERE username = %s`, sqlTableAdmins, sqlPlaceholders[0],
		sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6],
		sqlPlaceholders[7], sqlTableRoles, sqlPlaceholders[8], getCoalesceDefaultForRole(role), sqlPlaceholders[9])
}

func getDeleteAdminQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE username = %s`, sqlTableAdmins, sqlPlaceholders[0])
}

func getShareByIDQuery(filterUser bool) string {
	if filterUser {
		return fmt.Sprintf(`SELECT %s FROM %s s INNER JOIN %s u ON s.user_id = u.id WHERE s.share_id = %s AND u.username = %s`,
			selectShareFields, sqlTableShares, sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1])
	}
	return fmt.Sprintf(`SELECT %s FROM %s s INNER JOIN %s u ON s.user_id = u.id WHERE s.share_id = %s`,
		selectShareFields, sqlTableShares, sqlTableUsers, sqlPlaceholders[0])
}

func getSharesQuery(order string) string {
	return fmt.Sprintf(`SELECT %s FROM %s s INNER JOIN %s u ON s.user_id = u.id WHERE u.username = %s ORDER BY s.share_id %s LIMIT %s OFFSET %s`,
		selectShareFields, sqlTableShares, sqlTableUsers, sqlPlaceholders[0], order, sqlPlaceholders[1], sqlPlaceholders[2])
}

func getDumpSharesQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s s INNER JOIN %s u ON s.user_id = u.id`,
		selectShareFields, sqlTableShares, sqlTableUsers)
}

func getAddShareQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (share_id,name,description,scope,paths,created_at,updated_at,last_use_at,
		expires_at,password,max_tokens,used_tokens,allow_from,user_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)`,
		sqlTableShares, sqlPlaceholders[0], sqlPlaceholders[1],
		sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6],
		sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9], sqlPlaceholders[10], sqlPlaceholders[11],
		sqlPlaceholders[12], sqlPlaceholders[13])
}

func getUpdateShareRestoreQuery() string {
	return fmt.Sprintf(`UPDATE %s SET name=%s,description=%s,scope=%s,paths=%s,created_at=%s,updated_at=%s,
		last_use_at=%s,expires_at=%s,password=%s,max_tokens=%s,used_tokens=%s,allow_from=%s,user_id=%s WHERE share_id = %s`, sqlTableShares,
		sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4],
		sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9],
		sqlPlaceholders[10], sqlPlaceholders[11], sqlPlaceholders[12], sqlPlaceholders[13])
}

func getUpdateShareQuery() string {
	return fmt.Sprintf(`UPDATE %s SET name=%s,description=%s,scope=%s,paths=%s,updated_at=%s,expires_at=%s,
		password=%s,max_tokens=%s,allow_from=%s,user_id=%s WHERE share_id = %s`, sqlTableShares,
		sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4],
		sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9],
		sqlPlaceholders[10])
}

func getDeleteShareQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE share_id = %s`, sqlTableShares, sqlPlaceholders[0])
}

func getAPIKeyByIDQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE key_id = %s`, selectAPIKeyFields, sqlTableAPIKeys, sqlPlaceholders[0])
}

func getAPIKeysQuery(order string) string {
	return fmt.Sprintf(`SELECT %s FROM %s ORDER BY key_id %s LIMIT %s OFFSET %s`, selectAPIKeyFields, sqlTableAPIKeys,
		order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDumpAPIKeysQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s`, selectAPIKeyFields, sqlTableAPIKeys)
}

func getAddAPIKeyQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (key_id,name,api_key,scope,created_at,updated_at,last_use_at,expires_at,description,user_id,admin_id)
		VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)`, sqlTableAPIKeys, sqlPlaceholders[0], sqlPlaceholders[1],
		sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6],
		sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9], sqlPlaceholders[10])
}

func getUpdateAPIKeyQuery() string {
	return fmt.Sprintf(`UPDATE %s SET name=%s,scope=%s,expires_at=%s,user_id=%s,admin_id=%s,description=%s,updated_at=%s
		WHERE key_id = %s`, sqlTableAPIKeys, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2],
		sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7])
}

func getDeleteAPIKeyQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE key_id = %s`, sqlTableAPIKeys, sqlPlaceholders[0])
}

func getRelatedUsersForAPIKeysQuery(apiKeys []APIKey) string {
	var sb strings.Builder
	for _, k := range apiKeys {
		if k.userID == 0 {
			continue
		}
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(k.userID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	} else {
		sb.WriteString("(0)")
	}
	return fmt.Sprintf(`SELECT id,username FROM %s WHERE id IN %s ORDER BY username`, sqlTableUsers, sb.String())
}

func getRelatedAdminsForAPIKeysQuery(apiKeys []APIKey) string {
	var sb strings.Builder
	for _, k := range apiKeys {
		if k.adminID == 0 {
			continue
		}
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(k.adminID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	} else {
		sb.WriteString("(0)")
	}
	return fmt.Sprintf(`SELECT id,username FROM %s WHERE id IN %s ORDER BY username`, sqlTableAdmins, sb.String())
}

func getUserByUsernameQuery(role string) string {
	if role == "" {
		return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE u.username = %s AND u.deleted_at = 0`,
			selectUserFields, sqlTableUsers, sqlTableRoles, sqlPlaceholders[0])
	}
	return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE u.username = %s AND u.deleted_at = 0
		AND u.role_id is NOT NULL AND r.name = %s`,
		selectUserFields, sqlTableUsers, sqlTableRoles, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUsersQuery(order, role string) string {
	if role == "" {
		return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE
			u.deleted_at = 0 ORDER BY u.username %s LIMIT %s OFFSET %s`,
			selectUserFields, sqlTableUsers, sqlTableRoles, order, sqlPlaceholders[0], sqlPlaceholders[1])
	}
	return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE
		u.deleted_at = 0 AND u.role_id is NOT NULL AND r.name = %s ORDER BY u.username %s LIMIT %s OFFSET %s`,
		selectUserFields, sqlTableUsers, sqlTableRoles, sqlPlaceholders[0], order, sqlPlaceholders[1], sqlPlaceholders[2])
}

func getUsersForQuotaCheckQuery(numArgs int) string {
	var sb strings.Builder
	for idx := 0; idx < numArgs; idx++ {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(sqlPlaceholders[idx])
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT id,username,quota_size,used_quota_size,total_data_transfer,upload_data_transfer,
		download_data_transfer,used_upload_data_transfer,used_download_data_transfer,filters FROM %s WHERE username IN %s`,
		sqlTableUsers, sb.String())
}

func getRecentlyUpdatedUsersQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE u.updated_at >= %s OR u.deleted_at > 0`,
		selectUserFields, sqlTableUsers, sqlTableRoles, sqlPlaceholders[0])
}

func getDumpUsersQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE u.deleted_at = 0`,
		selectUserFields, sqlTableUsers, sqlTableRoles)
}

func getDumpFoldersQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s`, selectFolderFields, sqlTableFolders)
}

func getUpdateTransferQuotaQuery(reset bool) string {
	if reset {
		return fmt.Sprintf(`UPDATE %s SET used_upload_data_transfer = %s,used_download_data_transfer = %s,last_quota_update = %s
			WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
	}
	return fmt.Sprintf(`UPDATE %s SET used_upload_data_transfer = used_upload_data_transfer + %s,
		used_download_data_transfer = used_download_data_transfer + %s,last_quota_update = %s
		WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getUpdateQuotaQuery(reset bool) string {
	if reset {
		return fmt.Sprintf(`UPDATE %s SET used_quota_size = %s,used_quota_files = %s,last_quota_update = %s
			WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
	}
	return fmt.Sprintf(`UPDATE %s SET used_quota_size = used_quota_size + %s,used_quota_files = used_quota_files + %s,last_quota_update = %s
		WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getAdminSignatureQuery() string {
	return fmt.Sprintf(`SELECT updated_at FROM %s WHERE username = %s`, sqlTableAdmins, sqlPlaceholders[0])
}

func getUserSignatureQuery() string {
	return fmt.Sprintf(`SELECT updated_at FROM %s WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0])
}

func getSetUpdateAtQuery() string {
	return fmt.Sprintf(`UPDATE %s SET updated_at = %s WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getSetFirstUploadQuery() string {
	return fmt.Sprintf(`UPDATE %s SET first_upload = %s WHERE username = %s AND first_upload = 0`,
		sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getSetFirstDownloadQuery() string {
	return fmt.Sprintf(`UPDATE %s SET first_download = %s WHERE username = %s AND first_download = 0`,
		sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUpdateLastLoginQuery() string {
	return fmt.Sprintf(`UPDATE %s SET last_login = %s WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUpdateAdminLastLoginQuery() string {
	return fmt.Sprintf(`UPDATE %s SET last_login = %s WHERE username = %s`, sqlTableAdmins, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUpdateAPIKeyLastUseQuery() string {
	return fmt.Sprintf(`UPDATE %s SET last_use_at = %s WHERE key_id = %s`, sqlTableAPIKeys, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUpdateShareLastUseQuery() string {
	return fmt.Sprintf(`UPDATE %s SET last_use_at = %s, used_tokens = used_tokens +%s WHERE share_id = %s`,
		sqlTableShares, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2])
}

func getQuotaQuery() string {
	return fmt.Sprintf(`SELECT used_quota_size,used_quota_files,used_upload_data_transfer,
		used_download_data_transfer FROM %s WHERE username = %s`,
		sqlTableUsers, sqlPlaceholders[0])
}

func getAddUserQuery(role string) string {
	return fmt.Sprintf(`INSERT INTO %s (username,password,public_keys,home_dir,uid,gid,max_sessions,quota_size,quota_files,permissions,
		used_quota_size,used_quota_files,last_quota_update,upload_bandwidth,download_bandwidth,status,last_login,expiration_date,filters,
		filesystem,additional_info,description,email,created_at,updated_at,upload_data_transfer,download_data_transfer,total_data_transfer,
		used_upload_data_transfer,used_download_data_transfer,deleted_at,first_download,first_upload,role_id,last_password_change)
		VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0,0,%s,%s,%s,0,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0,0,0,0,
		COALESCE((SELECT id from %s WHERE name=%s),%s),%s)`,
		sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4],
		sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9],
		sqlPlaceholders[10], sqlPlaceholders[11], sqlPlaceholders[12], sqlPlaceholders[13], sqlPlaceholders[14],
		sqlPlaceholders[15], sqlPlaceholders[16], sqlPlaceholders[17], sqlPlaceholders[18], sqlPlaceholders[19],
		sqlPlaceholders[20], sqlPlaceholders[21], sqlPlaceholders[22], sqlPlaceholders[23], sqlTableRoles,
		sqlPlaceholders[24], getCoalesceDefaultForRole(role), sqlPlaceholders[25])
}

func getUpdateUserQuery(role string) string {
	return fmt.Sprintf(`UPDATE %s SET password=%s,public_keys=%s,home_dir=%s,uid=%s,gid=%s,max_sessions=%s,quota_size=%s,
		quota_files=%s,permissions=%s,upload_bandwidth=%s,download_bandwidth=%s,status=%s,expiration_date=%s,filters=%s,filesystem=%s,
		additional_info=%s,description=%s,email=%s,updated_at=%s,upload_data_transfer=%s,download_data_transfer=%s,
		total_data_transfer=%s,role_id=COALESCE((SELECT id from %s WHERE name=%s),%s),last_password_change=%s WHERE username = %s`,
		sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4],
		sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9],
		sqlPlaceholders[10], sqlPlaceholders[11], sqlPlaceholders[12], sqlPlaceholders[13], sqlPlaceholders[14],
		sqlPlaceholders[15], sqlPlaceholders[16], sqlPlaceholders[17], sqlPlaceholders[18], sqlPlaceholders[19],
		sqlPlaceholders[20], sqlPlaceholders[21], sqlTableRoles, sqlPlaceholders[22], getCoalesceDefaultForRole(role),
		sqlPlaceholders[23], sqlPlaceholders[24])
}

func getUpdateUserPasswordQuery() string {
	return fmt.Sprintf(`UPDATE %s SET password=%s,updated_at=%s WHERE username = %s`,
		sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2])
}

func getDeleteUserQuery(softDelete bool) string {
	if softDelete {
		return fmt.Sprintf(`UPDATE %s SET updated_at=%s,deleted_at=%s WHERE username = %s`,
			sqlTableUsers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2])
	}
	return fmt.Sprintf(`DELETE FROM %s WHERE username = %s`, sqlTableUsers, sqlPlaceholders[0])
}

func getRemoveSoftDeletedUserQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE username = %s AND deleted_at > 0`, sqlTableUsers, sqlPlaceholders[0])
}

func getFolderByNameQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE name = %s`, selectFolderFields, sqlTableFolders, sqlPlaceholders[0])
}

func getAddFolderQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (path,used_quota_size,used_quota_files,last_quota_update,name,description,filesystem)
		VALUES (%s,%s,%s,%s,%s,%s,%s)`, sqlTableFolders, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2],
		sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6])
}

func getUpdateFolderQuery() string {
	return fmt.Sprintf(`UPDATE %s SET path=%s,description=%s,filesystem=%s WHERE name = %s`, sqlTableFolders, sqlPlaceholders[0],
		sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getDeleteFolderQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE name = %s`, sqlTableFolders, sqlPlaceholders[0])
}

func getClearUserGroupMappingQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE user_id = (SELECT id FROM %s WHERE username = %s)`, sqlTableUsersGroupsMapping,
		sqlTableUsers, sqlPlaceholders[0])
}

func getAddUserGroupMappingQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (user_id,group_id,group_type) VALUES ((SELECT id FROM %s WHERE username = %s),
		(SELECT id FROM %s WHERE name = %s),%s)`,
		sqlTableUsersGroupsMapping, sqlTableUsers, sqlPlaceholders[0], getSQLQuotedName(sqlTableGroups),
		sqlPlaceholders[1], sqlPlaceholders[2])
}

func getClearAdminGroupMappingQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE admin_id = (SELECT id FROM %s WHERE username = %s)`, sqlTableAdminsGroupsMapping,
		sqlTableAdmins, sqlPlaceholders[0])
}

func getAddAdminGroupMappingQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (admin_id,group_id,options) VALUES ((SELECT id FROM %s WHERE username = %s),
		(SELECT id FROM %s WHERE name = %s),%s)`,
		sqlTableAdminsGroupsMapping, sqlTableAdmins, sqlPlaceholders[0], getSQLQuotedName(sqlTableGroups),
		sqlPlaceholders[1], sqlPlaceholders[2])
}

func getClearGroupFolderMappingQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE group_id = (SELECT id FROM %s WHERE name = %s)`, sqlTableGroupsFoldersMapping,
		getSQLQuotedName(sqlTableGroups), sqlPlaceholders[0])
}

func getAddGroupFolderMappingQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (virtual_path,quota_size,quota_files,folder_id,group_id)
		VALUES (%s,%s,%s,(SELECT id FROM %s WHERE name = %s),(SELECT id FROM %s WHERE name = %s))`,
		sqlTableGroupsFoldersMapping, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlTableFolders,
		sqlPlaceholders[3], getSQLQuotedName(sqlTableGroups), sqlPlaceholders[4])
}

func getClearUserFolderMappingQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE user_id = (SELECT id FROM %s WHERE username = %s)`, sqlTableUsersFoldersMapping,
		sqlTableUsers, sqlPlaceholders[0])
}

func getAddUserFolderMappingQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (virtual_path,quota_size,quota_files,folder_id,user_id)
		VALUES (%s,%s,%s,(SELECT id FROM %s WHERE name = %s),(SELECT id FROM %s WHERE username = %s))`,
		sqlTableUsersFoldersMapping, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlTableFolders,
		sqlPlaceholders[3], sqlTableUsers, sqlPlaceholders[4])
}

func getFoldersQuery(order string, minimal bool) string {
	var fieldSelection string
	if minimal {
		fieldSelection = selectMinimalFields
	} else {
		fieldSelection = selectFolderFields
	}
	return fmt.Sprintf(`SELECT %s FROM %s ORDER BY name %s LIMIT %s OFFSET %s`, fieldSelection, sqlTableFolders,
		order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUpdateFolderQuotaQuery(reset bool) string {
	if reset {
		return fmt.Sprintf(`UPDATE %s SET used_quota_size = %s,used_quota_files = %s,last_quota_update = %s
			WHERE name = %s`, sqlTableFolders, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
	}
	return fmt.Sprintf(`UPDATE %s SET used_quota_size = used_quota_size + %s,used_quota_files = used_quota_files + %s,last_quota_update = %s
		WHERE name = %s`, sqlTableFolders, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getQuotaFolderQuery() string {
	return fmt.Sprintf(`SELECT used_quota_size,used_quota_files FROM %s WHERE name = %s`, sqlTableFolders,
		sqlPlaceholders[0])
}

func getRelatedGroupsForUsersQuery(users []User) string {
	var sb strings.Builder
	for _, u := range users {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(u.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT g.name,ug.group_type,ug.user_id FROM %s g INNER JOIN %s ug ON g.id = ug.group_id WHERE
		ug.user_id IN %s ORDER BY g.name`, getSQLQuotedName(sqlTableGroups), sqlTableUsersGroupsMapping, sb.String())
}

func getRelatedGroupsForAdminsQuery(admins []Admin) string {
	var sb strings.Builder
	for _, a := range admins {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(a.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT g.name,ag.options,ag.admin_id FROM %s g INNER JOIN %s ag ON g.id = ag.group_id WHERE
		ag.admin_id IN %s ORDER BY g.name`, getSQLQuotedName(sqlTableGroups), sqlTableAdminsGroupsMapping, sb.String())
}

func getRelatedFoldersForUsersQuery(users []User) string {
	var sb strings.Builder
	for _, u := range users {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(u.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT f.id,f.name,f.path,f.used_quota_size,f.used_quota_files,f.last_quota_update,fm.virtual_path,
		fm.quota_size,fm.quota_files,fm.user_id,f.filesystem,f.description FROM %s f INNER JOIN %s fm ON f.id = fm.folder_id WHERE
		fm.user_id IN %s ORDER BY f.name`, sqlTableFolders, sqlTableUsersFoldersMapping, sb.String())
}

func getRelatedUsersForFoldersQuery(folders []vfs.BaseVirtualFolder) string {
	var sb strings.Builder
	for _, f := range folders {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(f.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT fm.folder_id,u.username FROM %s fm INNER JOIN %s u ON fm.user_id = u.id
		WHERE fm.folder_id IN %s ORDER BY u.username`, sqlTableUsersFoldersMapping, sqlTableUsers, sb.String())
}

func getRelatedGroupsForFoldersQuery(folders []vfs.BaseVirtualFolder) string {
	var sb strings.Builder
	for _, f := range folders {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(f.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT fm.folder_id,g.name FROM %s fm INNER JOIN %s g ON fm.group_id = g.id
		WHERE fm.folder_id IN %s ORDER BY g.name`, sqlTableGroupsFoldersMapping, getSQLQuotedName(sqlTableGroups),
		sb.String())
}

func getRelatedUsersForGroupsQuery(groups []Group) string {
	var sb strings.Builder
	for _, g := range groups {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(g.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT um.group_id,u.username FROM %s um INNER JOIN %s u ON um.user_id = u.id
		WHERE um.group_id IN %s ORDER BY u.username`, sqlTableUsersGroupsMapping, sqlTableUsers, sb.String())
}

func getRelatedAdminsForGroupsQuery(groups []Group) string {
	var sb strings.Builder
	for _, g := range groups {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(g.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT am.group_id,a.username FROM %s am INNER JOIN %s a ON am.admin_id = a.id
		WHERE am.group_id IN %s ORDER BY a.username`, sqlTableAdminsGroupsMapping, sqlTableAdmins, sb.String())
}

func getRelatedFoldersForGroupsQuery(groups []Group) string {
	var sb strings.Builder
	for _, g := range groups {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(g.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT f.id,f.name,f.path,f.used_quota_size,f.used_quota_files,f.last_quota_update,fm.virtual_path,
		fm.quota_size,fm.quota_files,fm.group_id,f.filesystem,f.description FROM %s f INNER JOIN %s fm ON f.id = fm.folder_id WHERE
		fm.group_id IN %s ORDER BY f.name`, sqlTableFolders, sqlTableGroupsFoldersMapping, sb.String())
}

func getActiveTransfersQuery() string {
	return fmt.Sprintf(`SELECT transfer_id,connection_id,transfer_type,username,folder_name,ip,truncated_size,
		current_ul_size,current_dl_size,created_at,updated_at FROM %s WHERE updated_at > %s`,
		sqlTableActiveTransfers, sqlPlaceholders[0])
}

func getAddActiveTransferQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (transfer_id,connection_id,transfer_type,username,folder_name,ip,truncated_size,
		current_ul_size,current_dl_size,created_at,updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)`,
		sqlTableActiveTransfers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3],
		sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8],
		sqlPlaceholders[9], sqlPlaceholders[10])
}

func getUpdateActiveTransferSizesQuery() string {
	return fmt.Sprintf(`UPDATE %s SET current_ul_size=%s,current_dl_size=%s,updated_at=%s WHERE connection_id = %s AND transfer_id = %s`,
		sqlTableActiveTransfers, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4])
}

func getRemoveActiveTransferQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE connection_id = %s AND transfer_id = %s`,
		sqlTableActiveTransfers, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getCleanupActiveTransfersQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE updated_at < %s`, sqlTableActiveTransfers, sqlPlaceholders[0])
}

func getRelatedRulesForActionsQuery(actions []BaseEventAction) string {
	var sb strings.Builder
	for _, a := range actions {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(a.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT am.action_id,r.name FROM %s am INNER JOIN %s r ON am.rule_id = r.id
		WHERE am.action_id IN %s ORDER BY r.name ASC`, sqlTableRulesActionsMapping, sqlTableEventsRules, sb.String())
}

func getEventsActionsQuery(order string, minimal bool) string {
	var fieldSelection string
	if minimal {
		fieldSelection = selectMinimalFields
	} else {
		fieldSelection = selectEventActionFields
	}
	return fmt.Sprintf(`SELECT %s FROM %s ORDER BY name %s LIMIT %s OFFSET %s`, fieldSelection,
		sqlTableEventsActions, order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDumpEventActionsQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s`, selectEventActionFields, sqlTableEventsActions)
}

func getEventActionByNameQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE name = %s`, selectEventActionFields, sqlTableEventsActions,
		sqlPlaceholders[0])
}

func getAddEventActionQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (name,description,type,options) VALUES (%s,%s,%s,%s)`,
		sqlTableEventsActions, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getUpdateEventActionQuery() string {
	return fmt.Sprintf(`UPDATE %s SET description=%s,type=%s,options=%s WHERE name = %s`, sqlTableEventsActions,
		sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getDeleteEventActionQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE name = %s`, sqlTableEventsActions, sqlPlaceholders[0])
}

func getEventRulesQuery(order string) string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE deleted_at = 0 ORDER BY name %s LIMIT %s OFFSET %s`,
		getSelectEventRuleFields(), sqlTableEventsRules, order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDumpEventRulesQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE deleted_at = 0`, getSelectEventRuleFields(), sqlTableEventsRules)
}

func getRecentlyUpdatedRulesQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE updated_at >= %s OR deleted_at > 0`, getSelectEventRuleFields(),
		sqlTableEventsRules, sqlPlaceholders[0])
}

func getEventRulesByNameQuery() string {
	return fmt.Sprintf(`SELECT %s FROM %s WHERE name = %s AND deleted_at = 0`, getSelectEventRuleFields(), sqlTableEventsRules,
		sqlPlaceholders[0])
}

func getAddEventRuleQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (name,description,created_at,updated_at,%s,conditions,deleted_at,status)
		VALUES (%s,%s,%s,%s,%s,%s,0,%s)`,
		sqlTableEventsRules, getSQLQuotedName("trigger"), sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2],
		sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6])
}

func getUpdateEventRuleQuery() string {
	return fmt.Sprintf(`UPDATE %s SET description=%s,updated_at=%s,%s=%s,conditions=%s,status=%s WHERE name = %s`,
		sqlTableEventsRules, sqlPlaceholders[0], sqlPlaceholders[1], getSQLQuotedName("trigger"), sqlPlaceholders[2],
		sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5])
}

func getDeleteEventRuleQuery(softDelete bool) string {
	if softDelete {
		return fmt.Sprintf(`UPDATE %s SET updated_at=%s,deleted_at=%s WHERE name = %s`,
			sqlTableEventsRules, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2])
	}
	return fmt.Sprintf(`DELETE FROM %s WHERE name = %s`, sqlTableEventsRules, sqlPlaceholders[0])
}

func getRemoveSoftDeletedRuleQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE name = %s AND deleted_at > 0`, sqlTableEventsRules, sqlPlaceholders[0])
}

func getClearRuleActionMappingQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE rule_id = (SELECT id FROM %s WHERE name = %s)`, sqlTableRulesActionsMapping,
		sqlTableEventsRules, sqlPlaceholders[0])
}

func getUpdateRulesTimestampQuery() string {
	return fmt.Sprintf(`UPDATE %s SET updated_at=%s WHERE id IN (SELECT rule_id FROM %s WHERE action_id = (SELECT id from %s WHERE name = %s))`,
		sqlTableEventsRules, sqlPlaceholders[0], sqlTableRulesActionsMapping, sqlTableEventsActions, sqlPlaceholders[1])
}

func getRelatedActionsForRulesQuery(rules []EventRule) string {
	var sb strings.Builder
	for _, r := range rules {
		if sb.Len() == 0 {
			sb.WriteString("(")
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(strconv.FormatInt(r.ID, 10))
	}
	if sb.Len() > 0 {
		sb.WriteString(")")
	}
	return fmt.Sprintf(`SELECT a.id,a.name,a.description,a.type,a.options,am.options,am.%s,
		am.rule_id FROM %s a INNER JOIN %s am ON a.id = am.action_id WHERE am.rule_id IN %s ORDER BY am.%s ASC`,
		getSQLQuotedName("order"), sqlTableEventsActions, sqlTableRulesActionsMapping, sb.String(),
		getSQLQuotedName("order"))
}

func getAddRuleActionMappingQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (rule_id,action_id,%s,options) VALUES ((SELECT id FROM %s WHERE name = %s),
		(SELECT id FROM %s WHERE name = %s),%s,%s)`,
		sqlTableRulesActionsMapping, getSQLQuotedName("order"), sqlTableEventsRules, sqlPlaceholders[0],
		sqlTableEventsActions, sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getTaskByNameQuery() string {
	return fmt.Sprintf(`SELECT updated_at,version FROM %s WHERE name = %s`, sqlTableTasks, sqlPlaceholders[0])
}

func getAddTaskQuery() string {
	return fmt.Sprintf(`INSERT INTO %s (name,updated_at,version) VALUES (%s,%s,0)`,
		sqlTableTasks, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUpdateTaskQuery() string {
	return fmt.Sprintf(`UPDATE %s SET updated_at=%s,version = version + 1 WHERE name = %s AND version = %s`,
		sqlTableTasks, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2])
}

func getUpdateTaskTimestampQuery() string {
	return fmt.Sprintf(`UPDATE %s SET updated_at=%s WHERE name = %s`,
		sqlTableTasks, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getDeleteTaskQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE name = %s`, sqlTableTasks, sqlPlaceholders[0])
}

func getAddNodeQuery() string {
	if config.Driver == MySQLDataProviderName {
		return fmt.Sprintf("INSERT INTO %s (`name`,`data`,created_at,`updated_at`) VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE "+
			"`data`=VALUES(`data`), `created_at`=VALUES(`created_at`), `updated_at`=VALUES(`updated_at`)",
			sqlTableNodes, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
	}
	return fmt.Sprintf(`INSERT INTO %s (name,data,created_at,updated_at) VALUES (%s,%s,%s,%s) ON CONFLICT(name)
		DO UPDATE SET data=EXCLUDED.data, created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at`,
		sqlTableNodes, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getUpdateNodeTimestampQuery() string {
	return fmt.Sprintf(`UPDATE %s SET updated_at=%s WHERE name = %s`,
		sqlTableNodes, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getNodeByNameQuery() string {
	return fmt.Sprintf(`SELECT name,data,created_at,updated_at FROM %s WHERE name = %s AND updated_at > %s`,
		sqlTableNodes, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getNodesQuery() string {
	return fmt.Sprintf(`SELECT name,data,created_at,updated_at FROM %s WHERE name != %s AND updated_at > %s`,
		sqlTableNodes, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getCleanupNodesQuery() string {
	return fmt.Sprintf(`DELETE FROM %s WHERE updated_at < %s`, sqlTableNodes, sqlPlaceholders[0])
}

func getDatabaseVersionQuery() string {
	return fmt.Sprintf("SELECT version from %s LIMIT 1", sqlTableSchemaVersion)
}

func getUpdateDBVersionQuery() string {
	return fmt.Sprintf(`UPDATE %s SET version=%s`, sqlTableSchemaVersion, sqlPlaceholders[0])
}
