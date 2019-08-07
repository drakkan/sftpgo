package dataprovider

import "fmt"

const (
	selectUserFields = "id,username,password,public_keys,home_dir,uid,gid,max_sessions,quota_size,quota_files,permissions," +
		"used_quota_size,used_quota_files,last_quota_update,upload_bandwidth,download_bandwidth"
)

func getSQLPlaceholders() []string {
	var placeholders []string
	for i := 1; i <= 20; i++ {
		if config.Driver == PGSSQLDataProviderName {
			placeholders = append(placeholders, fmt.Sprintf("$%v", i))
		} else {
			placeholders = append(placeholders, "?")
		}
	}
	return placeholders
}

func getUserByUsernameQuery() string {
	return fmt.Sprintf(`SELECT %v FROM %v WHERE username = %v`, selectUserFields, config.UsersTable, sqlPlaceholders[0])
}

func getUserByIDQuery() string {
	return fmt.Sprintf(`SELECT %v FROM %v WHERE id = %v`, selectUserFields, config.UsersTable, sqlPlaceholders[0])
}

func getUsersQuery(order string, username string) string {
	if len(username) > 0 {
		return fmt.Sprintf(`SELECT %v FROM %v WHERE username = %v ORDER BY username %v LIMIT %v OFFSET %v`,
			selectUserFields, config.UsersTable, sqlPlaceholders[0], order, sqlPlaceholders[1], sqlPlaceholders[2])
	}
	return fmt.Sprintf(`SELECT %v FROM %v ORDER BY username %v LIMIT %v OFFSET %v`, selectUserFields, config.UsersTable,
		order, sqlPlaceholders[0], sqlPlaceholders[1])
}

func getUpdateQuotaQuery(reset bool) string {
	if reset {
		return fmt.Sprintf(`UPDATE %v SET used_quota_size = %v,used_quota_files = %v,last_quota_update = %v 
			WHERE username = %v`, config.UsersTable, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
	}
	return fmt.Sprintf(`UPDATE %v SET used_quota_size = used_quota_size + %v,used_quota_files = used_quota_files + %v,last_quota_update = %v 
		WHERE username = %v`, config.UsersTable, sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3])
}

func getQuotaQuery() string {
	return fmt.Sprintf(`SELECT used_quota_size,used_quota_files FROM %v WHERE username = %v`, config.UsersTable,
		sqlPlaceholders[0])
}

func getAddUserQuery() string {
	return fmt.Sprintf(`INSERT INTO %v (username,password,public_keys,home_dir,uid,gid,max_sessions,quota_size,quota_files,permissions,
		used_quota_size,used_quota_files,last_quota_update,upload_bandwidth,download_bandwidth) 
		VALUES (%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,0,0,0,%v,%v)`, config.UsersTable, sqlPlaceholders[0], sqlPlaceholders[1],
		sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5], sqlPlaceholders[6], sqlPlaceholders[7],
		sqlPlaceholders[8], sqlPlaceholders[9], sqlPlaceholders[10], sqlPlaceholders[11])
}

func getUpdateUserQuery() string {
	return fmt.Sprintf(`UPDATE %v SET password=%v,public_keys=%v,home_dir=%v,uid=%v,gid=%v,max_sessions=%v,quota_size=%v,
		quota_files=%v,permissions=%v,upload_bandwidth=%v,download_bandwidth=%v WHERE id = %v`, config.UsersTable,
		sqlPlaceholders[0], sqlPlaceholders[1], sqlPlaceholders[2], sqlPlaceholders[3], sqlPlaceholders[4], sqlPlaceholders[5],
		sqlPlaceholders[6], sqlPlaceholders[7], sqlPlaceholders[8], sqlPlaceholders[9], sqlPlaceholders[10], sqlPlaceholders[11])
}

func getDeleteUserQuery() string {
	return fmt.Sprintf(`DELETE FROM %v WHERE id = %v`, config.UsersTable, sqlPlaceholders[0])
}
