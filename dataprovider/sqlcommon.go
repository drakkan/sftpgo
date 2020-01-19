package dataprovider

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

func getUserByUsername(username string, dbHandle *sql.DB) (User, error) {
	var user User
	q := getUserByUsernameQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return user, err
	}
	defer stmt.Close()

	row := stmt.QueryRow(username)
	return getUserFromDbRow(row, nil)
}

func sqlCommonValidateUserAndPass(username string, password string, dbHandle *sql.DB) (User, error) {
	var user User
	if len(password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := getUserByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, err
	}
	return checkUserAndPass(user, password)
}

func sqlCommonValidateUserAndPubKey(username string, pubKey string, dbHandle *sql.DB) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("Credentials cannot be null or empty")
	}
	user, err := getUserByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(user, pubKey)
}

func sqlCommonCheckAvailability(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return dbHandle.PingContext(ctx)
}

func sqlCommonGetUserByID(ID int64, dbHandle *sql.DB) (User, error) {
	var user User
	q := getUserByIDQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return user, err
	}
	defer stmt.Close()

	row := stmt.QueryRow(ID)
	return getUserFromDbRow(row, nil)
}

func sqlCommonUpdateQuota(username string, filesAdd int, sizeAdd int64, reset bool, dbHandle *sql.DB) error {
	q := getUpdateQuotaQuery(reset)
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(sizeAdd, filesAdd, utils.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "quota updated for user %#v, files increment: %v size increment: %v is reset? %v",
			username, filesAdd, sizeAdd, reset)
	} else {
		providerLog(logger.LevelWarn, "error updating quota for user %#v: %v", username, err)
	}
	return err
}

func sqlCommonUpdateLastLogin(username string, dbHandle *sql.DB) error {
	q := getUpdateLastLoginQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(utils.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "last login updated for user %#v", username)
	} else {
		providerLog(logger.LevelWarn, "error updating last login for user %#v: %v", username, err)
	}
	return err
}

func sqlCommonGetUsedQuota(username string, dbHandle *sql.DB) (int, int64, error) {
	q := getQuotaQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return 0, 0, err
	}
	defer stmt.Close()

	var usedFiles int
	var usedSize int64
	err = stmt.QueryRow(username).Scan(&usedSize, &usedFiles)
	if err != nil {
		providerLog(logger.LevelWarn, "error getting quota for user: %v, error: %v", username, err)
		return 0, 0, err
	}
	return usedFiles, usedSize, err
}

func sqlCommonCheckUserExists(username string, dbHandle *sql.DB) (User, error) {
	var user User
	q := getUserByUsernameQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return user, err
	}
	defer stmt.Close()
	row := stmt.QueryRow(username)
	return getUserFromDbRow(row, nil)
}

func sqlCommonAddUser(user User, dbHandle *sql.DB) error {
	err := validateUser(&user)
	if err != nil {
		return err
	}
	q := getAddUserQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
	_, err = stmt.Exec(user.Username, user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID, user.MaxSessions, user.QuotaSize,
		user.QuotaFiles, string(permissions), user.UploadBandwidth, user.DownloadBandwidth, user.Status, user.ExpirationDate, string(filters),
		string(fsConfig))
	return err
}

func sqlCommonUpdateUser(user User, dbHandle *sql.DB) error {
	err := validateUser(&user)
	if err != nil {
		return err
	}
	q := getUpdateUserQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
	_, err = stmt.Exec(user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID, user.MaxSessions, user.QuotaSize,
		user.QuotaFiles, string(permissions), user.UploadBandwidth, user.DownloadBandwidth, user.Status, user.ExpirationDate,
		string(filters), string(fsConfig), user.ID)
	return err
}

func sqlCommonDeleteUser(user User, dbHandle *sql.DB) error {
	q := getDeleteUserQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(user.ID)
	return err
}

func sqlCommonDumpUsers(dbHandle *sql.DB) ([]User, error) {
	users := []User{}
	q := getDumpUsersQuery()
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			u, err := getUserFromDbRow(nil, rows)
			if err == nil {
				users = append(users, u)
			} else {
				break
			}
		}
	}

	return users, err
}

func sqlCommonGetUsers(limit int, offset int, order string, username string, dbHandle *sql.DB) ([]User, error) {
	users := []User{}
	q := getUsersQuery(order, username)
	stmt, err := dbHandle.Prepare(q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	var rows *sql.Rows
	if len(username) > 0 {
		rows, err = stmt.Query(username, limit, offset)
	} else {
		rows, err = stmt.Query(limit, offset)
	}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			u, err := getUserFromDbRow(nil, rows)
			if err == nil {
				users = append(users, HideUserSensitiveData(&u))
			} else {
				break
			}
		}
	}

	return users, err
}

func getUserFromDbRow(row *sql.Row, rows *sql.Rows) (User, error) {
	var user User
	var permissions sql.NullString
	var password sql.NullString
	var publicKey sql.NullString
	var filters sql.NullString
	var fsConfig sql.NullString
	var err error
	if row != nil {
		err = row.Scan(&user.ID, &user.Username, &password, &publicKey, &user.HomeDir, &user.UID, &user.GID, &user.MaxSessions,
			&user.QuotaSize, &user.QuotaFiles, &permissions, &user.UsedQuotaSize, &user.UsedQuotaFiles, &user.LastQuotaUpdate,
			&user.UploadBandwidth, &user.DownloadBandwidth, &user.ExpirationDate, &user.LastLogin, &user.Status, &filters, &fsConfig)

	} else {
		err = rows.Scan(&user.ID, &user.Username, &password, &publicKey, &user.HomeDir, &user.UID, &user.GID, &user.MaxSessions,
			&user.QuotaSize, &user.QuotaFiles, &permissions, &user.UsedQuotaSize, &user.UsedQuotaFiles, &user.LastQuotaUpdate,
			&user.UploadBandwidth, &user.DownloadBandwidth, &user.ExpirationDate, &user.LastLogin, &user.Status, &filters, &fsConfig)
	}
	if err != nil {
		if err == sql.ErrNoRows {
			return user, &RecordNotFoundError{err: err.Error()}
		}
		return user, err
	}
	if password.Valid {
		user.Password = password.String
	}
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
		if err == nil {
			user.Permissions = perms
		} else {
			// compatibility layer: until version 0.9.4 permissions were a string list
			var list []string
			err = json.Unmarshal([]byte(permissions.String), &list)
			if err == nil {
				perms["/"] = list
				user.Permissions = perms
			}
		}
	}
	if filters.Valid {
		var userFilters UserFilters
		err = json.Unmarshal([]byte(filters.String), &userFilters)
		if err == nil {
			user.Filters = userFilters
		}
	} else {
		user.Filters = UserFilters{
			AllowedIP: []string{},
			DeniedIP:  []string{},
		}
	}
	if fsConfig.Valid {
		var fs Filesystem
		err = json.Unmarshal([]byte(fsConfig.String), &fs)
		if err == nil {
			user.FsConfig = fs
		}
	} else {
		user.FsConfig = Filesystem{
			Provider: 0,
		}
	}
	return user, err
}
