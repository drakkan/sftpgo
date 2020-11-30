package dataprovider

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	sqlDatabaseVersion     = 6
	initialDBVersionSQL    = "INSERT INTO {{schema_version}} (version) VALUES (1);"
	defaultSQLQueryTimeout = 10 * time.Second
	longSQLQueryTimeout    = 60 * time.Second
)

var errSQLFoldersAssosaction = errors.New("unable to associate virtual folders to user")

type sqlQuerier interface {
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

func getUserByUsername(username string, dbHandle sqlQuerier) (User, error) {
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUserByUsernameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return user, err
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, username)
	user, err = getUserFromDbRow(row, nil)
	if err != nil {
		return user, err
	}
	return getUserWithVirtualFolders(user, dbHandle)
}

func sqlCommonValidateUserAndPass(username, password, ip, protocol string, dbHandle *sql.DB) (User, error) {
	var user User
	if len(password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := getUserByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, err
	}
	return checkUserAndPass(user, password, ip, protocol)
}

func sqlCommonValidateUserAndPubKey(username string, pubKey []byte, dbHandle *sql.DB) (User, string, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return dbHandle.PingContext(ctx)
}

func sqlCommonGetUserByID(ID int64, dbHandle *sql.DB) (User, error) {
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUserByIDQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return user, err
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, ID)
	user, err = getUserFromDbRow(row, nil)
	if err != nil {
		return user, err
	}
	return getUserWithVirtualFolders(user, dbHandle)
}

func sqlCommonUpdateQuota(username string, filesAdd int, sizeAdd int64, reset bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateQuotaQuery(reset)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, sizeAdd, filesAdd, utils.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "quota updated for user %#v, files increment: %v size increment: %v is reset? %v",
			username, filesAdd, sizeAdd, reset)
	} else {
		providerLog(logger.LevelWarn, "error updating quota for user %#v: %v", username, err)
	}
	return err
}

func sqlCommonGetUsedQuota(username string, dbHandle *sql.DB) (int, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getQuotaQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return 0, 0, err
	}
	defer stmt.Close()

	var usedFiles int
	var usedSize int64
	err = stmt.QueryRowContext(ctx, username).Scan(&usedSize, &usedFiles)
	if err != nil {
		providerLog(logger.LevelWarn, "error getting quota for user: %v, error: %v", username, err)
		return 0, 0, err
	}
	return usedFiles, usedSize, err
}

func sqlCommonUpdateLastLogin(username string, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateLastLoginQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, utils.GetTimeAsMsSinceEpoch(time.Now()), username)
	if err == nil {
		providerLog(logger.LevelDebug, "last login updated for user %#v", username)
	} else {
		providerLog(logger.LevelWarn, "error updating last login for user %#v: %v", username, err)
	}
	return err
}

func sqlCommonCheckUserExists(username string, dbHandle *sql.DB) (User, error) {
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUserByUsernameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return user, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx, username)
	user, err = getUserFromDbRow(row, nil)
	if err != nil {
		return user, err
	}
	return getUserWithVirtualFolders(user, dbHandle)
}

func sqlCommonAddUser(user User, dbHandle *sql.DB) error {
	err := validateUser(&user)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	tx, err := dbHandle.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	q := getAddUserQuery()
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		sqlCommonRollbackTransaction(tx)
		return err
	}
	defer stmt.Close()
	permissions, err := user.GetPermissionsAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	publicKeys, err := user.GetPublicKeysAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	filters, err := user.GetFiltersAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	fsConfig, err := user.GetFsConfigAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = stmt.ExecContext(ctx, user.Username, user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID, user.MaxSessions, user.QuotaSize,
		user.QuotaFiles, string(permissions), user.UploadBandwidth, user.DownloadBandwidth, user.Status, user.ExpirationDate, string(filters),
		string(fsConfig), user.AdditionalInfo)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	err = generateVirtualFoldersMapping(ctx, user, tx)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	return tx.Commit()
}

func sqlCommonUpdateUser(user User, dbHandle *sql.DB) error {
	err := validateUser(&user)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	tx, err := dbHandle.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	q := getUpdateUserQuery()
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		sqlCommonRollbackTransaction(tx)
		return err
	}
	defer stmt.Close()
	permissions, err := user.GetPermissionsAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	publicKeys, err := user.GetPublicKeysAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	filters, err := user.GetFiltersAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	fsConfig, err := user.GetFsConfigAsJSON()
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	_, err = stmt.ExecContext(ctx, user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID, user.MaxSessions, user.QuotaSize,
		user.QuotaFiles, string(permissions), user.UploadBandwidth, user.DownloadBandwidth, user.Status, user.ExpirationDate,
		string(filters), string(fsConfig), user.AdditionalInfo, user.ID)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	err = generateVirtualFoldersMapping(ctx, user, tx)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	return tx.Commit()
}

func sqlCommonDeleteUser(user User, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteUserQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, user.ID)
	return err
}

func sqlCommonDumpUsers(dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, 100)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()
	q := getDumpUsersQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return users, err
	}

	defer rows.Close()
	for rows.Next() {
		u, err := getUserFromDbRow(nil, rows)
		if err != nil {
			return users, err
		}
		err = addCredentialsToUser(&u)
		if err != nil {
			return users, err
		}
		users = append(users, u)
	}
	return getUsersWithVirtualFolders(users, dbHandle)
}

func sqlCommonGetUsers(limit int, offset int, order string, username string, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUsersQuery(order, username)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	var rows *sql.Rows
	if len(username) > 0 {
		rows, err = stmt.QueryContext(ctx, username, limit, offset) //nolint:rowserrcheck // rows.Err() is checked
	} else {
		rows, err = stmt.QueryContext(ctx, limit, offset) //nolint:rowserrcheck // rows.Err() is checked
	}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			u, err := getUserFromDbRow(nil, rows)
			if err != nil {
				return users, err
			}
			u.HideConfidentialData()
			users = append(users, u)
		}
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	return getUsersWithVirtualFolders(users, dbHandle)
}

func updateUserPermissionsFromDb(user *User, permissions string) error {
	var err error
	perms := make(map[string][]string)
	err = json.Unmarshal([]byte(permissions), &perms)
	if err == nil {
		user.Permissions = perms
	} else {
		// compatibility layer: until version 0.9.4 permissions were a string list
		var list []string
		err = json.Unmarshal([]byte(permissions), &list)
		if err != nil {
			return err
		}
		perms["/"] = list
		user.Permissions = perms
	}
	return err
}

func getUserFromDbRow(row *sql.Row, rows *sql.Rows) (User, error) {
	var user User
	var permissions sql.NullString
	var password sql.NullString
	var publicKey sql.NullString
	var filters sql.NullString
	var fsConfig sql.NullString
	var additionalInfo sql.NullString
	var err error
	if row != nil {
		err = row.Scan(&user.ID, &user.Username, &password, &publicKey, &user.HomeDir, &user.UID, &user.GID, &user.MaxSessions,
			&user.QuotaSize, &user.QuotaFiles, &permissions, &user.UsedQuotaSize, &user.UsedQuotaFiles, &user.LastQuotaUpdate,
			&user.UploadBandwidth, &user.DownloadBandwidth, &user.ExpirationDate, &user.LastLogin, &user.Status, &filters, &fsConfig,
			&additionalInfo)
	} else {
		err = rows.Scan(&user.ID, &user.Username, &password, &publicKey, &user.HomeDir, &user.UID, &user.GID, &user.MaxSessions,
			&user.QuotaSize, &user.QuotaFiles, &permissions, &user.UsedQuotaSize, &user.UsedQuotaFiles, &user.LastQuotaUpdate,
			&user.UploadBandwidth, &user.DownloadBandwidth, &user.ExpirationDate, &user.LastLogin, &user.Status, &filters, &fsConfig,
			&additionalInfo)
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
		err = updateUserPermissionsFromDb(&user, permissions.String)
		if err != nil {
			return user, err
		}
	}
	if filters.Valid {
		var userFilters UserFilters
		err = json.Unmarshal([]byte(filters.String), &userFilters)
		if err == nil {
			user.Filters = userFilters
		}
	}
	if fsConfig.Valid {
		var fs Filesystem
		err = json.Unmarshal([]byte(fsConfig.String), &fs)
		if err == nil {
			user.FsConfig = fs
		}
	}
	if additionalInfo.Valid {
		user.AdditionalInfo = additionalInfo.String
	}
	user.SetEmptySecretsIfNil()
	return user, err
}

func sqlCommonCheckFolderExists(ctx context.Context, name string, dbHandle sqlQuerier) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	q := getFolderByPathQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return folder, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx, name)
	err = row.Scan(&folder.ID, &folder.MappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles, &folder.LastQuotaUpdate)
	if err == sql.ErrNoRows {
		return folder, &RecordNotFoundError{err: err.Error()}
	}
	return folder, err
}

func sqlCommonAddOrGetFolder(ctx context.Context, name string, usedQuotaSize int64, usedQuotaFiles int, lastQuotaUpdate int64, dbHandle sqlQuerier) (vfs.BaseVirtualFolder, error) {
	folder, err := sqlCommonCheckFolderExists(ctx, name, dbHandle)
	if _, ok := err.(*RecordNotFoundError); ok {
		f := vfs.BaseVirtualFolder{
			MappedPath:      name,
			UsedQuotaSize:   usedQuotaSize,
			UsedQuotaFiles:  usedQuotaFiles,
			LastQuotaUpdate: lastQuotaUpdate,
		}
		err = sqlCommonAddFolder(f, dbHandle)
		if err != nil {
			return folder, err
		}
		return sqlCommonCheckFolderExists(ctx, name, dbHandle)
	}
	return folder, err
}

func sqlCommonAddFolder(folder vfs.BaseVirtualFolder, dbHandle sqlQuerier) error {
	err := validateFolder(&folder)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAddFolderQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.MappedPath, folder.UsedQuotaSize, folder.UsedQuotaFiles, folder.LastQuotaUpdate)
	return err
}

func sqlCommonDeleteFolder(folder vfs.BaseVirtualFolder, dbHandle sqlQuerier) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteFolderQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.ID)
	return err
}

func sqlCommonDumpFolders(dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, 50)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()
	q := getDumpFoldersQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		err = rows.Scan(&folder.ID, &folder.MappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles, &folder.LastQuotaUpdate)
		if err != nil {
			return folders, err
		}
		folders = append(folders, folder)
	}
	err = rows.Err()
	if err != nil {
		return folders, err
	}
	return getVirtualFoldersWithUsers(folders, dbHandle)
}

func sqlCommonGetFolders(limit, offset int, order, folderPath string, dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getFoldersQuery(order, folderPath)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	var rows *sql.Rows
	if len(folderPath) > 0 {
		rows, err = stmt.QueryContext(ctx, folderPath, limit, offset) //nolint:rowserrcheck // rows.Err() is checked
	} else {
		rows, err = stmt.QueryContext(ctx, limit, offset) //nolint:rowserrcheck // rows.Err() is checked
	}
	if err != nil {
		return folders, err
	}
	defer rows.Close()
	for rows.Next() {
		var folder vfs.BaseVirtualFolder
		err = rows.Scan(&folder.ID, &folder.MappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles, &folder.LastQuotaUpdate)
		if err != nil {
			return folders, err
		}
		folders = append(folders, folder)
	}

	err = rows.Err()
	if err != nil {
		return folders, err
	}
	return getVirtualFoldersWithUsers(folders, dbHandle)
}

func sqlCommonClearFolderMapping(ctx context.Context, user User, dbHandle sqlQuerier) error {
	q := getClearFolderMappingQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, user.Username)
	return err
}

func sqlCommonAddFolderMapping(ctx context.Context, user User, folder vfs.VirtualFolder, dbHandle sqlQuerier) error {
	q := getAddFolderMappingQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.VirtualPath, folder.QuotaSize, folder.QuotaFiles, folder.ID, user.Username)
	return err
}

func generateVirtualFoldersMapping(ctx context.Context, user User, dbHandle sqlQuerier) error {
	err := sqlCommonClearFolderMapping(ctx, user, dbHandle)
	if err != nil {
		return err
	}
	for _, vfolder := range user.VirtualFolders {
		f, err := sqlCommonAddOrGetFolder(ctx, vfolder.MappedPath, 0, 0, 0, dbHandle)
		if err != nil {
			return err
		}
		vfolder.BaseVirtualFolder = f
		err = sqlCommonAddFolderMapping(ctx, user, vfolder, dbHandle)
		if err != nil {
			return err
		}
	}
	return err
}

func getUserWithVirtualFolders(user User, dbHandle sqlQuerier) (User, error) {
	users, err := getUsersWithVirtualFolders([]User{user}, dbHandle)
	if err != nil {
		return user, err
	}
	if len(users) == 0 {
		return user, errSQLFoldersAssosaction
	}
	return users[0], err
}

func getUsersWithVirtualFolders(users []User, dbHandle sqlQuerier) ([]User, error) {
	var err error
	usersVirtualFolders := make(map[int64][]vfs.VirtualFolder)
	if len(users) == 0 {
		return users, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getRelatedFoldersForUsersQuery(users)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		err = rows.Scan(&folder.ID, &folder.MappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles,
			&folder.LastQuotaUpdate, &folder.VirtualPath, &folder.QuotaSize, &folder.QuotaFiles, &userID)
		if err != nil {
			return users, err
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

func getVirtualFoldersWithUsers(folders []vfs.BaseVirtualFolder, dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	var err error
	vFoldersUsers := make(map[int64][]string)
	if len(folders) == 0 {
		return folders, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getRelatedUsersForFoldersQuery(folders)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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

func sqlCommonUpdateFolderQuota(mappedPath string, filesAdd int, sizeAdd int64, reset bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateFolderQuotaQuery(reset)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, sizeAdd, filesAdd, utils.GetTimeAsMsSinceEpoch(time.Now()), mappedPath)
	if err == nil {
		providerLog(logger.LevelDebug, "quota updated for folder %#v, files increment: %v size increment: %v is reset? %v",
			mappedPath, filesAdd, sizeAdd, reset)
	} else {
		providerLog(logger.LevelWarn, "error updating quota for folder %#v: %v", mappedPath, err)
	}
	return err
}

func sqlCommonGetFolderUsedQuota(mappedPath string, dbHandle *sql.DB) (int, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getQuotaFolderQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return 0, 0, err
	}
	defer stmt.Close()

	var usedFiles int
	var usedSize int64
	err = stmt.QueryRowContext(ctx, mappedPath).Scan(&usedSize, &usedFiles)
	if err != nil {
		providerLog(logger.LevelWarn, "error getting quota for folder: %v, error: %v", mappedPath, err)
		return 0, 0, err
	}
	return usedFiles, usedSize, err
}

func sqlCommonRollbackTransaction(tx *sql.Tx) {
	err := tx.Rollback()
	if err != nil {
		providerLog(logger.LevelWarn, "error rolling back transaction: %v", err)
	}
}

func sqlCommonGetDatabaseVersion(dbHandle *sql.DB, showInitWarn bool) (schemaVersion, error) {
	var result schemaVersion
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDatabaseVersionQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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

func sqlCommonUpdateDatabaseVersion(ctx context.Context, dbHandle sqlQuerier, version int) error {
	q := getUpdateDBVersionQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, version)
	return err
}

func sqlCommonExecSQLAndUpdateDBVersion(dbHandle *sql.DB, sql []string, newVersion int) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()
	tx, err := dbHandle.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, q := range sql {
		if len(strings.TrimSpace(q)) == 0 {
			continue
		}
		_, err = tx.ExecContext(ctx, q)
		if err != nil {
			sqlCommonRollbackTransaction(tx)
			return err
		}
	}
	err = sqlCommonUpdateDatabaseVersion(ctx, tx, newVersion)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	return tx.Commit()
}

func sqlCommonGetCompatVirtualFolders(dbHandle *sql.DB) ([]userCompactVFolders, error) {
	users := []userCompactVFolders{}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getCompatVirtualFoldersQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user userCompactVFolders
		var virtualFolders sql.NullString
		err = rows.Scan(&user.ID, &user.Username, &virtualFolders)
		if err != nil {
			return nil, err
		}
		if virtualFolders.Valid {
			var list []virtualFoldersCompact
			err = json.Unmarshal([]byte(virtualFolders.String), &list)
			if err == nil && len(list) > 0 {
				user.VirtualFolders = list
				users = append(users, user)
			}
		}
	}
	return users, rows.Err()
}

func sqlCommonRestoreCompatVirtualFolders(ctx context.Context, users []userCompactVFolders, dbHandle sqlQuerier) ([]string, error) {
	foldersToScan := []string{}
	for _, user := range users {
		for _, vfolder := range user.VirtualFolders {
			providerLog(logger.LevelInfo, "restoring virtual folder: %+v for user %#v", vfolder, user.Username)
			// -1 means included in user quota, 0 means unlimited
			quotaSize := int64(-1)
			quotaFiles := -1
			if vfolder.ExcludeFromQuota {
				quotaFiles = 0
				quotaSize = 0
			}
			b, err := sqlCommonAddOrGetFolder(ctx, vfolder.MappedPath, 0, 0, 0, dbHandle)
			if err != nil {
				providerLog(logger.LevelWarn, "error restoring virtual folder for user %#v: %v", user.Username, err)
				return foldersToScan, err
			}
			u := User{
				ID:       user.ID,
				Username: user.Username,
			}
			f := vfs.VirtualFolder{
				BaseVirtualFolder: b,
				VirtualPath:       vfolder.VirtualPath,
				QuotaSize:         quotaSize,
				QuotaFiles:        quotaFiles,
			}
			err = sqlCommonAddFolderMapping(ctx, u, f, dbHandle)
			if err != nil {
				providerLog(logger.LevelWarn, "error adding virtual folder mapping for user %#v: %v", user.Username, err)
				return foldersToScan, err
			}
			if !utils.IsStringInSlice(vfolder.MappedPath, foldersToScan) {
				foldersToScan = append(foldersToScan, vfolder.MappedPath)
			}
			providerLog(logger.LevelInfo, "virtual folder: %+v for user %#v successfully restored", vfolder, user.Username)
		}
	}
	return foldersToScan, nil
}

func sqlCommonUpdateDatabaseFrom3To4(sqlV4 string, dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 3 -> 4")
	providerLog(logger.LevelInfo, "updating database version: 3 -> 4")
	users, err := sqlCommonGetCompatVirtualFolders(dbHandle)
	if err != nil {
		return err
	}
	sql := strings.ReplaceAll(sqlV4, "{{users}}", sqlTableUsers)
	sql = strings.ReplaceAll(sql, "{{folders}}", sqlTableFolders)
	sql = strings.ReplaceAll(sql, "{{folders_mapping}}", sqlTableFoldersMapping)
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()
	tx, err := dbHandle.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, q := range strings.Split(sql, ";") {
		if len(strings.TrimSpace(q)) == 0 {
			continue
		}
		_, err = tx.ExecContext(ctx, q)
		if err != nil {
			sqlCommonRollbackTransaction(tx)
			return err
		}
	}
	foldersToScan, err := sqlCommonRestoreCompatVirtualFolders(ctx, users, tx)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	err = sqlCommonUpdateDatabaseVersion(ctx, tx, 4)
	if err != nil {
		sqlCommonRollbackTransaction(tx)
		return err
	}
	err = tx.Commit()
	if err == nil {
		go updateVFoldersQuotaAfterRestore(foldersToScan)
	}
	return err
}

//nolint:dupl
func sqlCommonUpdateDatabaseFrom4To5(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 4 -> 5")
	providerLog(logger.LevelInfo, "updating database version: 4 -> 5")
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()
	q := getCompatV4FsConfigQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var compatUser compatUserV4
		var fsConfigString sql.NullString
		err = rows.Scan(&compatUser.ID, &compatUser.Username, &fsConfigString)
		if err != nil {
			return err
		}
		if fsConfigString.Valid {
			err = json.Unmarshal([]byte(fsConfigString.String), &compatUser.FsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v4 user %#v, is it already migrated?", compatUser.Username)
				continue
			}
			fsConfig, err := convertFsConfigFromV4(compatUser.FsConfig, compatUser.Username)
			if err != nil {
				return err
			}
			users = append(users, createUserFromV4(compatUser, fsConfig))
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, user := range users {
		err = sqlCommonUpdateV4User(dbHandle, user)
		if err != nil {
			return err
		}
		providerLog(logger.LevelInfo, "filesystem config updated for user %#v", user.Username)
	}

	ctxVersion, cancelVersion := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancelVersion()

	return sqlCommonUpdateDatabaseVersion(ctxVersion, dbHandle, 5)
}

func sqlCommonUpdateV4CompatUser(dbHandle *sql.DB, user compatUserV4) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := updateCompatV4FsConfigQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	fsConfig, err := json.Marshal(user.FsConfig)
	if err != nil {
		return err
	}
	_, err = stmt.ExecContext(ctx, string(fsConfig), user.ID)
	return err
}

func sqlCommonUpdateV4User(dbHandle *sql.DB, user User) error {
	err := validateFilesystemConfig(&user)
	if err != nil {
		return err
	}
	err = saveGCSCredentials(&user)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := updateCompatV4FsConfigQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	fsConfig, err := user.GetFsConfigAsJSON()
	if err != nil {
		return err
	}
	_, err = stmt.ExecContext(ctx, string(fsConfig), user.ID)
	return err
}

//nolint:dupl
func sqlCommonDowngradeDatabaseFrom5To4(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 5 -> 4")
	providerLog(logger.LevelInfo, "downgrading database version: 5 -> 4")
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()
	q := getCompatV4FsConfigQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return err
	}
	defer rows.Close()

	users := []compatUserV4{}
	for rows.Next() {
		var user User
		var fsConfigString sql.NullString
		err = rows.Scan(&user.ID, &user.Username, &fsConfigString)
		if err != nil {
			return err
		}
		if fsConfigString.Valid {
			err = json.Unmarshal([]byte(fsConfigString.String), &user.FsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal user %#v to v4, is it already migrated?", user.Username)
				continue
			}
			fsConfig, err := convertFsConfigToV4(user.FsConfig, user.Username)
			if err != nil {
				return err
			}
			users = append(users, convertUserToV4(user, fsConfig))
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, user := range users {
		err = sqlCommonUpdateV4CompatUser(dbHandle, user)
		if err != nil {
			return err
		}
		providerLog(logger.LevelInfo, "filesystem config downgraded for user %#v", user.Username)
	}

	ctxVersion, cancelVersion := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancelVersion()

	return sqlCommonUpdateDatabaseVersion(ctxVersion, dbHandle, 4)
}
