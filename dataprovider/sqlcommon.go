package dataprovider

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/cockroach-go/v2/crdb"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	sqlDatabaseVersion     = 10
	defaultSQLQueryTimeout = 10 * time.Second
	longSQLQueryTimeout    = 60 * time.Second
)

var errSQLFoldersAssosaction = errors.New("unable to associate virtual folders to user")

type sqlQuerier interface {
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

type sqlScanner interface {
	Scan(dest ...interface{}) error
}

func sqlCommonGetAdminByUsername(username string, dbHandle sqlQuerier) (Admin, error) {
	var admin Admin
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAdminByUsernameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		string(filters), admin.AdditionalInfo, admin.Description)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		admin.AdditionalInfo, admin.Description, admin.Username)
	return err
}

func sqlCommonDeleteAdmin(admin *Admin, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteAdminQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, admin.Username)
	return err
}

func sqlCommonGetAdmins(limit, offset int, order string, dbHandle sqlQuerier) ([]Admin, error) {
	admins := make([]Admin, 0, limit)

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAdminsQuery(order)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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

func sqlCommonGetUserByUsername(username string, dbHandle sqlQuerier) (User, error) {
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
	user, err = getUserFromDbRow(row)
	if err != nil {
		return user, err
	}
	return getUserWithVirtualFolders(ctx, user, dbHandle)
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

func sqlCommonValidateUserAndPubKey(username string, pubKey []byte, dbHandle *sql.DB) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}
	user, err := sqlCommonGetUserByUsername(username, dbHandle)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey)
}

func sqlCommonCheckAvailability(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return dbHandle.PingContext(ctx)
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
		_, err = stmt.ExecContext(ctx, user.Username, user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID, user.MaxSessions, user.QuotaSize,
			user.QuotaFiles, string(permissions), user.UploadBandwidth, user.DownloadBandwidth, user.Status, user.ExpirationDate, string(filters),
			string(fsConfig), user.AdditionalInfo, user.Description)
		if err != nil {
			return err
		}
		return generateVirtualFoldersMapping(ctx, user, tx)
	})
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
		_, err = stmt.ExecContext(ctx, user.Password, string(publicKeys), user.HomeDir, user.UID, user.GID, user.MaxSessions, user.QuotaSize,
			user.QuotaFiles, string(permissions), user.UploadBandwidth, user.DownloadBandwidth, user.Status, user.ExpirationDate,
			string(filters), string(fsConfig), user.AdditionalInfo, user.Description, user.ID)
		if err != nil {
			return err
		}
		return generateVirtualFoldersMapping(ctx, user, tx)
	})
}

func sqlCommonDeleteUser(user *User, dbHandle *sql.DB) error {
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
		u, err := getUserFromDbRow(rows)
		if err != nil {
			return users, err
		}
		err = addCredentialsToUser(&u)
		if err != nil {
			return users, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	return getUsersWithVirtualFolders(ctx, users, dbHandle)
}

func sqlCommonGetUsers(limit int, offset int, order string, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUsersQuery(order)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
			u.PrepareForRendering()
			users = append(users, u)
		}
	}
	err = rows.Err()
	if err != nil {
		return users, err
	}
	return getUsersWithVirtualFolders(ctx, users, dbHandle)
}

func getAdminFromDbRow(row sqlScanner) (Admin, error) {
	var admin Admin
	var email, filters, additionalInfo, permissions, description sql.NullString

	err := row.Scan(&admin.ID, &admin.Username, &admin.Password, &admin.Status, &email, &permissions,
		&filters, &additionalInfo, &description)

	if err != nil {
		if err == sql.ErrNoRows {
			return admin, &RecordNotFoundError{err: err.Error()}
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

	return admin, err
}

func getUserFromDbRow(row sqlScanner) (User, error) {
	var user User
	var permissions sql.NullString
	var password sql.NullString
	var publicKey sql.NullString
	var filters sql.NullString
	var fsConfig sql.NullString
	var additionalInfo, description sql.NullString

	err := row.Scan(&user.ID, &user.Username, &password, &publicKey, &user.HomeDir, &user.UID, &user.GID, &user.MaxSessions,
		&user.QuotaSize, &user.QuotaFiles, &permissions, &user.UsedQuotaSize, &user.UsedQuotaFiles, &user.LastQuotaUpdate,
		&user.UploadBandwidth, &user.DownloadBandwidth, &user.ExpirationDate, &user.LastLogin, &user.Status, &filters, &fsConfig,
		&additionalInfo, &description)
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
		perms := make(map[string][]string)
		err = json.Unmarshal([]byte(permissions.String), &perms)
		if err != nil {
			providerLog(logger.LevelDebug, "unable to deserialize permissions for user %#v: %v", user.Username, err)
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
	user.SetEmptySecretsIfNil()
	return user, err
}

func sqlCommonCheckFolderExists(ctx context.Context, name string, dbHandle sqlQuerier) error {
	var folderName string
	q := checkFolderNameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx, name)
	return row.Scan(&folderName)
}

func sqlCommonGetFolder(ctx context.Context, name string, dbHandle sqlQuerier) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	q := getFolderByNameQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return folder, err
	}
	defer stmt.Close()
	row := stmt.QueryRowContext(ctx, name)
	var mappedPath, description, fsConfig sql.NullString
	err = row.Scan(&folder.ID, &mappedPath, &folder.UsedQuotaSize, &folder.UsedQuotaFiles, &folder.LastQuotaUpdate,
		&folder.Name, &description, &fsConfig)
	if err == sql.ErrNoRows {
		return folder, &RecordNotFoundError{err: err.Error()}
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
	return folders[0], nil
}

func sqlCommonAddOrUpdateFolder(ctx context.Context, baseFolder *vfs.BaseVirtualFolder, usedQuotaSize int64,
	usedQuotaFiles int, lastQuotaUpdate int64, dbHandle sqlQuerier) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	// FIXME: we could use an UPSERT here, this SELECT could be racy
	err := sqlCommonCheckFolderExists(ctx, baseFolder.Name, dbHandle)
	switch err {
	case nil:
		err = sqlCommonUpdateFolder(baseFolder, dbHandle)
		if err != nil {
			return folder, err
		}
	case sql.ErrNoRows:
		baseFolder.UsedQuotaFiles = usedQuotaFiles
		baseFolder.UsedQuotaSize = usedQuotaSize
		baseFolder.LastQuotaUpdate = lastQuotaUpdate
		err = sqlCommonAddFolder(baseFolder, dbHandle)
		if err != nil {
			return folder, err
		}
	default:
		return folder, err
	}

	return sqlCommonGetFolder(ctx, baseFolder.Name, dbHandle)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, folder.MappedPath, folder.Description, string(fsConfig), folder.Name)
	return err
}

func sqlCommonDeleteFolder(folder *vfs.BaseVirtualFolder, dbHandle sqlQuerier) error {
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
	err = rows.Err()
	if err != nil {
		return folders, err
	}
	return getVirtualFoldersWithUsers(folders, dbHandle)
}

func sqlCommonGetFolders(limit, offset int, order string, dbHandle sqlQuerier) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getFoldersQuery(order)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		folder.PrepareForRendering()
		folders = append(folders, folder)
	}

	err = rows.Err()
	if err != nil {
		return folders, err
	}
	return getVirtualFoldersWithUsers(folders, dbHandle)
}

func sqlCommonClearFolderMapping(ctx context.Context, user *User, dbHandle sqlQuerier) error {
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

func sqlCommonAddFolderMapping(ctx context.Context, user *User, folder *vfs.VirtualFolder, dbHandle sqlQuerier) error {
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

func generateVirtualFoldersMapping(ctx context.Context, user *User, dbHandle sqlQuerier) error {
	err := sqlCommonClearFolderMapping(ctx, user, dbHandle)
	if err != nil {
		return err
	}
	for idx := range user.VirtualFolders {
		vfolder := &user.VirtualFolders[idx]
		f, err := sqlCommonAddOrUpdateFolder(ctx, &vfolder.BaseVirtualFolder, 0, 0, 0, dbHandle)
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

func getUserWithVirtualFolders(ctx context.Context, user User, dbHandle sqlQuerier) (User, error) {
	users, err := getUsersWithVirtualFolders(ctx, []User{user}, dbHandle)
	if err != nil {
		return user, err
	}
	if len(users) == 0 {
		return user, errSQLFoldersAssosaction
	}
	return users[0], err
}

func getUsersWithVirtualFolders(ctx context.Context, users []User, dbHandle sqlQuerier) ([]User, error) {
	var err error
	usersVirtualFolders := make(map[int64][]vfs.VirtualFolder)
	if len(users) == 0 {
		return users, err
	}
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

func sqlCommonUpdateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateFolderQuotaQuery(reset)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, sizeAdd, filesAdd, utils.GetTimeAsMsSinceEpoch(time.Now()), name)
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

func sqlCommonExecSQLAndUpdateDBVersion(dbHandle *sql.DB, sqlQueries []string, newVersion int) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

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
		return sqlCommonUpdateDatabaseVersion(ctx, tx, newVersion)
	})
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

func sqlCommonUpdateDatabaseFrom9To10(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database version: 9 -> 10")
	providerLog(logger.LevelInfo, "updating database version: 9 -> 10")

	if err := sqlCommonUpdateV10Folders(dbHandle); err != nil {
		return err
	}

	if err := sqlCommonUpdateV10Users(dbHandle); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonUpdateDatabaseVersion(ctx, dbHandle, 10)
}

func sqlCommonDowngradeDatabaseFrom10To9(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database version: 10 -> 9")
	providerLog(logger.LevelInfo, "downgrading database version: 10 -> 9")

	if err := sqlCommonDowngradeV10Folders(dbHandle); err != nil {
		return err
	}

	if err := sqlCommonDowngradeV10Users(dbHandle); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	return sqlCommonUpdateDatabaseVersion(ctx, dbHandle, 9)
}

//nolint:dupl
func sqlCommonDowngradeV10Folders(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getCompatFolderV10FsConfigQuery()
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

	var folders []compatBaseFolderV9
	for rows.Next() {
		var folder compatBaseFolderV9
		var fsConfigString sql.NullString
		err = rows.Scan(&folder.ID, &folder.Name, &fsConfigString)
		if err != nil {
			return err
		}
		if fsConfigString.Valid {
			var fsConfig vfs.Filesystem
			err = json.Unmarshal([]byte(fsConfigString.String), &fsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v10 fsconfig for folder %#v, is it already migrated?", folder.Name)
				continue
			}
			if fsConfig.AzBlobConfig.SASURL != nil && !fsConfig.AzBlobConfig.SASURL.IsEmpty() {
				fsV9, err := convertFsConfigToV9(fsConfig)
				if err != nil {
					return err
				}
				folder.FsConfig = fsV9
				folders = append(folders, folder)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// update fsconfig for affected folders
	for _, folder := range folders {
		q := updateCompatFolderV10FsConfigQuery()
		stmt, err := dbHandle.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()
		cfg, err := json.Marshal(folder.FsConfig)
		if err != nil {
			return err
		}

		_, err = stmt.ExecContext(ctx, string(cfg), folder.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

//nolint:dupl
func sqlCommonDowngradeV10Users(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getCompatUserV10FsConfigQuery()
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

	var users []compatUserV9
	for rows.Next() {
		var user compatUserV9
		var fsConfigString sql.NullString
		err = rows.Scan(&user.ID, &user.Username, &fsConfigString)
		if err != nil {
			return err
		}
		if fsConfigString.Valid {
			var fsConfig vfs.Filesystem
			err = json.Unmarshal([]byte(fsConfigString.String), &fsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v10 fsconfig for user %#v, is it already migrated?", user.Username)
				continue
			}
			if fsConfig.AzBlobConfig.SASURL != nil && !fsConfig.AzBlobConfig.SASURL.IsEmpty() {
				fsV9, err := convertFsConfigToV9(fsConfig)
				if err != nil {
					return err
				}
				user.FsConfig = fsV9
				users = append(users, user)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// update fsconfig for affected users
	for _, user := range users {
		q := updateCompatUserV10FsConfigQuery()
		stmt, err := dbHandle.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()
		cfg, err := json.Marshal(user.FsConfig)
		if err != nil {
			return err
		}

		_, err = stmt.ExecContext(ctx, string(cfg), user.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func sqlCommonUpdateV10Folders(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getCompatFolderV10FsConfigQuery()
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

	var folders []vfs.BaseVirtualFolder
	for rows.Next() {
		var folder vfs.BaseVirtualFolder
		var fsConfigString sql.NullString
		err = rows.Scan(&folder.ID, &folder.Name, &fsConfigString)
		if err != nil {
			return err
		}
		if fsConfigString.Valid {
			var compatFsConfig compatFilesystemV9
			err = json.Unmarshal([]byte(fsConfigString.String), &compatFsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v9 fsconfig for folder %#v, is it already migrated?", folder.Name)
				continue
			}
			if compatFsConfig.AzBlobConfig.SASURL != "" {
				fsConfig, err := convertFsConfigFromV9(compatFsConfig, folder.GetEncrytionAdditionalData())
				if err != nil {
					return err
				}
				folder.FsConfig = fsConfig
				folders = append(folders, folder)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// update fsconfig for affected folders
	for _, folder := range folders {
		q := updateCompatFolderV10FsConfigQuery()
		stmt, err := dbHandle.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()
		cfg, err := json.Marshal(folder.FsConfig)
		if err != nil {
			return err
		}

		_, err = stmt.ExecContext(ctx, string(cfg), folder.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func sqlCommonUpdateV10Users(dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), longSQLQueryTimeout)
	defer cancel()

	q := getCompatUserV10FsConfigQuery()
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

	var users []User
	for rows.Next() {
		var user User
		var fsConfigString sql.NullString
		err = rows.Scan(&user.ID, &user.Username, &fsConfigString)
		if err != nil {
			return err
		}
		if fsConfigString.Valid {
			var compatFsConfig compatFilesystemV9
			err = json.Unmarshal([]byte(fsConfigString.String), &compatFsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v9 fsconfig for user %#v, is it already migrated?", user.Username)
				continue
			}
			if compatFsConfig.AzBlobConfig.SASURL != "" {
				fsConfig, err := convertFsConfigFromV9(compatFsConfig, user.GetEncrytionAdditionalData())
				if err != nil {
					return err
				}
				user.FsConfig = fsConfig
				users = append(users, user)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// update fsconfig for affected users
	for _, user := range users {
		q := updateCompatUserV10FsConfigQuery()
		stmt, err := dbHandle.PrepareContext(ctx, q)
		if err != nil {
			providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
			return err
		}
		defer stmt.Close()
		cfg, err := json.Marshal(user.FsConfig)
		if err != nil {
			return err
		}

		_, err = stmt.ExecContext(ctx, string(cfg), user.ID)
		if err != nil {
			return err
		}
	}

	return nil
}
