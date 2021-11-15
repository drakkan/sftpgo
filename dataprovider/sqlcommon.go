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

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/sdk"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	sqlDatabaseVersion     = 14
	defaultSQLQueryTimeout = 10 * time.Second
	longSQLQueryTimeout    = 60 * time.Second
)

var (
	errSQLFoldersAssosaction = errors.New("unable to associate virtual folders to user")
	errSchemaVersionEmpty    = errors.New("we can't determine schema version because the schema_migration table is empty. The SFTPGo database might be corrupted. Consider using the \"resetprovider\" sub-command")
)

type sqlQuerier interface {
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

type sqlScanner interface {
	Scan(dest ...interface{}) error
}

func sqlCommonGetShareByID(shareID, username string, dbHandle sqlQuerier) (Share, error) {
	var share Share
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	filterUser := username != ""
	q := getShareByIDQuery(filterUser)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, share.ShareID, share.Name, share.Description, share.Scope,
		string(paths), util.GetTimeAsMsSinceEpoch(time.Now()), util.GetTimeAsMsSinceEpoch(time.Now()),
		share.LastUseAt, share.ExpiresAt, share.Password, share.MaxTokens, allowFrom, user.ID)
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
	q := getUpdateShareQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, share.Name, share.Description, share.Scope, string(paths),
		util.GetTimeAsMsSinceEpoch(time.Now()), share.ExpiresAt, share.Password, share.MaxTokens,
		allowFrom, user.ID, share.ShareID)
	return err
}

func sqlCommonDeleteShare(share *Share, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()

	q := getDeleteShareQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, share.ShareID)
	return err
}

func sqlCommonGetShares(limit, offset int, order, username string, dbHandle sqlQuerier) ([]Share, error) {
	shares := make([]Share, 0, limit)

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getSharesQuery(order)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, apiKey.Name, apiKey.Scope, apiKey.ExpiresAt, userID, adminID,
		apiKey.Description, util.GetTimeAsMsSinceEpoch(time.Now()), apiKey.KeyID)
	return err
}

func sqlCommonDeleteAPIKey(apiKey *APIKey, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getDeleteAPIKeyQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, apiKey.KeyID)
	return err
}

func sqlCommonGetAPIKeys(limit, offset int, order string, dbHandle sqlQuerier) ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, limit)

	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getAPIKeysQuery(order)
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		admin.AdditionalInfo, admin.Description, util.GetTimeAsMsSinceEpoch(time.Now()), admin.Username)
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
	_, err = stmt.ExecContext(ctx, sizeAdd, filesAdd, util.GetTimeAsMsSinceEpoch(time.Now()), username)
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

func sqlCommonUpdateShareLastUse(shareID string, numTokens int, dbHandle *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getUpdateShareLastUseQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
			string(fsConfig), user.AdditionalInfo, user.Description, user.Email, util.GetTimeAsMsSinceEpoch(time.Now()),
			util.GetTimeAsMsSinceEpoch(time.Now()))
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
			string(filters), string(fsConfig), user.AdditionalInfo, user.Description, user.Email, util.GetTimeAsMsSinceEpoch(time.Now()),
			user.ID)
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

func sqlCommonGetRecentlyUpdatedUsers(after int64, dbHandle sqlQuerier) ([]User, error) {
	users := make([]User, 0, 10)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	q := getRecentlyUpdatedUsersQuery()
	stmt, err := dbHandle.PrepareContext(ctx, q)
	if err != nil {
		providerLog(logger.LevelWarn, "error preparing database query %#v: %v", q, err)
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
		&additionalInfo, &description, &email, &user.CreatedAt, &user.UpdatedAt)
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
			providerLog(logger.LevelWarn, "unable to deserialize permissions for user %#v: %v", user.Username, err)
			return user, fmt.Errorf("unable to deserialize permissions for user %#v: %v", user.Username, err)
		}
		user.Permissions = perms
	}
	if filters.Valid {
		var userFilters sdk.UserFilters
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
	if len(users) == 0 {
		return users, nil
	}

	var err error
	usersVirtualFolders := make(map[int64][]vfs.VirtualFolder)
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
	if len(folders) == 0 {
		return folders, nil
	}

	var err error
	vFoldersUsers := make(map[int64][]string)
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
		if newVersion == 0 {
			return nil
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
