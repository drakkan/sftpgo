package httpd

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/render"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

func getUsers(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	users, err := dataprovider.GetUsers(limit, offset, order)
	if err == nil {
		render.JSON(w, r, users)
	} else {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	}
}

func getUserByUsername(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	renderUser(w, r, username, http.StatusOK)
}

func renderUser(w http.ResponseWriter, r *http.Request, username string, status int) {
	user, err := dataprovider.UserExists(username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	user.PrepareForRendering()
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), user)
	} else {
		render.JSON(w, r, user)
	}
}

func addUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var user dataprovider.User
	err = render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddUser(&user, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	renderUser(w, r, user.Username, http.StatusCreated)
}

func disableUser2FA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	user.Filters.RecoveryCodes = nil
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled: false,
	}
	if err := dataprovider.UpdateUser(&user, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "2FA disabled", http.StatusOK)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	username := getURLParam(r, "username")
	disconnect := 0
	if _, ok := r.URL.Query()["disconnect"]; ok {
		disconnect, err = strconv.Atoi(r.URL.Query().Get("disconnect"))
		if err != nil {
			err = fmt.Errorf("invalid disconnect parameter: %v", err)
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	user, err := dataprovider.UserExists(username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	userID := user.ID
	username = user.Username
	totpConfig := user.Filters.TOTPConfig
	recoveryCodes := user.Filters.RecoveryCodes
	currentPermissions := user.Permissions
	currentS3AccessSecret := user.FsConfig.S3Config.AccessSecret
	currentAzAccountKey := user.FsConfig.AzBlobConfig.AccountKey
	currentAzSASUrl := user.FsConfig.AzBlobConfig.SASURL
	currentGCSCredentials := user.FsConfig.GCSConfig.Credentials
	currentCryptoPassphrase := user.FsConfig.CryptConfig.Passphrase
	currentSFTPPassword := user.FsConfig.SFTPConfig.Password
	currentSFTPKey := user.FsConfig.SFTPConfig.PrivateKey

	user.Permissions = make(map[string][]string)
	user.FsConfig.S3Config = vfs.S3FsConfig{}
	user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
	user.FsConfig.GCSConfig = vfs.GCSFsConfig{}
	user.FsConfig.CryptConfig = vfs.CryptFsConfig{}
	user.FsConfig.SFTPConfig = vfs.SFTPFsConfig{}
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{}
	user.Filters.RecoveryCodes = nil
	user.VirtualFolders = nil
	err = render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user.ID = userID
	user.Username = username
	user.Filters.TOTPConfig = totpConfig
	user.Filters.RecoveryCodes = recoveryCodes
	user.SetEmptySecretsIfNil()
	// we use new Permissions if passed otherwise the old ones
	if len(user.Permissions) == 0 {
		user.Permissions = currentPermissions
	}
	updateEncryptedSecrets(&user.FsConfig, currentS3AccessSecret, currentAzAccountKey, currentAzSASUrl,
		currentGCSCredentials, currentCryptoPassphrase, currentSFTPPassword, currentSFTPKey)
	err = dataprovider.UpdateUser(&user, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "User updated", http.StatusOK)
	if disconnect == 1 {
		disconnectUser(user.Username)
	}
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	username := getURLParam(r, "username")
	err = dataprovider.DeleteUser(username, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "User deleted", http.StatusOK)
	disconnectUser(dataprovider.ConvertName(username))
}

func forgotUserPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	if !smtp.IsEnabled() {
		sendAPIResponse(w, r, nil, "No SMTP configuration", http.StatusBadRequest)
		return
	}

	err := handleForgotPassword(r, getURLParam(r, "username"), false)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	sendAPIResponse(w, r, err, "Check your email for the confirmation code", http.StatusOK)
}

func resetUserPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req pwdReset
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	_, _, err = handleResetPassword(r, req.Code, req.Password, false)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Password reset successful", http.StatusOK)
}

func disconnectUser(username string) {
	for _, stat := range common.Connections.GetStats() {
		if stat.Username == username {
			common.Connections.Close(stat.ConnectionID)
		}
	}
}

func updateEncryptedSecrets(fsConfig *vfs.Filesystem, currentS3AccessSecret, currentAzAccountKey, currentAzSASUrl,
	currentGCSCredentials, currentCryptoPassphrase, currentSFTPPassword, currentSFTPKey *kms.Secret) {
	// we use the new access secret if plain or empty, otherwise the old value
	switch fsConfig.Provider {
	case sdk.S3FilesystemProvider:
		if fsConfig.S3Config.AccessSecret.IsNotPlainAndNotEmpty() {
			fsConfig.S3Config.AccessSecret = currentS3AccessSecret
		}
	case sdk.AzureBlobFilesystemProvider:
		if fsConfig.AzBlobConfig.AccountKey.IsNotPlainAndNotEmpty() {
			fsConfig.AzBlobConfig.AccountKey = currentAzAccountKey
		}
		if fsConfig.AzBlobConfig.SASURL.IsNotPlainAndNotEmpty() {
			fsConfig.AzBlobConfig.SASURL = currentAzSASUrl
		}
	case sdk.GCSFilesystemProvider:
		// for GCS credentials will be cleared if we enable automatic credentials
		// so keep the old credentials here if no new credentials are provided
		if !fsConfig.GCSConfig.Credentials.IsPlain() {
			fsConfig.GCSConfig.Credentials = currentGCSCredentials
		}
	case sdk.CryptedFilesystemProvider:
		if fsConfig.CryptConfig.Passphrase.IsNotPlainAndNotEmpty() {
			fsConfig.CryptConfig.Passphrase = currentCryptoPassphrase
		}
	case sdk.SFTPFilesystemProvider:
		if fsConfig.SFTPConfig.Password.IsNotPlainAndNotEmpty() {
			fsConfig.SFTPConfig.Password = currentSFTPPassword
		}
		if fsConfig.SFTPConfig.PrivateKey.IsNotPlainAndNotEmpty() {
			fsConfig.SFTPConfig.PrivateKey = currentSFTPKey
		}
	}
}
