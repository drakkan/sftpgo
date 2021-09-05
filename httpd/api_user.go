package httpd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/sdk"
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
	var user dataprovider.User
	err := render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user.SetEmptySecretsIfNil()
	switch user.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		if user.FsConfig.S3Config.AccessSecret.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid access_secret"), "", http.StatusBadRequest)
			return
		}
	case sdk.GCSFilesystemProvider:
		if user.FsConfig.GCSConfig.Credentials.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid credentials"), "", http.StatusBadRequest)
			return
		}
	case sdk.AzureBlobFilesystemProvider:
		if user.FsConfig.AzBlobConfig.AccountKey.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid account_key"), "", http.StatusBadRequest)
			return
		}
		if user.FsConfig.AzBlobConfig.SASURL.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid sas_url"), "", http.StatusBadRequest)
			return
		}
	case sdk.CryptedFilesystemProvider:
		if user.FsConfig.CryptConfig.Passphrase.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid passphrase"), "", http.StatusBadRequest)
			return
		}
	case sdk.SFTPFilesystemProvider:
		if user.FsConfig.SFTPConfig.Password.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid SFTP password"), "", http.StatusBadRequest)
			return
		}
		if user.FsConfig.SFTPConfig.PrivateKey.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid SFTP private key"), "", http.StatusBadRequest)
			return
		}
	}
	err = dataprovider.AddUser(&user)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	renderUser(w, r, user.Username, http.StatusCreated)
}

func disableUser2FA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	user.Filters.RecoveryCodes = nil
	user.Filters.TOTPConfig = sdk.TOTPConfig{
		Enabled: false,
	}
	if err := dataprovider.UpdateUser(&user); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "2FA disabled", http.StatusOK)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var err error

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
	user.Filters.TOTPConfig = sdk.TOTPConfig{}
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
	err = dataprovider.UpdateUser(&user)
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
	username := getURLParam(r, "username")
	err := dataprovider.DeleteUser(username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "User deleted", http.StatusOK)
	disconnectUser(username)
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
		if fsConfig.GCSConfig.Credentials.IsNotPlainAndNotEmpty() {
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
