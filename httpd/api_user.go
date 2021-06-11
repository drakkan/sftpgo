package httpd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/vfs"
)

func getUsers(w http.ResponseWriter, r *http.Request) {
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
	case vfs.S3FilesystemProvider:
		if user.FsConfig.S3Config.AccessSecret.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid access_secret"), "", http.StatusBadRequest)
			return
		}
	case vfs.GCSFilesystemProvider:
		if user.FsConfig.GCSConfig.Credentials.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid credentials"), "", http.StatusBadRequest)
			return
		}
	case vfs.AzureBlobFilesystemProvider:
		if user.FsConfig.AzBlobConfig.AccountKey.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid account_key"), "", http.StatusBadRequest)
			return
		}
		if user.FsConfig.AzBlobConfig.SASURL.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid sas_url"), "", http.StatusBadRequest)
			return
		}
	case vfs.CryptedFilesystemProvider:
		if user.FsConfig.CryptConfig.Passphrase.IsRedacted() {
			sendAPIResponse(w, r, errors.New("invalid passphrase"), "", http.StatusBadRequest)
			return
		}
	case vfs.SFTPFilesystemProvider:
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
	user.VirtualFolders = nil
	err = render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user.ID = userID
	user.Username = username
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
	case vfs.S3FilesystemProvider:
		if fsConfig.S3Config.AccessSecret.IsNotPlainAndNotEmpty() {
			fsConfig.S3Config.AccessSecret = currentS3AccessSecret
		}
	case vfs.AzureBlobFilesystemProvider:
		if fsConfig.AzBlobConfig.AccountKey.IsNotPlainAndNotEmpty() {
			fsConfig.AzBlobConfig.AccountKey = currentAzAccountKey
		}
		if fsConfig.AzBlobConfig.SASURL.IsNotPlainAndNotEmpty() {
			fsConfig.AzBlobConfig.SASURL = currentAzSASUrl
		}
	case vfs.GCSFilesystemProvider:
		if fsConfig.GCSConfig.Credentials.IsNotPlainAndNotEmpty() {
			fsConfig.GCSConfig.Credentials = currentGCSCredentials
		}
	case vfs.CryptedFilesystemProvider:
		if fsConfig.CryptConfig.Passphrase.IsNotPlainAndNotEmpty() {
			fsConfig.CryptConfig.Passphrase = currentCryptoPassphrase
		}
	case vfs.SFTPFilesystemProvider:
		if fsConfig.SFTPConfig.Password.IsNotPlainAndNotEmpty() {
			fsConfig.SFTPConfig.Password = currentSFTPPassword
		}
		if fsConfig.SFTPConfig.PrivateKey.IsNotPlainAndNotEmpty() {
			fsConfig.SFTPConfig.PrivateKey = currentSFTPKey
		}
	}
}
