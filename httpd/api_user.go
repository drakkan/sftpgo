package httpd

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/utils"
)

func getUsers(w http.ResponseWriter, r *http.Request) {
	limit := 100
	offset := 0
	order := dataprovider.OrderASC
	username := ""
	var err error
	if _, ok := r.URL.Query()["limit"]; ok {
		limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			err = errors.New("Invalid limit")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
		if limit > 500 {
			limit = 500
		}
	}
	if _, ok := r.URL.Query()["offset"]; ok {
		offset, err = strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			err = errors.New("Invalid offset")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	if _, ok := r.URL.Query()["order"]; ok {
		order = r.URL.Query().Get("order")
		if order != dataprovider.OrderASC && order != dataprovider.OrderDESC {
			err = errors.New("Invalid order")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	if _, ok := r.URL.Query()["username"]; ok {
		username = r.URL.Query().Get("username")
	}
	users, err := dataprovider.GetUsers(limit, offset, order, username)
	if err == nil {
		render.JSON(w, r, users)
	} else {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	}
}

func getUserByID(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil {
		err = errors.New("Invalid userID")
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserByID(userID)
	if err == nil {
		render.JSON(w, r, dataprovider.HideUserSensitiveData(&user))
	} else {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
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
	err = dataprovider.AddUser(user)
	if err == nil {
		user, err = dataprovider.UserExists(user.Username)
		if err == nil {
			render.JSON(w, r, dataprovider.HideUserSensitiveData(&user))
		} else {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
		}
	} else {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil {
		err = errors.New("Invalid userID")
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	disconnect := 0
	if _, ok := r.URL.Query()["disconnect"]; ok {
		disconnect, err = strconv.Atoi(r.URL.Query().Get("disconnect"))
		if err != nil {
			err = fmt.Errorf("invalid disconnect parameter: %v", err)
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	user, err := dataprovider.GetUserByID(userID)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	currentPermissions := user.Permissions
	currentS3AccessSecret := ""
	currentAzAccountKey := ""
	if user.FsConfig.Provider == dataprovider.S3FilesystemProvider {
		currentS3AccessSecret = user.FsConfig.S3Config.AccessSecret
	}
	if user.FsConfig.Provider == dataprovider.AzureBlobFilesystemProvider {
		currentAzAccountKey = user.FsConfig.AzBlobConfig.AccountKey
	}
	user.Permissions = make(map[string][]string)
	err = render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	// we use new Permissions if passed otherwise the old ones
	if len(user.Permissions) == 0 {
		user.Permissions = currentPermissions
	}
	updateEncryptedSecrets(&user, currentS3AccessSecret, currentAzAccountKey)

	if user.ID != userID {
		sendAPIResponse(w, r, err, "user ID in request body does not match user ID in path parameter", http.StatusBadRequest)
		return
	}
	err = dataprovider.UpdateUser(user)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	} else {
		sendAPIResponse(w, r, err, "User updated", http.StatusOK)
		if disconnect == 1 {
			disconnectUser(user.Username)
		}
	}
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil {
		err = errors.New("Invalid userID")
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserByID(userID)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	err = dataprovider.DeleteUser(user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	} else {
		sendAPIResponse(w, r, err, "User deleted", http.StatusOK)
		disconnectUser(user.Username)
	}
}

func disconnectUser(username string) {
	for _, stat := range common.Connections.GetStats() {
		if stat.Username == username {
			common.Connections.Close(stat.ConnectionID)
		}
	}
}

func updateEncryptedSecrets(user *dataprovider.User, currentS3AccessSecret, currentAzAccountKey string) {
	// we use the new access secret if different from the old one and not empty
	if user.FsConfig.Provider == dataprovider.S3FilesystemProvider {
		if utils.RemoveDecryptionKey(currentS3AccessSecret) == user.FsConfig.S3Config.AccessSecret ||
			(user.FsConfig.S3Config.AccessSecret == "" && user.FsConfig.S3Config.AccessKey != "") {
			user.FsConfig.S3Config.AccessSecret = currentS3AccessSecret
		}
	}
	if user.FsConfig.Provider == dataprovider.AzureBlobFilesystemProvider {
		if utils.RemoveDecryptionKey(currentAzAccountKey) == user.FsConfig.AzBlobConfig.AccountKey ||
			(user.FsConfig.AzBlobConfig.AccountKey == "" && user.FsConfig.AzBlobConfig.AccountName != "") {
			user.FsConfig.AzBlobConfig.AccountKey = currentAzAccountKey
		}
	}
}
