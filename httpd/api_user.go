package httpd

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/utils"
	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func getUsers(w http.ResponseWriter, r *http.Request) {
	limit := 100
	offset := 0
	order := "ASC"
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
		if order != "ASC" && order != "DESC" {
			err = errors.New("Invalid order")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	if _, ok := r.URL.Query()["username"]; ok {
		username = r.URL.Query().Get("username")
	}
	users, err := dataprovider.GetUsers(dataProvider, limit, offset, order, username)
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
	user, err := dataprovider.GetUserByID(dataProvider, userID)
	if err == nil {
		render.JSON(w, r, dataprovider.HideUserSensitiveData(&user))
	} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		sendAPIResponse(w, r, err, "", http.StatusNotFound)
	} else {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	}
}

func addUser(w http.ResponseWriter, r *http.Request) {
	var user dataprovider.User
	err := render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddUser(dataProvider, user)
	if err == nil {
		user, err = dataprovider.UserExists(dataProvider, user.Username)
		if err == nil {
			render.JSON(w, r, dataprovider.HideUserSensitiveData(&user))
		} else {
			sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		}
	} else {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	}
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil {
		err = errors.New("Invalid userID")
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserByID(dataProvider, userID)
	oldPermissions := user.Permissions
	oldS3AccessSecret := ""
	if user.FsConfig.Provider == 1 {
		oldS3AccessSecret = user.FsConfig.S3Config.AccessSecret
	}
	user.Permissions = make(map[string][]string)
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		sendAPIResponse(w, r, err, "", http.StatusNotFound)
		return
	} else if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	err = render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	// we use new Permissions if passed otherwise the old ones
	if len(user.Permissions) == 0 {
		user.Permissions = oldPermissions
	}
	// we use the new access secret if different from the old one and not empty
	if user.FsConfig.Provider == 1 {
		if utils.RemoveDecryptionKey(oldS3AccessSecret) == user.FsConfig.S3Config.AccessSecret ||
			len(user.FsConfig.S3Config.AccessSecret) == 0 {
			user.FsConfig.S3Config.AccessSecret = oldS3AccessSecret
		}
	}
	if user.ID != userID {
		sendAPIResponse(w, r, err, "user ID in request body does not match user ID in path parameter", http.StatusBadRequest)
		return
	}
	err = dataprovider.UpdateUser(dataProvider, user)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	} else {
		sendAPIResponse(w, r, err, "User updated", http.StatusOK)
	}
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil {
		err = errors.New("Invalid userID")
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserByID(dataProvider, userID)
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		sendAPIResponse(w, r, err, "", http.StatusNotFound)
		return
	} else if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	err = dataprovider.DeleteUser(dataProvider, user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	} else {
		sendAPIResponse(w, r, err, "User deleted", http.StatusOK)
	}
}
