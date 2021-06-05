package httpd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/utils"
)

func readUserFolder(w http.ResponseWriter, r *http.Request) {
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return
	}
	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, r.RemoteAddr, user),
		request:        r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := utils.CleanPath(r.URL.Query().Get("path"))
	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}
	results := make([]map[string]interface{}, 0, len(contents))
	for _, info := range contents {
		res := make(map[string]interface{})
		res["name"] = info.Name()
		if info.Mode().IsRegular() {
			res["size"] = info.Size()
		}
		res["mode"] = info.Mode()
		res["last_modified"] = info.ModTime().UTC().Format(time.RFC3339)
		results = append(results, res)
	}

	render.JSON(w, r, results)
}

func getUserFile(w http.ResponseWriter, r *http.Request) {
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return
	}
	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, r.RemoteAddr, user),
		request:        r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := utils.CleanPath(r.URL.Query().Get("path"))
	if name == "/" {
		sendAPIResponse(w, r, nil, "Please set the path to a valid file", http.StatusBadRequest)
		return
	}
	info, err := connection.Stat(name, 0)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to stat the requested file", getMappedStatusCode(err))
		return
	}
	if info.IsDir() {
		sendAPIResponse(w, r, nil, fmt.Sprintf("Please set the path to a valid file, %#v is a directory", name), http.StatusBadRequest)
		return
	}

	if status, err := downloadFile(w, r, connection, name, info); err != nil {
		resp := apiResponse{
			Error:   err.Error(),
			Message: http.StatusText(status),
		}
		ctx := r.Context()
		if status != 0 {
			ctx = context.WithValue(ctx, render.StatusCtxKey, status)
		}
		render.JSON(w, r.WithContext(ctx), resp)
	}
}

func getUserFilesAsZipStream(w http.ResponseWriter, r *http.Request) {
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return
	}
	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, r.RemoteAddr, user),
		request:        r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	var filesList []string
	err = render.DecodeJSON(r.Body, &filesList)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	baseDir := "/"
	for idx := range filesList {
		filesList[idx] = utils.CleanPath(filesList[idx])
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\"sftpgo-download.zip\"")
	renderCompressedFiles(w, connection, baseDir, filesList)
}

func getUserPublicKeys(w http.ResponseWriter, r *http.Request) {
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return
	}
	render.JSON(w, r, user.PublicKeys)
}

func setUserPublicKeys(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return
	}

	var publicKeys []string
	err = render.DecodeJSON(r.Body, &publicKeys)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	user.PublicKeys = publicKeys
	err = dataprovider.UpdateUser(&user)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Public keys updated", http.StatusOK)
}

func changeUserPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var pwd pwdChange
	err := render.DecodeJSON(r.Body, &pwd)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = doChangeUserPassword(r, pwd.CurrentPassword, pwd.NewPassword, pwd.NewPassword)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Password updated", http.StatusOK)
}

func doChangeUserPassword(r *http.Request, currentPassword, newPassword, confirmNewPassword string) error {
	if currentPassword == "" || newPassword == "" || confirmNewPassword == "" {
		return dataprovider.NewValidationError("please provide the current password and the new one two times")
	}
	if newPassword != confirmNewPassword {
		return dataprovider.NewValidationError("the two password fields do not match")
	}
	if currentPassword == newPassword {
		return dataprovider.NewValidationError("the new password must be different from the current one")
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		return errors.New("invalid token claims")
	}
	user, err := dataprovider.CheckUserAndPass(claims.Username, currentPassword, utils.GetIPFromRemoteAddress(r.RemoteAddr),
		common.ProtocolHTTP)
	if err != nil {
		return dataprovider.NewValidationError("current password does not match")
	}
	user.Password = newPassword

	return dataprovider.UpdateUser(&user)
}
