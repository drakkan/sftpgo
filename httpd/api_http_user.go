package httpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/go-chi/render"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

func getUserConnection(w http.ResponseWriter, r *http.Request) (*Connection, error) {
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return nil, fmt.Errorf("invalid token claims %w", err)
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return nil, err
	}
	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil, err
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, r.RemoteAddr, user),
		request:        r,
	}
	return connection, nil
}

func readUserFolder(w http.ResponseWriter, r *http.Request) {
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := util.CleanPath(r.URL.Query().Get("path"))
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

func createUserDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := util.CleanPath(r.URL.Query().Get("path"))
	err = connection.CreateDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to create directory %#v", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("Directory %#v created", name), http.StatusCreated)
}

func renameUserDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	oldName := util.CleanPath(r.URL.Query().Get("path"))
	newName := util.CleanPath(r.URL.Query().Get("target"))
	err = connection.Rename(oldName, newName)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to rename directory %#v to %#v", oldName, newName),
			getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("Directory %#v renamed to %#v", oldName, newName), http.StatusOK)
}

func deleteUserDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := util.CleanPath(r.URL.Query().Get("path"))
	err = connection.RemoveDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete directory %#v", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("Directory %#v deleted", name), http.StatusOK)
}

func getUserFile(w http.ResponseWriter, r *http.Request) {
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := util.CleanPath(r.URL.Query().Get("path"))
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

func uploadUserFiles(w http.ResponseWriter, r *http.Request) {
	if maxUploadFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize)
	}

	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	err = r.ParseMultipartForm(maxMultipartMem)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to parse multipart form", http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	parentDir := util.CleanPath(r.URL.Query().Get("path"))
	files := r.MultipartForm.File["filename"]
	if len(files) == 0 {
		sendAPIResponse(w, r, err, "No files uploaded!", http.StatusBadRequest)
		return
	}

	for _, f := range files {
		file, err := f.Open()
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Unable to read uploaded file %#v", f.Filename), getMappedStatusCode(err))
			return
		}
		defer file.Close()

		filePath := path.Join(parentDir, f.Filename)
		writer, err := connection.getFileWriter(filePath)
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Unable to write file %#v", f.Filename), getMappedStatusCode(err))
			return
		}
		_, err = io.Copy(writer, file)
		if err != nil {
			writer.Close() //nolint:errcheck
			sendAPIResponse(w, r, err, fmt.Sprintf("Error saving file %#v", f.Filename), getMappedStatusCode(err))
			return
		}
		err = writer.Close()
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Error closing file %#v", f.Filename), getMappedStatusCode(err))
			return
		}
	}
	sendAPIResponse(w, r, nil, "Upload completed", http.StatusCreated)
}

func renameUserFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	oldName := util.CleanPath(r.URL.Query().Get("path"))
	newName := util.CleanPath(r.URL.Query().Get("target"))
	err = connection.Rename(oldName, newName)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to rename file %#v to %#v", oldName, newName),
			getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("File %#v renamed to %#v", oldName, newName), http.StatusOK)
}

func deleteUserFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := util.CleanPath(r.URL.Query().Get("path"))
	fs, p, err := connection.GetFsAndResolvedPath(name)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete file %#v", name), getMappedStatusCode(err))
		return
	}

	var fi os.FileInfo
	if fi, err = fs.Lstat(p); err != nil {
		connection.Log(logger.LevelWarn, "failed to remove a file %#v: stat error: %+v", p, err)
		err = connection.GetFsError(fs, err)
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete file %#v", name), getMappedStatusCode(err))
		return
	}

	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		connection.Log(logger.LevelDebug, "cannot remove %#v is not a file/symlink", p)
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable delete %#v, it is not a file/symlink", name), http.StatusBadRequest)
		return
	}
	err = connection.RemoveFile(fs, p, name, fi)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete file %#v", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("File %#v deleted", name), http.StatusOK)
}

func getUserFilesAsZipStream(w http.ResponseWriter, r *http.Request) {
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
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
		filesList[idx] = util.CleanPath(filesList[idx])
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
		return util.NewValidationError("please provide the current password and the new one two times")
	}
	if newPassword != confirmNewPassword {
		return util.NewValidationError("the two password fields do not match")
	}
	if currentPassword == newPassword {
		return util.NewValidationError("the new password must be different from the current one")
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		return errors.New("invalid token claims")
	}
	user, err := dataprovider.CheckUserAndPass(claims.Username, currentPassword, util.GetIPFromRemoteAddress(r.RemoteAddr),
		common.ProtocolHTTP)
	if err != nil {
		return util.NewValidationError("current password does not match")
	}
	user.Password = newPassword

	return dataprovider.UpdateUser(&user)
}
