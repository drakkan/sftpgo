package httpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strconv"

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
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil, err
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	return connection, nil
}

func readUserFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}
	renderAPIDirContents(w, r, contents, false)
}

func createUserDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	if getBoolQueryParam(r, "mkdir_parents") {
		if err = connection.CheckParentDirs(path.Dir(name)); err != nil {
			sendAPIResponse(w, r, err, "Error checking parent directories", getMappedStatusCode(err))
			return
		}
	}
	err = connection.CreateDir(name, true)
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

	oldName := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	newName := connection.User.GetCleanedPath(r.URL.Query().Get("target"))
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

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	err = connection.RemoveDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete directory %#v", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("Directory %#v deleted", name), http.StatusOK)
}

func getUserFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
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

	inline := r.URL.Query().Get("inline") != ""
	if status, err := downloadFile(w, r, connection, name, info, inline, nil); err != nil {
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

func setFileDirMetadata(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	metadata := make(map[string]int64)
	err := render.DecodeJSON(r.Body, &metadata)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	mTime, ok := metadata["modification_time"]
	if !ok || !r.URL.Query().Has("path") {
		sendAPIResponse(w, r, errors.New("please set a modification_time and a path"), "", http.StatusBadRequest)
		return
	}

	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	attrs := common.StatAttributes{
		Flags: common.StatAttrTimes,
		Atime: util.GetTimeFromMsecSinceEpoch(mTime),
		Mtime: util.GetTimeFromMsecSinceEpoch(mTime),
	}
	err = connection.SetStat(name, &attrs)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to set metadata for path %#v", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, "OK", http.StatusOK)
}

func uploadUserFile(w http.ResponseWriter, r *http.Request) {
	if maxUploadFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize)
	}

	if !r.URL.Query().Has("path") {
		sendAPIResponse(w, r, errors.New("please set a file path"), "", http.StatusBadRequest)
		return
	}

	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	filePath := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	if getBoolQueryParam(r, "mkdir_parents") {
		if err = connection.CheckParentDirs(path.Dir(filePath)); err != nil {
			sendAPIResponse(w, r, err, "Error checking parent directories", getMappedStatusCode(err))
			return
		}
	}
	doUploadFile(w, r, connection, filePath) //nolint:errcheck
}

func doUploadFile(w http.ResponseWriter, r *http.Request, connection *Connection, filePath string) error {
	writer, err := connection.getFileWriter(filePath)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to write file %#v", filePath), getMappedStatusCode(err))
		return err
	}
	_, err = io.Copy(writer, r.Body)
	if err != nil {
		writer.Close() //nolint:errcheck
		sendAPIResponse(w, r, err, fmt.Sprintf("Error saving file %#v", filePath), getMappedStatusCode(err))
		return err
	}
	err = writer.Close()
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Error closing file %#v", filePath), getMappedStatusCode(err))
		return err
	}
	setModificationTimeFromHeader(r, connection, filePath)
	sendAPIResponse(w, r, nil, "Upload completed", http.StatusCreated)
	return nil
}

func uploadUserFiles(w http.ResponseWriter, r *http.Request) {
	if maxUploadFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize)
	}

	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	transferQuota := connection.GetTransferQuota()
	if !transferQuota.HasUploadSpace() {
		connection.Log(logger.LevelInfo, "denying file write due to transfer quota limits")
		sendAPIResponse(w, r, common.ErrQuotaExceeded, "Denying file write due to transfer quota limits",
			http.StatusRequestEntityTooLarge)
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	t := newThrottledReader(r.Body, connection.User.UploadBandwidth, connection)
	r.Body = t
	err = r.ParseMultipartForm(maxMultipartMem)
	if err != nil {
		connection.RemoveTransfer(t)
		sendAPIResponse(w, r, err, "Unable to parse multipart form", http.StatusBadRequest)
		return
	}
	connection.RemoveTransfer(t)
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	parentDir := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	files := r.MultipartForm.File["filenames"]
	if len(files) == 0 {
		sendAPIResponse(w, r, nil, "No files uploaded!", http.StatusBadRequest)
		return
	}
	if getBoolQueryParam(r, "mkdir_parents") {
		if err = connection.CheckParentDirs(parentDir); err != nil {
			sendAPIResponse(w, r, err, "Error checking parent directories", getMappedStatusCode(err))
			return
		}
	}
	doUploadFiles(w, r, connection, parentDir, files)
}

func doUploadFiles(w http.ResponseWriter, r *http.Request, connection *Connection, parentDir string,
	files []*multipart.FileHeader,
) int {
	uploaded := 0
	connection.User.UploadBandwidth = 0
	for _, f := range files {
		file, err := f.Open()
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Unable to read uploaded file %#v", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		defer file.Close()

		filePath := path.Join(parentDir, f.Filename)
		writer, err := connection.getFileWriter(filePath)
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Unable to write file %#v", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		_, err = io.Copy(writer, file)
		if err != nil {
			writer.Close() //nolint:errcheck
			sendAPIResponse(w, r, err, fmt.Sprintf("Error saving file %#v", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		err = writer.Close()
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Error closing file %#v", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		uploaded++
	}
	sendAPIResponse(w, r, nil, "Upload completed", http.StatusCreated)
	return uploaded
}

func renameUserFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	oldName := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	newName := connection.User.GetCleanedPath(r.URL.Query().Get("target"))
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

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	fs, p, err := connection.GetFsAndResolvedPath(name)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete file %#v", name), getMappedStatusCode(err))
		return
	}

	var fi os.FileInfo
	if fi, err = fs.Lstat(p); err != nil {
		connection.Log(logger.LevelError, "failed to remove file %#v: stat error: %+v", p, err)
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
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
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

	filesList = util.RemoveDuplicates(filesList)

	w.Header().Set("Content-Disposition", "attachment; filename=\"sftpgo-download.zip\"")
	renderCompressedFiles(w, connection, baseDir, filesList, nil)
}

func getUserPublicKeys(w http.ResponseWriter, r *http.Request) {
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
	err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Public keys updated", http.StatusOK)
}

func getUserProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	resp := userProfile{
		baseProfile: baseProfile{
			Email:           user.Email,
			Description:     user.Description,
			AllowAPIKeyAuth: user.Filters.AllowAPIKeyAuth,
		},
		PublicKeys: user.PublicKeys,
	}
	render.JSON(w, r, resp)
}

func updateUserProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var req userProfile
	err = render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !user.CanManagePublicKeys() && !user.CanChangeAPIKeyAuth() && !user.CanChangeInfo() {
		sendAPIResponse(w, r, nil, "You are not allowed to change anything", http.StatusForbidden)
		return
	}
	if user.CanManagePublicKeys() {
		user.PublicKeys = req.PublicKeys
	}
	if user.CanChangeAPIKeyAuth() {
		user.Filters.AllowAPIKeyAuth = req.AllowAPIKeyAuth
	}
	if user.CanChangeInfo() {
		user.Email = req.Email
		user.Description = req.Description
	}
	if err := dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Profile updated", http.StatusOK)
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
		getProtocolFromRequest(r))
	if err != nil {
		return util.NewValidationError("current password does not match")
	}
	user.Password = newPassword

	return dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func setModificationTimeFromHeader(r *http.Request, c *Connection, filePath string) {
	mTimeString := r.Header.Get(mTimeHeader)
	if mTimeString != "" {
		// we don't return an error here if we fail to set the modification time
		mTime, err := strconv.ParseInt(mTimeString, 10, 64)
		if err == nil {
			attrs := common.StatAttributes{
				Flags: common.StatAttrTimes,
				Atime: util.GetTimeFromMsecSinceEpoch(mTime),
				Mtime: util.GetTimeFromMsecSinceEpoch(mTime),
			}
			err = c.SetStat(filePath, &attrs)
			c.Log(logger.LevelDebug, "requested modification time %v for file %#v, error: %v",
				attrs.Mtime, filePath, err)
		} else {
			c.Log(logger.LevelInfo, "invalid modification time header was ignored: %v", mTimeString)
		}
	}
}
