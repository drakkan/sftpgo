// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
	"strings"

	"github.com/go-chi/render"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getUserConnection(w http.ResponseWriter, r *http.Request) (*Connection, error) {
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return nil, fmt.Errorf("invalid token claims %w", err)
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return nil, err
	}
	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false, false); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil, err
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return connection, err
	}
	return connection, nil
}

func readUserFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	lister, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory lister", getMappedStatusCode(err))
		return
	}
	renderAPIDirContents(w, lister, false)
}

func createUserDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	if getBoolQueryParam(r, "mkdir_parents") {
		if err = connection.CheckParentDirs(path.Dir(name)); err != nil {
			sendAPIResponse(w, r, err, "Error checking parent directories", getMappedStatusCode(err))
			return
		}
	}
	err = connection.CreateDir(name, true)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to create directory %q", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("Directory %q created", name), http.StatusCreated)
}

func deleteUserDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	err = connection.RemoveAll(name)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete directory %q", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("Directory %q deleted", name), http.StatusOK)
}

func renameUserFsEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	oldName := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	newName := connection.User.GetCleanedPath(r.URL.Query().Get("target"))
	if !connection.IsSameResource(oldName, newName) {
		if err := connection.Copy(oldName, newName); err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Cannot perform copy step to rename %q -> %q", oldName, newName),
				getMappedStatusCode(err))
			return
		}
		if err := connection.RemoveAll(oldName); err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Cannot perform remove step to rename %q -> %q", oldName, newName),
				getMappedStatusCode(err))
			return
		}
	} else {
		if err := connection.Rename(oldName, newName); err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Unable to rename %q => %q", oldName, newName),
				getMappedStatusCode(err))
			return
		}
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("%q renamed to %q", oldName, newName), http.StatusOK)
}

func copyUserFsEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	source := r.URL.Query().Get("path")
	target := r.URL.Query().Get("target")
	copyFromSource := strings.HasSuffix(source, "/")
	copyInTarget := strings.HasSuffix(target, "/")
	source = connection.User.GetCleanedPath(source)
	target = connection.User.GetCleanedPath(target)
	if copyFromSource {
		source += "/"
	}
	if copyInTarget {
		target += "/"
	}
	err = connection.Copy(source, target)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to copy %q => %q", source, target),
			getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("%q copied to %q", source, target), http.StatusOK)
}

func getUserFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
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
		sendAPIResponse(w, r, nil, fmt.Sprintf("Please set the path to a valid file, %q is a directory", name), http.StatusBadRequest)
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
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	attrs := common.StatAttributes{
		Flags: common.StatAttrTimes,
		Atime: util.GetTimeFromMsecSinceEpoch(mTime),
		Mtime: util.GetTimeFromMsecSinceEpoch(mTime),
	}
	err = connection.SetStat(name, &attrs)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to set metadata for path %q", name), getMappedStatusCode(err))
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
	defer common.Connections.Remove(connection.GetID())

	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
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
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to write file %q", filePath), getMappedStatusCode(err))
		return err
	}
	_, err = io.Copy(writer, r.Body)
	if err != nil {
		writer.Close() //nolint:errcheck
		sendAPIResponse(w, r, err, fmt.Sprintf("Error saving file %q", filePath), getMappedStatusCode(err))
		return err
	}
	err = writer.Close()
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Error closing file %q", filePath), getMappedStatusCode(err))
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
	defer common.Connections.Remove(connection.GetID())

	if err := common.Connections.IsNewTransferAllowed(connection.User.Username); err != nil {
		connection.Log(logger.LevelInfo, "denying file write due to number of transfer limits")
		sendAPIResponse(w, r, err, "Denying file write due to transfer count limits",
			http.StatusConflict)
		return
	}

	transferQuota := connection.GetTransferQuota()
	if !transferQuota.HasUploadSpace() {
		connection.Log(logger.LevelInfo, "denying file write due to transfer quota limits")
		sendAPIResponse(w, r, common.ErrQuotaExceeded, "Denying file write due to transfer quota limits",
			http.StatusRequestEntityTooLarge)
		return
	}

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
	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
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
			sendAPIResponse(w, r, err, fmt.Sprintf("Unable to read uploaded file %q", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		defer file.Close()

		filePath := path.Join(parentDir, path.Base(util.CleanPath(f.Filename)))
		writer, err := connection.getFileWriter(filePath)
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Unable to write file %q", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		_, err = io.Copy(writer, file)
		if err != nil {
			writer.Close() //nolint:errcheck
			sendAPIResponse(w, r, err, fmt.Sprintf("Error saving file %q", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		err = writer.Close()
		if err != nil {
			sendAPIResponse(w, r, err, fmt.Sprintf("Error closing file %q", f.Filename), getMappedStatusCode(err))
			return uploaded
		}
		uploaded++
	}
	sendAPIResponse(w, r, nil, "Upload completed", http.StatusCreated)
	return uploaded
}

func deleteUserFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	fs, p, err := connection.GetFsAndResolvedPath(name)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete file %q", name), getMappedStatusCode(err))
		return
	}

	var fi os.FileInfo
	if fi, err = fs.Lstat(p); err != nil {
		connection.Log(logger.LevelError, "failed to remove file %q: stat error: %+v", p, err)
		err = connection.GetFsError(fs, err)
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete file %q", name), getMappedStatusCode(err))
		return
	}

	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		connection.Log(logger.LevelDebug, "cannot remove %q is not a file/symlink", p)
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable delete %q, it is not a file/symlink", name), http.StatusBadRequest)
		return
	}
	err = connection.RemoveFile(fs, p, name, fi)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to delete file %q", name), getMappedStatusCode(err))
		return
	}
	sendAPIResponse(w, r, nil, fmt.Sprintf("File %q deleted", name), http.StatusOK)
}

func getUserFilesAsZipStream(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
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

	filesList = util.RemoveDuplicates(filesList, false)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		getCompressedFileName(connection.GetUsername(), filesList)))
	renderCompressedFiles(w, connection, baseDir, filesList, nil)
}

func getUserProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username, "")
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
		AdditionalEmails: user.Filters.AdditionalEmails,
		PublicKeys:       user.PublicKeys,
		TLSCerts:         user.Filters.TLSCerts,
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
	user, userMerged, err := dataprovider.GetUserVariants(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !userMerged.CanUpdateProfile() {
		sendAPIResponse(w, r, nil, "You are not allowed to change anything", http.StatusForbidden)
		return
	}
	if userMerged.CanManagePublicKeys() {
		user.PublicKeys = req.PublicKeys
	}
	if userMerged.CanManageTLSCerts() {
		user.Filters.TLSCerts = req.TLSCerts
	}
	if userMerged.CanChangeAPIKeyAuth() {
		user.Filters.AllowAPIKeyAuth = req.AllowAPIKeyAuth
	}
	if userMerged.CanChangeInfo() {
		user.Email = req.Email
		user.Filters.AdditionalEmails = req.AdditionalEmails
		user.Description = req.Description
	}
	if err := dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr), user.Role); err != nil {
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
	invalidateToken(r)
	sendAPIResponse(w, r, err, "Password updated", http.StatusOK)
}

func doChangeUserPassword(r *http.Request, currentPassword, newPassword, confirmNewPassword string) error {
	if currentPassword == "" || newPassword == "" || confirmNewPassword == "" {
		return util.NewI18nError(
			util.NewValidationError("please provide the current password and the new one two times"),
			util.I18nErrorChangePwdRequiredFields,
		)
	}
	if newPassword != confirmNewPassword {
		return util.NewI18nError(util.NewValidationError("the two password fields do not match"), util.I18nErrorChangePwdNoMatch)
	}
	if currentPassword == newPassword {
		return util.NewI18nError(
			util.NewValidationError("the new password must be different from the current one"),
			util.I18nErrorChangePwdNoDifferent,
		)
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		return util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken)
	}
	_, err = dataprovider.CheckUserAndPass(claims.Username, currentPassword, util.GetIPFromRemoteAddress(r.RemoteAddr),
		getProtocolFromRequest(r))
	if err != nil {
		return util.NewI18nError(util.NewValidationError("current password does not match"), util.I18nErrorChangePwdCurrentNoMatch)
	}

	return dataprovider.UpdateUserPassword(claims.Username, newPassword, dataprovider.ActionExecutorSelf,
		util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
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
			c.Log(logger.LevelDebug, "requested modification time %v for file %q, error: %v",
				attrs.Mtime, filePath, err)
		} else {
			c.Log(logger.LevelInfo, "invalid modification time header was ignored: %v", mTimeString)
		}
	}
}
