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
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	quotaUpdateModeAdd   = "add"
	quotaUpdateModeReset = "reset"
)

type quotaUsage struct {
	UsedQuotaSize  int64 `json:"used_quota_size"`
	UsedQuotaFiles int   `json:"used_quota_files"`
}

type transferQuotaUsage struct {
	UsedUploadDataTransfer   int64 `json:"used_upload_data_transfer"`
	UsedDownloadDataTransfer int64 `json:"used_download_data_transfer"`
}

func getUsersQuotaScans(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	render.JSON(w, r, common.QuotaScans.GetUsersQuotaScans(claims.Role))
}

func getFoldersQuotaScans(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	render.JSON(w, r, common.QuotaScans.GetVFoldersQuotaScans())
}

func updateUserQuotaUsage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var usage quotaUsage
	err := render.DecodeJSON(r.Body, &usage)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	doUpdateUserQuotaUsage(w, r, getURLParam(r, "username"), usage)
}

func updateFolderQuotaUsage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var usage quotaUsage
	err := render.DecodeJSON(r.Body, &usage)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	doUpdateFolderQuotaUsage(w, r, getURLParam(r, "name"), usage)
}

func startUserQuotaScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	doStartUserQuotaScan(w, r, getURLParam(r, "username"))
}

func startFolderQuotaScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	doStartFolderQuotaScan(w, r, getURLParam(r, "name"))
}

func updateUserTransferQuotaUsage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var usage transferQuotaUsage
	err = render.DecodeJSON(r.Body, &usage)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if usage.UsedUploadDataTransfer < 0 || usage.UsedDownloadDataTransfer < 0 {
		sendAPIResponse(w, r, errors.New("invalid used transfer quota parameters, negative values are not allowed"),
			"", http.StatusBadRequest)
		return
	}
	mode, err := getQuotaUpdateMode(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(getURLParam(r, "username"), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if mode == quotaUpdateModeAdd && !user.HasTransferQuotaRestrictions() && dataprovider.GetQuotaTracking() == 2 {
		sendAPIResponse(w, r, errors.New("this user has no transfer quota restrictions, only reset mode is supported"),
			"", http.StatusBadRequest)
		return
	}
	err = dataprovider.UpdateUserTransferQuota(&user, usage.UsedUploadDataTransfer, usage.UsedDownloadDataTransfer,
		mode == quotaUpdateModeReset)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Quota updated", http.StatusOK)
}

func doUpdateUserQuotaUsage(w http.ResponseWriter, r *http.Request, username string, usage quotaUsage) {
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	if usage.UsedQuotaFiles < 0 || usage.UsedQuotaSize < 0 {
		sendAPIResponse(w, r, errors.New("invalid used quota parameters, negative values are not allowed"),
			"", http.StatusBadRequest)
		return
	}
	mode, err := getQuotaUpdateMode(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(username, claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if mode == quotaUpdateModeAdd && !user.HasQuotaRestrictions() && dataprovider.GetQuotaTracking() == 2 {
		sendAPIResponse(w, r, errors.New("this user has no quota restrictions, only reset mode is supported"),
			"", http.StatusBadRequest)
		return
	}
	if !common.QuotaScans.AddUserQuotaScan(user.Username, user.Role) {
		sendAPIResponse(w, r, err, "A quota scan is in progress for this user", http.StatusConflict)
		return
	}
	defer common.QuotaScans.RemoveUserQuotaScan(user.Username)
	err = dataprovider.UpdateUserQuota(&user, usage.UsedQuotaFiles, usage.UsedQuotaSize, mode == quotaUpdateModeReset)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Quota updated", http.StatusOK)
}

func doUpdateFolderQuotaUsage(w http.ResponseWriter, r *http.Request, name string, usage quotaUsage) {
	if usage.UsedQuotaFiles < 0 || usage.UsedQuotaSize < 0 {
		sendAPIResponse(w, r, errors.New("invalid used quota parameters, negative values are not allowed"),
			"", http.StatusBadRequest)
		return
	}
	mode, err := getQuotaUpdateMode(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	folder, err := dataprovider.GetFolderByName(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !common.QuotaScans.AddVFolderQuotaScan(folder.Name) {
		sendAPIResponse(w, r, err, "A quota scan is in progress for this folder", http.StatusConflict)
		return
	}
	defer common.QuotaScans.RemoveVFolderQuotaScan(folder.Name)
	err = dataprovider.UpdateVirtualFolderQuota(&folder, usage.UsedQuotaFiles, usage.UsedQuotaSize, mode == quotaUpdateModeReset)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	} else {
		sendAPIResponse(w, r, err, "Quota updated", http.StatusOK)
	}
}

func doStartUserQuotaScan(w http.ResponseWriter, r *http.Request, username string) {
	if dataprovider.GetQuotaTracking() == 0 {
		sendAPIResponse(w, r, nil, "Quota tracking is disabled!", http.StatusForbidden)
		return
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(username, claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !common.QuotaScans.AddUserQuotaScan(user.Username, user.Role) {
		sendAPIResponse(w, r, nil, fmt.Sprintf("Another scan is already in progress for user %q", username),
			http.StatusConflict)
		return
	}
	go doUserQuotaScan(user) //nolint:errcheck
	sendAPIResponse(w, r, err, "Scan started", http.StatusAccepted)
}

func doStartFolderQuotaScan(w http.ResponseWriter, r *http.Request, name string) {
	if dataprovider.GetQuotaTracking() == 0 {
		sendAPIResponse(w, r, nil, "Quota tracking is disabled!", http.StatusForbidden)
		return
	}
	folder, err := dataprovider.GetFolderByName(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !common.QuotaScans.AddVFolderQuotaScan(folder.Name) {
		sendAPIResponse(w, r, err, fmt.Sprintf("Another scan is already in progress for folder %q", name),
			http.StatusConflict)
		return
	}
	go doFolderQuotaScan(folder) //nolint:errcheck
	sendAPIResponse(w, r, err, "Scan started", http.StatusAccepted)
}

func doUserQuotaScan(user dataprovider.User) error {
	defer common.QuotaScans.RemoveUserQuotaScan(user.Username)
	numFiles, size, err := user.ScanQuota()
	if err != nil {
		logger.Warn(logSender, "", "error scanning user quota %q: %v", user.Username, err)
		return err
	}
	err = dataprovider.UpdateUserQuota(&user, numFiles, size, true)
	logger.Debug(logSender, "", "user quota scanned, user: %q, error: %v", user.Username, err)
	return err
}

func doFolderQuotaScan(folder vfs.BaseVirtualFolder) error {
	defer common.QuotaScans.RemoveVFolderQuotaScan(folder.Name)
	f := vfs.VirtualFolder{
		BaseVirtualFolder: folder,
		VirtualPath:       "/",
	}
	numFiles, size, err := f.ScanQuota()
	if err != nil {
		logger.Warn(logSender, "", "error scanning folder %q: %v", folder.Name, err)
		return err
	}
	err = dataprovider.UpdateVirtualFolderQuota(&folder, numFiles, size, true)
	logger.Debug(logSender, "", "virtual folder %q scanned, error: %v", folder.Name, err)
	return err
}

func getQuotaUpdateMode(r *http.Request) (string, error) {
	mode := quotaUpdateModeReset
	if _, ok := r.URL.Query()["mode"]; ok {
		mode = r.URL.Query().Get("mode")
		if mode != quotaUpdateModeReset && mode != quotaUpdateModeAdd {
			return "", errors.New("invalid mode")
		}
	}
	return mode, nil
}
