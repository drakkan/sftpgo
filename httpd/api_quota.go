package httpd

import (
	"errors"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	quotaUpdateModeAdd   = "add"
	quotaUpdateModeReset = "reset"
)

func getQuotaScans(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, common.QuotaScans.GetUsersQuotaScans())
}

func getVFolderQuotaScans(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, common.QuotaScans.GetVFoldersQuotaScans())
}

func updateUserQuotaUsage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var u dataprovider.User
	err := render.DecodeJSON(r.Body, &u)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if u.UsedQuotaFiles < 0 || u.UsedQuotaSize < 0 {
		sendAPIResponse(w, r, errors.New("Invalid used quota parameters, negative values are not allowed"),
			"", http.StatusBadRequest)
		return
	}
	mode, err := getQuotaUpdateMode(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(u.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if mode == quotaUpdateModeAdd && !user.HasQuotaRestrictions() && dataprovider.GetQuotaTracking() == 2 {
		sendAPIResponse(w, r, errors.New("this user has no quota restrictions, only reset mode is supported"),
			"", http.StatusBadRequest)
		return
	}
	if !common.QuotaScans.AddUserQuotaScan(user.Username) {
		sendAPIResponse(w, r, err, "A quota scan is in progress for this user", http.StatusConflict)
		return
	}
	defer common.QuotaScans.RemoveUserQuotaScan(user.Username)
	err = dataprovider.UpdateUserQuota(user, u.UsedQuotaFiles, u.UsedQuotaSize, mode == quotaUpdateModeReset)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	} else {
		sendAPIResponse(w, r, err, "Quota updated", http.StatusOK)
	}
}

func updateVFolderQuotaUsage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var f vfs.BaseVirtualFolder
	err := render.DecodeJSON(r.Body, &f)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if f.UsedQuotaFiles < 0 || f.UsedQuotaSize < 0 {
		sendAPIResponse(w, r, errors.New("Invalid used quota parameters, negative values are not allowed"),
			"", http.StatusBadRequest)
		return
	}
	mode, err := getQuotaUpdateMode(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	folder, err := dataprovider.GetFolderByPath(f.MappedPath)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !common.QuotaScans.AddVFolderQuotaScan(folder.MappedPath) {
		sendAPIResponse(w, r, err, "A quota scan is in progress for this folder", http.StatusConflict)
		return
	}
	defer common.QuotaScans.RemoveVFolderQuotaScan(folder.MappedPath)
	err = dataprovider.UpdateVirtualFolderQuota(folder, f.UsedQuotaFiles, f.UsedQuotaSize, mode == quotaUpdateModeReset)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	} else {
		sendAPIResponse(w, r, err, "Quota updated", http.StatusOK)
	}
}

func startQuotaScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if dataprovider.GetQuotaTracking() == 0 {
		sendAPIResponse(w, r, nil, "Quota tracking is disabled!", http.StatusForbidden)
		return
	}
	var u dataprovider.User
	err := render.DecodeJSON(r.Body, &u)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(u.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if common.QuotaScans.AddUserQuotaScan(user.Username) {
		go doQuotaScan(user) //nolint:errcheck
		sendAPIResponse(w, r, err, "Scan started", http.StatusAccepted)
	} else {
		sendAPIResponse(w, r, err, "Another scan is already in progress", http.StatusConflict)
	}
}

func startVFolderQuotaScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if dataprovider.GetQuotaTracking() == 0 {
		sendAPIResponse(w, r, nil, "Quota tracking is disabled!", http.StatusForbidden)
		return
	}
	var f vfs.BaseVirtualFolder
	err := render.DecodeJSON(r.Body, &f)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	folder, err := dataprovider.GetFolderByPath(f.MappedPath)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if common.QuotaScans.AddVFolderQuotaScan(folder.MappedPath) {
		go doFolderQuotaScan(folder) //nolint:errcheck
		sendAPIResponse(w, r, err, "Scan started", http.StatusAccepted)
	} else {
		sendAPIResponse(w, r, err, "Another scan is already in progress", http.StatusConflict)
	}
}

func doQuotaScan(user dataprovider.User) error {
	defer common.QuotaScans.RemoveUserQuotaScan(user.Username)
	fs, err := user.GetFilesystem("")
	if err != nil {
		logger.Warn(logSender, "", "unable scan quota for user %#v error creating filesystem: %v", user.Username, err)
		return err
	}
	numFiles, size, err := fs.ScanRootDirContents()
	if err != nil {
		logger.Warn(logSender, "", "error scanning user home dir %#v: %v", user.Username, err)
		return err
	}
	err = dataprovider.UpdateUserQuota(user, numFiles, size, true)
	logger.Debug(logSender, "", "user home dir scanned, user: %#v, error: %v", user.Username, err)
	return err
}

func doFolderQuotaScan(folder vfs.BaseVirtualFolder) error {
	defer common.QuotaScans.RemoveVFolderQuotaScan(folder.MappedPath)
	fs := vfs.NewOsFs("", "", nil).(*vfs.OsFs)
	numFiles, size, err := fs.GetDirSize(folder.MappedPath)
	if err != nil {
		logger.Warn(logSender, "", "error scanning folder %#v: %v", folder.MappedPath, err)
		return err
	}
	err = dataprovider.UpdateVirtualFolderQuota(folder, numFiles, size, true)
	logger.Debug(logSender, "", "virtual folder %#v scanned, error: %v", folder.MappedPath, err)
	return err
}

func getQuotaUpdateMode(r *http.Request) (string, error) {
	mode := quotaUpdateModeReset
	if _, ok := r.URL.Query()["mode"]; ok {
		mode = r.URL.Query().Get("mode")
		if mode != quotaUpdateModeReset && mode != quotaUpdateModeAdd {
			return "", errors.New("Invalid mode")
		}
	}
	return mode, nil
}
