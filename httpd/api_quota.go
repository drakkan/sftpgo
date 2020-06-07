package httpd

import (
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/vfs"
)

func getQuotaScans(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, sftpd.GetQuotaScans())
}

func getVFolderQuotaScans(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, sftpd.GetVFoldersQuotaScans())
}

func startQuotaScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var u dataprovider.User
	err := render.DecodeJSON(r.Body, &u)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(dataProvider, u.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusNotFound)
		return
	}
	if dataprovider.GetQuotaTracking() == 0 {
		sendAPIResponse(w, r, nil, "Quota tracking is disabled!", http.StatusForbidden)
		return
	}
	if sftpd.AddQuotaScan(user.Username) {
		go doQuotaScan(user) //nolint:errcheck
		sendAPIResponse(w, r, err, "Scan started", http.StatusCreated)
	} else {
		sendAPIResponse(w, r, err, "Another scan is already in progress", http.StatusConflict)
	}
}

func startVFolderQuotaScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var f vfs.BaseVirtualFolder
	err := render.DecodeJSON(r.Body, &f)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	folder, err := dataprovider.GetFolderByPath(dataProvider, f.MappedPath)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusNotFound)
		return
	}
	if dataprovider.GetQuotaTracking() == 0 {
		sendAPIResponse(w, r, nil, "Quota tracking is disabled!", http.StatusForbidden)
		return
	}
	if sftpd.AddVFolderQuotaScan(folder.MappedPath) {
		go doFolderQuotaScan(folder) //nolint:errcheck
		sendAPIResponse(w, r, err, "Scan started", http.StatusCreated)
	} else {
		sendAPIResponse(w, r, err, "Another scan is already in progress", http.StatusConflict)
	}
}

func doQuotaScan(user dataprovider.User) error {
	defer sftpd.RemoveQuotaScan(user.Username) //nolint:errcheck
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
	err = dataprovider.UpdateUserQuota(dataProvider, user, numFiles, size, true)
	logger.Debug(logSender, "", "user home dir scanned, user: %#v, error: %v", user.Username, err)
	return err
}

func doFolderQuotaScan(folder vfs.BaseVirtualFolder) error {
	defer sftpd.RemoveVFolderQuotaScan(folder.MappedPath) //nolint:errcheck
	fs := vfs.NewOsFs("", "", nil).(vfs.OsFs)
	numFiles, size, err := fs.GetDirSize(folder.MappedPath)
	if err != nil {
		logger.Warn(logSender, "", "error scanning folder %#v: %v", folder.MappedPath, err)
		return err
	}
	err = dataprovider.UpdateVirtualFolderQuota(dataProvider, folder, numFiles, size, true)
	logger.Debug(logSender, "", "virtual folder %#v scanned, error: %v", folder.MappedPath, err)
	return err
}
