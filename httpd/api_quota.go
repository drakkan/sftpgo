package httpd

import (
	"net/http"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/go-chi/render"
)

func getQuotaScans(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, sftpd.GetQuotaScans())
}

func startQuotaScan(w http.ResponseWriter, r *http.Request) {
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
	if sftpd.AddQuotaScan(user.Username) {
		go doQuotaScan(user)
		sendAPIResponse(w, r, err, "Scan started", http.StatusCreated)
	} else {
		sendAPIResponse(w, r, err, "Another scan is already in progress", http.StatusConflict)
	}
}

func doQuotaScan(user dataprovider.User) error {
	defer sftpd.RemoveQuotaScan(user.Username)
	fs, err := user.GetFilesystem("")
	if err != nil {
		logger.Warn(logSender, "", "unable scan quota for user %#v error creating filesystem: %v", user.Username, err)
		return err
	}
	numFiles, size, err := fs.ScanDirContents(user.HomeDir)
	if err != nil {
		logger.Warn(logSender, "", "error scanning user home dir %#v: %v", user.HomeDir, err)
	} else {
		err = dataprovider.UpdateUserQuota(dataProvider, user, numFiles, size, true)
		logger.Debug(logSender, "", "user home dir scanned, user: %#v, dir: %#v, error: %v", user.Username, user.HomeDir, err)
	}
	return err
}
