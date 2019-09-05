package api

import (
	"net/http"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
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
		sendAPIResponse(w, r, err, "Scan started", http.StatusCreated)
		go func() {
			numFiles, size, _, err := utils.ScanDirContents(user.HomeDir)
			if err != nil {
				logger.Warn(logSender, "", "error scanning user home dir %v: %v", user.HomeDir, err)
			} else {
				err := dataprovider.UpdateUserQuota(dataProvider, user, numFiles, size, true)
				logger.Debug(logSender, "", "user dir scanned, user: %v, dir: %v, error: %v", user.Username, user.HomeDir, err)
			}
			sftpd.RemoveQuotaScan(user.Username)
		}()
	} else {
		sendAPIResponse(w, r, err, "Another scan is already in progress", http.StatusConflict)
	}
}
