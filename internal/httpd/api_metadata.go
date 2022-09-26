// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package httpd

import (
	"fmt"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
)

func getMetadataChecks(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	render.JSON(w, r, common.ActiveMetadataChecks.Get())
}

func startMetadataCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	user, err := dataprovider.GetUserWithGroupSettings(getURLParam(r, "username"))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !common.ActiveMetadataChecks.Add(user.Username) {
		sendAPIResponse(w, r, err, fmt.Sprintf("Another check is already in progress for user %#v", user.Username),
			http.StatusConflict)
		return
	}
	go doMetadataCheck(user) //nolint:errcheck

	sendAPIResponse(w, r, err, "Check started", http.StatusAccepted)
}

func doMetadataCheck(user dataprovider.User) error {
	defer common.ActiveMetadataChecks.Remove(user.Username)

	err := user.CheckMetadataConsistency()
	if err != nil {
		logger.Warn(logSender, "", "error checking metadata for user %#v: %v", user.Username, err)
		return err
	}
	logger.Debug(logSender, "", "metadata check completed for user: %#v", user.Username)
	return nil
}
