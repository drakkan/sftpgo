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
	"fmt"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
)

func getRetentionChecks(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	render.JSON(w, r, common.RetentionChecks.Get(claims.Role))
}

func startRetentionCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	username := getURLParam(r, "username")
	user, err := dataprovider.GetUserWithGroupSettings(username, claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	var check common.RetentionCheck

	err = render.DecodeJSON(r.Body, &check.Folders)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	check.Notifications = getCommaSeparatedQueryParam(r, "notifications")
	for _, notification := range check.Notifications {
		if notification == common.RetentionCheckNotificationEmail {
			admin, err := dataprovider.AdminExists(claims.Username)
			if err != nil {
				sendAPIResponse(w, r, err, "", getRespStatus(err))
				return
			}
			check.Email = admin.Email
		}
	}
	if err := check.Validate(); err != nil {
		sendAPIResponse(w, r, err, "Invalid retention check", http.StatusBadRequest)
		return
	}
	c := common.RetentionChecks.Add(check, &user)
	if c == nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Another check is already in progress for user %q", username),
			http.StatusConflict)
		return
	}
	go c.Start() //nolint:errcheck
	sendAPIResponse(w, r, err, "Check started", http.StatusAccepted)
}
