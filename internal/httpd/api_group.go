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
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getGroups(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	groups, err := dataprovider.GetGroups(limit, offset, order, false)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, groups)
}

func addGroup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var group dataprovider.Group
	err = render.DecodeJSON(r.Body, &group)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddGroup(&group, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%s/%s", groupPath, url.PathEscape(group.Name)))
	renderGroup(w, r, group.Name, &claims, http.StatusCreated)
}

func updateGroup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	name := getURLParam(r, "name")
	group, err := dataprovider.GroupExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	currentS3AccessSecret := group.UserSettings.FsConfig.S3Config.AccessSecret
	currentAzAccountKey := group.UserSettings.FsConfig.AzBlobConfig.AccountKey
	currentAzSASUrl := group.UserSettings.FsConfig.AzBlobConfig.SASURL
	currentGCSCredentials := group.UserSettings.FsConfig.GCSConfig.Credentials
	currentCryptoPassphrase := group.UserSettings.FsConfig.CryptConfig.Passphrase
	currentSFTPPassword := group.UserSettings.FsConfig.SFTPConfig.Password
	currentSFTPKey := group.UserSettings.FsConfig.SFTPConfig.PrivateKey
	currentSFTPKeyPassphrase := group.UserSettings.FsConfig.SFTPConfig.KeyPassphrase
	currentHTTPPassword := group.UserSettings.FsConfig.HTTPConfig.Password
	currentHTTPAPIKey := group.UserSettings.FsConfig.HTTPConfig.APIKey

	var updatedGroup dataprovider.Group
	err = render.DecodeJSON(r.Body, &updatedGroup)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	updatedGroup.ID = group.ID
	updatedGroup.Name = group.Name
	updatedGroup.UserSettings.FsConfig.SetEmptySecretsIfNil()
	updateEncryptedSecrets(&updatedGroup.UserSettings.FsConfig, currentS3AccessSecret, currentAzAccountKey, currentAzSASUrl,
		currentGCSCredentials, currentCryptoPassphrase, currentSFTPPassword, currentSFTPKey, currentSFTPKeyPassphrase,
		currentHTTPPassword, currentHTTPAPIKey)
	err = dataprovider.UpdateGroup(&updatedGroup, group.Users, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr),
		claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Group updated", http.StatusOK)
}

func renderGroup(w http.ResponseWriter, r *http.Request, name string, claims *jwtTokenClaims, status int) {
	group, err := dataprovider.GroupExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if hideConfidentialData(claims, r) {
		group.PrepareForRendering()
	}
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), group)
	} else {
		render.JSON(w, r, group)
	}
}

func getGroupByName(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	renderGroup(w, r, name, &claims, http.StatusOK)
}

func deleteGroup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	err = dataprovider.DeleteGroup(name, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Group deleted", http.StatusOK)
}
