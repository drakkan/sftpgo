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
	"context"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
	err = dataprovider.AddGroup(&group, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	renderGroup(w, r, group.Name, http.StatusCreated)
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
	users := group.Users
	groupID := group.ID
	name = group.Name
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

	group.UserSettings.FsConfig.S3Config = vfs.S3FsConfig{}
	group.UserSettings.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
	group.UserSettings.FsConfig.GCSConfig = vfs.GCSFsConfig{}
	group.UserSettings.FsConfig.CryptConfig = vfs.CryptFsConfig{}
	group.UserSettings.FsConfig.SFTPConfig = vfs.SFTPFsConfig{}
	group.UserSettings.FsConfig.HTTPConfig = vfs.HTTPFsConfig{}
	err = render.DecodeJSON(r.Body, &group)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	group.ID = groupID
	group.Name = name
	group.UserSettings.FsConfig.SetEmptySecretsIfNil()
	updateEncryptedSecrets(&group.UserSettings.FsConfig, currentS3AccessSecret, currentAzAccountKey, currentAzSASUrl,
		currentGCSCredentials, currentCryptoPassphrase, currentSFTPPassword, currentSFTPKey, currentSFTPKeyPassphrase,
		currentHTTPPassword, currentHTTPAPIKey)
	err = dataprovider.UpdateGroup(&group, users, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Group updated", http.StatusOK)
}

func renderGroup(w http.ResponseWriter, r *http.Request, name string, status int) {
	group, err := dataprovider.GroupExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	group.PrepareForRendering()
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), group)
	} else {
		render.JSON(w, r, group)
	}
}

func getGroupByName(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	renderGroup(w, r, name, http.StatusOK)
}

func deleteGroup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	err = dataprovider.DeleteGroup(name, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Group deleted", http.StatusOK)
}
