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
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func getFolders(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	folders, err := dataprovider.GetFolders(limit, offset, order, false)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, folders)
}

func addFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	var folder vfs.BaseVirtualFolder
	err = render.DecodeJSON(r.Body, &folder)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if err := dataprovider.AddFolder(&folder, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%s/%s", folderPath, url.PathEscape(folder.Name)))
	renderFolder(w, r, folder.Name, &claims, http.StatusCreated)
}

func updateFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	var updatedFolder vfs.BaseVirtualFolder
	err = render.DecodeJSON(r.Body, &updatedFolder)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	updatedFolder.ID = folder.ID
	updatedFolder.Name = folder.Name
	updatedFolder.FsConfig.SetEmptySecretsIfNil()
	updateEncryptedSecrets(&updatedFolder.FsConfig, folder.FsConfig.S3Config.AccessSecret, folder.FsConfig.AzBlobConfig.AccountKey,
		folder.FsConfig.AzBlobConfig.SASURL, folder.FsConfig.GCSConfig.Credentials, folder.FsConfig.CryptConfig.Passphrase,
		folder.FsConfig.SFTPConfig.Password, folder.FsConfig.SFTPConfig.PrivateKey, folder.FsConfig.SFTPConfig.KeyPassphrase,
		folder.FsConfig.HTTPConfig.Password, folder.FsConfig.HTTPConfig.APIKey)

	err = dataprovider.UpdateFolder(&updatedFolder, folder.Users, folder.Groups, claims.Username,
		util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Folder updated", http.StatusOK)
}

func renderFolder(w http.ResponseWriter, r *http.Request, name string, claims *jwtTokenClaims, status int) {
	folder, err := dataprovider.GetFolderByName(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if hideConfidentialData(claims, r) {
		folder.PrepareForRendering()
	}
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), folder)
	} else {
		render.JSON(w, r, folder)
	}
}

func getFolderByName(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	renderFolder(w, r, name, &claims, http.StatusOK)
}

func deleteFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	err = dataprovider.DeleteFolder(name, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Folder deleted", http.StatusOK)
}
