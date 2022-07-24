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

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
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
	err = dataprovider.AddFolder(&folder, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	renderFolder(w, r, folder.Name, http.StatusCreated)
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
	users := folder.Users
	groups := folder.Groups
	folderID := folder.ID
	name = folder.Name
	currentS3AccessSecret := folder.FsConfig.S3Config.AccessSecret
	currentAzAccountKey := folder.FsConfig.AzBlobConfig.AccountKey
	currentAzSASUrl := folder.FsConfig.AzBlobConfig.SASURL
	currentGCSCredentials := folder.FsConfig.GCSConfig.Credentials
	currentCryptoPassphrase := folder.FsConfig.CryptConfig.Passphrase
	currentSFTPPassword := folder.FsConfig.SFTPConfig.Password
	currentSFTPKey := folder.FsConfig.SFTPConfig.PrivateKey
	currentSFTPKeyPassphrase := folder.FsConfig.SFTPConfig.KeyPassphrase

	folder.FsConfig.S3Config = vfs.S3FsConfig{}
	folder.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
	folder.FsConfig.GCSConfig = vfs.GCSFsConfig{}
	folder.FsConfig.CryptConfig = vfs.CryptFsConfig{}
	folder.FsConfig.SFTPConfig = vfs.SFTPFsConfig{}
	err = render.DecodeJSON(r.Body, &folder)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	folder.ID = folderID
	folder.Name = name
	folder.FsConfig.SetEmptySecretsIfNil()
	updateEncryptedSecrets(&folder.FsConfig, currentS3AccessSecret, currentAzAccountKey, currentAzSASUrl, currentGCSCredentials,
		currentCryptoPassphrase, currentSFTPPassword, currentSFTPKey, currentSFTPKeyPassphrase)
	err = dataprovider.UpdateFolder(&folder, users, groups, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Folder updated", http.StatusOK)
}

func renderFolder(w http.ResponseWriter, r *http.Request, name string, status int) {
	folder, err := dataprovider.GetFolderByName(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	folder.PrepareForRendering()
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), folder)
	} else {
		render.JSON(w, r, folder)
	}
}

func getFolderByName(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	renderFolder(w, r, name, http.StatusOK)
}

func deleteFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	err = dataprovider.DeleteFolder(name, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Folder deleted", http.StatusOK)
}
