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
	"strconv"
	"time"

	"github.com/go-chi/render"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func getUsers(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	users, err := dataprovider.GetUsers(limit, offset, order, claims.Role)
	if err == nil {
		render.JSON(w, r, users)
	} else {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	}
}

func getUserByUsername(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	username := getURLParam(r, "username")
	renderUser(w, r, username, &claims, http.StatusOK)
}

func renderUser(w http.ResponseWriter, r *http.Request, username string, claims *jwtTokenClaims, status int) {
	user, err := dataprovider.UserExists(username, claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if hideConfidentialData(claims, r) {
		user.PrepareForRendering()
	}
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), user)
	} else {
		render.JSON(w, r, user)
	}
}

func addUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	var user dataprovider.User
	if admin.Filters.Preferences.DefaultUsersExpiration > 0 {
		user.ExpirationDate = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(admin.Filters.Preferences.DefaultUsersExpiration)))
	}
	err = render.DecodeJSON(r.Body, &user)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if claims.Role != "" {
		user.Role = claims.Role
	}
	user.LastPasswordChange = 0
	user.Filters.RecoveryCodes = nil
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled: false,
	}
	err = dataprovider.AddUser(&user, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%s/%s", userPath, url.PathEscape(user.Username)))
	renderUser(w, r, user.Username, &claims, http.StatusCreated)
}

func disableUser2FA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username, claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !user.Filters.TOTPConfig.Enabled {
		sendAPIResponse(w, r, nil, "two-factor authentication is not enabled", http.StatusBadRequest)
		return
	}
	user.Filters.RecoveryCodes = nil
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled: false,
	}
	if err := dataprovider.UpdateUser(&user, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "2FA disabled", http.StatusOK)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	username := getURLParam(r, "username")
	disconnect := 0
	if _, ok := r.URL.Query()["disconnect"]; ok {
		disconnect, err = strconv.Atoi(r.URL.Query().Get("disconnect"))
		if err != nil {
			err = fmt.Errorf("invalid disconnect parameter: %v", err)
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	user, err := dataprovider.UserExists(username, claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	var updatedUser dataprovider.User
	updatedUser.Password = user.Password
	err = render.DecodeJSON(r.Body, &updatedUser)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	updatedUser.ID = user.ID
	updatedUser.Username = user.Username
	updatedUser.Filters.RecoveryCodes = user.Filters.RecoveryCodes
	updatedUser.Filters.TOTPConfig = user.Filters.TOTPConfig
	updatedUser.LastPasswordChange = user.LastPasswordChange
	updatedUser.SetEmptySecretsIfNil()
	updateEncryptedSecrets(&updatedUser.FsConfig, user.FsConfig.S3Config.AccessSecret, user.FsConfig.AzBlobConfig.AccountKey,
		user.FsConfig.AzBlobConfig.SASURL, user.FsConfig.GCSConfig.Credentials, user.FsConfig.CryptConfig.Passphrase,
		user.FsConfig.SFTPConfig.Password, user.FsConfig.SFTPConfig.PrivateKey, user.FsConfig.SFTPConfig.KeyPassphrase,
		user.FsConfig.HTTPConfig.Password, user.FsConfig.HTTPConfig.APIKey)
	if claims.Role != "" {
		updatedUser.Role = claims.Role
	}
	err = dataprovider.UpdateUser(&updatedUser, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "User updated", http.StatusOK)
	if disconnect == 1 {
		disconnectUser(user.Username, claims.Username, claims.Role)
	}
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	username := getURLParam(r, "username")
	err = dataprovider.DeleteUser(username, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "User deleted", http.StatusOK)
	disconnectUser(dataprovider.ConvertName(username), claims.Username, claims.Role)
}

func forgotUserPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	if !smtp.IsEnabled() {
		sendAPIResponse(w, r, nil, "No SMTP configuration", http.StatusBadRequest)
		return
	}

	err := handleForgotPassword(r, getURLParam(r, "username"), false)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	sendAPIResponse(w, r, err, "Check your email for the confirmation code", http.StatusOK)
}

func resetUserPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req pwdReset
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	_, _, err = handleResetPassword(r, req.Code, req.Password, req.Password, false)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Password reset successful", http.StatusOK)
}

func disconnectUser(username, admin, role string) {
	for _, stat := range common.Connections.GetStats("") {
		if stat.Username == username {
			common.Connections.Close(stat.ConnectionID, "")
		}
	}
	for _, stat := range getNodesConnections(admin, role) {
		if stat.Username == username {
			n, err := dataprovider.GetNodeByName(stat.Node)
			if err != nil {
				logger.Warn(logSender, "", "unable to disconnect user %q, error getting node %q: %v", username, stat.Node, err)
				continue
			}
			if err := n.SendDeleteRequest(admin, role, fmt.Sprintf("%s/%s", activeConnectionsPath, stat.ConnectionID)); err != nil {
				logger.Warn(logSender, "", "unable to disconnect user %q from node %q, error: %v", username, n.Name, err)
			}
		}
	}
}

func updateEncryptedSecrets(fsConfig *vfs.Filesystem, currentS3AccessSecret, currentAzAccountKey, currentAzSASUrl,
	currentGCSCredentials, currentCryptoPassphrase, currentSFTPPassword, currentSFTPKey, currentSFTPKeyPassphrase,
	currentHTTPPassword, currentHTTPAPIKey *kms.Secret) {
	// we use the new access secret if plain or empty, otherwise the old value
	switch fsConfig.Provider {
	case sdk.S3FilesystemProvider:
		if fsConfig.S3Config.AccessSecret.IsNotPlainAndNotEmpty() {
			fsConfig.S3Config.AccessSecret = currentS3AccessSecret
		}
	case sdk.AzureBlobFilesystemProvider:
		if fsConfig.AzBlobConfig.AccountKey.IsNotPlainAndNotEmpty() {
			fsConfig.AzBlobConfig.AccountKey = currentAzAccountKey
		}
		if fsConfig.AzBlobConfig.SASURL.IsNotPlainAndNotEmpty() {
			fsConfig.AzBlobConfig.SASURL = currentAzSASUrl
		}
	case sdk.GCSFilesystemProvider:
		// for GCS credentials will be cleared if we enable automatic credentials
		// so keep the old credentials here if no new credentials are provided
		if !fsConfig.GCSConfig.Credentials.IsPlain() {
			fsConfig.GCSConfig.Credentials = currentGCSCredentials
		}
	case sdk.CryptedFilesystemProvider:
		if fsConfig.CryptConfig.Passphrase.IsNotPlainAndNotEmpty() {
			fsConfig.CryptConfig.Passphrase = currentCryptoPassphrase
		}
	case sdk.SFTPFilesystemProvider:
		updateSFTPFsEncryptedSecrets(fsConfig, currentSFTPPassword, currentSFTPKey, currentSFTPKeyPassphrase)
	case sdk.HTTPFilesystemProvider:
		updateHTTPFsEncryptedSecrets(fsConfig, currentHTTPPassword, currentHTTPAPIKey)
	}
}

func updateSFTPFsEncryptedSecrets(fsConfig *vfs.Filesystem, currentSFTPPassword, currentSFTPKey,
	currentSFTPKeyPassphrase *kms.Secret,
) {
	if fsConfig.SFTPConfig.Password.IsNotPlainAndNotEmpty() {
		fsConfig.SFTPConfig.Password = currentSFTPPassword
	}
	if fsConfig.SFTPConfig.PrivateKey.IsNotPlainAndNotEmpty() {
		fsConfig.SFTPConfig.PrivateKey = currentSFTPKey
	}
	if fsConfig.SFTPConfig.KeyPassphrase.IsNotPlainAndNotEmpty() {
		fsConfig.SFTPConfig.KeyPassphrase = currentSFTPKeyPassphrase
	}
}

func updateHTTPFsEncryptedSecrets(fsConfig *vfs.Filesystem, currentHTTPPassword, currentHTTPAPIKey *kms.Secret) {
	if fsConfig.HTTPConfig.Password.IsNotPlainAndNotEmpty() {
		fsConfig.HTTPConfig.Password = currentHTTPPassword
	}
	if fsConfig.HTTPConfig.APIKey.IsNotPlainAndNotEmpty() {
		fsConfig.HTTPConfig.APIKey = currentHTTPAPIKey
	}
}
