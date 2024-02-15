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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	shares, err := dataprovider.GetShares(limit, offset, order, claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	render.JSON(w, r, shares)
}

func getShareByID(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	share.HideConfidentialData()

	render.JSON(w, r, share)
}

func addShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to retrieve your user", getRespStatus(err))
		return
	}
	var share dataprovider.Share
	if user.Filters.DefaultSharesExpiration > 0 {
		share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(user.Filters.DefaultSharesExpiration)))
	}
	err = render.DecodeJSON(r.Body, &share)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if err := user.CheckMaxShareExpiration(util.GetTimeFromMsecSinceEpoch(share.ExpiresAt)); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	share.ID = 0
	share.ShareID = util.GenerateUniqueID()
	share.LastUseAt = 0
	share.Username = claims.Username
	if share.Name == "" {
		share.Name = share.ShareID
	}
	if share.Password == "" {
		if util.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			sendAPIResponse(w, r, nil, "You are not authorized to share files/folders without a password",
				http.StatusForbidden)
			return
		}
	}
	err = dataprovider.AddShare(&share, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%s/%s", userSharesPath, url.PathEscape(share.ShareID)))
	w.Header().Add("X-Object-ID", share.ShareID)
	sendAPIResponse(w, r, nil, "Share created", http.StatusCreated)
}

func updateShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to retrieve your user", getRespStatus(err))
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	var updatedShare dataprovider.Share
	err = render.DecodeJSON(r.Body, &updatedShare)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	updatedShare.ShareID = shareID
	updatedShare.Username = claims.Username
	if updatedShare.Password == redactedSecret {
		updatedShare.Password = share.Password
	}
	if updatedShare.Password == "" {
		if util.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			sendAPIResponse(w, r, nil, "You are not authorized to share files/folders without a password",
				http.StatusForbidden)
			return
		}
	}
	if err := user.CheckMaxShareExpiration(util.GetTimeFromMsecSinceEpoch(updatedShare.ExpiresAt)); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	err = dataprovider.UpdateShare(&updatedShare, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Share updated", http.StatusOK)
}

func deleteShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	shareID := getURLParam(r, "id")
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	err = dataprovider.DeleteShare(shareID, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Share deleted", http.StatusOK)
}

func (s *httpdServer) readBrowsableShareContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	lister, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory lister", getMappedStatusCode(err))
		return
	}
	renderAPIDirContents(w, lister, true)
}

func (s *httpdServer) downloadBrowsableSharedFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	info, err := connection.Stat(name, 1)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to stat the requested file", getMappedStatusCode(err))
		return
	}
	if info.IsDir() {
		sendAPIResponse(w, r, nil, fmt.Sprintf("Please set the path to a valid file, %q is a directory", name),
			http.StatusBadRequest)
		return
	}

	inline := r.URL.Query().Get("inline") != ""
	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	if status, err := downloadFile(w, r, connection, name, info, inline, &share); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
		resp := apiResponse{
			Error:   err.Error(),
			Message: http.StatusText(status),
		}
		ctx := r.Context()
		if status != 0 {
			ctx = context.WithValue(ctx, render.StatusCtxKey, status)
		}
		render.JSON(w, r.WithContext(ctx), resp)
	}
}

func (s *httpdServer) downloadFromShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	compress := true
	var info os.FileInfo
	if len(share.Paths) == 1 {
		info, err = connection.Stat(share.Paths[0], 1)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if info.Mode().IsRegular() && r.URL.Query().Get("compress") == "false" {
			compress = false
		}
	}

	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	if compress {
		transferQuota := connection.GetTransferQuota()
		if !transferQuota.HasDownloadSpace() {
			err = connection.GetReadQuotaExceededError()
			connection.Log(logger.LevelInfo, "denying share read due to quota limits")
			sendAPIResponse(w, r, err, "", getMappedStatusCode(err))
			dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
			return
		}
		baseDir := "/"
		if info != nil && info.IsDir() {
			baseDir = share.Paths[0]
			share.Paths[0] = "/"
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"share-%v.zip\"", share.Name))
		renderCompressedFiles(w, connection, baseDir, share.Paths, &share)
		return
	}
	if status, err := downloadFile(w, r, connection, share.Paths[0], info, false, &share); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
		resp := apiResponse{
			Error:   err.Error(),
			Message: http.StatusText(status),
		}
		ctx := r.Context()
		if status != 0 {
			ctx = context.WithValue(ctx, render.StatusCtxKey, status)
		}
		render.JSON(w, r.WithContext(ctx), resp)
	}
}

func (s *httpdServer) uploadFileToShare(w http.ResponseWriter, r *http.Request) {
	if maxUploadFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize)
	}
	name := getURLParam(r, "name")
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeWrite, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	filePath := util.CleanPath(path.Join(share.Paths[0], name))
	expectedPrefix := share.Paths[0]
	if !strings.HasSuffix(expectedPrefix, "/") {
		expectedPrefix += "/"
	}
	if !strings.HasPrefix(filePath, expectedPrefix) {
		sendAPIResponse(w, r, err, "Uploading outside the share is not allowed", http.StatusForbidden)
		return
	}
	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck

	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())
	if err := doUploadFile(w, r, connection, filePath); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
	}
}

func (s *httpdServer) uploadFilesToShare(w http.ResponseWriter, r *http.Request) {
	if maxUploadFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize)
	}
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeWrite, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}

	transferQuota := connection.GetTransferQuota()
	if !transferQuota.HasUploadSpace() {
		connection.Log(logger.LevelInfo, "denying file write due to transfer quota limits")
		sendAPIResponse(w, r, common.ErrQuotaExceeded, "Denying file write due to transfer quota limits",
			http.StatusRequestEntityTooLarge)
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	t := newThrottledReader(r.Body, connection.User.UploadBandwidth, connection)
	r.Body = t
	err = r.ParseMultipartForm(maxMultipartMem)
	if err != nil {
		connection.RemoveTransfer(t)
		sendAPIResponse(w, r, err, "Unable to parse multipart form", http.StatusBadRequest)
		return
	}
	connection.RemoveTransfer(t)
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	files := r.MultipartForm.File["filenames"]
	if len(files) == 0 {
		sendAPIResponse(w, r, nil, "No files uploaded!", http.StatusBadRequest)
		return
	}
	if share.MaxTokens > 0 {
		if len(files) > (share.MaxTokens - share.UsedTokens) {
			sendAPIResponse(w, r, nil, "Allowed usage exceeded", http.StatusBadRequest)
			return
		}
	}
	dataprovider.UpdateShareLastUse(&share, len(files)) //nolint:errcheck

	numUploads := doUploadFiles(w, r, connection, share.Paths[0], files)
	if numUploads != len(files) {
		dataprovider.UpdateShareLastUse(&share, numUploads-len(files)) //nolint:errcheck
	}
}

func (s *httpdServer) checkWebClientShareCredentials(w http.ResponseWriter, r *http.Request, share *dataprovider.Share) error {
	doRedirect := func() {
		redirectURL := path.Join(webClientPubSharesPath, share.ShareID, fmt.Sprintf("login?next=%s", url.QueryEscape(r.RequestURI)))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}

	token, err := jwtauth.VerifyRequest(s.tokenAuth, r, jwtauth.TokenFromCookie)
	if err != nil || token == nil {
		doRedirect()
		return errInvalidToken
	}
	if !util.Contains(token.Audience(), tokenAudienceWebShare) {
		logger.Debug(logSender, "", "invalid token audience for share %q", share.ShareID)
		doRedirect()
		return errInvalidToken
	}
	if tokenValidationMode != tokenValidationNoIPMatch {
		ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
		if !util.Contains(token.Audience(), ipAddr) {
			logger.Debug(logSender, "", "token for share %q is not valid for the ip address %q", share.ShareID, ipAddr)
			doRedirect()
			return errInvalidToken
		}
	}
	ctx := jwtauth.NewContext(r.Context(), token, nil)
	claims, err := getTokenClaims(r.WithContext(ctx))
	if err != nil || claims.Username != share.ShareID {
		logger.Debug(logSender, "", "token not valid for share %q", share.ShareID)
		doRedirect()
		return errInvalidToken
	}
	return nil
}

func (s *httpdServer) checkPublicShare(w http.ResponseWriter, r *http.Request, validScopes []dataprovider.ShareScope,
) (dataprovider.Share, *Connection, error) {
	isWebClient := isWebClientRequest(r)
	renderError := func(err error, message string, statusCode int) {
		if isWebClient {
			s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, statusCode, err, message)
		} else {
			sendAPIResponse(w, r, err, message, statusCode)
		}
	}

	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, "")
	if err != nil {
		statusCode := getRespStatus(err)
		if statusCode == http.StatusNotFound {
			err = util.NewI18nError(errors.New("share does not exist"), util.I18nError404Message)
		}
		renderError(err, "", statusCode)
		return share, nil, err
	}
	if !util.Contains(validScopes, share.Scope) {
		err := errors.New("invalid share scope")
		renderError(util.NewI18nError(err, util.I18nErrorShareScope), "", http.StatusForbidden)
		return share, nil, err
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	ok, err := share.IsUsable(ipAddr)
	if !ok || err != nil {
		renderError(err, "", getRespStatus(err))
		return share, nil, err
	}
	if share.Password != "" {
		if isWebClient {
			if err := s.checkWebClientShareCredentials(w, r, &share); err != nil {
				handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
				return share, nil, dataprovider.ErrInvalidCredentials
			}
		} else {
			_, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
				renderError(dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return share, nil, dataprovider.ErrInvalidCredentials
			}
			match, err := share.CheckCredentials(password)
			if !match || err != nil {
				handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
				w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
				renderError(dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return share, nil, dataprovider.ErrInvalidCredentials
			}
		}
	}
	user, err := getUserForShare(share)
	if err != nil {
		renderError(err, "", getRespStatus(err))
		return share, nil, err
	}
	connID := xid.New().String()
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTPShare, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}

	return share, connection, nil
}

func getUserForShare(share dataprovider.Share) (dataprovider.User, error) {
	user, err := dataprovider.GetUserWithGroupSettings(share.Username, "")
	if err != nil {
		return user, err
	}
	if !user.CanManageShares() {
		return user, util.NewI18nError(util.NewRecordNotFoundError("this share does not exist"), util.I18nError404Message)
	}
	if share.Password == "" && util.Contains(user.Filters.WebClient, sdk.WebClientShareNoPasswordDisabled) {
		return user, util.NewI18nError(
			fmt.Errorf("sharing without a password was disabled: %w", os.ErrPermission),
			util.I18nError403Message,
		)
	}
	if user.MustSetSecondFactorForProtocol(common.ProtocolHTTP) {
		return user, util.NewI18nError(
			util.NewMethodDisabledError("two-factor authentication requirements not met"),
			util.I18nError403Message,
		)
	}
	return user, nil
}

func validateBrowsableShare(share dataprovider.Share, connection *Connection) error {
	if len(share.Paths) != 1 {
		return util.NewI18nError(
			util.NewValidationError("a share with multiple paths is not browsable"),
			util.I18nErrorShareBrowsePaths,
		)
	}
	basePath := share.Paths[0]
	info, err := connection.Stat(basePath, 0)
	if err != nil {
		return util.NewI18nError(
			fmt.Errorf("unable to check the share directory: %w", err),
			util.I18nErrorShareInvalidPath,
		)
	}
	if !info.IsDir() {
		return util.NewI18nError(
			util.NewValidationError("the shared object is not a directory and so it is not browsable"),
			util.I18nErrorShareBrowseNoDir,
		)
	}
	return nil
}

func getBrowsableSharedPath(shareBasePath string, r *http.Request) (string, error) {
	name := util.CleanPath(path.Join(shareBasePath, r.URL.Query().Get("path")))
	if shareBasePath == "/" {
		return name, nil
	}
	if name != shareBasePath && !strings.HasPrefix(name, shareBasePath+"/") {
		return "", util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("Invalid path %q", r.URL.Query().Get("path"))),
			util.I18nErrorPathInvalid,
		)
	}
	return name, nil
}
