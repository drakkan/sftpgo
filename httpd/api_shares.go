package httpd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/go-chi/render"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
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
	var share dataprovider.Share
	err = render.DecodeJSON(r.Body, &share)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
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
		if util.IsStringInSlice(sdk.WebClientShareNoPasswordDisabled, claims.Permissions) {
			sendAPIResponse(w, r, nil, "You are not authorized to share files/folders without a password",
				http.StatusForbidden)
			return
		}
	}
	err = dataprovider.AddShare(&share, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%v/%v", userSharesPath, share.ShareID))
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
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	oldPassword := share.Password
	err = render.DecodeJSON(r.Body, &share)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	share.ShareID = shareID
	share.Username = claims.Username
	if share.Password == redactedSecret {
		share.Password = oldPassword
	}
	if share.Password == "" {
		if util.IsStringInSlice(sdk.WebClientShareNoPasswordDisabled, claims.Permissions) {
			sendAPIResponse(w, r, nil, "You are not authorized to share files/folders without a password",
				http.StatusForbidden)
			return
		}
	}
	if err := dataprovider.UpdateShare(&share, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
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

	err = dataprovider.DeleteShare(shareID, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Share deleted", http.StatusOK)
}

func (s *httpdServer) readBrowsableShareContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share, connection, err := s.checkPublicShare(w, r, dataprovider.ShareScopeRead, false)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	name, err := getBrowsableSharedPath(share, r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}
	renderAPIDirContents(w, r, contents, true)
}

func (s *httpdServer) downloadBrowsableSharedFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share, connection, err := s.checkPublicShare(w, r, dataprovider.ShareScopeRead, false)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	name, err := getBrowsableSharedPath(share, r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	info, err := connection.Stat(name, 1)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to stat the requested file", getMappedStatusCode(err))
		return
	}
	if info.IsDir() {
		sendAPIResponse(w, r, nil, fmt.Sprintf("Please set the path to a valid file, %#v is a directory", name),
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
	share, connection, err := s.checkPublicShare(w, r, dataprovider.ShareScopeRead, false)
	if err != nil {
		return
	}

	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	compress := true
	var info os.FileInfo
	if len(share.Paths) == 1 && r.URL.Query().Get("compress") == "false" {
		info, err = connection.Stat(share.Paths[0], 1)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if info.Mode().IsRegular() {
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
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"share-%v.zip\"", share.ShareID))
		renderCompressedFiles(w, connection, "/", share.Paths, &share)
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
	share, connection, err := s.checkPublicShare(w, r, dataprovider.ShareScopeWrite, false)
	if err != nil {
		return
	}
	filePath := path.Join(share.Paths[0], name)
	if path.Dir(filePath) != share.Paths[0] {
		sendAPIResponse(w, r, err, "Uploading outside the share is not allowed", http.StatusForbidden)
		return
	}
	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck

	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())
	if err := doUploadFile(w, r, connection, filePath); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
	}
}

func (s *httpdServer) uploadFilesToShare(w http.ResponseWriter, r *http.Request) {
	if maxUploadFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize)
	}
	share, connection, err := s.checkPublicShare(w, r, dataprovider.ShareScopeWrite, false)
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

	common.Connections.Add(connection)
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

func (s *httpdServer) checkPublicShare(w http.ResponseWriter, r *http.Request, shareShope dataprovider.ShareScope,
	isWebClient bool,
) (dataprovider.Share, *Connection, error) {
	renderError := func(err error, message string, statusCode int) {
		if isWebClient {
			s.renderClientMessagePage(w, r, "Unable to access the share", message, statusCode, err, "")
		} else {
			sendAPIResponse(w, r, err, message, statusCode)
		}
	}

	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, "")
	if err != nil {
		statusCode := getRespStatus(err)
		if statusCode == http.StatusNotFound {
			err = errors.New("share does not exist")
		}
		renderError(err, "", statusCode)
		return share, nil, err
	}
	if share.Scope != shareShope {
		renderError(nil, "Invalid share scope", http.StatusForbidden)
		return share, nil, errors.New("invalid share scope")
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	ok, err := share.IsUsable(ipAddr)
	if !ok || err != nil {
		renderError(err, "", getRespStatus(err))
		return share, nil, err
	}
	if share.Password != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			renderError(dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return share, nil, dataprovider.ErrInvalidCredentials
		}
		match, err := share.CheckCredentials(username, password)
		if !match || err != nil {
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			renderError(dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return share, nil, dataprovider.ErrInvalidCredentials
		}
	}
	user, err := dataprovider.UserExists(share.Username)
	if err != nil {
		renderError(err, "", getRespStatus(err))
		return share, nil, err
	}
	if user.MustSetSecondFactorForProtocol(common.ProtocolHTTP) {
		err := util.NewMethodDisabledError("two-factor authentication requirements not met")
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

func validateBrowsableShare(share dataprovider.Share, connection *Connection) error {
	if len(share.Paths) != 1 {
		return util.NewValidationError("A share with multiple paths is not browsable")
	}
	basePath := share.Paths[0]
	info, err := connection.Stat(basePath, 0)
	if err != nil {
		return fmt.Errorf("unable to check the share directory: %w", err)
	}
	if !info.IsDir() {
		return util.NewValidationError("The shared object is not a directory and so it is not browsable")
	}
	return nil
}

func getBrowsableSharedPath(share dataprovider.Share, r *http.Request) (string, error) {
	name := util.CleanPath(path.Join(share.Paths[0], r.URL.Query().Get("path")))
	if share.Paths[0] == "/" {
		return name, nil
	}
	if name != share.Paths[0] && !strings.HasPrefix(name, share.Paths[0]+"/") {
		return "", util.NewValidationError(fmt.Sprintf("Invalid path %#v", r.URL.Query().Get("path")))
	}
	return name, nil
}
