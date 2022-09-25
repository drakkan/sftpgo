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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/klauspost/compress/zip"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

type pwdChange struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type pwdReset struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

type baseProfile struct {
	Email           string `json:"email,omitempty"`
	Description     string `json:"description,omitempty"`
	AllowAPIKeyAuth bool   `json:"allow_api_key_auth"`
}

type adminProfile struct {
	baseProfile
}

type userProfile struct {
	baseProfile
	PublicKeys []string `json:"public_keys,omitempty"`
}

func sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
	var errorString string
	if _, ok := err.(*util.RecordNotFoundError); ok {
		errorString = http.StatusText(http.StatusNotFound)
	} else if err != nil {
		errorString = err.Error()
	}
	resp := apiResponse{
		Error:   errorString,
		Message: message,
	}
	ctx := context.WithValue(r.Context(), render.StatusCtxKey, code)
	render.JSON(w, r.WithContext(ctx), resp)
}

func getRespStatus(err error) int {
	if _, ok := err.(*util.ValidationError); ok {
		return http.StatusBadRequest
	}
	if _, ok := err.(*util.MethodDisabledError); ok {
		return http.StatusForbidden
	}
	if _, ok := err.(*util.RecordNotFoundError); ok {
		return http.StatusNotFound
	}
	if errors.Is(err, fs.ErrNotExist) {
		return http.StatusBadRequest
	}
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, dataprovider.ErrLoginNotAllowedFromIP) {
		return http.StatusForbidden
	}
	if errors.Is(err, plugin.ErrNoSearcher) || errors.Is(err, dataprovider.ErrNotImplemented) {
		return http.StatusNotImplemented
	}
	return http.StatusInternalServerError
}

// mappig between fs errors for HTTP protocol and HTTP response status codes
func getMappedStatusCode(err error) int {
	var statusCode int
	switch {
	case errors.Is(err, os.ErrPermission):
		statusCode = http.StatusForbidden
	case errors.Is(err, common.ErrReadQuotaExceeded):
		statusCode = http.StatusForbidden
	case errors.Is(err, os.ErrNotExist):
		statusCode = http.StatusNotFound
	case errors.Is(err, common.ErrQuotaExceeded):
		statusCode = http.StatusRequestEntityTooLarge
	case errors.Is(err, common.ErrOpUnsupported):
		statusCode = http.StatusBadRequest
	default:
		statusCode = http.StatusInternalServerError
	}
	return statusCode
}

func getURLParam(r *http.Request, key string) string {
	v := chi.URLParam(r, key)
	unescaped, err := url.PathUnescape(v)
	if err != nil {
		return v
	}
	return unescaped
}

func getCommaSeparatedQueryParam(r *http.Request, key string) []string {
	var result []string

	for _, val := range strings.Split(r.URL.Query().Get(key), ",") {
		val = strings.TrimSpace(val)
		if val != "" {
			result = append(result, val)
		}
	}

	return util.RemoveDuplicates(result, false)
}

func getBoolQueryParam(r *http.Request, param string) bool {
	return r.URL.Query().Get(param) == "true"
}

func getActiveConnections(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	stats := common.Connections.GetStats()
	if claims.NodeID == "" {
		stats = append(stats, getNodesConnections()...)
	}
	render.JSON(w, r, stats)
}

func handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connectionID := getURLParam(r, "connectionID")
	if connectionID == "" {
		sendAPIResponse(w, r, nil, "connectionID is mandatory", http.StatusBadRequest)
		return
	}
	node := r.URL.Query().Get("node")
	if node == "" || node == dataprovider.GetNodeName() {
		if common.Connections.Close(connectionID) {
			sendAPIResponse(w, r, nil, "Connection closed", http.StatusOK)
		} else {
			sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
		}
		return
	}
	n, err := dataprovider.GetNodeByName(node)
	if err != nil {
		logger.Warn(logSender, "", "unable to get node with name %q: %v", node, err)
		status := getRespStatus(err)
		sendAPIResponse(w, r, nil, http.StatusText(status), status)
		return
	}
	if err := n.SendDeleteRequest(fmt.Sprintf("%s/%s", activeConnectionsPath, connectionID)); err != nil {
		logger.Warn(logSender, "", "unable to delete connection id %q from node %q: %v", connectionID, n.Name, err)
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
		return
	}
	sendAPIResponse(w, r, nil, "Connection closed", http.StatusOK)
}

// getNodesConnections returns the active connections from other nodes.
// Errors are silently ignored
func getNodesConnections() []common.ConnectionStatus {
	nodes, err := dataprovider.GetNodes()
	if err != nil || len(nodes) == 0 {
		return nil
	}
	var results []common.ConnectionStatus
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, n := range nodes {
		wg.Add(1)

		go func(node dataprovider.Node) {
			defer wg.Done()

			var stats []common.ConnectionStatus
			if err := node.SendGetRequest(activeConnectionsPath, &stats); err != nil {
				logger.Warn(logSender, "", "unable to get connections from node %s: %v", node.Name, err)
				return
			}

			mu.Lock()
			results = append(results, stats...)
			mu.Unlock()
		}(n)
	}
	wg.Wait()

	return results
}

func getSearchFilters(w http.ResponseWriter, r *http.Request) (int, int, string, error) {
	var err error
	limit := 100
	offset := 0
	order := dataprovider.OrderASC
	if _, ok := r.URL.Query()["limit"]; ok {
		limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			err = errors.New("invalid limit")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return limit, offset, order, err
		}
		if limit > 500 {
			limit = 500
		}
	}
	if _, ok := r.URL.Query()["offset"]; ok {
		offset, err = strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			err = errors.New("invalid offset")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return limit, offset, order, err
		}
	}
	if _, ok := r.URL.Query()["order"]; ok {
		order = r.URL.Query().Get("order")
		if order != dataprovider.OrderASC && order != dataprovider.OrderDESC {
			err = errors.New("invalid order")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return limit, offset, order, err
		}
	}

	return limit, offset, order, err
}

func renderAPIDirContents(w http.ResponseWriter, r *http.Request, contents []os.FileInfo, omitNonRegularFiles bool) {
	results := make([]map[string]any, 0, len(contents))
	for _, info := range contents {
		if omitNonRegularFiles && !info.Mode().IsDir() && !info.Mode().IsRegular() {
			continue
		}
		res := make(map[string]any)
		res["name"] = info.Name()
		if info.Mode().IsRegular() {
			res["size"] = info.Size()
		}
		res["mode"] = info.Mode()
		res["last_modified"] = info.ModTime().UTC().Format(time.RFC3339)
		results = append(results, res)
	}

	render.JSON(w, r, results)
}

func getCompressedFileName(username string, files []string) string {
	if len(files) == 1 {
		name := path.Base(files[0])
		return fmt.Sprintf("%s-%s.zip", username, strings.TrimSuffix(name, path.Ext(name)))
	}
	return fmt.Sprintf("%s-download.zip", username)
}

func renderCompressedFiles(w http.ResponseWriter, conn *Connection, baseDir string, files []string,
	share *dataprovider.Share,
) {
	conn.User.CheckFsRoot(conn.ID) //nolint:errcheck
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Accept-Ranges", "none")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.WriteHeader(http.StatusOK)

	wr := zip.NewWriter(w)

	for _, file := range files {
		fullPath := util.CleanPath(path.Join(baseDir, file))
		if err := addZipEntry(wr, conn, fullPath, baseDir); err != nil {
			if share != nil {
				dataprovider.UpdateShareLastUse(share, -1) //nolint:errcheck
			}
			panic(http.ErrAbortHandler)
		}
	}
	if err := wr.Close(); err != nil {
		conn.Log(logger.LevelError, "unable to close zip file: %v", err)
		if share != nil {
			dataprovider.UpdateShareLastUse(share, -1) //nolint:errcheck
		}
		panic(http.ErrAbortHandler)
	}
}

func addZipEntry(wr *zip.Writer, conn *Connection, entryPath, baseDir string) error {
	info, err := conn.Stat(entryPath, 1)
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to add zip entry %#v, stat error: %v", entryPath, err)
		return err
	}
	entryName, err := getZipEntryName(entryPath, baseDir)
	if err != nil {
		conn.Log(logger.LevelError, "unable to get zip entry name: %v", err)
		return err
	}
	if info.IsDir() {
		_, err = wr.CreateHeader(&zip.FileHeader{
			Name:     entryName + "/",
			Method:   zip.Deflate,
			Modified: info.ModTime(),
		})
		if err != nil {
			conn.Log(logger.LevelError, "unable to create zip entry %#v: %v", entryPath, err)
			return err
		}
		contents, err := conn.ReadDir(entryPath)
		if err != nil {
			conn.Log(logger.LevelDebug, "unable to add zip entry %#v, read dir error: %v", entryPath, err)
			return err
		}
		for _, info := range contents {
			fullPath := util.CleanPath(path.Join(entryPath, info.Name()))
			if err := addZipEntry(wr, conn, fullPath, baseDir); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		// we only allow regular files
		conn.Log(logger.LevelInfo, "skipping zip entry for non regular file %#v", entryPath)
		return nil
	}
	reader, err := conn.getFileReader(entryPath, 0, http.MethodGet)
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to add zip entry %#v, cannot open file: %v", entryPath, err)
		return err
	}
	defer reader.Close()

	f, err := wr.CreateHeader(&zip.FileHeader{
		Name:     entryName,
		Method:   zip.Deflate,
		Modified: info.ModTime(),
	})
	if err != nil {
		conn.Log(logger.LevelError, "unable to create zip entry %#v: %v", entryPath, err)
		return err
	}
	_, err = io.Copy(f, reader)
	return err
}

func getZipEntryName(entryPath, baseDir string) (string, error) {
	if !strings.HasPrefix(entryPath, baseDir) {
		return "", fmt.Errorf("entry path %q is outside base dir %q", entryPath, baseDir)
	}
	entryPath = strings.TrimPrefix(entryPath, baseDir)
	return strings.TrimPrefix(entryPath, "/"), nil
}

func checkDownloadFileFromShare(share *dataprovider.Share, info os.FileInfo) error {
	if share != nil && !info.Mode().IsRegular() {
		return util.NewValidationError("non regular files are not supported for shares")
	}
	return nil
}

func downloadFile(w http.ResponseWriter, r *http.Request, connection *Connection, name string,
	info os.FileInfo, inline bool, share *dataprovider.Share,
) (int, error) {
	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	err := checkDownloadFileFromShare(share, info)
	if err != nil {
		return http.StatusBadRequest, err
	}
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" && checkIfRange(r, info.ModTime()) == condFalse {
		rangeHeader = ""
	}
	offset := int64(0)
	size := info.Size()
	responseStatus := http.StatusOK
	if strings.HasPrefix(rangeHeader, "bytes=") {
		if strings.Contains(rangeHeader, ",") {
			return http.StatusRequestedRangeNotSatisfiable, fmt.Errorf("unsupported range %#v", rangeHeader)
		}
		offset, size, err = parseRangeRequest(rangeHeader[6:], size)
		if err != nil {
			return http.StatusRequestedRangeNotSatisfiable, err
		}
		responseStatus = http.StatusPartialContent
	}
	reader, err := connection.getFileReader(name, offset, r.Method)
	if err != nil {
		return getMappedStatusCode(err), fmt.Errorf("unable to read file %#v: %v", name, err)
	}
	defer reader.Close()

	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	if checkPreconditions(w, r, info.ModTime()) {
		return 0, fmt.Errorf("%v", http.StatusText(http.StatusPreconditionFailed))
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	if responseStatus == http.StatusPartialContent {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, info.Size()))
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Type", ctype)
	if !inline {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%#v", path.Base(name)))
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(responseStatus)
	if r.Method != http.MethodHead {
		_, err = io.CopyN(w, reader, size)
		if err != nil {
			if share != nil {
				dataprovider.UpdateShareLastUse(share, -1) //nolint:errcheck
			}
			connection.Log(logger.LevelDebug, "error reading file to download: %v", err)
			panic(http.ErrAbortHandler)
		}
	}
	return http.StatusOK, nil
}

func checkPreconditions(w http.ResponseWriter, r *http.Request, modtime time.Time) bool {
	if checkIfUnmodifiedSince(r, modtime) == condFalse {
		w.WriteHeader(http.StatusPreconditionFailed)
		return true
	}
	if checkIfModifiedSince(r, modtime) == condFalse {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	return false
}

func checkIfUnmodifiedSince(r *http.Request, modtime time.Time) condResult {
	ius := r.Header.Get("If-Unmodified-Since")
	if ius == "" || isZeroTime(modtime) {
		return condNone
	}
	t, err := http.ParseTime(ius)
	if err != nil {
		return condNone
	}

	// The Last-Modified header truncates sub-second precision so
	// the modtime needs to be truncated too.
	modtime = modtime.Truncate(time.Second)
	if modtime.Before(t) || modtime.Equal(t) {
		return condTrue
	}
	return condFalse
}

func checkIfModifiedSince(r *http.Request, modtime time.Time) condResult {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return condNone
	}
	ims := r.Header.Get("If-Modified-Since")
	if ims == "" || isZeroTime(modtime) {
		return condNone
	}
	t, err := http.ParseTime(ims)
	if err != nil {
		return condNone
	}
	// The Last-Modified header truncates sub-second precision so
	// the modtime needs to be truncated too.
	modtime = modtime.Truncate(time.Second)
	if modtime.Before(t) || modtime.Equal(t) {
		return condFalse
	}
	return condTrue
}

func checkIfRange(r *http.Request, modtime time.Time) condResult {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return condNone
	}
	ir := r.Header.Get("If-Range")
	if ir == "" {
		return condNone
	}
	if modtime.IsZero() {
		return condFalse
	}
	t, err := http.ParseTime(ir)
	if err != nil {
		return condFalse
	}
	if modtime.Unix() == t.Unix() {
		return condTrue
	}
	return condFalse
}

func parseRangeRequest(bytesRange string, size int64) (int64, int64, error) {
	var start, end int64
	var err error

	values := strings.Split(bytesRange, "-")
	if values[0] == "" {
		start = -1
	} else {
		start, err = strconv.ParseInt(values[0], 10, 64)
		if err != nil {
			return start, size, err
		}
	}
	if len(values) >= 2 {
		if values[1] != "" {
			end, err = strconv.ParseInt(values[1], 10, 64)
			if err != nil {
				return start, size, err
			}
			if end >= size {
				end = size - 1
			}
		}
	}
	if start == -1 && end == 0 {
		return 0, 0, fmt.Errorf("unsupported range %#v", bytesRange)
	}

	if end > 0 {
		if start == -1 {
			// we have something like -500
			start = size - end
			size = end
			// start cannot be < 0 here, we did end = size -1 above
		} else {
			// we have something like 500-600
			size = end - start + 1
			if size < 0 {
				return 0, 0, fmt.Errorf("unacceptable range %#v", bytesRange)
			}
		}
		return start, size, nil
	}
	// we have something like 500-
	size -= start
	if size < 0 {
		return 0, 0, fmt.Errorf("unacceptable range %#v", bytesRange)
	}
	return start, size, err
}

func updateLoginMetrics(user *dataprovider.User, loginMethod, ip string, err error) {
	metric.AddLoginAttempt(loginMethod)
	var protocol string
	switch loginMethod {
	case dataprovider.LoginMethodIDP:
		protocol = common.ProtocolOIDC
	default:
		protocol = common.ProtocolHTTP
	}
	if err != nil && err != common.ErrInternalFailure && err != common.ErrNoCredentials {
		logger.ConnectionFailedLog(user.Username, ip, loginMethod, protocol, err.Error())
		event := common.HostEventLoginFailed
		if _, ok := err.(*util.RecordNotFoundError); ok {
			event = common.HostEventUserNotFound
		}
		common.AddDefenderEvent(ip, event)
	}
	metric.AddLoginResult(loginMethod, err)
	dataprovider.ExecutePostLoginHook(user, loginMethod, ip, protocol, err)
}

func checkHTTPClientUser(user *dataprovider.User, r *http.Request, connectionID string, checkSessions bool) error {
	if util.Contains(user.Filters.DeniedProtocols, common.ProtocolHTTP) {
		logger.Info(logSender, connectionID, "cannot login user %#v, protocol HTTP is not allowed", user.Username)
		return fmt.Errorf("protocol HTTP is not allowed for user %#v", user.Username)
	}
	if !isLoggedInWithOIDC(r) && !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolHTTP, nil) {
		logger.Info(logSender, connectionID, "cannot login user %#v, password login method is not allowed", user.Username)
		return fmt.Errorf("login method password is not allowed for user %#v", user.Username)
	}
	if checkSessions && user.MaxSessions > 0 {
		activeSessions := common.Connections.GetActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Info(logSender, connectionID, "authentication refused for user: %#v, too many open sessions: %v/%v", user.Username,
				activeSessions, user.MaxSessions)
			return fmt.Errorf("too many open sessions: %v", activeSessions)
		}
	}
	if !user.IsLoginFromAddrAllowed(r.RemoteAddr) {
		logger.Info(logSender, connectionID, "cannot login user %#v, remote address is not allowed: %v", user.Username, r.RemoteAddr)
		return fmt.Errorf("login for user %#v is not allowed from this address: %v", user.Username, r.RemoteAddr)
	}
	return nil
}

func handleForgotPassword(r *http.Request, username string, isAdmin bool) error {
	var email, subject string
	var err error
	var admin dataprovider.Admin
	var user dataprovider.User

	if username == "" {
		return util.NewValidationError("username is mandatory")
	}
	if isAdmin {
		admin, err = dataprovider.AdminExists(username)
		email = admin.Email
		subject = fmt.Sprintf("Email Verification Code for admin %#v", username)
	} else {
		user, err = dataprovider.GetUserWithGroupSettings(username)
		email = user.Email
		subject = fmt.Sprintf("Email Verification Code for user %#v", username)
		if err == nil {
			if !isUserAllowedToResetPassword(r, &user) {
				return util.NewValidationError("you are not allowed to reset your password")
			}
		}
	}
	if err != nil {
		if _, ok := err.(*util.RecordNotFoundError); ok {
			logger.Debug(logSender, middleware.GetReqID(r.Context()), "username %#v does not exists, reset password request silently ignored, is admin? %v",
				username, isAdmin)
			return nil
		}
		return util.NewGenericError("Error retrieving your account, please try again later")
	}
	if email == "" {
		return util.NewValidationError("Your account does not have an email address, it is not possible to reset your password by sending an email verification code")
	}
	c := newResetCode(username, isAdmin)
	body := new(bytes.Buffer)
	data := make(map[string]string)
	data["Code"] = c.Code
	if err := smtp.RenderPasswordResetTemplate(body, data); err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "unable to render password reset template: %v", err)
		return util.NewGenericError("Unable to render password reset template")
	}
	startTime := time.Now()
	if err := smtp.SendEmail([]string{email}, subject, body.String(), smtp.EmailContentTypeTextHTML); err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "unable to send password reset code via email: %v, elapsed: %v",
			err, time.Since(startTime))
		return util.NewGenericError(fmt.Sprintf("Unable to send confirmation code via email: %v", err))
	}
	logger.Debug(logSender, middleware.GetReqID(r.Context()), "reset code sent via email to %#v, email: %#v, is admin? %v, elapsed: %v",
		username, email, isAdmin, time.Since(startTime))
	return resetCodesMgr.Add(c)
}

func handleResetPassword(r *http.Request, code, newPassword string, isAdmin bool) (
	*dataprovider.Admin, *dataprovider.User, error,
) {
	var admin dataprovider.Admin
	var user dataprovider.User
	var err error

	if newPassword == "" {
		return &admin, &user, util.NewValidationError("please set a password")
	}
	if code == "" {
		return &admin, &user, util.NewValidationError("please set a confirmation code")
	}
	resetCode, err := resetCodesMgr.Get(code)
	if err != nil {
		return &admin, &user, util.NewValidationError("confirmation code not found")
	}
	if resetCode.IsAdmin != isAdmin {
		return &admin, &user, util.NewValidationError("invalid confirmation code")
	}
	if isAdmin {
		admin, err = dataprovider.AdminExists(resetCode.Username)
		if err != nil {
			return &admin, &user, util.NewValidationError("unable to associate the confirmation code with an existing admin")
		}
		admin.Password = newPassword
		err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
		if err != nil {
			return &admin, &user, util.NewGenericError(fmt.Sprintf("unable to set the new password: %v", err))
		}
		err = resetCodesMgr.Delete(code)
		return &admin, &user, err
	}
	user, err = dataprovider.GetUserWithGroupSettings(resetCode.Username)
	if err != nil {
		return &admin, &user, util.NewValidationError("Unable to associate the confirmation code with an existing user")
	}
	if err == nil {
		if !isUserAllowedToResetPassword(r, &user) {
			return &admin, &user, util.NewValidationError("you are not allowed to reset your password")
		}
	}
	err = dataprovider.UpdateUserPassword(user.Username, newPassword, dataprovider.ActionExecutorSelf,
		util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err == nil {
		err = resetCodesMgr.Delete(code)
	}
	return &admin, &user, err
}

func isUserAllowedToResetPassword(r *http.Request, user *dataprovider.User) bool {
	if !user.CanResetPassword() {
		return false
	}
	if util.Contains(user.Filters.DeniedProtocols, common.ProtocolHTTP) {
		return false
	}
	if !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolHTTP, nil) {
		return false
	}
	if !user.IsLoginFromAddrAllowed(r.RemoteAddr) {
		return false
	}
	return true
}

func getProtocolFromRequest(r *http.Request) string {
	if isLoggedInWithOIDC(r) {
		return common.ProtocolOIDC
	}
	return common.ProtocolHTTP
}
