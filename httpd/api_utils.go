package httpd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/klauspost/compress/zip"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
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
	if os.IsNotExist(err) {
		return http.StatusBadRequest
	}
	if os.IsPermission(err) || errors.Is(err, dataprovider.ErrLoginNotAllowedFromIP) {
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

	return util.RemoveDuplicates(result)
}

func getBoolQueryParam(r *http.Request, param string) bool {
	return r.URL.Query().Get(param) == "true"
}

func handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connectionID := getURLParam(r, "connectionID")
	if connectionID == "" {
		sendAPIResponse(w, r, nil, "connectionID is mandatory", http.StatusBadRequest)
		return
	}
	if common.Connections.Close(connectionID) {
		sendAPIResponse(w, r, nil, "Connection closed", http.StatusOK)
	} else {
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
	}
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
	results := make([]map[string]interface{}, 0, len(contents))
	for _, info := range contents {
		if omitNonRegularFiles && !info.Mode().IsDir() && !info.Mode().IsRegular() {
			continue
		}
		res := make(map[string]interface{})
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

func renderCompressedFiles(w http.ResponseWriter, conn *Connection, baseDir string, files []string,
	share *dataprovider.Share,
) {
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
	if info.IsDir() {
		_, err := wr.Create(getZipEntryName(entryPath, baseDir) + "/")
		if err != nil {
			conn.Log(logger.LevelDebug, "unable to create zip entry %#v: %v", entryPath, err)
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
		conn.Log(logger.LevelDebug, "skipping zip entry for non regular file %#v", entryPath)
		return nil
	}
	reader, err := conn.getFileReader(entryPath, 0, http.MethodGet)
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to add zip entry %#v, cannot open file: %v", entryPath, err)
		return err
	}
	defer reader.Close()

	f, err := wr.Create(getZipEntryName(entryPath, baseDir))
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to create zip entry %#v: %v", entryPath, err)
		return err
	}
	_, err = io.Copy(f, reader)
	return err
}

func getZipEntryName(entryPath, baseDir string) string {
	entryPath = strings.TrimPrefix(entryPath, baseDir)
	return strings.TrimPrefix(entryPath, "/")
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
	if modtime.Add(60 * time.Second).Before(t) {
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
			// start cannit be < 0 here, we did end = size -1 above
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

func checkHTTPClientUser(user *dataprovider.User, r *http.Request, connectionID string) error {
	if util.IsStringInSlice(common.ProtocolHTTP, user.Filters.DeniedProtocols) {
		logger.Info(logSender, connectionID, "cannot login user %#v, protocol HTTP is not allowed", user.Username)
		return fmt.Errorf("protocol HTTP is not allowed for user %#v", user.Username)
	}
	if !isLoggedInWithOIDC(r) && !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolHTTP, nil) {
		logger.Info(logSender, connectionID, "cannot login user %#v, password login method is not allowed", user.Username)
		return fmt.Errorf("login method password is not allowed for user %#v", user.Username)
	}
	if user.MaxSessions > 0 {
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
		return util.NewValidationError("Username is mandatory")
	}
	if isAdmin {
		admin, err = dataprovider.AdminExists(username)
		email = admin.Email
		subject = fmt.Sprintf("Email Verification Code for admin %#v", username)
	} else {
		user, err = dataprovider.UserExists(username)
		email = user.Email
		subject = fmt.Sprintf("Email Verification Code for user %#v", username)
		if err == nil {
			if !isUserAllowedToResetPassword(r, &user) {
				return util.NewValidationError("You are not allowed to reset your password")
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
	if err := smtp.SendEmail(email, subject, body.String(), smtp.EmailContentTypeTextHTML); err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "unable to send password reset code via email: %v, elapsed: %v",
			err, time.Since(startTime))
		return util.NewGenericError(fmt.Sprintf("Unable to send confirmation code via email: %v", err))
	}
	logger.Debug(logSender, middleware.GetReqID(r.Context()), "reset code sent via email to %#v, email: %#v, is admin? %v, elapsed: %v",
		username, email, isAdmin, time.Since(startTime))
	resetCodes.Store(c.Code, c)
	return nil
}

func handleResetPassword(r *http.Request, code, newPassword string, isAdmin bool) (
	*dataprovider.Admin, *dataprovider.User, error,
) {
	var admin dataprovider.Admin
	var user dataprovider.User
	var err error

	if newPassword == "" {
		return &admin, &user, util.NewValidationError("Please set a password")
	}
	if code == "" {
		return &admin, &user, util.NewValidationError("Please set a confirmation code")
	}
	c, ok := resetCodes.Load(code)
	if !ok {
		return &admin, &user, util.NewValidationError("Confirmation code not found")
	}
	resetCode := c.(*resetCode)
	if resetCode.IsAdmin != isAdmin {
		return &admin, &user, util.NewValidationError("Invalid confirmation code")
	}
	if isAdmin {
		admin, err = dataprovider.AdminExists(resetCode.Username)
		if err != nil {
			return &admin, &user, util.NewValidationError("Unable to associate the confirmation code with an existing admin")
		}
		admin.Password = newPassword
		err = dataprovider.UpdateAdmin(&admin, admin.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
		if err != nil {
			return &admin, &user, util.NewGenericError(fmt.Sprintf("Unable to set the new password: %v", err))
		}
	} else {
		user, err = dataprovider.UserExists(resetCode.Username)
		if err != nil {
			return &admin, &user, util.NewValidationError("Unable to associate the confirmation code with an existing user")
		}
		if err == nil {
			if !isUserAllowedToResetPassword(r, &user) {
				return &admin, &user, util.NewValidationError("You are not allowed to reset your password")
			}
		}
		user.Password = newPassword
		err = dataprovider.UpdateUser(&user, user.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
		if err != nil {
			return &admin, &user, util.NewGenericError(fmt.Sprintf("Unable to set the new password: %v", err))
		}
	}
	resetCodes.Delete(code)
	return &admin, &user, nil
}

func isUserAllowedToResetPassword(r *http.Request, user *dataprovider.User) bool {
	if !user.CanResetPassword() {
		return false
	}
	if util.IsStringInSlice(common.ProtocolHTTP, user.Filters.DeniedProtocols) {
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
