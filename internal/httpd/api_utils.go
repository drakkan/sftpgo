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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/klauspost/compress/zip"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
	AdditionalEmails []string `json:"additional_emails,omitempty"`
	PublicKeys       []string `json:"public_keys,omitempty"`
	TLSCerts         []string `json:"tls_certs,omitempty"`
}

func sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
	var errorString string
	if errors.Is(err, util.ErrNotFound) {
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
	if errors.Is(err, util.ErrValidation) {
		return http.StatusBadRequest
	}
	if errors.Is(err, util.ErrMethodDisabled) {
		return http.StatusForbidden
	}
	if errors.Is(err, util.ErrNotFound) {
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
	if errors.Is(err, dataprovider.ErrDuplicatedKey) || errors.Is(err, dataprovider.ErrForeignKeyViolated) {
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// mappig between fs errors for HTTP protocol and HTTP response status codes
func getMappedStatusCode(err error) int {
	var statusCode int
	switch {
	case errors.Is(err, fs.ErrPermission):
		statusCode = http.StatusForbidden
	case errors.Is(err, common.ErrReadQuotaExceeded):
		statusCode = http.StatusForbidden
	case errors.Is(err, fs.ErrNotExist):
		statusCode = http.StatusNotFound
	case errors.Is(err, common.ErrQuotaExceeded):
		statusCode = http.StatusRequestEntityTooLarge
	case errors.Is(err, common.ErrOpUnsupported):
		statusCode = http.StatusBadRequest
	default:
		if _, ok := err.(*http.MaxBytesError); ok {
			statusCode = http.StatusRequestEntityTooLarge
		} else {
			statusCode = http.StatusInternalServerError
		}
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

func getURLPath(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx != nil && rctx.RoutePath != "" {
		return rctx.RoutePath
	}
	return r.URL.Path
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
	stats := common.Connections.GetStats(claims.Role)
	if claims.NodeID == "" {
		stats = append(stats, getNodesConnections(claims.Username, claims.Role)...)
	}
	render.JSON(w, r, stats)
}

func handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	connectionID := getURLParam(r, "connectionID")
	if connectionID == "" {
		sendAPIResponse(w, r, nil, "connectionID is mandatory", http.StatusBadRequest)
		return
	}
	node := r.URL.Query().Get("node")
	if node == "" || node == dataprovider.GetNodeName() {
		if common.Connections.Close(connectionID, claims.Role) {
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
	if err := n.SendDeleteRequest(claims.Username, claims.Role, fmt.Sprintf("%s/%s", activeConnectionsPath, connectionID)); err != nil {
		logger.Warn(logSender, "", "unable to delete connection id %q from node %q: %v", connectionID, n.Name, err)
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
		return
	}
	sendAPIResponse(w, r, nil, "Connection closed", http.StatusOK)
}

// getNodesConnections returns the active connections from other nodes.
// Errors are silently ignored
func getNodesConnections(admin, role string) []common.ConnectionStatus {
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
			if err := node.SendGetRequest(admin, role, activeConnectionsPath, &stats); err != nil {
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

func renderAPIDirContents(w http.ResponseWriter, lister vfs.DirLister, omitNonRegularFiles bool) {
	defer lister.Close()

	dataGetter := func(limit, _ int) ([]byte, int, error) {
		contents, err := lister.Next(limit)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if err != nil {
			return nil, 0, err
		}
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
		data, err := json.Marshal(results)
		count := limit
		if len(results) == 0 {
			count = 0
		}
		return data, count, err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func streamData(w io.Writer, data []byte) {
	b := bytes.NewBuffer(data)
	_, err := io.CopyN(w, b, int64(len(data)))
	if err != nil {
		panic(http.ErrAbortHandler)
	}
}

func streamJSONArray(w http.ResponseWriter, chunkSize int, dataGetter func(limit, offset int) ([]byte, int, error)) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Accept-Ranges", "none")
	w.WriteHeader(http.StatusOK)

	streamData(w, []byte("["))
	offset := 0
	for {
		data, count, err := dataGetter(chunkSize, offset)
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		if count == 0 {
			break
		}
		if offset > 0 {
			streamData(w, []byte(","))
		}
		streamData(w, data[1:len(data)-1])
		if count < chunkSize {
			break
		}
		offset += count
	}
	streamData(w, []byte("]"))
}

func renderPNGImage(w http.ResponseWriter, r *http.Request, b []byte) {
	if len(b) == 0 {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, http.StatusNotFound)
		render.PlainText(w, r.WithContext(ctx), http.StatusText(http.StatusNotFound))
		return
	}
	w.Header().Set("Content-Type", "image/png")
	streamData(w, b)
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
		if err := addZipEntry(wr, conn, fullPath, baseDir, nil, 0); err != nil {
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

func addZipEntry(wr *zip.Writer, conn *Connection, entryPath, baseDir string, info os.FileInfo, recursion int) error {
	if recursion >= util.MaxRecursion {
		conn.Log(logger.LevelDebug, "unable to add zip entry %q, recursion too depth: %d", entryPath, recursion)
		return util.ErrRecursionTooDeep
	}
	recursion++
	var err error
	if info == nil {
		info, err = conn.Stat(entryPath, 1)
		if err != nil {
			conn.Log(logger.LevelDebug, "unable to add zip entry %q, stat error: %v", entryPath, err)
			return err
		}
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
			conn.Log(logger.LevelError, "unable to create zip entry %q: %v", entryPath, err)
			return err
		}
		lister, err := conn.ReadDir(entryPath)
		if err != nil {
			conn.Log(logger.LevelDebug, "unable to add zip entry %q, get list dir error: %v", entryPath, err)
			return err
		}
		defer lister.Close()

		for {
			contents, err := lister.Next(vfs.ListerBatchSize)
			finished := errors.Is(err, io.EOF)
			if err != nil && !finished {
				return err
			}
			for _, info := range contents {
				fullPath := util.CleanPath(path.Join(entryPath, info.Name()))
				if err := addZipEntry(wr, conn, fullPath, baseDir, info, recursion); err != nil {
					return err
				}
			}
			if finished {
				return nil
			}
		}
	}
	if !info.Mode().IsRegular() {
		// we only allow regular files
		conn.Log(logger.LevelInfo, "skipping zip entry for non regular file %q", entryPath)
		return nil
	}
	return addFileToZipEntry(wr, conn, entryPath, entryName, info)
}

func addFileToZipEntry(wr *zip.Writer, conn *Connection, entryPath, entryName string, info os.FileInfo) error {
	reader, err := conn.getFileReader(entryPath, 0, http.MethodGet)
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to add zip entry %q, cannot open file: %v", entryPath, err)
		return err
	}
	defer reader.Close()

	f, err := wr.CreateHeader(&zip.FileHeader{
		Name:     entryName,
		Method:   zip.Deflate,
		Modified: info.ModTime(),
	})
	if err != nil {
		conn.Log(logger.LevelError, "unable to create zip entry %q: %v", entryPath, err)
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
			return http.StatusRequestedRangeNotSatisfiable, fmt.Errorf("unsupported range %q", rangeHeader)
		}
		offset, size, err = parseRangeRequest(rangeHeader[6:], size)
		if err != nil {
			return http.StatusRequestedRangeNotSatisfiable, err
		}
		responseStatus = http.StatusPartialContent
	}
	reader, err := connection.getFileReader(name, offset, r.Method)
	if err != nil {
		return getMappedStatusCode(err), fmt.Errorf("unable to read file %q: %v", name, err)
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
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(name)))
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
		return 0, 0, fmt.Errorf("unsupported range %q", bytesRange)
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
				return 0, 0, fmt.Errorf("unacceptable range %q", bytesRange)
			}
		}
		return start, size, nil
	}
	// we have something like 500-
	size -= start
	if size < 0 {
		return 0, 0, fmt.Errorf("unacceptable range %q", bytesRange)
	}
	return start, size, err
}

func handleDefenderEventLoginFailed(ipAddr string, err error) error {
	event := common.HostEventLoginFailed
	if errors.Is(err, util.ErrNotFound) {
		event = common.HostEventUserNotFound
		err = dataprovider.ErrInvalidCredentials
	}
	common.AddDefenderEvent(ipAddr, common.ProtocolHTTP, event)
	common.DelayLogin(err)
	return err
}

func updateLoginMetrics(user *dataprovider.User, loginMethod, ip string, err error, r *http.Request) {
	metric.AddLoginAttempt(loginMethod)
	var protocol string
	switch loginMethod {
	case dataprovider.LoginMethodIDP:
		protocol = common.ProtocolOIDC
	default:
		protocol = common.ProtocolHTTP
	}
	if err == nil {
		logger.LoginLog(user.Username, ip, loginMethod, protocol, "", r.UserAgent(), r.TLS != nil, "")
		plugin.Handler.NotifyLogEvent(notifier.LogEventTypeLoginOK, protocol, user.Username, ip, "", nil)
		common.DelayLogin(nil)
	} else if err != common.ErrInternalFailure && err != common.ErrNoCredentials {
		logger.ConnectionFailedLog(user.Username, ip, loginMethod, protocol, err.Error())
		err = handleDefenderEventLoginFailed(ip, err)
		logEv := notifier.LogEventTypeLoginFailed
		if errors.Is(err, util.ErrNotFound) {
			logEv = notifier.LogEventTypeLoginNoUser
		}
		plugin.Handler.NotifyLogEvent(logEv, protocol, user.Username, ip, "", err)
	}
	metric.AddLoginResult(loginMethod, err)
	dataprovider.ExecutePostLoginHook(user, loginMethod, ip, protocol, err)
}

func checkHTTPClientUser(user *dataprovider.User, r *http.Request, connectionID string, checkSessions, isOIDCLogin bool) error {
	if slices.Contains(user.Filters.DeniedProtocols, common.ProtocolHTTP) {
		logger.Info(logSender, connectionID, "cannot login user %q, protocol HTTP is not allowed", user.Username)
		return util.NewI18nError(
			fmt.Errorf("protocol HTTP is not allowed for user %q", user.Username),
			util.I18nErrorProtocolForbidden,
		)
	}
	if !isLoggedInWithOIDC(r) && !isOIDCLogin && !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolHTTP) {
		logger.Info(logSender, connectionID, "cannot login user %q, password login method is not allowed", user.Username)
		return util.NewI18nError(
			fmt.Errorf("login method password is not allowed for user %q", user.Username),
			util.I18nErrorPwdLoginForbidden,
		)
	}
	if checkSessions && user.MaxSessions > 0 {
		activeSessions := common.Connections.GetActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Info(logSender, connectionID, "authentication refused for user: %q, too many open sessions: %v/%v", user.Username,
				activeSessions, user.MaxSessions)
			return util.NewI18nError(fmt.Errorf("too many open sessions: %v", activeSessions), util.I18nError429Message)
		}
	}
	if !user.IsLoginFromAddrAllowed(r.RemoteAddr) {
		logger.Info(logSender, connectionID, "cannot login user %q, remote address is not allowed: %v", user.Username, r.RemoteAddr)
		return util.NewI18nError(
			fmt.Errorf("login for user %q is not allowed from this address: %v", user.Username, r.RemoteAddr),
			util.I18nErrorIPForbidden,
		)
	}
	return nil
}

func getActiveAdmin(username, ipAddr string) (dataprovider.Admin, error) {
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		return admin, err
	}
	if err := admin.CanLogin(ipAddr); err != nil {
		return admin, util.NewRecordNotFoundError(fmt.Sprintf("admin %q cannot login: %v", username, err))
	}
	return admin, nil
}

func getActiveUser(username string, r *http.Request) (dataprovider.User, error) {
	user, err := dataprovider.GetUserWithGroupSettings(username, "")
	if err != nil {
		return user, err
	}
	if err := user.CheckLoginConditions(); err != nil {
		return user, util.NewRecordNotFoundError(fmt.Sprintf("user %q cannot login: %v", username, err))
	}
	if err := checkHTTPClientUser(&user, r, xid.New().String(), false, false); err != nil {
		return user, util.NewRecordNotFoundError(fmt.Sprintf("user %q cannot login: %v", username, err))
	}
	return user, nil
}

func handleForgotPassword(r *http.Request, username string, isAdmin bool) error {
	var emails []string
	var subject string
	var err error
	var admin dataprovider.Admin
	var user dataprovider.User

	if username == "" {
		return util.NewI18nError(util.NewValidationError("username is mandatory"), util.I18nErrorUsernameRequired)
	}
	if isAdmin {
		admin, err = getActiveAdmin(username, util.GetIPFromRemoteAddress(r.RemoteAddr))
		if admin.Email != "" {
			emails = []string{admin.Email}
		}
		subject = fmt.Sprintf("Email Verification Code for admin %q", username)
	} else {
		user, err = getActiveUser(username, r)
		emails = user.GetEmailAddresses()
		subject = fmt.Sprintf("Email Verification Code for user %q", username)
		if err == nil {
			if !isUserAllowedToResetPassword(r, &user) {
				return util.NewI18nError(
					util.NewValidationError("you are not allowed to reset your password"),
					util.I18nErrorPwdResetForbidded,
				)
			}
		}
	}
	if err != nil {
		if errors.Is(err, util.ErrNotFound) {
			handleDefenderEventLoginFailed(util.GetIPFromRemoteAddress(r.RemoteAddr), err) //nolint:errcheck
			logger.Debug(logSender, middleware.GetReqID(r.Context()),
				"username %q does not exists or cannot login, reset password request silently ignored, is admin? %t, err: %v",
				username, isAdmin, err)
			return nil
		}
		return util.NewI18nError(util.NewGenericError("Error retrieving your account, please try again later"), util.I18nErrorGetUser)
	}
	if len(emails) == 0 {
		return util.NewI18nError(
			util.NewValidationError("Your account does not have an email address, it is not possible to reset your password by sending an email verification code"),
			util.I18nErrorPwdResetNoEmail,
		)
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
	if err := smtp.SendEmail(emails, nil, subject, body.String(), smtp.EmailContentTypeTextHTML); err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "unable to send password reset code via email: %v, elapsed: %v",
			err, time.Since(startTime))
		return util.NewI18nError(
			util.NewGenericError(fmt.Sprintf("Error sending confirmation code via email: %v", err)),
			util.I18nErrorPwdResetSendEmail,
		)
	}
	logger.Debug(logSender, middleware.GetReqID(r.Context()), "reset code sent via email to %q, emails: %+v, is admin? %v, elapsed: %v",
		username, emails, isAdmin, time.Since(startTime))
	return resetCodesMgr.Add(c)
}

func handleResetPassword(r *http.Request, code, newPassword, confirmPassword string, isAdmin bool) (
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
	if newPassword != confirmPassword {
		return &admin, &user, util.NewI18nError(errors.New("the two password fields do not match"), util.I18nErrorChangePwdNoMatch)
	}

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	resetCode, err := resetCodesMgr.Get(code)
	if err != nil {
		handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
		return &admin, &user, util.NewValidationError("confirmation code not found")
	}
	if resetCode.IsAdmin != isAdmin {
		return &admin, &user, util.NewValidationError("invalid confirmation code")
	}
	if isAdmin {
		admin, err = getActiveAdmin(resetCode.Username, ipAddr)
		if err != nil {
			return &admin, &user, util.NewValidationError("unable to associate the confirmation code with an existing admin")
		}
		admin.Password = newPassword
		admin.Filters.RequirePasswordChange = false
		err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr, admin.Role)
		if err != nil {
			return &admin, &user, util.NewGenericError(fmt.Sprintf("unable to set the new password: %v", err))
		}
		err = resetCodesMgr.Delete(code)
		return &admin, &user, err
	}
	user, err = getActiveUser(resetCode.Username, r)
	if err != nil {
		return &admin, &user, util.NewValidationError("Unable to associate the confirmation code with an existing user")
	}
	if !isUserAllowedToResetPassword(r, &user) {
		return &admin, &user, util.NewI18nError(
			util.NewValidationError("you are not allowed to reset your password"),
			util.I18nErrorPwdResetForbidded,
		)
	}
	err = dataprovider.UpdateUserPassword(user.Username, newPassword, dataprovider.ActionExecutorSelf,
		util.GetIPFromRemoteAddress(r.RemoteAddr), user.Role)
	if err == nil {
		err = resetCodesMgr.Delete(code)
	}
	user.LastPasswordChange = util.GetTimeAsMsSinceEpoch(time.Now())
	user.Filters.RequirePasswordChange = false
	return &admin, &user, err
}

func isUserAllowedToResetPassword(r *http.Request, user *dataprovider.User) bool {
	if !user.CanResetPassword() {
		return false
	}
	if slices.Contains(user.Filters.DeniedProtocols, common.ProtocolHTTP) {
		return false
	}
	if !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolHTTP) {
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

func hideConfidentialData(claims *jwtTokenClaims, r *http.Request) bool {
	if !claims.hasPerm(dataprovider.PermAdminAny) {
		return true
	}
	return r.URL.Query().Get("confidential_data") != "1"
}
