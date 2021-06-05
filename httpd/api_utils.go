package httpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/klauspost/compress/zip"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
)

type pwdChange struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
	var errorString string
	if err != nil {
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
	if _, ok := err.(*dataprovider.ValidationError); ok {
		return http.StatusBadRequest
	}
	if _, ok := err.(*dataprovider.MethodDisabledError); ok {
		return http.StatusForbidden
	}
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		return http.StatusNotFound
	}
	if os.IsNotExist(err) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func getMappedStatusCode(err error) int {
	var statusCode int
	switch err {
	case os.ErrPermission:
		statusCode = http.StatusForbidden
	case os.ErrNotExist:
		statusCode = http.StatusNotFound
	default:
		statusCode = http.StatusInternalServerError
	}
	return statusCode
}

func handleCloseConnection(w http.ResponseWriter, r *http.Request) {
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

func renderCompressedFiles(w http.ResponseWriter, conn *Connection, baseDir string, files []string) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Accept-Ranges", "none")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.WriteHeader(http.StatusOK)

	wr := zip.NewWriter(w)

	for _, file := range files {
		fullPath := path.Join(baseDir, file)
		if err := addZipEntry(wr, conn, fullPath, baseDir); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if err := wr.Close(); err != nil {
		conn.Log(logger.LevelWarn, "unable to close zip file: %v", err)
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
			fullPath := path.Join(entryPath, info.Name())
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

func downloadFile(w http.ResponseWriter, r *http.Request, connection *Connection, name string, info os.FileInfo) (int, error) {
	var err error
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
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%#v", path.Base(name)))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(responseStatus)
	if r.Method != http.MethodHead {
		io.CopyN(w, reader, size) //nolint:errcheck
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

func updateLoginMetrics(user *dataprovider.User, ip string, err error) {
	metrics.AddLoginAttempt(dataprovider.LoginMethodPassword)
	if err != nil && err != common.ErrInternalFailure {
		logger.ConnectionFailedLog(user.Username, ip, dataprovider.LoginMethodPassword, common.ProtocolHTTP, err.Error())
		event := common.HostEventLoginFailed
		if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
			event = common.HostEventUserNotFound
		}
		common.AddDefenderEvent(ip, event)
	}
	metrics.AddLoginResult(dataprovider.LoginMethodPassword, err)
	dataprovider.ExecutePostLoginHook(user, dataprovider.LoginMethodPassword, ip, common.ProtocolHTTP, err)
}

func checkHTTPClientUser(user *dataprovider.User, r *http.Request, connectionID string) error {
	if utils.IsStringInSlice(common.ProtocolHTTP, user.Filters.DeniedProtocols) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, protocol HTTP is not allowed", user.Username)
		return fmt.Errorf("protocol HTTP is not allowed for user %#v", user.Username)
	}
	if !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, nil) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, password login method is not allowed", user.Username)
		return fmt.Errorf("login method password is not allowed for user %#v", user.Username)
	}
	if user.MaxSessions > 0 {
		activeSessions := common.Connections.GetActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Debug(logSender, connectionID, "authentication refused for user: %#v, too many open sessions: %v/%v", user.Username,
				activeSessions, user.MaxSessions)
			return fmt.Errorf("too many open sessions: %v", activeSessions)
		}
	}
	if !user.IsLoginFromAddrAllowed(r.RemoteAddr) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, remote address is not allowed: %v", user.Username, r.RemoteAddr)
		return fmt.Errorf("login for user %#v is not allowed from this address: %v", user.Username, r.RemoteAddr)
	}
	return nil
}
