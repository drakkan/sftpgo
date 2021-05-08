package httpd

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	templateClientDir          = "webclient"
	templateClientBase         = "base.html"
	templateClientLogin        = "login.html"
	templateClientFiles        = "files.html"
	templateClientMessage      = "message.html"
	templateClientCredentials  = "credentials.html"
	pageClientFilesTitle       = "My Files"
	pageClientCredentialsTitle = "Credentials"
)

// condResult is the result of an HTTP request precondition check.
// See https://tools.ietf.org/html/rfc7232 section 3.
type condResult int

const (
	condNone condResult = iota
	condTrue
	condFalse
)

var (
	clientTemplates = make(map[string]*template.Template)
	unixEpochTime   = time.Unix(0, 0)
)

// isZeroTime reports whether t is obviously unspecified (either zero or Unix()=0).
func isZeroTime(t time.Time) bool {
	return t.IsZero() || t.Equal(unixEpochTime)
}

type baseClientPage struct {
	Title            string
	CurrentURL       string
	FilesURL         string
	CredentialsURL   string
	StaticURL        string
	LogoutURL        string
	FilesTitle       string
	CredentialsTitle string
	Version          string
	CSRFToken        string
	LoggedUser       *dataprovider.User
}

type dirMapping struct {
	DirName string
	Href    string
}

type filesPage struct {
	baseClientPage
	CurrentDir   string
	Files        []os.FileInfo
	Error        string
	Paths        []dirMapping
	FormatTime   func(time.Time) string
	GetObjectURL func(string, string) string
	GetSize      func(int64) string
	IsLink       func(os.FileInfo) bool
}

type clientMessagePage struct {
	baseClientPage
	Error   string
	Success string
}

type credentialsPage struct {
	baseClientPage
	PublicKeys    []string
	ChangePwdURL  string
	ManageKeysURL string
	PwdError      string
	KeyError      string
}

func getFileObjectURL(baseDir, name string) string {
	return fmt.Sprintf("%v?path=%v", webClientFilesPath, url.QueryEscape(path.Join(baseDir, name)))
}

func getFileObjectModTime(t time.Time) string {
	if isZeroTime(t) {
		return ""
	}
	return t.Format("2006-01-02 15:04")
}

func isFileObjectLink(info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func loadClientTemplates(templatesPath string) {
	filesPaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientFiles),
	}
	credentialsPaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientCredentials),
	}
	loginPath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientLogin),
	}
	messagePath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientMessage),
	}

	filesTmpl := utils.LoadTemplate(template.ParseFiles(filesPaths...))
	credentialsTmpl := utils.LoadTemplate(template.ParseFiles(credentialsPaths...))
	loginTmpl := utils.LoadTemplate(template.ParseFiles(loginPath...))
	messageTmpl := utils.LoadTemplate(template.ParseFiles(messagePath...))

	clientTemplates[templateClientFiles] = filesTmpl
	clientTemplates[templateClientCredentials] = credentialsTmpl
	clientTemplates[templateClientLogin] = loginTmpl
	clientTemplates[templateClientMessage] = messageTmpl
}

func getBaseClientPageData(title, currentURL string, r *http.Request) baseClientPage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken()
	}
	v := version.Get()

	return baseClientPage{
		Title:            title,
		CurrentURL:       currentURL,
		FilesURL:         webClientFilesPath,
		CredentialsURL:   webClientCredentialsPath,
		StaticURL:        webStaticFilesPath,
		LogoutURL:        webClientLogoutPath,
		FilesTitle:       pageClientFilesTitle,
		CredentialsTitle: pageClientCredentialsTitle,
		Version:          fmt.Sprintf("%v-%v", v.Version, v.CommitHash),
		CSRFToken:        csrfToken,
		LoggedUser:       getUserFromToken(r),
	}
}

func renderClientTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := clientTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderClientLoginPage(w http.ResponseWriter, error string) {
	data := loginPage{
		CurrentURL: webClientLoginPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(),
		StaticURL:  webStaticFilesPath,
	}
	renderClientTemplate(w, templateClientLogin, data)
}

func renderClientMessagePage(w http.ResponseWriter, r *http.Request, title, body string, statusCode int, err error, message string) {
	var errorString string
	if body != "" {
		errorString = body + " "
	}
	if err != nil {
		errorString += err.Error()
	}
	data := clientMessagePage{
		baseClientPage: getBaseClientPageData(title, "", r),
		Error:          errorString,
		Success:        message,
	}
	w.WriteHeader(statusCode)
	renderClientTemplate(w, templateClientMessage, data)
}

func renderClientInternalServerErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	renderClientMessagePage(w, r, page500Title, page500Body, http.StatusInternalServerError, err, "")
}

func renderClientBadRequestPage(w http.ResponseWriter, r *http.Request, err error) {
	renderClientMessagePage(w, r, page400Title, "", http.StatusBadRequest, err, "")
}

func renderClientForbiddenPage(w http.ResponseWriter, r *http.Request, body string) {
	renderClientMessagePage(w, r, page403Title, "", http.StatusForbidden, nil, body)
}

func renderClientNotFoundPage(w http.ResponseWriter, r *http.Request, err error) {
	renderClientMessagePage(w, r, page404Title, page404Body, http.StatusNotFound, err, "")
}

func renderFilesPage(w http.ResponseWriter, r *http.Request, files []os.FileInfo, dirName, error string) {
	data := filesPage{
		baseClientPage: getBaseClientPageData(pageClientFilesTitle, webClientFilesPath, r),
		Files:          files,
		Error:          error,
		CurrentDir:     dirName,
		FormatTime:     getFileObjectModTime,
		GetObjectURL:   getFileObjectURL,
		GetSize:        utils.ByteCountIEC,
		IsLink:         isFileObjectLink,
	}
	paths := []dirMapping{}
	if dirName != "/" {
		paths = append(paths, dirMapping{
			DirName: path.Base(dirName),
			Href:    "",
		})
		for {
			dirName = path.Dir(dirName)
			if dirName == "/" || dirName == "." {
				break
			}
			paths = append([]dirMapping{{
				DirName: path.Base(dirName),
				Href:    getFileObjectURL("/", dirName)},
			}, paths...)
		}
	}
	data.Paths = paths
	renderClientTemplate(w, templateClientFiles, data)
}

func renderCredentialsPage(w http.ResponseWriter, r *http.Request, pwdError string, keyError string) {
	data := credentialsPage{
		baseClientPage: getBaseClientPageData(pageClientCredentialsTitle, webClientCredentialsPath, r),
		ChangePwdURL:   webChangeClientPwdPath,
		ManageKeysURL:  webChangeClientKeysPath,
		PwdError:       pwdError,
		KeyError:       keyError,
	}
	user, err := dataprovider.UserExists(data.LoggedUser.Username)
	if err != nil {
		renderClientInternalServerErrorPage(w, r, err)
	}
	data.PublicKeys = user.PublicKeys
	renderClientTemplate(w, templateClientCredentials, data)
}

func handleClientWebLogin(w http.ResponseWriter, r *http.Request) {
	renderClientLoginPage(w, "")
}

func handleWebClientLogout(w http.ResponseWriter, r *http.Request) {
	c := jwtTokenClaims{}
	c.removeCookie(w, r)

	http.Redirect(w, r, webClientLoginPath, http.StatusFound)
}

func handleClientGetFiles(w http.ResponseWriter, r *http.Request) {
	ipAddr := utils.GetIPFromRemoteAddress(r.RemoteAddr)
	common.Connections.AddClientConnection(ipAddr)
	defer common.Connections.RemoveClientConnection(ipAddr)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	if !common.Connections.IsNewConnectionAllowed(ipAddr) {
		logger.Log(logger.LevelDebug, common.ProtocolHTTP, "", "connection refused, configured limit reached")
		renderClientForbiddenPage(w, r, "configured connections limit reached")
		return
	}
	if common.IsBanned(ipAddr) {
		renderClientForbiddenPage(w, r, "your IP address is banned")
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		renderClientInternalServerErrorPage(w, r, err)
		return
	}

	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkWebClientUser(&user, r, connectionID); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, user),
		request:        r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		name = utils.CleanPath(r.URL.Query().Get("path"))
	}
	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Now(), false)
	} else {
		info, err = connection.Stat(name, 0)
	}
	if err != nil {
		renderFilesPage(w, r, nil, name, fmt.Sprintf("unable to stat file %#v: %v", name, err))
		return
	}
	if info.IsDir() {
		renderDirContents(w, r, connection, name)
		return
	}
	downloadFile(w, r, connection, name, info)
}

func handleClientGetCredentials(w http.ResponseWriter, r *http.Request) {
	renderCredentialsPage(w, r, "", "")
}

func handleWebClientChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		renderCredentialsPage(w, r, err.Error(), "")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	err = doChangeUserPassword(r, r.Form.Get("current_password"), r.Form.Get("new_password1"),
		r.Form.Get("new_password2"))
	if err != nil {
		renderCredentialsPage(w, r, err.Error(), "")
		return
	}
	handleWebClientLogout(w, r)
}

func handleWebClientManageKeysPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		renderCredentialsPage(w, r, "", err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderCredentialsPage(w, r, "", "Invalid token claims")
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		renderCredentialsPage(w, r, "", err.Error())
		return
	}
	publicKeysFormValue := r.Form.Get("public_keys")
	publicKeys := getSliceFromDelimitedValues(publicKeysFormValue, "\n")
	user.PublicKeys = publicKeys
	err = dataprovider.UpdateUser(&user)
	if err != nil {
		renderCredentialsPage(w, r, "", err.Error())
		return
	}
	renderClientMessagePage(w, r, "Public keys updated", "", http.StatusOK, nil, "Your public keys has been successfully updated")
}

func doChangeUserPassword(r *http.Request, currentPassword, newPassword, confirmNewPassword string) error {
	if currentPassword == "" || newPassword == "" || confirmNewPassword == "" {
		return dataprovider.NewValidationError("please provide the current password and the new one two times")
	}
	if newPassword != confirmNewPassword {
		return dataprovider.NewValidationError("the two password fields do not match")
	}
	if currentPassword == newPassword {
		return dataprovider.NewValidationError("the new password must be different from the current one")
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		return errors.New("invalid token claims")
	}
	user, err := dataprovider.CheckUserAndPass(claims.Username, currentPassword, utils.GetIPFromRemoteAddress(r.RemoteAddr),
		common.ProtocolHTTP)
	if err != nil {
		return dataprovider.NewValidationError("current password does not match")
	}
	user.Password = newPassword

	return dataprovider.UpdateUser(&user)
}

func renderDirContents(w http.ResponseWriter, r *http.Request, connection *Connection, name string) {
	contents, err := connection.ReadDir(name)
	if err != nil {
		renderFilesPage(w, r, nil, name, fmt.Sprintf("unable to get contents for directory %#v: %v", name, err))
		return
	}
	renderFilesPage(w, r, contents, name, "")
}

func downloadFile(w http.ResponseWriter, r *http.Request, connection *Connection, name string, info os.FileInfo) {
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
			http.Error(w, fmt.Sprintf("unsupported range %#v", rangeHeader), http.StatusRequestedRangeNotSatisfiable)
			return
		}
		offset, size, err = parseRangeRequest(rangeHeader[6:], size)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
			return
		}
		responseStatus = http.StatusPartialContent
	}
	reader, err := connection.getFileReader(name, offset)
	if err != nil {
		renderFilesPage(w, r, nil, name, fmt.Sprintf("unable to read file %#v: %v", name, err))
		return
	}
	defer reader.Close()

	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	if checkPreconditions(w, r, info.ModTime()) {
		return
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
	if err != nil {
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

func checkWebClientUser(user *dataprovider.User, r *http.Request, connectionID string) error {
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
	if connAddr, ok := r.Context().Value(connAddrKey).(string); ok {
		if connAddr != r.RemoteAddr {
			connIPAddr := utils.GetIPFromRemoteAddress(connAddr)
			if common.IsBanned(connIPAddr) {
				return errors.New("your IP address is banned")
			}
			if !user.IsLoginFromAddrAllowed(connIPAddr) {
				return fmt.Errorf("login from IP %v is not allowed", connIPAddr)
			}
		}
	}
	return nil
}
