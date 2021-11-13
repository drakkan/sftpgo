package httpd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/sdk"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	templateClientDir               = "webclient"
	templateClientBase              = "base.html"
	templateClientBaseLogin         = "baselogin.html"
	templateClientLogin             = "login.html"
	templateClientFiles             = "files.html"
	templateClientMessage           = "message.html"
	templateClientProfile           = "profile.html"
	templateClientChangePwd         = "changepassword.html"
	templateClientTwoFactor         = "twofactor.html"
	templateClientTwoFactorRecovery = "twofactor-recovery.html"
	templateClientMFA               = "mfa.html"
	templateClientEditFile          = "editfile.html"
	templateClientShare             = "share.html"
	templateClientShares            = "shares.html"
	pageClientFilesTitle            = "My Files"
	pageClientSharesTitle           = "Shares"
	pageClientProfileTitle          = "My Profile"
	pageClientChangePwdTitle        = "Change password"
	pageClient2FATitle              = "Two-factor auth"
	pageClientEditFileTitle         = "Edit file"
	pageClientForgotPwdTitle        = "SFTPGo WebClient - Forgot password"
	pageClientResetPwdTitle         = "SFTPGo WebClient - Reset password"
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
	Title        string
	CurrentURL   string
	FilesURL     string
	SharesURL    string
	ShareURL     string
	ProfileURL   string
	ChangePwdURL string
	StaticURL    string
	LogoutURL    string
	MFAURL       string
	MFATitle     string
	FilesTitle   string
	SharesTitle  string
	ProfileTitle string
	Version      string
	CSRFToken    string
	LoggedUser   *dataprovider.User
}

type dirMapping struct {
	DirName string
	Href    string
}

type editFilePage struct {
	baseClientPage
	CurrentDir string
	Path       string
	Name       string
	Data       string
}

type filesPage struct {
	baseClientPage
	CurrentDir    string
	DirsURL       string
	DownloadURL   string
	CanAddFiles   bool
	CanCreateDirs bool
	CanRename     bool
	CanDelete     bool
	CanDownload   bool
	CanShare      bool
	Error         string
	Paths         []dirMapping
}

type clientMessagePage struct {
	baseClientPage
	Error   string
	Success string
}

type clientProfilePage struct {
	baseClientPage
	PublicKeys      []string
	CanSubmit       bool
	AllowAPIKeyAuth bool
	Email           string
	Description     string
	Error           string
}

type changeClientPasswordPage struct {
	baseClientPage
	Error string
}

type clientMFAPage struct {
	baseClientPage
	TOTPConfigs     []string
	TOTPConfig      sdk.TOTPConfig
	GenerateTOTPURL string
	ValidateTOTPURL string
	SaveTOTPURL     string
	RecCodesURL     string
	Protocols       []string
}

type clientSharesPage struct {
	baseClientPage
	Shares              []dataprovider.Share
	BasePublicSharesURL string
}

type clientSharePage struct {
	baseClientPage
	Share *dataprovider.Share
	Error string
	IsAdd bool
}

func getFileObjectURL(baseDir, name string) string {
	return fmt.Sprintf("%v?path=%v&_=%v", webClientFilesPath, url.QueryEscape(path.Join(baseDir, name)), time.Now().UTC().Unix())
}

func getFileObjectModTime(t time.Time) string {
	if isZeroTime(t) {
		return ""
	}
	return t.Format("2006-01-02 15:04")
}

func loadClientTemplates(templatesPath string) {
	filesPaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientFiles),
	}
	editFilePath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientEditFile),
	}
	sharesPaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShares),
	}
	sharePaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShare),
	}
	profilePaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientProfile),
	}
	changePwdPaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientChangePwd),
	}
	loginPath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateClientLogin),
	}
	messagePath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientMessage),
	}
	mfaPath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientMFA),
	}
	twoFactorPath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateClientTwoFactor),
	}
	twoFactorRecoveryPath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateClientTwoFactorRecovery),
	}
	forgotPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateForgotPassword),
	}
	resetPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateResetPassword),
	}

	filesTmpl := util.LoadTemplate(nil, filesPaths...)
	profileTmpl := util.LoadTemplate(nil, profilePaths...)
	changePwdTmpl := util.LoadTemplate(nil, changePwdPaths...)
	loginTmpl := util.LoadTemplate(nil, loginPath...)
	messageTmpl := util.LoadTemplate(nil, messagePath...)
	mfaTmpl := util.LoadTemplate(nil, mfaPath...)
	twoFactorTmpl := util.LoadTemplate(nil, twoFactorPath...)
	twoFactorRecoveryTmpl := util.LoadTemplate(nil, twoFactorRecoveryPath...)
	editFileTmpl := util.LoadTemplate(nil, editFilePath...)
	sharesTmpl := util.LoadTemplate(nil, sharesPaths...)
	shareTmpl := util.LoadTemplate(nil, sharePaths...)
	forgotPwdTmpl := util.LoadTemplate(nil, forgotPwdPaths...)
	resetPwdTmpl := util.LoadTemplate(nil, resetPwdPaths...)

	clientTemplates[templateClientFiles] = filesTmpl
	clientTemplates[templateClientProfile] = profileTmpl
	clientTemplates[templateClientChangePwd] = changePwdTmpl
	clientTemplates[templateClientLogin] = loginTmpl
	clientTemplates[templateClientMessage] = messageTmpl
	clientTemplates[templateClientMFA] = mfaTmpl
	clientTemplates[templateClientTwoFactor] = twoFactorTmpl
	clientTemplates[templateClientTwoFactorRecovery] = twoFactorRecoveryTmpl
	clientTemplates[templateClientEditFile] = editFileTmpl
	clientTemplates[templateClientShares] = sharesTmpl
	clientTemplates[templateClientShare] = shareTmpl
	clientTemplates[templateForgotPassword] = forgotPwdTmpl
	clientTemplates[templateResetPassword] = resetPwdTmpl
}

func getBaseClientPageData(title, currentURL string, r *http.Request) baseClientPage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken()
	}
	v := version.Get()

	return baseClientPage{
		Title:        title,
		CurrentURL:   currentURL,
		FilesURL:     webClientFilesPath,
		SharesURL:    webClientSharesPath,
		ShareURL:     webClientSharePath,
		ProfileURL:   webClientProfilePath,
		ChangePwdURL: webChangeClientPwdPath,
		StaticURL:    webStaticFilesPath,
		LogoutURL:    webClientLogoutPath,
		MFAURL:       webClientMFAPath,
		MFATitle:     pageClient2FATitle,
		FilesTitle:   pageClientFilesTitle,
		SharesTitle:  pageClientSharesTitle,
		ProfileTitle: pageClientProfileTitle,
		Version:      fmt.Sprintf("%v-%v", v.Version, v.CommitHash),
		CSRFToken:    csrfToken,
		LoggedUser:   getUserFromToken(r),
	}
}

func renderClientForgotPwdPage(w http.ResponseWriter, error string) {
	data := forgotPwdPage{
		CurrentURL: webClientForgotPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(),
		StaticURL:  webStaticFilesPath,
		Title:      pageClientForgotPwdTitle,
	}
	renderClientTemplate(w, templateForgotPassword, data)
}

func renderClientResetPwdPage(w http.ResponseWriter, error string) {
	data := resetPwdPage{
		CurrentURL: webClientResetPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(),
		StaticURL:  webStaticFilesPath,
		Title:      pageClientResetPwdTitle,
	}
	renderClientTemplate(w, templateResetPassword, data)
}

func renderClientTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := clientTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

func renderClientTwoFactorPage(w http.ResponseWriter, error string) {
	data := twoFactorPage{
		CurrentURL:  webClientTwoFactorPath,
		Version:     version.Get().Version,
		Error:       error,
		CSRFToken:   createCSRFToken(),
		StaticURL:   webStaticFilesPath,
		RecoveryURL: webClientTwoFactorRecoveryPath,
	}
	renderClientTemplate(w, templateTwoFactor, data)
}

func renderClientTwoFactorRecoveryPage(w http.ResponseWriter, error string) {
	data := twoFactorPage{
		CurrentURL: webClientTwoFactorRecoveryPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(),
		StaticURL:  webStaticFilesPath,
	}
	renderClientTemplate(w, templateTwoFactorRecovery, data)
}

func renderClientMFAPage(w http.ResponseWriter, r *http.Request) {
	data := clientMFAPage{
		baseClientPage:  getBaseClientPageData(pageMFATitle, webClientMFAPath, r),
		TOTPConfigs:     mfa.GetAvailableTOTPConfigNames(),
		GenerateTOTPURL: webClientTOTPGeneratePath,
		ValidateTOTPURL: webClientTOTPValidatePath,
		SaveTOTPURL:     webClientTOTPSavePath,
		RecCodesURL:     webClientRecoveryCodesPath,
		Protocols:       dataprovider.MFAProtocols,
	}
	user, err := dataprovider.UserExists(data.LoggedUser.Username)
	if err != nil {
		renderInternalServerErrorPage(w, r, err)
		return
	}
	data.TOTPConfig = user.Filters.TOTPConfig
	renderClientTemplate(w, templateClientMFA, data)
}

func renderEditFilePage(w http.ResponseWriter, r *http.Request, fileName, fileData string) {
	data := editFilePage{
		baseClientPage: getBaseClientPageData(pageClientEditFileTitle, webClientEditFilePath, r),
		Path:           fileName,
		Name:           path.Base(fileName),
		CurrentDir:     path.Dir(fileName),
		Data:           fileData,
	}

	renderClientTemplate(w, templateClientEditFile, data)
}

func renderAddUpdateSharePage(w http.ResponseWriter, r *http.Request, share *dataprovider.Share,
	error string, isAdd bool) {
	currentURL := webClientSharePath
	title := "Add a new share"
	if !isAdd {
		currentURL = fmt.Sprintf("%v/%v", webClientSharePath, url.PathEscape(share.ShareID))
		title = "Update share"
	}
	data := clientSharePage{
		baseClientPage: getBaseClientPageData(title, currentURL, r),
		Share:          share,
		Error:          error,
		IsAdd:          isAdd,
	}

	renderClientTemplate(w, templateClientShare, data)
}

func renderFilesPage(w http.ResponseWriter, r *http.Request, dirName, error string, user dataprovider.User) {
	data := filesPage{
		baseClientPage: getBaseClientPageData(pageClientFilesTitle, webClientFilesPath, r),
		Error:          error,
		CurrentDir:     url.QueryEscape(dirName),
		DownloadURL:    webClientDownloadZipPath,
		DirsURL:        webClientDirsPath,
		CanAddFiles:    user.CanAddFilesFromWeb(dirName),
		CanCreateDirs:  user.CanAddDirsFromWeb(dirName),
		CanRename:      user.CanRenameFromWeb(dirName, dirName),
		CanDelete:      user.CanDeleteFromWeb(dirName),
		CanDownload:    user.HasPerm(dataprovider.PermDownload, dirName),
		CanShare:       user.CanManageShares(),
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

func renderClientProfilePage(w http.ResponseWriter, r *http.Request, error string) {
	data := clientProfilePage{
		baseClientPage: getBaseClientPageData(pageClientProfileTitle, webClientProfilePath, r),
		Error:          error,
	}
	user, err := dataprovider.UserExists(data.LoggedUser.Username)
	if err != nil {
		renderClientInternalServerErrorPage(w, r, err)
		return
	}
	data.PublicKeys = user.PublicKeys
	data.AllowAPIKeyAuth = user.Filters.AllowAPIKeyAuth
	data.Email = user.Email
	data.Description = user.Description
	data.CanSubmit = user.CanChangeAPIKeyAuth() || user.CanManagePublicKeys() || user.CanChangeInfo()
	renderClientTemplate(w, templateClientProfile, data)
}

func renderClientChangePasswordPage(w http.ResponseWriter, r *http.Request, error string) {
	data := changeClientPasswordPage{
		baseClientPage: getBaseClientPageData(pageClientChangePwdTitle, webChangeClientPwdPath, r),
		Error:          error,
	}

	renderClientTemplate(w, templateClientChangePwd, data)
}

func handleWebClientLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	c := jwtTokenClaims{}
	c.removeCookie(w, r, webBaseClientPath)

	http.Redirect(w, r, webClientLoginPath, http.StatusFound)
}

func handleWebClientDownloadZip(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientMessagePage(w, r, "Invalid token claims", "", http.StatusForbidden, nil, "")
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		name = util.CleanPath(r.URL.Query().Get("path"))
	}

	files := r.URL.Query().Get("files")
	var filesList []string
	err = json.Unmarshal([]byte(files), &filesList)
	if err != nil {
		renderClientMessagePage(w, r, "Unable to get files list", "", http.StatusInternalServerError, err, "")
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\"sftpgo-download.zip\"")
	renderCompressedFiles(w, connection, name, filesList, nil)
}

func handleClientGetDirContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, nil, "invalid token claims", http.StatusForbidden)
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return
	}

	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		name = util.CleanPath(r.URL.Query().Get("path"))
	}

	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}

	results := make([]map[string]string, 0, len(contents))
	for _, info := range contents {
		res := make(map[string]string)
		res["url"] = getFileObjectURL(name, info.Name())
		editURL := ""
		if info.IsDir() {
			res["type"] = "1"
			res["size"] = ""
		} else {
			res["type"] = "2"
			if info.Mode()&os.ModeSymlink != 0 {
				res["size"] = ""
			} else {
				res["size"] = util.ByteCountIEC(info.Size())
				if info.Size() < httpdMaxEditFileSize {
					editURL = strings.Replace(res["url"], webClientFilesPath, webClientEditFilePath, 1)
				}
			}
		}
		res["meta"] = fmt.Sprintf("%v_%v", res["type"], info.Name())
		res["name"] = info.Name()
		res["last_modified"] = getFileObjectModTime(info.ModTime())
		res["edit_url"] = editURL
		results = append(results, res)
	}

	render.JSON(w, r, results)
}

func handleClientGetFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		name = util.CleanPath(r.URL.Query().Get("path"))
	}
	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Now(), false)
	} else {
		info, err = connection.Stat(name, 0)
	}
	if err != nil {
		renderFilesPage(w, r, path.Dir(name), fmt.Sprintf("unable to stat file %#v: %v", name, err), user)
		return
	}
	if info.IsDir() {
		renderFilesPage(w, r, name, "", user)
		return
	}
	if status, err := downloadFile(w, r, connection, name, info); err != nil && status != 0 {
		if status > 0 {
			if status == http.StatusRequestedRangeNotSatisfiable {
				renderClientMessagePage(w, r, http.StatusText(status), "", status, err, "")
				return
			}
			renderFilesPage(w, r, path.Dir(name), err.Error(), user)
		}
	}
}

func handleClientEditFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := util.CleanPath(r.URL.Query().Get("path"))
	info, err := connection.Stat(name, 0)
	if err != nil {
		renderClientMessagePage(w, r, fmt.Sprintf("Unable to stat file %#v", name), "",
			getRespStatus(err), nil, "")
		return
	}
	if info.IsDir() {
		renderClientMessagePage(w, r, fmt.Sprintf("The path %#v does not point to a file", name), "",
			http.StatusBadRequest, nil, "")
		return
	}
	if info.Size() > httpdMaxEditFileSize {
		renderClientMessagePage(w, r, fmt.Sprintf("The file size %v for %#v exceeds the maximum allowed size",
			util.ByteCountIEC(info.Size()), name), "", http.StatusBadRequest, nil, "")
		return
	}

	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		renderClientMessagePage(w, r, fmt.Sprintf("Unable to get a reader for the file %#v", name), "",
			getRespStatus(err), nil, "")
		return
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.Copy(&b, reader)
	if err != nil {
		renderClientMessagePage(w, r, fmt.Sprintf("Unable to read the file %#v", name), "", http.StatusInternalServerError,
			nil, "")
		return
	}

	renderEditFilePage(w, r, name, b.String())
}

func handleClientAddShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share := &dataprovider.Share{Scope: dataprovider.ShareScopeRead}
	dirName := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		dirName = util.CleanPath(r.URL.Query().Get("path"))
	}

	if _, ok := r.URL.Query()["files"]; ok {
		files := r.URL.Query().Get("files")
		var filesList []string
		err := json.Unmarshal([]byte(files), &filesList)
		if err != nil {
			renderClientMessagePage(w, r, "Invalid share list", "", http.StatusBadRequest, err, "")
			return
		}
		for _, f := range filesList {
			if f != "" {
				share.Paths = append(share.Paths, path.Join(dirName, f))
			}
		}
	}

	renderAddUpdateSharePage(w, r, share, "", true)
}

func handleClientUpdateShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err == nil {
		share.HideConfidentialData()
		renderAddUpdateSharePage(w, r, &share, "", false)
	} else if _, ok := err.(*util.RecordNotFoundError); ok {
		renderClientNotFoundPage(w, r, err)
	} else {
		renderClientInternalServerErrorPage(w, r, err)
	}
}

func handleClientAddSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	share, err := getShareFromPostFields(r)
	if err != nil {
		renderAddUpdateSharePage(w, r, share, err.Error(), true)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	share.ID = 0
	share.ShareID = util.GenerateUniqueID()
	share.LastUseAt = 0
	share.Username = claims.Username
	err = dataprovider.AddShare(share, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		renderAddUpdateSharePage(w, r, share, err.Error(), true)
	}
}

func handleClientUpdateSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if _, ok := err.(*util.RecordNotFoundError); ok {
		renderClientNotFoundPage(w, r, err)
		return
	} else if err != nil {
		renderClientInternalServerErrorPage(w, r, err)
		return
	}
	updatedShare, err := getShareFromPostFields(r)
	if err != nil {
		renderAddUpdateSharePage(w, r, updatedShare, err.Error(), false)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	updatedShare.ShareID = shareID
	updatedShare.Username = claims.Username
	if updatedShare.Password == redactedSecret {
		updatedShare.Password = share.Password
	}
	err = dataprovider.UpdateShare(updatedShare, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		renderAddUpdateSharePage(w, r, updatedShare, err.Error(), false)
	}
}

func handleClientGetShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	limit := defaultQueryLimit
	if _, ok := r.URL.Query()["qlimit"]; ok {
		var err error
		limit, err = strconv.Atoi(r.URL.Query().Get("qlimit"))
		if err != nil {
			limit = defaultQueryLimit
		}
	}
	shares := make([]dataprovider.Share, 0, limit)
	for {
		s, err := dataprovider.GetShares(limit, len(shares), dataprovider.OrderASC, claims.Username)
		if err != nil {
			renderInternalServerErrorPage(w, r, err)
			return
		}
		shares = append(shares, s...)
		if len(s) < limit {
			break
		}
	}
	data := clientSharesPage{
		baseClientPage:      getBaseClientPageData(pageClientSharesTitle, webClientSharesPath, r),
		Shares:              shares,
		BasePublicSharesURL: webClientPubSharesPath,
	}
	renderClientTemplate(w, templateClientShares, data)
}

func handleClientGetProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	renderClientProfilePage(w, r, "")
}

func handleWebClientChangePwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	renderClientChangePasswordPage(w, r, "")
}

func handleWebClientChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		renderClientChangePasswordPage(w, r, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	err = doChangeUserPassword(r, r.Form.Get("current_password"), r.Form.Get("new_password1"),
		r.Form.Get("new_password2"))
	if err != nil {
		renderClientChangePasswordPage(w, r, err.Error())
		return
	}
	handleWebClientLogout(w, r)
}

func handleWebClientProfilePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		renderClientProfilePage(w, r, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		renderClientProfilePage(w, r, err.Error())
		return
	}
	if !user.CanManagePublicKeys() && !user.CanChangeAPIKeyAuth() && !user.CanChangeInfo() {
		renderClientForbiddenPage(w, r, "You are not allowed to change anything")
		return
	}
	if user.CanManagePublicKeys() {
		user.PublicKeys = r.Form["public_keys"]
	}
	if user.CanChangeAPIKeyAuth() {
		user.Filters.AllowAPIKeyAuth = len(r.Form.Get("allow_api_key_auth")) > 0
	}
	if user.CanChangeInfo() {
		user.Email = r.Form.Get("email")
		user.Description = r.Form.Get("description")
	}
	err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		renderClientProfilePage(w, r, err.Error())
		return
	}
	renderClientMessagePage(w, r, "Profile updated", "", http.StatusOK, nil,
		"Your profile has been successfully updated")
}

func handleWebClientMFA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	renderClientMFAPage(w, r)
}

func handleWebClientTwoFactor(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	renderClientTwoFactorPage(w, "")
}

func handleWebClientTwoFactorRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	renderClientTwoFactorRecoveryPage(w, "")
}

func getShareFromPostFields(r *http.Request) (*dataprovider.Share, error) {
	share := &dataprovider.Share{}
	if err := r.ParseForm(); err != nil {
		return share, err
	}
	share.Name = r.Form.Get("name")
	share.Description = r.Form.Get("description")
	share.Paths = r.Form["paths"]
	share.Password = r.Form.Get("password")
	share.AllowFrom = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	scope, err := strconv.Atoi(r.Form.Get("scope"))
	if err != nil {
		return share, err
	}
	share.Scope = dataprovider.ShareScope(scope)
	maxTokens, err := strconv.Atoi(r.Form.Get("max_tokens"))
	if err != nil {
		return share, err
	}
	share.MaxTokens = maxTokens
	expirationDateMillis := int64(0)
	expirationDateString := r.Form.Get("expiration_date")
	if strings.TrimSpace(expirationDateString) != "" {
		expirationDate, err := time.Parse(webDateTimeFormat, expirationDateString)
		if err != nil {
			return share, err
		}
		expirationDateMillis = util.GetTimeAsMsSinceEpoch(expirationDate)
	}
	share.ExpiresAt = expirationDateMillis
	return share, nil
}

func handleWebClientForgotPwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if !smtp.IsEnabled() {
		renderClientNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	renderClientForgotPwdPage(w, "")
}

func handleWebClientForgotPwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		renderClientForgotPwdPage(w, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	username := r.Form.Get("username")
	err = handleForgotPassword(r, username, false)
	if err != nil {
		if e, ok := err.(*util.ValidationError); ok {
			renderClientForgotPwdPage(w, e.GetErrorString())
			return
		}
		renderClientForgotPwdPage(w, err.Error())
		return
	}
	http.Redirect(w, r, webClientResetPwdPath, http.StatusFound)
}

func handleWebClientPasswordReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !smtp.IsEnabled() {
		renderClientNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	renderClientResetPwdPage(w, "")
}
