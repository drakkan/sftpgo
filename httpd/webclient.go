package httpd

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/go-chi/render"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
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
	CurrentDir  string
	ReadDirURL  string
	DownloadURL string
	Error       string
	Paths       []dirMapping
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

func renderFilesPage(w http.ResponseWriter, r *http.Request, dirName, error string) {
	data := filesPage{
		baseClientPage: getBaseClientPageData(pageClientFilesTitle, webClientFilesPath, r),
		Error:          error,
		CurrentDir:     url.QueryEscape(dirName),
		DownloadURL:    webClientDownloadZipPath,
		ReadDirURL:     webClientDirContentsPath,
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
	c.removeCookie(w, r, webBaseClientPath)

	http.Redirect(w, r, webClientLoginPath, http.StatusFound)
}

func handleWebClientDownloadZip(w http.ResponseWriter, r *http.Request) {
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
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, r.RemoteAddr, user),
		request:        r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		name = utils.CleanPath(r.URL.Query().Get("path"))
	}

	files := r.URL.Query().Get("files")
	var filesList []string
	err = json.Unmarshal([]byte(files), &filesList)
	if err != nil {
		renderClientMessagePage(w, r, "Unable to get files list", "", http.StatusInternalServerError, err, "")
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\"sftpgo-download.zip\"")
	renderCompressedFiles(w, connection, name, filesList)
}

func handleClientGetDirContents(w http.ResponseWriter, r *http.Request) {
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
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, r.RemoteAddr, user),
		request:        r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		name = utils.CleanPath(r.URL.Query().Get("path"))
	}

	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}

	results := make([]map[string]string, 0, len(contents))
	for _, info := range contents {
		res := make(map[string]string)
		if info.IsDir() {
			res["type"] = "1"
			res["size"] = ""
		} else {
			res["type"] = "2"
			if info.Mode()&os.ModeSymlink != 0 {
				res["size"] = ""
			} else {
				res["size"] = utils.ByteCountIEC(info.Size())
			}
		}
		res["name"] = info.Name()
		res["last_modified"] = getFileObjectModTime(info.ModTime())
		res["url"] = getFileObjectURL(name, info.Name())
		results = append(results, res)
	}

	render.JSON(w, r, results)
}

func handleClientGetFiles(w http.ResponseWriter, r *http.Request) {
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
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTP, r.RemoteAddr, user),
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
		renderFilesPage(w, r, path.Dir(name), fmt.Sprintf("unable to stat file %#v: %v", name, err))
		return
	}
	if info.IsDir() {
		renderFilesPage(w, r, name, "")
		return
	}
	if status, err := downloadFile(w, r, connection, name, info); err != nil && status != 0 {
		if status > 0 {
			if status == http.StatusRequestedRangeNotSatisfiable {
				renderClientMessagePage(w, r, http.StatusText(status), "", status, err, "")
				return
			}
			renderFilesPage(w, r, path.Dir(name), err.Error())
		}
	}
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
	user.PublicKeys = r.Form["public_keys"]
	err = dataprovider.UpdateUser(&user)
	if err != nil {
		renderCredentialsPage(w, r, "", err.Error())
		return
	}
	renderClientMessagePage(w, r, "Public keys updated", "", http.StatusOK, nil, "Your public keys has been successfully updated")
}
