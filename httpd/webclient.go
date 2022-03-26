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
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/mfa"
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
	templateClientViewPDF           = "viewpdf.html"
	templateShareFiles              = "sharefiles.html"
	templateUploadToShare           = "shareupload.html"
	pageClientFilesTitle            = "My Files"
	pageClientSharesTitle           = "Shares"
	pageClientProfileTitle          = "My Profile"
	pageClientChangePwdTitle        = "Change password"
	pageClient2FATitle              = "Two-factor auth"
	pageClientEditFileTitle         = "Edit file"
	pageClientForgotPwdTitle        = "SFTPGo WebClient - Forgot password"
	pageClientResetPwdTitle         = "SFTPGo WebClient - Reset password"
	pageExtShareTitle               = "Shared files"
	pageUploadToShareTitle          = "Upload to share"
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
	SharesURL        string
	ShareURL         string
	ProfileURL       string
	ChangePwdURL     string
	StaticURL        string
	LogoutURL        string
	MFAURL           string
	MFATitle         string
	FilesTitle       string
	SharesTitle      string
	ProfileTitle     string
	Version          string
	CSRFToken        string
	HasExternalLogin bool
	LoggedUser       *dataprovider.User
	ExtraCSS         []CustomCSS
}

type dirMapping struct {
	DirName string
	Href    string
}

type viewPDFPage struct {
	Title     string
	URL       string
	StaticURL string
	ExtraCSS  []CustomCSS
}

type editFilePage struct {
	baseClientPage
	CurrentDir string
	FileURL    string
	Path       string
	Name       string
	ReadOnly   bool
	Data       string
}

type filesPage struct {
	baseClientPage
	CurrentDir      string
	DirsURL         string
	DownloadURL     string
	ViewPDFURL      string
	FileURL         string
	CanAddFiles     bool
	CanCreateDirs   bool
	CanRename       bool
	CanDelete       bool
	CanDownload     bool
	CanShare        bool
	Error           string
	Paths           []dirMapping
	HasIntegrations bool
}

type shareFilesPage struct {
	baseClientPage
	CurrentDir  string
	DirsURL     string
	FilesURL    string
	DownloadURL string
	Error       string
	Paths       []dirMapping
}

type shareUploadPage struct {
	baseClientPage
	Share          *dataprovider.Share
	UploadBasePath string
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
	TOTPConfig      dataprovider.UserTOTPConfig
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

func getFileObjectURL(baseDir, name, baseWebPath string) string {
	return fmt.Sprintf("%v?path=%v&_=%v", baseWebPath, url.QueryEscape(path.Join(baseDir, name)), time.Now().UTC().Unix())
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
	viewPDFPaths := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientViewPDF),
	}
	shareFilesPath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateShareFiles),
	}
	shareUploadPath := []string{
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateUploadToShare),
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
	viewPDFTmpl := util.LoadTemplate(nil, viewPDFPaths...)
	shareFilesTmpl := util.LoadTemplate(nil, shareFilesPath...)
	shareUploadTmpl := util.LoadTemplate(nil, shareUploadPath...)

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
	clientTemplates[templateClientViewPDF] = viewPDFTmpl
	clientTemplates[templateShareFiles] = shareFilesTmpl
	clientTemplates[templateUploadToShare] = shareUploadTmpl
}

func (s *httpdServer) getBaseClientPageData(title, currentURL string, r *http.Request) baseClientPage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken(util.GetIPFromRemoteAddress(r.RemoteAddr))
	}
	v := version.Get()

	return baseClientPage{
		Title:            title,
		CurrentURL:       currentURL,
		FilesURL:         webClientFilesPath,
		SharesURL:        webClientSharesPath,
		ShareURL:         webClientSharePath,
		ProfileURL:       webClientProfilePath,
		ChangePwdURL:     webChangeClientPwdPath,
		StaticURL:        webStaticFilesPath,
		LogoutURL:        webClientLogoutPath,
		MFAURL:           webClientMFAPath,
		MFATitle:         pageClient2FATitle,
		FilesTitle:       pageClientFilesTitle,
		SharesTitle:      pageClientSharesTitle,
		ProfileTitle:     pageClientProfileTitle,
		Version:          fmt.Sprintf("%v-%v", v.Version, v.CommitHash),
		CSRFToken:        csrfToken,
		HasExternalLogin: isLoggedInWithOIDC(r),
		LoggedUser:       getUserFromToken(r),
		ExtraCSS:         s.binding.ExtraCSS,
	}
}

func (s *httpdServer) renderClientForgotPwdPage(w http.ResponseWriter, error, ip string) {
	data := forgotPwdPage{
		CurrentURL: webClientForgotPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Title:      pageClientForgotPwdTitle,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	renderClientTemplate(w, templateForgotPassword, data)
}

func (s *httpdServer) renderClientResetPwdPage(w http.ResponseWriter, error, ip string) {
	data := resetPwdPage{
		CurrentURL: webClientResetPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Title:      pageClientResetPwdTitle,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	renderClientTemplate(w, templateResetPassword, data)
}

func renderClientTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := clientTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *httpdServer) renderClientMessagePage(w http.ResponseWriter, r *http.Request, title, body string, statusCode int, err error, message string) {
	var errorString string
	if body != "" {
		errorString = body + " "
	}
	if err != nil {
		errorString += err.Error()
	}
	data := clientMessagePage{
		baseClientPage: s.getBaseClientPageData(title, "", r),
		Error:          errorString,
		Success:        message,
	}
	w.WriteHeader(statusCode)
	renderClientTemplate(w, templateClientMessage, data)
}

func (s *httpdServer) renderClientInternalServerErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, page500Title, page500Body, http.StatusInternalServerError, err, "")
}

func (s *httpdServer) renderClientBadRequestPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, page400Title, "", http.StatusBadRequest, err, "")
}

func (s *httpdServer) renderClientForbiddenPage(w http.ResponseWriter, r *http.Request, body string) {
	s.renderClientMessagePage(w, r, page403Title, "", http.StatusForbidden, nil, body)
}

func (s *httpdServer) renderClientNotFoundPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, page404Title, page404Body, http.StatusNotFound, err, "")
}

func (s *httpdServer) renderClientTwoFactorPage(w http.ResponseWriter, error, ip string) {
	data := twoFactorPage{
		CurrentURL:  webClientTwoFactorPath,
		Version:     version.Get().Version,
		Error:       error,
		CSRFToken:   createCSRFToken(ip),
		StaticURL:   webStaticFilesPath,
		RecoveryURL: webClientTwoFactorRecoveryPath,
		ExtraCSS:    s.binding.ExtraCSS,
	}
	renderClientTemplate(w, templateTwoFactor, data)
}

func (s *httpdServer) renderClientTwoFactorRecoveryPage(w http.ResponseWriter, error, ip string) {
	data := twoFactorPage{
		CurrentURL: webClientTwoFactorRecoveryPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	renderClientTemplate(w, templateTwoFactorRecovery, data)
}

func (s *httpdServer) renderClientMFAPage(w http.ResponseWriter, r *http.Request) {
	data := clientMFAPage{
		baseClientPage:  s.getBaseClientPageData(pageMFATitle, webClientMFAPath, r),
		TOTPConfigs:     mfa.GetAvailableTOTPConfigNames(),
		GenerateTOTPURL: webClientTOTPGeneratePath,
		ValidateTOTPURL: webClientTOTPValidatePath,
		SaveTOTPURL:     webClientTOTPSavePath,
		RecCodesURL:     webClientRecoveryCodesPath,
		Protocols:       dataprovider.MFAProtocols,
	}
	user, err := dataprovider.UserExists(data.LoggedUser.Username)
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	data.TOTPConfig = user.Filters.TOTPConfig
	renderClientTemplate(w, templateClientMFA, data)
}

func (s *httpdServer) renderEditFilePage(w http.ResponseWriter, r *http.Request, fileName, fileData string, readOnly bool) {
	data := editFilePage{
		baseClientPage: s.getBaseClientPageData(pageClientEditFileTitle, webClientEditFilePath, r),
		Path:           fileName,
		Name:           path.Base(fileName),
		CurrentDir:     path.Dir(fileName),
		FileURL:        webClientFilePath,
		ReadOnly:       readOnly,
		Data:           fileData,
	}

	renderClientTemplate(w, templateClientEditFile, data)
}

func (s *httpdServer) renderAddUpdateSharePage(w http.ResponseWriter, r *http.Request, share *dataprovider.Share,
	error string, isAdd bool) {
	currentURL := webClientSharePath
	title := "Add a new share"
	if !isAdd {
		currentURL = fmt.Sprintf("%v/%v", webClientSharePath, url.PathEscape(share.ShareID))
		title = "Update share"
	}
	data := clientSharePage{
		baseClientPage: s.getBaseClientPageData(title, currentURL, r),
		Share:          share,
		Error:          error,
		IsAdd:          isAdd,
	}

	renderClientTemplate(w, templateClientShare, data)
}

func getDirMapping(dirName, baseWebPath string) []dirMapping {
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
				Href:    getFileObjectURL("/", dirName, baseWebPath)},
			}, paths...)
		}
	}
	return paths
}

func (s *httpdServer) renderSharedFilesPage(w http.ResponseWriter, r *http.Request, dirName, error string,
	share dataprovider.Share,
) {
	currentURL := path.Join(webClientPubSharesPath, share.ShareID, "browse")
	data := shareFilesPage{
		baseClientPage: s.getBaseClientPageData(pageExtShareTitle, currentURL, r),
		CurrentDir:     url.QueryEscape(dirName),
		DirsURL:        path.Join(webClientPubSharesPath, share.ShareID, "dirs"),
		FilesURL:       currentURL,
		DownloadURL:    path.Join(webClientPubSharesPath, share.ShareID),
		Error:          error,
		Paths:          getDirMapping(dirName, currentURL),
	}
	renderClientTemplate(w, templateShareFiles, data)
}

func (s *httpdServer) renderUploadToSharePage(w http.ResponseWriter, r *http.Request, share dataprovider.Share) {
	currentURL := path.Join(webClientPubSharesPath, share.ShareID, "upload")
	data := shareUploadPage{
		baseClientPage: s.getBaseClientPageData(pageUploadToShareTitle, currentURL, r),
		Share:          &share,
		UploadBasePath: path.Join(webClientPubSharesPath, share.ShareID),
	}
	renderClientTemplate(w, templateUploadToShare, data)
}

func (s *httpdServer) renderFilesPage(w http.ResponseWriter, r *http.Request, dirName, error string, user dataprovider.User,
	hasIntegrations bool,
) {
	data := filesPage{
		baseClientPage:  s.getBaseClientPageData(pageClientFilesTitle, webClientFilesPath, r),
		Error:           error,
		CurrentDir:      url.QueryEscape(dirName),
		DownloadURL:     webClientDownloadZipPath,
		ViewPDFURL:      webClientViewPDFPath,
		DirsURL:         webClientDirsPath,
		FileURL:         webClientFilePath,
		CanAddFiles:     user.CanAddFilesFromWeb(dirName),
		CanCreateDirs:   user.CanAddDirsFromWeb(dirName),
		CanRename:       user.CanRenameFromWeb(dirName, dirName),
		CanDelete:       user.CanDeleteFromWeb(dirName),
		CanDownload:     user.HasPerm(dataprovider.PermDownload, dirName),
		CanShare:        user.CanManageShares(),
		HasIntegrations: hasIntegrations,
		Paths:           getDirMapping(dirName, webClientFilesPath),
	}
	renderClientTemplate(w, templateClientFiles, data)
}

func (s *httpdServer) renderClientProfilePage(w http.ResponseWriter, r *http.Request, error string) {
	data := clientProfilePage{
		baseClientPage: s.getBaseClientPageData(pageClientProfileTitle, webClientProfilePath, r),
		Error:          error,
	}
	user, err := dataprovider.UserExists(data.LoggedUser.Username)
	if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	data.PublicKeys = user.PublicKeys
	data.AllowAPIKeyAuth = user.Filters.AllowAPIKeyAuth
	data.Email = user.Email
	data.Description = user.Description
	data.CanSubmit = user.CanChangeAPIKeyAuth() || user.CanManagePublicKeys() || user.CanChangeInfo()
	renderClientTemplate(w, templateClientProfile, data)
}

func (s *httpdServer) renderClientChangePasswordPage(w http.ResponseWriter, r *http.Request, error string) {
	data := changeClientPasswordPage{
		baseClientPage: s.getBaseClientPageData(pageClientChangePwdTitle, webChangeClientPwdPath, r),
		Error:          error,
	}

	renderClientTemplate(w, templateClientChangePwd, data)
}

func (s *httpdServer) handleWebClientDownloadZip(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientMessagePage(w, r, "Invalid token claims", "", http.StatusForbidden, nil, "")
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	files := r.URL.Query().Get("files")
	var filesList []string
	err = json.Unmarshal([]byte(files), &filesList)
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to get files list", "", http.StatusInternalServerError, err, "")
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\"sftpgo-download.zip\"")
	renderCompressedFiles(w, connection, name, filesList, nil)
}

func (s *httpdServer) handleShareGetDirContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share, connection, err := s.checkPublicShare(w, r, dataprovider.ShareScopeRead, true)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to validate share", "", getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share, r)
	if err != nil {
		s.renderClientMessagePage(w, r, "Invalid share path", "", getRespStatus(err), err, "")
		return
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}
	results := make([]map[string]string, 0, len(contents))
	for _, info := range contents {
		if !info.Mode().IsDir() && !info.Mode().IsRegular() {
			continue
		}
		res := make(map[string]string)
		if info.IsDir() {
			res["type"] = "1"
			res["size"] = ""
		} else {
			res["type"] = "2"
			res["size"] = util.ByteCountIEC(info.Size())
		}
		res["name"] = info.Name()
		res["url"] = getFileObjectURL(share.GetRelativePath(name), info.Name(),
			path.Join(webClientPubSharesPath, share.ShareID, "browse"))
		res["last_modified"] = getFileObjectModTime(info.ModTime())
		results = append(results, res)
	}

	render.JSON(w, r, results)
}

func (s *httpdServer) handleClientUploadToShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share, _, err := s.checkPublicShare(w, r, dataprovider.ShareScopeWrite, true)
	if err != nil {
		return
	}
	s.renderUploadToSharePage(w, r, share)
}

func (s *httpdServer) handleShareGetFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share, connection, err := s.checkPublicShare(w, r, dataprovider.ShareScopeRead, true)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to validate share", "", getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share, r)
	if err != nil {
		s.renderClientMessagePage(w, r, "Invalid share path", "", getRespStatus(err), err, "")
		return
	}

	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Now(), false)
	} else {
		info, err = connection.Stat(name, 1)
	}
	if err != nil {
		s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)), err.Error(), share)
		return
	}
	if info.IsDir() {
		s.renderSharedFilesPage(w, r, share.GetRelativePath(name), "", share)
		return
	}
	inline := r.URL.Query().Get("inline") != ""
	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	if status, err := downloadFile(w, r, connection, name, info, inline, &share); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
		if status > 0 {
			s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)), err.Error(), share)
		}
	}
}

func (s *httpdServer) handleClientGetDirContents(w http.ResponseWriter, r *http.Request) {
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
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}

	results := make([]map[string]string, 0, len(contents))
	for _, info := range contents {
		res := make(map[string]string)
		res["url"] = getFileObjectURL(name, info.Name(), webClientFilesPath)
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
					res["edit_url"] = strings.Replace(res["url"], webClientFilesPath, webClientEditFilePath, 1)
				}
				if len(s.binding.WebClientIntegrations) > 0 {
					extension := path.Ext(info.Name())
					for idx := range s.binding.WebClientIntegrations {
						if util.IsStringInSlice(extension, s.binding.WebClientIntegrations[idx].FileExtensions) {
							res["ext_url"] = s.binding.WebClientIntegrations[idx].URL
							res["ext_link"] = fmt.Sprintf("%v?path=%v&_=%v", webClientFilePath,
								url.QueryEscape(path.Join(name, info.Name())), time.Now().UTC().Unix())
							break
						}
					}
				}
			}
		}
		res["meta"] = fmt.Sprintf("%v_%v", res["type"], info.Name())
		res["name"] = info.Name()
		res["last_modified"] = getFileObjectModTime(info.ModTime())
		results = append(results, res)
	}

	render.JSON(w, r, results)
}

func (s *httpdServer) handleClientGetFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Now(), false)
	} else {
		info, err = connection.Stat(name, 0)
	}
	if err != nil {
		s.renderFilesPage(w, r, path.Dir(name), fmt.Sprintf("unable to stat file %#v: %v", name, err),
			user, len(s.binding.WebClientIntegrations) > 0)
		return
	}
	if info.IsDir() {
		s.renderFilesPage(w, r, name, "", user, len(s.binding.WebClientIntegrations) > 0)
		return
	}
	inline := r.URL.Query().Get("inline") != ""
	if status, err := downloadFile(w, r, connection, name, info, inline, nil); err != nil && status != 0 {
		if status > 0 {
			if status == http.StatusRequestedRangeNotSatisfiable {
				s.renderClientMessagePage(w, r, http.StatusText(status), "", status, err, "")
				return
			}
			s.renderFilesPage(w, r, path.Dir(name), err.Error(), user, len(s.binding.WebClientIntegrations) > 0)
		}
	}
}

func (s *httpdServer) handleClientEditFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}

	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	info, err := connection.Stat(name, 0)
	if err != nil {
		s.renderClientMessagePage(w, r, fmt.Sprintf("Unable to stat file %#v", name), "",
			getRespStatus(err), nil, "")
		return
	}
	if info.IsDir() {
		s.renderClientMessagePage(w, r, fmt.Sprintf("The path %#v does not point to a file", name), "",
			http.StatusBadRequest, nil, "")
		return
	}
	if info.Size() > httpdMaxEditFileSize {
		s.renderClientMessagePage(w, r, fmt.Sprintf("The file size %v for %#v exceeds the maximum allowed size",
			util.ByteCountIEC(info.Size()), name), "", http.StatusBadRequest, nil, "")
		return
	}

	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		s.renderClientMessagePage(w, r, fmt.Sprintf("Unable to get a reader for the file %#v", name), "",
			getRespStatus(err), nil, "")
		return
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.Copy(&b, reader)
	if err != nil {
		s.renderClientMessagePage(w, r, fmt.Sprintf("Unable to read the file %#v", name), "", http.StatusInternalServerError,
			nil, "")
		return
	}

	s.renderEditFilePage(w, r, name, b.String(), util.IsStringInSlice(sdk.WebClientWriteDisabled, user.Filters.WebClient))
}

func (s *httpdServer) handleClientAddShareGet(w http.ResponseWriter, r *http.Request) {
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
			s.renderClientMessagePage(w, r, "Invalid share list", "", http.StatusBadRequest, err, "")
			return
		}
		for _, f := range filesList {
			if f != "" {
				share.Paths = append(share.Paths, path.Join(dirName, f))
			}
		}
	}

	s.renderAddUpdateSharePage(w, r, share, "", true)
}

func (s *httpdServer) handleClientUpdateShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err == nil {
		share.HideConfidentialData()
		s.renderAddUpdateSharePage(w, r, &share, "", false)
	} else if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderClientNotFoundPage(w, r, err)
	} else {
		s.renderClientInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleClientAddSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	share, err := getShareFromPostFields(r)
	if err != nil {
		s.renderAddUpdateSharePage(w, r, share, err.Error(), true)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	share.ID = 0
	share.ShareID = util.GenerateUniqueID()
	share.LastUseAt = 0
	share.Username = claims.Username
	if share.Password == "" {
		if util.IsStringInSlice(sdk.WebClientShareNoPasswordDisabled, claims.Permissions) {
			s.renderClientForbiddenPage(w, r, "You are not authorized to share files/folders without a password")
			return
		}
	}
	err = dataprovider.AddShare(share, claims.Username, ipAddr)
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		s.renderAddUpdateSharePage(w, r, share, err.Error(), true)
	}
}

func (s *httpdServer) handleClientUpdateSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderClientNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	updatedShare, err := getShareFromPostFields(r)
	if err != nil {
		s.renderAddUpdateSharePage(w, r, updatedShare, err.Error(), false)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	updatedShare.ShareID = shareID
	updatedShare.Username = claims.Username
	if updatedShare.Password == redactedSecret {
		updatedShare.Password = share.Password
	}
	if updatedShare.Password == "" {
		if util.IsStringInSlice(sdk.WebClientShareNoPasswordDisabled, claims.Permissions) {
			s.renderClientForbiddenPage(w, r, "You are not authorized to share files/folders without a password")
			return
		}
	}
	err = dataprovider.UpdateShare(updatedShare, claims.Username, ipAddr)
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		s.renderAddUpdateSharePage(w, r, updatedShare, err.Error(), false)
	}
}

func (s *httpdServer) handleClientGetShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
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
		sh, err := dataprovider.GetShares(limit, len(shares), dataprovider.OrderASC, claims.Username)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return
		}
		shares = append(shares, sh...)
		if len(sh) < limit {
			break
		}
	}
	data := clientSharesPage{
		baseClientPage:      s.getBaseClientPageData(pageClientSharesTitle, webClientSharesPath, r),
		Shares:              shares,
		BasePublicSharesURL: webClientPubSharesPath,
	}
	renderClientTemplate(w, templateClientShares, data)
}

func (s *httpdServer) handleClientGetProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientProfilePage(w, r, "")
}

func (s *httpdServer) handleWebClientChangePwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientChangePasswordPage(w, r, "")
}

func (s *httpdServer) handleWebClientProfilePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderClientProfilePage(w, r, err.Error())
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	user, err := dataprovider.UserExists(claims.Username)
	if err != nil {
		s.renderClientProfilePage(w, r, err.Error())
		return
	}
	if !user.CanManagePublicKeys() && !user.CanChangeAPIKeyAuth() && !user.CanChangeInfo() {
		s.renderClientForbiddenPage(w, r, "You are not allowed to change anything")
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
	err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr)
	if err != nil {
		s.renderClientProfilePage(w, r, err.Error())
		return
	}
	s.renderClientMessagePage(w, r, "Profile updated", "", http.StatusOK, nil,
		"Your profile has been successfully updated")
}

func (s *httpdServer) handleWebClientMFA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientMFAPage(w, r)
}

func (s *httpdServer) handleWebClientTwoFactor(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientTwoFactorPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebClientTwoFactorRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientTwoFactorRecoveryPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
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

func (s *httpdServer) handleWebClientForgotPwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if !smtp.IsEnabled() {
		s.renderClientNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderClientForgotPwdPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebClientForgotPwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderClientForgotPwdPage(w, err.Error(), ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	username := r.Form.Get("username")
	err = handleForgotPassword(r, username, false)
	if err != nil {
		if e, ok := err.(*util.ValidationError); ok {
			s.renderClientForgotPwdPage(w, e.GetErrorString(), ipAddr)
			return
		}
		s.renderClientForgotPwdPage(w, err.Error(), ipAddr)
		return
	}
	http.Redirect(w, r, webClientResetPwdPath, http.StatusFound)
}

func (s *httpdServer) handleWebClientPasswordReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !smtp.IsEnabled() {
		s.renderClientNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderClientResetPwdPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleClientViewPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	name := r.URL.Query().Get("path")
	if name == "" {
		s.renderClientBadRequestPage(w, r, errors.New("no file specified"))
		return
	}
	name = util.CleanPath(name)
	data := viewPDFPage{
		Title:     path.Base(name),
		URL:       fmt.Sprintf("%v?path=%v&inline=1", webClientFilesPath, url.QueryEscape(name)),
		StaticURL: webStaticFilesPath,
		ExtraCSS:  s.binding.ExtraCSS,
	}
	renderClientTemplate(w, templateClientViewPDF, data)
}
