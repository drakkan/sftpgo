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
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
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

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	templateClientDir      = "webclient"
	templateClientBase     = "base.html"
	templateClientFiles    = "files.html"
	templateClientProfile  = "profile.html"
	templateClientMFA      = "mfa.html"
	templateClientEditFile = "editfile.html"
	templateClientShare    = "share.html"
	templateClientShares   = "shares.html"
	templateClientViewPDF  = "viewpdf.html"
	templateShareLogin     = "sharelogin.html"
	templateShareDownload  = "sharedownload.html"
	templateUploadToShare  = "shareupload.html"
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
	commonBasePage
	Title        string
	CurrentURL   string
	FilesURL     string
	SharesURL    string
	ShareURL     string
	ProfileURL   string
	PingURL      string
	ChangePwdURL string
	LogoutURL    string
	LoginURL     string
	EditURL      string
	MFAURL       string
	CSRFToken    string
	LoggedUser   *dataprovider.User
	Branding     UIBranding
}

type dirMapping struct {
	DirName string
	Href    string
}

type viewPDFPage struct {
	commonBasePage
	Title    string
	URL      string
	Branding UIBranding
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
	CurrentDir         string
	DirsURL            string
	FileActionsURL     string
	CheckExistURL      string
	DownloadURL        string
	ViewPDFURL         string
	FileURL            string
	TasksURL           string
	CanAddFiles        bool
	CanCreateDirs      bool
	CanRename          bool
	CanDelete          bool
	CanDownload        bool
	CanShare           bool
	CanCopy            bool
	ShareUploadBaseURL string
	Error              *util.I18nError
	Paths              []dirMapping
	QuotaUsage         *userQuotaUsage
}

type shareLoginPage struct {
	commonBasePage
	CurrentURL string
	Error      *util.I18nError
	CSRFToken  string
	Title      string
	Branding   UIBranding
}

type shareDownloadPage struct {
	baseClientPage
	DownloadLink string
}

type shareUploadPage struct {
	baseClientPage
	Share          *dataprovider.Share
	UploadBasePath string
}

type clientMessagePage struct {
	baseClientPage
	Error   *util.I18nError
	Success string
	Text    string
}

type clientProfilePage struct {
	baseClientPage
	PublicKeys      []string
	CanSubmit       bool
	AllowAPIKeyAuth bool
	Email           string
	Description     string
	Error           *util.I18nError
}

type changeClientPasswordPage struct {
	baseClientPage
	Error *util.I18nError
}

type clientMFAPage struct {
	baseClientPage
	TOTPConfigs       []string
	TOTPConfig        dataprovider.UserTOTPConfig
	GenerateTOTPURL   string
	ValidateTOTPURL   string
	SaveTOTPURL       string
	RecCodesURL       string
	Protocols         []string
	RequiredProtocols []string
}

type clientSharesPage struct {
	baseClientPage
	BasePublicSharesURL string
}

type clientSharePage struct {
	baseClientPage
	Share *dataprovider.Share
	Error *util.I18nError
	IsAdd bool
}

type userQuotaUsage struct {
	QuotaSize                int64
	QuotaFiles               int
	UsedQuotaSize            int64
	UsedQuotaFiles           int
	UploadDataTransfer       int64
	DownloadDataTransfer     int64
	TotalDataTransfer        int64
	UsedUploadDataTransfer   int64
	UsedDownloadDataTransfer int64
}

func (u *userQuotaUsage) HasQuotaInfo() bool {
	if dataprovider.GetQuotaTracking() == 0 {
		return false
	}
	if u.HasDiskQuota() {
		return true
	}
	return u.HasTranferQuota()
}

func (u *userQuotaUsage) HasDiskQuota() bool {
	if u.QuotaSize > 0 || u.UsedQuotaSize > 0 {
		return true
	}
	return u.QuotaFiles > 0 || u.UsedQuotaFiles > 0
}

func (u *userQuotaUsage) HasTranferQuota() bool {
	if u.TotalDataTransfer > 0 || u.UploadDataTransfer > 0 || u.DownloadDataTransfer > 0 {
		return true
	}
	return u.UsedDownloadDataTransfer > 0 || u.UsedUploadDataTransfer > 0
}

func (u *userQuotaUsage) GetQuotaSize() string {
	if u.QuotaSize > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(u.UsedQuotaSize), util.ByteCountIEC(u.QuotaSize))
	}
	if u.UsedQuotaSize > 0 {
		return util.ByteCountIEC(u.UsedQuotaSize)
	}
	return ""
}

func (u *userQuotaUsage) GetQuotaFiles() string {
	if u.QuotaFiles > 0 {
		return fmt.Sprintf("%d/%d", u.UsedQuotaFiles, u.QuotaFiles)
	}
	if u.UsedQuotaFiles > 0 {
		return strconv.FormatInt(int64(u.UsedQuotaFiles), 10)
	}
	return ""
}

func (u *userQuotaUsage) GetQuotaSizePercentage() int {
	if u.QuotaSize > 0 {
		return int(math.Round(100 * float64(u.UsedQuotaSize) / float64(u.QuotaSize)))
	}
	return 0
}

func (u *userQuotaUsage) GetQuotaFilesPercentage() int {
	if u.QuotaFiles > 0 {
		return int(math.Round(100 * float64(u.UsedQuotaFiles) / float64(u.QuotaFiles)))
	}
	return 0
}

func (u *userQuotaUsage) IsQuotaSizeLow() bool {
	return u.GetQuotaSizePercentage() > 85
}

func (u *userQuotaUsage) IsQuotaFilesLow() bool {
	return u.GetQuotaFilesPercentage() > 85
}

func (u *userQuotaUsage) IsDiskQuotaLow() bool {
	return u.IsQuotaSizeLow() || u.IsQuotaFilesLow()
}

func (u *userQuotaUsage) GetTotalTransferQuota() string {
	total := u.UsedUploadDataTransfer + u.UsedDownloadDataTransfer
	if u.TotalDataTransfer > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(total), util.ByteCountIEC(u.TotalDataTransfer*1048576))
	}
	if total > 0 {
		return util.ByteCountIEC(total)
	}
	return ""
}

func (u *userQuotaUsage) GetUploadTransferQuota() string {
	if u.UploadDataTransfer > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(u.UsedUploadDataTransfer),
			util.ByteCountIEC(u.UploadDataTransfer*1048576))
	}
	if u.UsedUploadDataTransfer > 0 {
		return util.ByteCountIEC(u.UsedUploadDataTransfer)
	}
	return ""
}

func (u *userQuotaUsage) GetDownloadTransferQuota() string {
	if u.DownloadDataTransfer > 0 {
		return fmt.Sprintf("%s/%s", util.ByteCountIEC(u.UsedDownloadDataTransfer),
			util.ByteCountIEC(u.DownloadDataTransfer*1048576))
	}
	if u.UsedDownloadDataTransfer > 0 {
		return util.ByteCountIEC(u.UsedDownloadDataTransfer)
	}
	return ""
}

func (u *userQuotaUsage) GetTotalTransferQuotaPercentage() int {
	if u.TotalDataTransfer > 0 {
		return int(math.Round(100 * float64(u.UsedDownloadDataTransfer+u.UsedUploadDataTransfer) / float64(u.TotalDataTransfer*1048576)))
	}
	return 0
}

func (u *userQuotaUsage) GetUploadTransferQuotaPercentage() int {
	if u.UploadDataTransfer > 0 {
		return int(math.Round(100 * float64(u.UsedUploadDataTransfer) / float64(u.UploadDataTransfer*1048576)))
	}
	return 0
}

func (u *userQuotaUsage) GetDownloadTransferQuotaPercentage() int {
	if u.DownloadDataTransfer > 0 {
		return int(math.Round(100 * float64(u.UsedDownloadDataTransfer) / float64(u.DownloadDataTransfer*1048576)))
	}
	return 0
}

func (u *userQuotaUsage) IsTotalTransferQuotaLow() bool {
	if u.TotalDataTransfer > 0 {
		return u.GetTotalTransferQuotaPercentage() > 85
	}
	return false
}

func (u *userQuotaUsage) IsUploadTransferQuotaLow() bool {
	if u.UploadDataTransfer > 0 {
		return u.GetUploadTransferQuotaPercentage() > 85
	}
	return false
}

func (u *userQuotaUsage) IsDownloadTransferQuotaLow() bool {
	if u.DownloadDataTransfer > 0 {
		return u.GetDownloadTransferQuotaPercentage() > 85
	}
	return false
}

func (u *userQuotaUsage) IsTransferQuotaLow() bool {
	return u.IsTotalTransferQuotaLow() || u.IsUploadTransferQuotaLow() || u.IsDownloadTransferQuotaLow()
}

func (u *userQuotaUsage) IsQuotaLow() bool {
	return u.IsDiskQuotaLow() || u.IsTransferQuotaLow()
}

func newUserQuotaUsage(u *dataprovider.User) *userQuotaUsage {
	return &userQuotaUsage{
		QuotaSize:                u.QuotaSize,
		QuotaFiles:               u.QuotaFiles,
		UsedQuotaSize:            u.UsedQuotaSize,
		UsedQuotaFiles:           u.UsedQuotaFiles,
		TotalDataTransfer:        u.TotalDataTransfer,
		UploadDataTransfer:       u.UploadDataTransfer,
		DownloadDataTransfer:     u.DownloadDataTransfer,
		UsedUploadDataTransfer:   u.UsedUploadDataTransfer,
		UsedDownloadDataTransfer: u.UsedDownloadDataTransfer,
	}
}

func getFileObjectURL(baseDir, name, baseWebPath string) string {
	return fmt.Sprintf("%v?path=%v&_=%v", baseWebPath, url.QueryEscape(path.Join(baseDir, name)), time.Now().UTC().Unix())
}

func getFileObjectModTime(t time.Time) int64 {
	if isZeroTime(t) {
		return 0
	}
	return t.UnixMilli()
}

func loadClientTemplates(templatesPath string) {
	filesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientFiles),
	}
	editFilePath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientEditFile),
	}
	sharesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShares),
	}
	sharePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShare),
	}
	profilePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientProfile),
	}
	changePwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateCommonDir, templateChangePwd),
	}
	loginPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateCommonLogin),
	}
	messagePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateCommonDir, templateMessage),
	}
	mfaPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientMFA),
	}
	twoFactorPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateTwoFactor),
	}
	twoFactorRecoveryPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateTwoFactorRecovery),
	}
	forgotPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateForgotPassword),
	}
	resetPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateResetPassword),
	}
	viewPDFPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientViewPDF),
	}
	shareLoginPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateShareLogin),
	}
	shareUploadPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateUploadToShare),
	}
	shareDownloadPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateShareDownload),
	}

	filesTmpl := util.LoadTemplate(nil, filesPaths...)
	profileTmpl := util.LoadTemplate(nil, profilePaths...)
	changePwdTmpl := util.LoadTemplate(nil, changePwdPaths...)
	loginTmpl := util.LoadTemplate(nil, loginPaths...)
	messageTmpl := util.LoadTemplate(nil, messagePaths...)
	mfaTmpl := util.LoadTemplate(nil, mfaPaths...)
	twoFactorTmpl := util.LoadTemplate(nil, twoFactorPaths...)
	twoFactorRecoveryTmpl := util.LoadTemplate(nil, twoFactorRecoveryPaths...)
	editFileTmpl := util.LoadTemplate(nil, editFilePath...)
	shareLoginTmpl := util.LoadTemplate(nil, shareLoginPath...)
	sharesTmpl := util.LoadTemplate(nil, sharesPaths...)
	shareTmpl := util.LoadTemplate(nil, sharePaths...)
	forgotPwdTmpl := util.LoadTemplate(nil, forgotPwdPaths...)
	resetPwdTmpl := util.LoadTemplate(nil, resetPwdPaths...)
	viewPDFTmpl := util.LoadTemplate(nil, viewPDFPaths...)
	shareUploadTmpl := util.LoadTemplate(nil, shareUploadPath...)
	shareDownloadTmpl := util.LoadTemplate(nil, shareDownloadPath...)

	clientTemplates[templateClientFiles] = filesTmpl
	clientTemplates[templateClientProfile] = profileTmpl
	clientTemplates[templateChangePwd] = changePwdTmpl
	clientTemplates[templateCommonLogin] = loginTmpl
	clientTemplates[templateMessage] = messageTmpl
	clientTemplates[templateClientMFA] = mfaTmpl
	clientTemplates[templateTwoFactor] = twoFactorTmpl
	clientTemplates[templateTwoFactorRecovery] = twoFactorRecoveryTmpl
	clientTemplates[templateClientEditFile] = editFileTmpl
	clientTemplates[templateClientShares] = sharesTmpl
	clientTemplates[templateClientShare] = shareTmpl
	clientTemplates[templateForgotPassword] = forgotPwdTmpl
	clientTemplates[templateResetPassword] = resetPwdTmpl
	clientTemplates[templateClientViewPDF] = viewPDFTmpl
	clientTemplates[templateShareLogin] = shareLoginTmpl
	clientTemplates[templateUploadToShare] = shareUploadTmpl
	clientTemplates[templateShareDownload] = shareDownloadTmpl
}

func (s *httpdServer) getBaseClientPageData(title, currentURL string, r *http.Request) baseClientPage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken(util.GetIPFromRemoteAddress(r.RemoteAddr))
	}

	data := baseClientPage{
		commonBasePage: getCommonBasePage(r),
		Title:          title,
		CurrentURL:     currentURL,
		FilesURL:       webClientFilesPath,
		SharesURL:      webClientSharesPath,
		ShareURL:       webClientSharePath,
		ProfileURL:     webClientProfilePath,
		PingURL:        webClientPingPath,
		ChangePwdURL:   webChangeClientPwdPath,
		LogoutURL:      webClientLogoutPath,
		EditURL:        webClientEditFilePath,
		MFAURL:         webClientMFAPath,
		CSRFToken:      csrfToken,
		LoggedUser:     getUserFromToken(r),
		Branding:       s.binding.Branding.WebClient,
	}
	if !strings.HasPrefix(r.RequestURI, webClientPubSharesPath) {
		data.LoginURL = webClientLoginPath
	}
	return data
}

func (s *httpdServer) renderClientForgotPwdPage(w http.ResponseWriter, r *http.Request, err *util.I18nError, ip string) {
	data := forgotPwdPage{
		commonBasePage: getCommonBasePage(r),
		CurrentURL:     webClientForgotPwdPath,
		Error:          err,
		CSRFToken:      createCSRFToken(ip),
		LoginURL:       webClientLoginPath,
		Title:          util.I18nForgotPwdTitle,
		Branding:       s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateForgotPassword, data)
}

func (s *httpdServer) renderClientResetPwdPage(w http.ResponseWriter, r *http.Request, err *util.I18nError, ip string) {
	data := resetPwdPage{
		commonBasePage: getCommonBasePage(r),
		CurrentURL:     webClientResetPwdPath,
		Error:          err,
		CSRFToken:      createCSRFToken(ip),
		LoginURL:       webClientLoginPath,
		Title:          util.I18nResetPwdTitle,
		Branding:       s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateResetPassword, data)
}

func (s *httpdServer) renderShareLoginPage(w http.ResponseWriter, r *http.Request, err *util.I18nError, ip string) {
	data := shareLoginPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18nShareLoginTitle,
		CurrentURL:     r.RequestURI,
		Error:          err,
		CSRFToken:      createCSRFToken(ip),
		Branding:       s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateShareLogin, data)
}

func renderClientTemplate(w http.ResponseWriter, tmplName string, data any) {
	err := clientTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *httpdServer) renderClientMessagePage(w http.ResponseWriter, r *http.Request, title string, statusCode int, err error, message string) {
	data := clientMessagePage{
		baseClientPage: s.getBaseClientPageData(title, "", r),
		Error:          getI18nError(err),
		Success:        message,
	}
	w.WriteHeader(statusCode)
	renderClientTemplate(w, templateMessage, data)
}

func (s *httpdServer) renderClientInternalServerErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError500Title, http.StatusInternalServerError,
		util.NewI18nError(err, util.I18nError500Message), "")
}

func (s *httpdServer) renderClientBadRequestPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError400Title, http.StatusBadRequest,
		util.NewI18nError(err, util.I18nError400Message), "")
}

func (s *httpdServer) renderClientForbiddenPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError403Title, http.StatusForbidden,
		util.NewI18nError(err, util.I18nError403Message), "")
}

func (s *httpdServer) renderClientNotFoundPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError404Title, http.StatusNotFound,
		util.NewI18nError(err, util.I18nError404Message), "")
}

func (s *httpdServer) renderClientTwoFactorPage(w http.ResponseWriter, r *http.Request, err *util.I18nError, ip string) {
	data := twoFactorPage{
		commonBasePage: getCommonBasePage(r),
		Title:          pageTwoFactorTitle,
		CurrentURL:     webClientTwoFactorPath,
		Error:          err,
		CSRFToken:      createCSRFToken(ip),
		RecoveryURL:    webClientTwoFactorRecoveryPath,
		Branding:       s.binding.Branding.WebClient,
	}
	if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
		data.CurrentURL += "?next=" + url.QueryEscape(next)
	}
	renderClientTemplate(w, templateTwoFactor, data)
}

func (s *httpdServer) renderClientTwoFactorRecoveryPage(w http.ResponseWriter, r *http.Request, err *util.I18nError, ip string) {
	data := twoFactorPage{
		commonBasePage: getCommonBasePage(r),
		Title:          pageTwoFactorRecoveryTitle,
		CurrentURL:     webClientTwoFactorRecoveryPath,
		Error:          err,
		CSRFToken:      createCSRFToken(ip),
		Branding:       s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateTwoFactorRecovery, data)
}

func (s *httpdServer) renderClientMFAPage(w http.ResponseWriter, r *http.Request) {
	data := clientMFAPage{
		baseClientPage:  s.getBaseClientPageData(util.I18n2FATitle, webClientMFAPath, r),
		TOTPConfigs:     mfa.GetAvailableTOTPConfigNames(),
		GenerateTOTPURL: webClientTOTPGeneratePath,
		ValidateTOTPURL: webClientTOTPValidatePath,
		SaveTOTPURL:     webClientTOTPSavePath,
		RecCodesURL:     webClientRecoveryCodesPath,
		Protocols:       dataprovider.MFAProtocols,
	}
	user, err := dataprovider.GetUserWithGroupSettings(data.LoggedUser.Username, "")
	if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	data.TOTPConfig = user.Filters.TOTPConfig
	data.RequiredProtocols = user.Filters.TwoFactorAuthProtocols
	renderClientTemplate(w, templateClientMFA, data)
}

func (s *httpdServer) renderEditFilePage(w http.ResponseWriter, r *http.Request, fileName, fileData string, readOnly bool) {
	title := util.I18nViewFileTitle
	if !readOnly {
		title = util.I18nEditFileTitle
	}
	data := editFilePage{
		baseClientPage: s.getBaseClientPageData(title, webClientEditFilePath, r),
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
	err *util.I18nError, isAdd bool) {
	currentURL := webClientSharePath
	title := util.I18nShareAddTitle
	if !isAdd {
		currentURL = fmt.Sprintf("%v/%v", webClientSharePath, url.PathEscape(share.ShareID))
		title = util.I18nShareUpdateTitle
	}
	data := clientSharePage{
		baseClientPage: s.getBaseClientPageData(title, currentURL, r),
		Share:          share,
		Error:          err,
		IsAdd:          isAdd,
	}

	renderClientTemplate(w, templateClientShare, data)
}

func getDirMapping(dirName, baseWebPath string) []dirMapping {
	paths := []dirMapping{}
	if dirName != "/" {
		paths = append(paths, dirMapping{
			DirName: path.Base(dirName),
			Href:    getFileObjectURL("/", dirName, baseWebPath),
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

func (s *httpdServer) renderSharedFilesPage(w http.ResponseWriter, r *http.Request, dirName string,
	err *util.I18nError, share dataprovider.Share,
) {
	currentURL := path.Join(webClientPubSharesPath, share.ShareID, "browse")
	baseData := s.getBaseClientPageData(util.I18nSharedFilesTitle, currentURL, r)
	baseData.FilesURL = currentURL
	baseSharePath := path.Join(webClientPubSharesPath, share.ShareID)

	data := filesPage{
		baseClientPage: baseData,
		Error:          err,
		CurrentDir:     url.QueryEscape(dirName),
		DownloadURL:    path.Join(baseSharePath, "partial"),
		// dirName must be escaped because the router expects the full path as single argument
		ShareUploadBaseURL: path.Join(baseSharePath, url.PathEscape(dirName)),
		ViewPDFURL:         path.Join(baseSharePath, "viewpdf"),
		DirsURL:            path.Join(baseSharePath, "dirs"),
		FileURL:            "",
		FileActionsURL:     "",
		CheckExistURL:      path.Join(baseSharePath, "browse", "exist"),
		TasksURL:           "",
		CanAddFiles:        share.Scope == dataprovider.ShareScopeReadWrite,
		CanCreateDirs:      false,
		CanRename:          false,
		CanDelete:          false,
		CanDownload:        share.Scope != dataprovider.ShareScopeWrite,
		CanShare:           false,
		CanCopy:            false,
		Paths:              getDirMapping(dirName, currentURL),
		QuotaUsage:         newUserQuotaUsage(&dataprovider.User{}),
	}
	renderClientTemplate(w, templateClientFiles, data)
}

func (s *httpdServer) renderShareDownloadPage(w http.ResponseWriter, r *http.Request, downloadLink string) {
	data := shareDownloadPage{
		baseClientPage: s.getBaseClientPageData(util.I18nShareDownloadTitle, "", r),
		DownloadLink:   downloadLink,
	}
	renderClientTemplate(w, templateShareDownload, data)
}

func (s *httpdServer) renderUploadToSharePage(w http.ResponseWriter, r *http.Request, share dataprovider.Share) {
	currentURL := path.Join(webClientPubSharesPath, share.ShareID, "upload")
	data := shareUploadPage{
		baseClientPage: s.getBaseClientPageData(util.I18nShareUploadTitle, currentURL, r),
		Share:          &share,
		UploadBasePath: path.Join(webClientPubSharesPath, share.ShareID),
	}
	renderClientTemplate(w, templateUploadToShare, data)
}

func (s *httpdServer) renderFilesPage(w http.ResponseWriter, r *http.Request, dirName string,
	err *util.I18nError, user *dataprovider.User) {
	data := filesPage{
		baseClientPage:     s.getBaseClientPageData(util.I18nFilesTitle, webClientFilesPath, r),
		Error:              err,
		CurrentDir:         url.QueryEscape(dirName),
		DownloadURL:        webClientDownloadZipPath,
		ViewPDFURL:         webClientViewPDFPath,
		DirsURL:            webClientDirsPath,
		FileURL:            webClientFilePath,
		FileActionsURL:     webClientFileActionsPath,
		CheckExistURL:      webClientExistPath,
		TasksURL:           webClientTasksPath,
		CanAddFiles:        user.CanAddFilesFromWeb(dirName),
		CanCreateDirs:      user.CanAddDirsFromWeb(dirName),
		CanRename:          user.CanRenameFromWeb(dirName, dirName),
		CanDelete:          user.CanDeleteFromWeb(dirName),
		CanDownload:        user.HasPerm(dataprovider.PermDownload, dirName),
		CanShare:           user.CanManageShares(),
		CanCopy:            user.CanCopyFromWeb(dirName, dirName),
		ShareUploadBaseURL: "",
		Paths:              getDirMapping(dirName, webClientFilesPath),
		QuotaUsage:         newUserQuotaUsage(user),
	}
	renderClientTemplate(w, templateClientFiles, data)
}

func (s *httpdServer) renderClientProfilePage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := clientProfilePage{
		baseClientPage: s.getBaseClientPageData(util.I18nProfileTitle, webClientProfilePath, r),
		Error:          err,
	}
	user, userMerged, errUser := dataprovider.GetUserVariants(data.LoggedUser.Username, "")
	if errUser != nil {
		s.renderClientInternalServerErrorPage(w, r, errUser)
		return
	}
	data.PublicKeys = user.PublicKeys
	data.AllowAPIKeyAuth = user.Filters.AllowAPIKeyAuth
	data.Email = user.Email
	data.Description = user.Description
	data.CanSubmit = userMerged.CanChangeAPIKeyAuth() || userMerged.CanManagePublicKeys() || userMerged.CanChangeInfo()
	renderClientTemplate(w, templateClientProfile, data)
}

func (s *httpdServer) renderClientChangePasswordPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := changeClientPasswordPage{
		baseClientPage: s.getBaseClientPageData(util.I18nChangePwdTitle, webChangeClientPwdPath, r),
		Error:          err,
	}

	renderClientTemplate(w, templateChangePwd, data)
}

func (s *httpdServer) handleWebClientDownloadZip(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartMem)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	files := r.Form.Get("files")
	var filesList []string
	err = json.Unmarshal([]byte(files), &filesList)
	if err != nil {
		s.renderClientBadRequestPage(w, r, err)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		getCompressedFileName(connection.GetUsername(), filesList)))
	renderCompressedFiles(w, connection, name, filesList, nil)
}

func (s *httpdServer) handleClientSharePartialDownload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartMem)
	if err := r.ParseForm(); err != nil {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	transferQuota := connection.GetTransferQuota()
	if !transferQuota.HasDownloadSpace() {
		err = util.NewI18nError(connection.GetReadQuotaExceededError(), util.I18nErrorQuotaRead)
		connection.Log(logger.LevelInfo, "denying share read due to quota limits")
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getMappedStatusCode(err), err, "")
		return
	}
	files := r.Form.Get("files")
	var filesList []string
	err = json.Unmarshal([]byte(files), &filesList)
	if err != nil {
		s.renderClientBadRequestPage(w, r, err)
		return
	}

	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		getCompressedFileName(fmt.Sprintf("share-%s", share.Name), filesList)))
	renderCompressedFiles(w, connection, name, filesList, &share)
}

func (s *httpdServer) handleShareGetDirContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nError500Message), getRespStatus(err))
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nError500Message), getRespStatus(err))
		return
	}
	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nError429Message), http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	lister, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nErrorDirListGeneric), getMappedStatusCode(err))
		return
	}
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
			if !info.Mode().IsDir() && !info.Mode().IsRegular() {
				continue
			}
			res := make(map[string]any)
			if info.IsDir() {
				res["type"] = "1"
				res["size"] = ""
			} else {
				res["type"] = "2"
				res["size"] = info.Size()
			}
			res["meta"] = fmt.Sprintf("%v_%v", res["type"], info.Name())
			res["name"] = info.Name()
			res["url"] = getFileObjectURL(share.GetRelativePath(name), info.Name(),
				path.Join(webClientPubSharesPath, share.ShareID, "browse"))
			res["last_modified"] = getFileObjectModTime(info.ModTime())
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

func (s *httpdServer) handleClientUploadToShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeWrite, dataprovider.ShareScopeReadWrite}
	share, _, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if share.Scope == dataprovider.ShareScopeReadWrite {
		http.Redirect(w, r, path.Join(webClientPubSharesPath, share.ShareID, "browse"), http.StatusFound)
		return
	}
	s.renderUploadToSharePage(w, r, share)
}

func (s *httpdServer) handleShareGetFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)),
			util.NewI18nError(err, util.I18nError429Message), share)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Unix(0, 0), false)
	} else {
		info, err = connection.Stat(name, 1)
	}
	if err != nil {
		s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)),
			util.NewI18nError(err, i18nFsMsg(getRespStatus(err))), share)
		return
	}
	if info.IsDir() {
		s.renderSharedFilesPage(w, r, share.GetRelativePath(name), nil, share)
		return
	}
	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	if status, err := downloadFile(w, r, connection, name, info, false, &share); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
		if status > 0 {
			s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)),
				util.NewI18nError(err, i18nFsMsg(getRespStatus(err))), share)
		}
	}
}

func (s *httpdServer) handleShareViewPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, _, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	name := util.CleanPath(r.URL.Query().Get("path"))
	data := viewPDFPage{
		commonBasePage: getCommonBasePage(r),
		Title:          path.Base(name),
		URL: fmt.Sprintf("%s?path=%s&_=%d", path.Join(webClientPubSharesPath, share.ShareID, "getpdf"),
			url.QueryEscape(name), time.Now().UTC().Unix()),
		Branding: s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateClientViewPDF, data)
}

func (s *httpdServer) handleShareGetPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	info, err := connection.Stat(name, 1)
	if err != nil {
		status := getRespStatus(err)
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, status,
			util.NewI18nError(err, i18nFsMsg(status)), "")
		return
	}
	if info.IsDir() {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(fmt.Errorf("%q is not a file", name), util.I18nErrorPDFMessage))
		return
	}
	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	if err := s.ensurePDF(w, r, name, connection); err != nil {
		return
	}
	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	if _, err := downloadFile(w, r, connection, name, info, true, &share); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
	}
}

func (s *httpdServer) handleClientGetDirContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, nil, util.I18nErrorDirList403, http.StatusForbidden)
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, nil, util.I18nErrorDirListUser, getRespStatus(err))
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%s_%s", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nErrorDirList403), http.StatusForbidden)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, util.I18nErrorDirList429, http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	lister, err := connection.ReadDir(name)
	if err != nil {
		statusCode := getMappedStatusCode(err)
		sendAPIResponse(w, r, err, i18nListDirMsg(statusCode), statusCode)
		return
	}
	defer lister.Close()

	dirTree := r.URL.Query().Get("dirtree") == "1"
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
			res := make(map[string]any)
			res["url"] = getFileObjectURL(name, info.Name(), webClientFilesPath)
			if info.IsDir() {
				res["type"] = "1"
				res["size"] = ""
				res["dir_path"] = url.QueryEscape(path.Join(name, info.Name()))
			} else {
				if dirTree {
					continue
				}
				res["type"] = "2"
				if info.Mode()&os.ModeSymlink != 0 {
					res["size"] = ""
				} else {
					res["size"] = info.Size()
					if info.Size() < httpdMaxEditFileSize {
						res["edit_url"] = strings.Replace(res["url"].(string), webClientFilesPath, webClientEditFilePath, 1)
					}
				}
			}
			res["meta"] = fmt.Sprintf("%v_%v", res["type"], info.Name())
			res["name"] = info.Name()
			res["last_modified"] = getFileObjectModTime(info.ModTime())
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

func (s *httpdServer) handleClientGetFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Unix(0, 0), false)
	} else {
		info, err = connection.Stat(name, 0)
	}
	if err != nil {
		s.renderFilesPage(w, r, path.Dir(name), util.NewI18nError(err, i18nFsMsg(getRespStatus(err))), &user)
		return
	}
	if info.IsDir() {
		s.renderFilesPage(w, r, name, nil, &user)
		return
	}
	if status, err := downloadFile(w, r, connection, name, info, false, nil); err != nil && status != 0 {
		if status > 0 {
			if status == http.StatusRequestedRangeNotSatisfiable {
				s.renderClientMessagePage(w, r, util.I18nError416Title, status,
					util.NewI18nError(err, util.I18nError416Message), "")
				return
			}
			s.renderFilesPage(w, r, path.Dir(name), util.NewI18nError(err, i18nFsMsg(status)), &user)
		}
	}
}

func (s *httpdServer) handleClientEditFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	info, err := connection.Stat(name, 0)
	if err != nil {
		status := getRespStatus(err)
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, status, util.NewI18nError(err, i18nFsMsg(status)), "")
		return
	}
	if info.IsDir() {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, http.StatusBadRequest,
			util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("The path %q does not point to a file", name)),
				util.I18nErrorEditDir,
			), "")
		return
	}
	if info.Size() > httpdMaxEditFileSize {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, http.StatusBadRequest,
			util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("The file size %v for %q exceeds the maximum allowed size",
					util.ByteCountIEC(info.Size()), name)),
				util.I18nErrorEditSize,
			), "")
		return
	}

	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, getRespStatus(err),
			util.NewI18nError(err, util.I18nError500Message), "")
		return
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.Copy(&b, reader)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, getRespStatus(err),
			util.NewI18nError(err, util.I18nError500Message), "")
		return
	}

	s.renderEditFilePage(w, r, name, b.String(), !user.CanAddFilesFromWeb(path.Dir(name)))
}

func (s *httpdServer) handleClientAddShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}
	share := &dataprovider.Share{Scope: dataprovider.ShareScopeRead}
	if user.Filters.DefaultSharesExpiration > 0 {
		share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(user.Filters.DefaultSharesExpiration)))
	} else if user.Filters.MaxSharesExpiration > 0 {
		share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(user.Filters.MaxSharesExpiration)))
	}
	dirName := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		dirName = util.CleanPath(r.URL.Query().Get("path"))
	}

	if _, ok := r.URL.Query()["files"]; ok {
		files := r.URL.Query().Get("files")
		var filesList []string
		err := json.Unmarshal([]byte(files), &filesList)
		if err != nil {
			s.renderClientBadRequestPage(w, r, err)
			return
		}
		for _, f := range filesList {
			if f != "" {
				share.Paths = append(share.Paths, path.Join(dirName, f))
			}
		}
	}

	s.renderAddUpdateSharePage(w, r, share, nil, true)
}

func (s *httpdServer) handleClientUpdateShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err == nil {
		share.HideConfidentialData()
		s.renderAddUpdateSharePage(w, r, &share, nil, false)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderClientNotFoundPage(w, r, err)
	} else {
		s.renderClientInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleClientAddSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	share, err := getShareFromPostFields(r)
	if err != nil {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(err, util.I18nError500Message), true)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	share.ID = 0
	share.ShareID = util.GenerateUniqueID()
	share.LastUseAt = 0
	share.Username = claims.Username
	if share.Password == "" {
		if util.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			s.renderAddUpdateSharePage(w, r, share,
				util.NewI18nError(util.NewValidationError("You are not allowed to share files/folders without password"), util.I18nErrorShareNoPwd),
				true)
			return
		}
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(err, util.I18nErrorGetUser), true)
		return
	}
	if err := user.CheckMaxShareExpiration(util.GetTimeFromMsecSinceEpoch(share.ExpiresAt)); err != nil {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(
			err,
			util.I18nErrorShareExpirationOutOfRange,
			util.I18nErrorArgs(
				map[string]any{
					"val": time.Now().Add(24 * time.Hour * time.Duration(user.Filters.MaxSharesExpiration+1)).UnixMilli(),
					"formatParams": map[string]string{
						"year":  "numeric",
						"month": "numeric",
						"day":   "numeric",
					},
				},
			),
		), true)
		return
	}
	err = dataprovider.AddShare(share, claims.Username, ipAddr, claims.Role)
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(err, util.I18nErrorShareGeneric), true)
	}
}

func (s *httpdServer) handleClientUpdateSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if errors.Is(err, util.ErrNotFound) {
		s.renderClientNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	updatedShare, err := getShareFromPostFields(r)
	if err != nil {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(err, util.I18nError500Message), false)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedShare.ShareID = shareID
	updatedShare.Username = claims.Username
	if updatedShare.Password == redactedSecret {
		updatedShare.Password = share.Password
	}
	if updatedShare.Password == "" {
		if util.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			s.renderAddUpdateSharePage(w, r, updatedShare,
				util.NewI18nError(util.NewValidationError("You are not allowed to share files/folders without password"), util.I18nErrorShareNoPwd),
				false)
			return
		}
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(err, util.I18nErrorGetUser), false)
		return
	}
	if err := user.CheckMaxShareExpiration(util.GetTimeFromMsecSinceEpoch(updatedShare.ExpiresAt)); err != nil {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(
			err,
			util.I18nErrorShareExpirationOutOfRange,
			util.I18nErrorArgs(
				map[string]any{
					"val": time.Now().Add(24 * time.Hour * time.Duration(user.Filters.MaxSharesExpiration+1)).UnixMilli(),
					"formatParams": map[string]string{
						"year":  "numeric",
						"month": "numeric",
						"day":   "numeric",
					},
				},
			),
		), false)
		return
	}
	err = dataprovider.UpdateShare(updatedShare, claims.Username, ipAddr, claims.Role)
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(err, util.I18nErrorShareGeneric), false)
	}
}

func getAllShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, nil, util.I18nErrorInvalidToken, http.StatusForbidden)
		return
	}

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		shares, err := dataprovider.GetShares(limit, offset, dataprovider.OrderASC, claims.Username)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(shares)
		return data, len(shares), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleClientGetShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := clientSharesPage{
		baseClientPage:      s.getBaseClientPageData(util.I18nSharesTitle, webClientSharesPath, r),
		BasePublicSharesURL: webClientPubSharesPath,
	}
	renderClientTemplate(w, templateClientShares, data)
}

func (s *httpdServer) handleClientGetProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientProfilePage(w, r, nil)
}

func (s *httpdServer) handleWebClientChangePwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientChangePasswordPage(w, r, nil)
}

func (s *httpdServer) handleWebClientProfilePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderClientProfilePage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	user, userMerged, err := dataprovider.GetUserVariants(claims.Username, "")
	if err != nil {
		s.renderClientProfilePage(w, r, util.NewI18nError(err, util.I18nErrorGetUser))
		return
	}
	if !userMerged.CanManagePublicKeys() && !userMerged.CanChangeAPIKeyAuth() && !userMerged.CanChangeInfo() {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(
			errors.New("you are not allowed to change anything"),
			util.I18nErrorNoPermissions,
		))
		return
	}
	if userMerged.CanManagePublicKeys() {
		for k := range r.Form {
			if hasPrefixAndSuffix(k, "public_keys[", "][public_key]") {
				r.Form.Add("public_keys", r.Form.Get(k))
			}
		}
		user.PublicKeys = r.Form["public_keys"]
	}
	if userMerged.CanChangeAPIKeyAuth() {
		user.Filters.AllowAPIKeyAuth = r.Form.Get("allow_api_key_auth") != ""
	}
	if userMerged.CanChangeInfo() {
		user.Email = strings.TrimSpace(r.Form.Get("email"))
		user.Description = r.Form.Get("description")
	}
	err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role)
	if err != nil {
		s.renderClientProfilePage(w, r, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	s.renderClientMessagePage(w, r, util.I18nProfileTitle, http.StatusOK, nil, util.I18nProfileUpdated)
}

func (s *httpdServer) handleWebClientMFA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientMFAPage(w, r)
}

func (s *httpdServer) handleWebClientTwoFactor(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientTwoFactorPage(w, r, nil, util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebClientTwoFactorRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientTwoFactorRecoveryPage(w, r, nil, util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func getShareFromPostFields(r *http.Request) (*dataprovider.Share, error) {
	share := &dataprovider.Share{}
	if err := r.ParseForm(); err != nil {
		return share, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	for k := range r.Form {
		if hasPrefixAndSuffix(k, "paths[", "][path]") {
			r.Form.Add("paths", r.Form.Get(k))
		}
	}

	share.Name = strings.TrimSpace(r.Form.Get("name"))
	share.Description = r.Form.Get("description")
	for _, p := range r.Form["paths"] {
		if strings.TrimSpace(p) != "" {
			share.Paths = append(share.Paths, p)
		}
	}
	share.Password = strings.TrimSpace(r.Form.Get("password"))
	share.AllowFrom = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	scope, err := strconv.Atoi(r.Form.Get("scope"))
	if err != nil {
		return share, util.NewI18nError(err, util.I18nErrorShareScope)
	}
	share.Scope = dataprovider.ShareScope(scope)
	maxTokens, err := strconv.Atoi(r.Form.Get("max_tokens"))
	if err != nil {
		return share, util.NewI18nError(err, util.I18nErrorShareMaxTokens)
	}
	share.MaxTokens = maxTokens
	expirationDateMillis := int64(0)
	expirationDateString := strings.TrimSpace(r.Form.Get("expiration_date"))
	if expirationDateString != "" {
		expirationDate, err := time.Parse(webDateTimeFormat, expirationDateString)
		if err != nil {
			return share, util.NewI18nError(err, util.I18nErrorShareExpiration)
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
	s.renderClientForgotPwdPage(w, r, nil, util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebClientForgotPwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderClientForgotPwdPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm), ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	err = handleForgotPassword(r, username, false)
	if err != nil {
		s.renderClientForgotPwdPage(w, r, util.NewI18nError(err, util.I18nErrorPwdResetGeneric), ipAddr)
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
	s.renderClientResetPwdPage(w, r, nil, util.GetIPFromRemoteAddress(r.RemoteAddr))
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
		commonBasePage: getCommonBasePage(r),
		Title:          path.Base(name),
		URL:            fmt.Sprintf("%s?path=%s&_=%d", webClientGetPDFPath, url.QueryEscape(name), time.Now().UTC().Unix()),
		Branding:       s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateClientViewPDF, data)
}

func (s *httpdServer) handleClientGetPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	name := r.URL.Query().Get("path")
	if name == "" {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(errors.New("no file specified"), util.I18nError400Message))
		return
	}
	name = util.CleanPath(name)
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	info, err := connection.Stat(name, 0)
	if err != nil {
		status := getRespStatus(err)
		s.renderClientMessagePage(w, r, util.I18nErrorPDFTitle, status, util.NewI18nError(err, i18nFsMsg(status)), "")
		return
	}
	if info.IsDir() {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(fmt.Errorf("%q is not a file", name), util.I18nErrorPDFMessage))
		return
	}
	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	if err := s.ensurePDF(w, r, name, connection); err != nil {
		return
	}
	downloadFile(w, r, connection, name, info, true, nil) //nolint:errcheck
}

func (s *httpdServer) ensurePDF(w http.ResponseWriter, r *http.Request, name string, connection *Connection) error {
	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorPDFTitle,
			getRespStatus(err), util.NewI18nError(err, util.I18nError500Message), "")
		return err
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.CopyN(&b, reader, 128)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorPDFTitle, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorPDFMessage), "")
		return err
	}
	if ctype := http.DetectContentType(b.Bytes()); ctype != "application/pdf" {
		connection.Log(logger.LevelDebug, "detected %q content type, expected PDF, file %q", ctype, name)
		err := fmt.Errorf("the file %q does not look like a PDF", name)
		s.renderClientBadRequestPage(w, r, util.NewI18nError(err, util.I18nErrorPDFMessage))
		return err
	}
	return nil
}

func (s *httpdServer) handleClientShareLoginGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	s.renderShareLoginPage(w, r, nil, util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleClientShareLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm), ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF), ipAddr)
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, "")
	if err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCredentials), ipAddr)
		return
	}
	match, err := share.CheckCredentials(strings.TrimSpace(r.Form.Get("share_password")))
	if !match || err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials),
			ipAddr)
		return
	}
	c := jwtTokenClaims{
		Username: shareID,
	}
	err = c.createAndSetCookie(w, r, s.tokenAuth, tokenAudienceWebShare, ipAddr)
	if err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nError500Message), ipAddr)
		return
	}
	next := path.Clean(r.URL.Query().Get("next"))
	baseShareURL := path.Join(webClientPubSharesPath, share.ShareID)
	isRedirect, redirectTo := checkShareRedirectURL(next, baseShareURL)
	if isRedirect {
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}
	s.renderClientMessagePage(w, r, util.I18nSharedFilesTitle, http.StatusOK, nil, util.I18nShareLoginOK)
}

func (s *httpdServer) handleClientSharedFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead}
	share, _, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	s.renderShareDownloadPage(w, r, path.Join(webClientPubSharesPath, share.ShareID)+query)
}

func (s *httpdServer) handleClientCheckExist(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))

	doCheckExist(w, r, connection, name)
}

func (s *httpdServer) handleClientShareCheckExist(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeReadWrite}
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
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	doCheckExist(w, r, connection, name)
}

type filesToCheck struct {
	Files []string `json:"files"`
}

func doCheckExist(w http.ResponseWriter, r *http.Request, connection *Connection, name string) {
	var filesList filesToCheck
	err := render.DecodeJSON(r.Body, &filesList)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if len(filesList.Files) == 0 {
		sendAPIResponse(w, r, errors.New("files to be checked are mandatory"), "", http.StatusBadRequest)
		return
	}

	lister, err := connection.ListDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}
	defer lister.Close()

	dataGetter := func(limit, _ int) ([]byte, int, error) {
		contents, err := lister.Next(limit)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if err != nil {
			return nil, 0, err
		}
		existing := make([]map[string]any, 0)
		for _, info := range contents {
			if util.Contains(filesList.Files, info.Name()) {
				res := make(map[string]any)
				res["name"] = info.Name()
				if info.IsDir() {
					res["type"] = "1"
					res["size"] = ""
				} else {
					res["type"] = "2"
					res["size"] = info.Size()
				}
				existing = append(existing, res)
			}
		}
		data, err := json.Marshal(existing)
		count := limit
		if len(existing) == 0 {
			count = 0
		}
		return data, count, err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func checkShareRedirectURL(next, base string) (bool, string) {
	if !strings.HasPrefix(next, base) {
		return false, ""
	}
	if next == base {
		return true, path.Join(next, "download")
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return false, ""
	}
	nextURL, err := url.Parse(next)
	if err != nil {
		return false, ""
	}
	if nextURL.Path == baseURL.Path {
		redirectURL := nextURL.JoinPath("download")
		return true, redirectURL.String()
	}
	return true, next
}

func getWebTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	taskID := getURLParam(r, "id")

	task, err := webTaskMgr.Get(taskID)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get task", getMappedStatusCode(err))
		return
	}
	if task.User != claims.Username {
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	render.JSON(w, r, task)
}

func taskDeleteDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	task := webTaskData{
		ID:        connection.GetID(),
		User:      connection.GetUsername(),
		Path:      name,
		Timestamp: util.GetTimeAsMsSinceEpoch(time.Now()),
		Status:    0,
	}
	if err := webTaskMgr.Add(task); err != nil {
		common.Connections.Remove(connection.GetID())
		sendAPIResponse(w, r, nil, "Unable to create task", http.StatusInternalServerError)
		return
	}
	go executeDeleteTask(connection, task)
	sendAPIResponse(w, r, nil, task.ID, http.StatusAccepted)
}

func taskRenameFsEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	oldName := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	newName := connection.User.GetCleanedPath(r.URL.Query().Get("target"))
	task := webTaskData{
		ID:        connection.GetID(),
		User:      connection.GetUsername(),
		Path:      oldName,
		Target:    newName,
		Timestamp: util.GetTimeAsMsSinceEpoch(time.Now()),
		Status:    0,
	}
	if err := webTaskMgr.Add(task); err != nil {
		common.Connections.Remove(connection.GetID())
		sendAPIResponse(w, r, nil, "Unable to create task", http.StatusInternalServerError)
		return
	}
	go executeRenameTask(connection, task)
	sendAPIResponse(w, r, nil, task.ID, http.StatusAccepted)
}

func taskCopyFsEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	source := r.URL.Query().Get("path")
	target := r.URL.Query().Get("target")
	copyFromSource := strings.HasSuffix(source, "/")
	copyInTarget := strings.HasSuffix(target, "/")
	source = connection.User.GetCleanedPath(source)
	target = connection.User.GetCleanedPath(target)
	if copyFromSource {
		source += "/"
	}
	if copyInTarget {
		target += "/"
	}
	task := webTaskData{
		ID:        connection.GetID(),
		User:      connection.GetUsername(),
		Path:      source,
		Target:    target,
		Timestamp: util.GetTimeAsMsSinceEpoch(time.Now()),
		Status:    0,
	}
	if err := webTaskMgr.Add(task); err != nil {
		common.Connections.Remove(connection.GetID())
		sendAPIResponse(w, r, nil, "Unable to create task", http.StatusInternalServerError)
		return
	}
	go executeCopyTask(connection, task)
	sendAPIResponse(w, r, nil, task.ID, http.StatusAccepted)
}

func executeDeleteTask(conn *Connection, task webTaskData) {
	done := make(chan bool)

	defer func() {
		close(done)
		common.Connections.Remove(conn.GetID())
	}()

	go keepAliveTask(task, done, 2*time.Minute)

	status := http.StatusOK
	if err := conn.RemoveAll(task.Path); err != nil {
		status = getMappedStatusCode(err)
	}

	task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
	task.Status = status
	err := webTaskMgr.Add(task)
	conn.Log(logger.LevelDebug, "delete task finished, status: %d, update task err: %v", status, err)
}

func executeRenameTask(conn *Connection, task webTaskData) {
	done := make(chan bool)

	defer func() {
		close(done)
		common.Connections.Remove(conn.GetID())
	}()

	go keepAliveTask(task, done, 2*time.Minute)

	status := http.StatusOK

	if !conn.IsSameResource(task.Path, task.Target) {
		if err := conn.Copy(task.Path, task.Target); err != nil {
			status = getMappedStatusCode(err)
			task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
			task.Status = status
			err = webTaskMgr.Add(task)
			conn.Log(logger.LevelDebug, "copy step for rename task finished, status: %d, update task err: %v", status, err)
			return
		}
		if err := conn.RemoveAll(task.Path); err != nil {
			status = getMappedStatusCode(err)
		}
	} else {
		if err := conn.Rename(task.Path, task.Target); err != nil {
			status = getMappedStatusCode(err)
		}
	}

	task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
	task.Status = status
	err := webTaskMgr.Add(task)
	conn.Log(logger.LevelDebug, "rename task finished, status: %d, update task err: %v", status, err)
}

func executeCopyTask(conn *Connection, task webTaskData) {
	done := make(chan bool)

	defer func() {
		close(done)
		common.Connections.Remove(conn.GetID())
	}()

	go keepAliveTask(task, done, 2*time.Minute)

	status := http.StatusOK
	if err := conn.Copy(task.Path, task.Target); err != nil {
		status = getMappedStatusCode(err)
	}

	task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
	task.Status = status
	err := webTaskMgr.Add(task)
	conn.Log(logger.LevelDebug, "copy task finished, status: %d, update task err: %v", status, err)
}

func keepAliveTask(task webTaskData, done chan bool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
			err := webTaskMgr.Add(task)
			logger.Debug(logSender, task.ID, "task timestamp updated, err: %v", err)
		}
	}
}
