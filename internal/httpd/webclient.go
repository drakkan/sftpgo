// Copyright (C) 2019-2023 Nicola Murino
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
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
	templateShareLogin              = "sharelogin.html"
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
	Branding     UIBranding
}

type dirMapping struct {
	DirName string
	Href    string
}

type viewPDFPage struct {
	Title     string
	URL       string
	StaticURL string
	Branding  UIBranding
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
	FileActionsURL  string
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
	QuotaUsage      *userQuotaUsage
}

type shareLoginPage struct {
	CurrentURL string
	Version    string
	Error      string
	CSRFToken  string
	StaticURL  string
	Branding   UIBranding
}

type shareFilesPage struct {
	baseClientPage
	CurrentDir    string
	DirsURL       string
	FilesURL      string
	DownloadURL   string
	UploadBaseURL string
	Error         string
	Paths         []dirMapping
	Scope         dataprovider.ShareScope
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

func getFileObjectModTime(t time.Time) string {
	if isZeroTime(t) {
		return ""
	}
	return t.Format("2006-01-02 15:04")
}

func loadClientTemplates(templatesPath string) {
	filesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientFiles),
	}
	editFilePath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientEditFile),
	}
	sharesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShares),
	}
	sharePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShare),
	}
	profilePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientProfile),
	}
	changePwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientChangePwd),
	}
	loginPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateClientLogin),
	}
	messagePath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientMessage),
	}
	mfaPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientMFA),
	}
	twoFactorPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateClientTwoFactor),
	}
	twoFactorRecoveryPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateClientTwoFactorRecovery),
	}
	forgotPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateCommonDir, templateForgotPassword),
	}
	resetPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateCommonDir, templateResetPassword),
	}
	viewPDFPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientViewPDF),
	}
	shareLoginPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateShareLogin),
	}
	shareFilesPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateShareFiles),
	}
	shareUploadPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonCSS),
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
	shareLoginTmpl := util.LoadTemplate(nil, shareLoginPath...)
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
	clientTemplates[templateShareLogin] = shareLoginTmpl
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
		Branding:     s.binding.Branding.WebClient,
	}
}

func (s *httpdServer) renderClientForgotPwdPage(w http.ResponseWriter, error, ip string) {
	data := forgotPwdPage{
		CurrentURL: webClientForgotPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Title:      pageClientForgotPwdTitle,
		Branding:   s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateForgotPassword, data)
}

func (s *httpdServer) renderClientResetPwdPage(w http.ResponseWriter, _ *http.Request, error, ip string) {
	data := resetPwdPage{
		CurrentURL: webClientResetPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Title:      pageClientResetPwdTitle,
		Branding:   s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateResetPassword, data)
}

func (s *httpdServer) renderShareLoginPage(w http.ResponseWriter, currentURL, error, ip string) {
	data := shareLoginPage{
		CurrentURL: currentURL,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Branding:   s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateShareLogin, data)
}

func renderClientTemplate(w http.ResponseWriter, tmplName string, data any) {
	err := clientTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *httpdServer) renderClientMessagePage(w http.ResponseWriter, r *http.Request, title, body string, statusCode int, err error, message string) {
	var errorString strings.Builder
	if body != "" {
		errorString.WriteString(body)
		errorString.WriteString(" ")
	}
	if err != nil {
		errorString.WriteString(err.Error())
	}
	data := clientMessagePage{
		baseClientPage: s.getBaseClientPageData(title, "", r),
		Error:          errorString.String(),
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

func (s *httpdServer) renderClientTwoFactorPage(w http.ResponseWriter, r *http.Request, error, ip string) {
	data := twoFactorPage{
		CurrentURL:  webClientTwoFactorPath,
		Version:     version.Get().Version,
		Error:       error,
		CSRFToken:   createCSRFToken(ip),
		StaticURL:   webStaticFilesPath,
		RecoveryURL: webClientTwoFactorRecoveryPath,
		Branding:    s.binding.Branding.WebClient,
	}
	if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
		data.CurrentURL += "?next=" + url.QueryEscape(next)
	}
	renderClientTemplate(w, templateTwoFactor, data)
}

func (s *httpdServer) renderClientTwoFactorRecoveryPage(w http.ResponseWriter, _ *http.Request, error, ip string) {
	data := twoFactorPage{
		CurrentURL: webClientTwoFactorRecoveryPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Branding:   s.binding.Branding.WebClient,
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
	user, err := dataprovider.UserExists(data.LoggedUser.Username, "")
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
		DownloadURL:    path.Join(webClientPubSharesPath, share.ShareID, "partial"),
		UploadBaseURL:  path.Join(webClientPubSharesPath, share.ShareID, url.PathEscape(dirName)),
		Error:          error,
		Paths:          getDirMapping(dirName, currentURL),
		Scope:          share.Scope,
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

func (s *httpdServer) renderFilesPage(w http.ResponseWriter, r *http.Request, dirName, error string, user *dataprovider.User,
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
		FileActionsURL:  webClientFileActionsPath,
		CanAddFiles:     user.CanAddFilesFromWeb(dirName),
		CanCreateDirs:   user.CanAddDirsFromWeb(dirName),
		CanRename:       user.CanRenameFromWeb(dirName, dirName),
		CanDelete:       user.CanDeleteFromWeb(dirName),
		CanDownload:     user.HasPerm(dataprovider.PermDownload, dirName),
		CanShare:        user.CanManageShares(),
		HasIntegrations: hasIntegrations,
		Paths:           getDirMapping(dirName, webClientFilesPath),
		QuotaUsage:      newUserQuotaUsage(user),
	}
	renderClientTemplate(w, templateClientFiles, data)
}

func (s *httpdServer) renderClientProfilePage(w http.ResponseWriter, r *http.Request, error string) {
	data := clientProfilePage{
		baseClientPage: s.getBaseClientPageData(pageClientProfileTitle, webClientProfilePath, r),
		Error:          error,
	}
	user, userMerged, err := dataprovider.GetUserVariants(data.LoggedUser.Username, "")
	if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	data.PublicKeys = user.PublicKeys
	data.AllowAPIKeyAuth = user.Filters.AllowAPIKeyAuth
	data.Email = user.Email
	data.Description = user.Description
	data.CanSubmit = userMerged.CanChangeAPIKeyAuth() || userMerged.CanManagePublicKeys() || userMerged.CanChangeInfo()
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

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	files := r.URL.Query().Get("files")
	var filesList []string
	err = json.Unmarshal([]byte(files), &filesList)
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to get files list", "", http.StatusInternalServerError, err, "")
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		getCompressedFileName(connection.GetUsername(), filesList)))
	renderCompressedFiles(w, connection, name, filesList, nil)
}

func (s *httpdServer) handleClientSharePartialDownload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
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
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	transferQuota := connection.GetTransferQuota()
	if !transferQuota.HasDownloadSpace() {
		err = connection.GetReadQuotaExceededError()
		connection.Log(logger.LevelInfo, "denying share read due to quota limits")
		s.renderClientMessagePage(w, r, "Denying share read due to quota limits", "", getMappedStatusCode(err), err, "")
		return
	}
	files := r.URL.Query().Get("files")
	var filesList []string
	err = json.Unmarshal([]byte(files), &filesList)
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to get files list", "", http.StatusInternalServerError, err, "")
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
		s.renderClientMessagePage(w, r, "Unable to validate share", "", getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share, r)
	if err != nil {
		s.renderClientMessagePage(w, r, "Invalid share path", "", getRespStatus(err), err, "")
		return
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
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

	render.JSON(w, r, results)
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
		s.renderClientMessagePage(w, r, "Unable to validate share", "", getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share, r)
	if err != nil {
		s.renderClientMessagePage(w, r, "Invalid share path", "", getRespStatus(err), err, "")
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
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
		s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)), err.Error(), share)
		return
	}
	if info.IsDir() {
		s.renderSharedFilesPage(w, r, share.GetRelativePath(name), "", share)
		return
	}
	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	if status, err := downloadFile(w, r, connection, name, info, false, &share); err != nil {
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

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, nil, "Unable to retrieve your user", getRespStatus(err))
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	contents, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}

	results := make([]map[string]any, 0, len(contents))
	for _, info := range contents {
		res := make(map[string]any)
		res["url"] = getFileObjectURL(name, info.Name(), webClientFilesPath)
		if info.IsDir() {
			res["type"] = "1"
			res["size"] = ""
		} else {
			res["type"] = "2"
			if info.Mode()&os.ModeSymlink != 0 {
				res["size"] = ""
			} else {
				res["size"] = info.Size()
				if info.Size() < httpdMaxEditFileSize {
					res["edit_url"] = strings.Replace(res["url"].(string), webClientFilesPath, webClientEditFilePath, 1)
				}
				if len(s.binding.WebClientIntegrations) > 0 {
					extension := path.Ext(info.Name())
					for idx := range s.binding.WebClientIntegrations {
						if util.Contains(s.binding.WebClientIntegrations[idx].FileExtensions, extension) {
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

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
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
		s.renderFilesPage(w, r, path.Dir(name), fmt.Sprintf("unable to stat file %q: %v", name, err),
			&user, len(s.binding.WebClientIntegrations) > 0)
		return
	}
	if info.IsDir() {
		s.renderFilesPage(w, r, name, "", &user, len(s.binding.WebClientIntegrations) > 0)
		return
	}
	if status, err := downloadFile(w, r, connection, name, info, false, nil); err != nil && status != 0 {
		if status > 0 {
			if status == http.StatusRequestedRangeNotSatisfiable {
				s.renderClientMessagePage(w, r, http.StatusText(status), "", status, err, "")
				return
			}
			s.renderFilesPage(w, r, path.Dir(name), err.Error(), &user, len(s.binding.WebClientIntegrations) > 0)
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

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	info, err := connection.Stat(name, 0)
	if err != nil {
		s.renderClientMessagePage(w, r, fmt.Sprintf("Unable to stat file %q", name), "",
			getRespStatus(err), nil, "")
		return
	}
	if info.IsDir() {
		s.renderClientMessagePage(w, r, fmt.Sprintf("The path %q does not point to a file", name), "",
			http.StatusBadRequest, nil, "")
		return
	}
	if info.Size() > httpdMaxEditFileSize {
		s.renderClientMessagePage(w, r, fmt.Sprintf("The file size %v for %q exceeds the maximum allowed size",
			util.ByteCountIEC(info.Size()), name), "", http.StatusBadRequest, nil, "")
		return
	}

	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		s.renderClientMessagePage(w, r, fmt.Sprintf("Unable to get a reader for the file %q", name), "",
			getRespStatus(err), nil, "")
		return
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.Copy(&b, reader)
	if err != nil {
		s.renderClientMessagePage(w, r, fmt.Sprintf("Unable to read the file %q", name), "", http.StatusInternalServerError,
			nil, "")
		return
	}

	s.renderEditFilePage(w, r, name, b.String(), util.Contains(user.Filters.WebClient, sdk.WebClientWriteDisabled))
}

func (s *httpdServer) handleClientAddShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}
	share := &dataprovider.Share{Scope: dataprovider.ShareScopeRead}
	if user.Filters.DefaultSharesExpiration > 0 {
		share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(user.Filters.DefaultSharesExpiration)))
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
		if util.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			s.renderClientForbiddenPage(w, r, "You are not authorized to share files/folders without a password")
			return
		}
	}
	err = dataprovider.AddShare(share, claims.Username, ipAddr, claims.Role)
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
	if errors.Is(err, util.ErrNotFound) {
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
		if util.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			s.renderClientForbiddenPage(w, r, "You are not authorized to share files/folders without a password")
			return
		}
	}
	err = dataprovider.UpdateShare(updatedShare, claims.Username, ipAddr, claims.Role)
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
	user, userMerged, err := dataprovider.GetUserVariants(claims.Username, "")
	if err != nil {
		s.renderClientProfilePage(w, r, err.Error())
		return
	}
	if !userMerged.CanManagePublicKeys() && !userMerged.CanChangeAPIKeyAuth() && !userMerged.CanChangeInfo() {
		s.renderClientForbiddenPage(w, r, "You are not allowed to change anything")
		return
	}
	if userMerged.CanManagePublicKeys() {
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
	s.renderClientTwoFactorPage(w, r, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebClientTwoFactorRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientTwoFactorRecoveryPage(w, r, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func getShareFromPostFields(r *http.Request) (*dataprovider.Share, error) {
	share := &dataprovider.Share{}
	if err := r.ParseForm(); err != nil {
		return share, err
	}
	share.Name = strings.TrimSpace(r.Form.Get("name"))
	share.Description = r.Form.Get("description")
	for _, p := range r.Form["paths"] {
		p = strings.TrimSpace(p)
		if p != "" {
			share.Paths = append(share.Paths, p)
		}
	}
	share.Password = strings.TrimSpace(r.Form.Get("password"))
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
	expirationDateString := strings.TrimSpace(r.Form.Get("expiration_date"))
	if expirationDateString != "" {
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
	username := strings.TrimSpace(r.Form.Get("username"))
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
	s.renderClientResetPwdPage(w, r, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
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
		URL:       fmt.Sprintf("%s?path=%s&_=%d", webClientGetPDFPath, url.QueryEscape(name), time.Now().UTC().Unix()),
		StaticURL: webStaticFilesPath,
		Branding:  s.binding.Branding.WebClient,
	}
	renderClientTemplate(w, templateClientViewPDF, data)
}

func (s *httpdServer) handleClientGetPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, "Invalid token claims")
		return
	}
	name := r.URL.Query().Get("path")
	if name == "" {
		s.renderClientBadRequestPage(w, r, errors.New("no file specified"))
		return
	}
	name = util.CleanPath(name)
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to retrieve your user", "", getRespStatus(err), nil, "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, "Unable to add connection", "", http.StatusTooManyRequests, err, "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	info, err := connection.Stat(name, 0)
	if err != nil {
		s.renderClientMessagePage(w, r, "Unable to get file", "", getRespStatus(err), err, "")
		return
	}
	if info.IsDir() {
		s.renderClientMessagePage(w, r, "Invalid file", fmt.Sprintf("%q is not a file", name),
			http.StatusBadRequest, nil, "")
		return
	}
	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		s.renderClientMessagePage(w, r, fmt.Sprintf("Unable to get a reader for the file %q", name), "",
			getRespStatus(err), err, "")
		return
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.CopyN(&b, reader, 128)
	if err != nil {
		s.renderClientMessagePage(w, r, "Invalid PDF file", fmt.Sprintf("Unable to validate the file %q as PDF", name),
			http.StatusBadRequest, nil, "")
		return
	}
	if ctype := http.DetectContentType(b.Bytes()); ctype != "application/pdf" {
		connection.Log(logger.LevelDebug, "detected %q content type, expected PDF, file %q", ctype, name)
		s.renderClientBadRequestPage(w, r, fmt.Errorf("the file %q does not look like a PDF", name))
		return
	}
	downloadFile(w, r, connection, name, info, true, nil) //nolint:errcheck
}

func (s *httpdServer) handleClientShareLoginGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	s.renderShareLoginPage(w, r.RequestURI, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleClientShareLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderShareLoginPage(w, r.RequestURI, err.Error(), ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderShareLoginPage(w, r.RequestURI, err.Error(), ipAddr)
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, "")
	if err != nil {
		s.renderShareLoginPage(w, r.RequestURI, dataprovider.ErrInvalidCredentials.Error(), ipAddr)
		return
	}
	match, err := share.CheckCredentials(strings.TrimSpace(r.Form.Get("share_password")))
	if !match || err != nil {
		s.renderShareLoginPage(w, r.RequestURI, dataprovider.ErrInvalidCredentials.Error(), ipAddr)
		return
	}
	c := jwtTokenClaims{
		Username: shareID,
	}
	err = c.createAndSetCookie(w, r, s.tokenAuth, tokenAudienceWebShare, ipAddr)
	if err != nil {
		s.renderShareLoginPage(w, r.RequestURI, common.ErrInternalFailure.Error(), ipAddr)
		return
	}
	next := path.Clean(r.URL.Query().Get("next"))
	if strings.HasPrefix(next, path.Join(webClientPubSharesPath, share.ShareID)) {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	s.renderClientMessagePage(w, r, "Share Login OK", "Share login successful, you can now use your link",
		http.StatusOK, nil, "")
}
