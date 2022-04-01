package httpd

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

type userPageMode int

const (
	userPageModeAdd userPageMode = iota + 1
	userPageModeUpdate
	userPageModeTemplate
)

type folderPageMode int

const (
	folderPageModeAdd folderPageMode = iota + 1
	folderPageModeUpdate
	folderPageModeTemplate
)

const (
	templateAdminDir     = "webadmin"
	templateBase         = "base.html"
	templateBaseLogin    = "baselogin.html"
	templateFsConfig     = "fsconfig.html"
	templateUsers        = "users.html"
	templateUser         = "user.html"
	templateAdmins       = "admins.html"
	templateAdmin        = "admin.html"
	templateConnections  = "connections.html"
	templateFolders      = "folders.html"
	templateFolder       = "folder.html"
	templateMessage      = "message.html"
	templateStatus       = "status.html"
	templateLogin        = "login.html"
	templateDefender     = "defender.html"
	templateProfile      = "profile.html"
	templateChangePwd    = "changepassword.html"
	templateMaintenance  = "maintenance.html"
	templateMFA          = "mfa.html"
	templateSetup        = "adminsetup.html"
	pageUsersTitle       = "Users"
	pageAdminsTitle      = "Admins"
	pageConnectionsTitle = "Connections"
	pageStatusTitle      = "Status"
	pageFoldersTitle     = "Folders"
	pageProfileTitle     = "My profile"
	pageChangePwdTitle   = "Change password"
	pageMaintenanceTitle = "Maintenance"
	pageDefenderTitle    = "Defender"
	pageForgotPwdTitle   = "SFTPGo Admin - Forgot password"
	pageResetPwdTitle    = "SFTPGo Admin - Reset password"
	pageSetupTitle       = "Create first admin user"
	defaultQueryLimit    = 500
)

var (
	adminTemplates = make(map[string]*template.Template)
)

type basePage struct {
	Title              string
	CurrentURL         string
	UsersURL           string
	UserURL            string
	UserTemplateURL    string
	AdminsURL          string
	AdminURL           string
	QuotaScanURL       string
	ConnectionsURL     string
	FoldersURL         string
	FolderURL          string
	FolderTemplateURL  string
	DefenderURL        string
	LogoutURL          string
	ProfileURL         string
	ChangePwdURL       string
	MFAURL             string
	FolderQuotaScanURL string
	StatusURL          string
	MaintenanceURL     string
	StaticURL          string
	UsersTitle         string
	AdminsTitle        string
	ConnectionsTitle   string
	FoldersTitle       string
	StatusTitle        string
	MaintenanceTitle   string
	DefenderTitle      string
	Version            string
	CSRFToken          string
	HasDefender        bool
	HasExternalLogin   bool
	LoggedAdmin        *dataprovider.Admin
	ExtraCSS           []CustomCSS
}

type usersPage struct {
	basePage
	Users []dataprovider.User
}

type adminsPage struct {
	basePage
	Admins []dataprovider.Admin
}

type foldersPage struct {
	basePage
	Folders []vfs.BaseVirtualFolder
}

type connectionsPage struct {
	basePage
	Connections []common.ConnectionStatus
}

type statusPage struct {
	basePage
	Status *ServicesStatus
}

type fsWrapper struct {
	vfs.Filesystem
	IsUserPage      bool
	HasUsersBaseDir bool
	DirPath         string
}

type userPage struct {
	basePage
	User               *dataprovider.User
	RootPerms          []string
	Error              string
	ValidPerms         []string
	ValidLoginMethods  []string
	ValidProtocols     []string
	TwoFactorProtocols []string
	WebClientOptions   []string
	RootDirPerms       []string
	RedactedSecret     string
	Mode               userPageMode
	VirtualFolders     []vfs.BaseVirtualFolder
	CanImpersonate     bool
	FsWrapper          fsWrapper
}

type adminPage struct {
	basePage
	Admin *dataprovider.Admin
	Error string
	IsAdd bool
}

type profilePage struct {
	basePage
	Error           string
	AllowAPIKeyAuth bool
	Email           string
	Description     string
}

type changePasswordPage struct {
	basePage
	Error string
}

type mfaPage struct {
	basePage
	TOTPConfigs     []string
	TOTPConfig      dataprovider.AdminTOTPConfig
	GenerateTOTPURL string
	ValidateTOTPURL string
	SaveTOTPURL     string
	RecCodesURL     string
}

type maintenancePage struct {
	basePage
	BackupPath  string
	RestorePath string
	Error       string
}

type defenderHostsPage struct {
	basePage
	DefenderHostsURL string
}

type setupPage struct {
	basePage
	Username             string
	HasInstallationCode  bool
	InstallationCodeHint string
	Error                string
}

type folderPage struct {
	basePage
	Folder    vfs.BaseVirtualFolder
	Error     string
	Mode      folderPageMode
	FsWrapper fsWrapper
}

type messagePage struct {
	basePage
	Error   string
	Success string
}

type userTemplateFields struct {
	Username   string
	Password   string
	PublicKeys []string
}

func loadAdminTemplates(templatesPath string) {
	usersPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateUsers),
	}
	userPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFsConfig),
		filepath.Join(templatesPath, templateAdminDir, templateUser),
	}
	adminsPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateAdmins),
	}
	adminPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateAdmin),
	}
	profilePaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateProfile),
	}
	changePwdPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateChangePwd),
	}
	connectionsPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateConnections),
	}
	messagePaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateMessage),
	}
	foldersPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFolders),
	}
	folderPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFsConfig),
		filepath.Join(templatesPath, templateAdminDir, templateFolder),
	}
	statusPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateStatus),
	}
	loginPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBaseLogin),
		filepath.Join(templatesPath, templateAdminDir, templateLogin),
	}
	maintenancePaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateMaintenance),
	}
	defenderPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateDefender),
	}
	mfaPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateMFA),
	}
	twoFactorPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBaseLogin),
		filepath.Join(templatesPath, templateAdminDir, templateTwoFactor),
	}
	twoFactorRecoveryPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBaseLogin),
		filepath.Join(templatesPath, templateAdminDir, templateTwoFactorRecovery),
	}
	setupPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBaseLogin),
		filepath.Join(templatesPath, templateAdminDir, templateSetup),
	}
	forgotPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateForgotPassword),
	}
	resetPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateResetPassword),
	}

	fsBaseTpl := template.New("fsBaseTemplate").Funcs(template.FuncMap{
		"ListFSProviders": func() []sdk.FilesystemProvider {
			return []sdk.FilesystemProvider{sdk.LocalFilesystemProvider, sdk.CryptedFilesystemProvider,
				sdk.S3FilesystemProvider, sdk.GCSFilesystemProvider,
				sdk.AzureBlobFilesystemProvider, sdk.SFTPFilesystemProvider,
			}
		},
	})
	usersTmpl := util.LoadTemplate(nil, usersPaths...)
	userTmpl := util.LoadTemplate(fsBaseTpl, userPaths...)
	adminsTmpl := util.LoadTemplate(nil, adminsPaths...)
	adminTmpl := util.LoadTemplate(nil, adminPaths...)
	connectionsTmpl := util.LoadTemplate(nil, connectionsPaths...)
	messageTmpl := util.LoadTemplate(nil, messagePaths...)
	foldersTmpl := util.LoadTemplate(nil, foldersPaths...)
	folderTmpl := util.LoadTemplate(fsBaseTpl, folderPaths...)
	statusTmpl := util.LoadTemplate(nil, statusPaths...)
	loginTmpl := util.LoadTemplate(nil, loginPaths...)
	profileTmpl := util.LoadTemplate(nil, profilePaths...)
	changePwdTmpl := util.LoadTemplate(nil, changePwdPaths...)
	maintenanceTmpl := util.LoadTemplate(nil, maintenancePaths...)
	defenderTmpl := util.LoadTemplate(nil, defenderPaths...)
	mfaTmpl := util.LoadTemplate(nil, mfaPaths...)
	twoFactorTmpl := util.LoadTemplate(nil, twoFactorPaths...)
	twoFactorRecoveryTmpl := util.LoadTemplate(nil, twoFactorRecoveryPaths...)
	setupTmpl := util.LoadTemplate(nil, setupPaths...)
	forgotPwdTmpl := util.LoadTemplate(nil, forgotPwdPaths...)
	resetPwdTmpl := util.LoadTemplate(nil, resetPwdPaths...)

	adminTemplates[templateUsers] = usersTmpl
	adminTemplates[templateUser] = userTmpl
	adminTemplates[templateAdmins] = adminsTmpl
	adminTemplates[templateAdmin] = adminTmpl
	adminTemplates[templateConnections] = connectionsTmpl
	adminTemplates[templateMessage] = messageTmpl
	adminTemplates[templateFolders] = foldersTmpl
	adminTemplates[templateFolder] = folderTmpl
	adminTemplates[templateStatus] = statusTmpl
	adminTemplates[templateLogin] = loginTmpl
	adminTemplates[templateProfile] = profileTmpl
	adminTemplates[templateChangePwd] = changePwdTmpl
	adminTemplates[templateMaintenance] = maintenanceTmpl
	adminTemplates[templateDefender] = defenderTmpl
	adminTemplates[templateMFA] = mfaTmpl
	adminTemplates[templateTwoFactor] = twoFactorTmpl
	adminTemplates[templateTwoFactorRecovery] = twoFactorRecoveryTmpl
	adminTemplates[templateSetup] = setupTmpl
	adminTemplates[templateForgotPassword] = forgotPwdTmpl
	adminTemplates[templateResetPassword] = resetPwdTmpl
}

func (s *httpdServer) getBasePageData(title, currentURL string, r *http.Request) basePage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken(util.GetIPFromRemoteAddress(r.RemoteAddr))
	}
	return basePage{
		Title:              title,
		CurrentURL:         currentURL,
		UsersURL:           webUsersPath,
		UserURL:            webUserPath,
		UserTemplateURL:    webTemplateUser,
		AdminsURL:          webAdminsPath,
		AdminURL:           webAdminPath,
		FoldersURL:         webFoldersPath,
		FolderURL:          webFolderPath,
		FolderTemplateURL:  webTemplateFolder,
		DefenderURL:        webDefenderPath,
		LogoutURL:          webLogoutPath,
		ProfileURL:         webAdminProfilePath,
		ChangePwdURL:       webChangeAdminPwdPath,
		MFAURL:             webAdminMFAPath,
		QuotaScanURL:       webQuotaScanPath,
		ConnectionsURL:     webConnectionsPath,
		StatusURL:          webStatusPath,
		FolderQuotaScanURL: webScanVFolderPath,
		MaintenanceURL:     webMaintenancePath,
		StaticURL:          webStaticFilesPath,
		UsersTitle:         pageUsersTitle,
		AdminsTitle:        pageAdminsTitle,
		ConnectionsTitle:   pageConnectionsTitle,
		FoldersTitle:       pageFoldersTitle,
		StatusTitle:        pageStatusTitle,
		MaintenanceTitle:   pageMaintenanceTitle,
		DefenderTitle:      pageDefenderTitle,
		Version:            version.GetAsString(),
		LoggedAdmin:        getAdminFromToken(r),
		HasDefender:        common.Config.DefenderConfig.Enabled,
		HasExternalLogin:   isLoggedInWithOIDC(r),
		CSRFToken:          csrfToken,
		ExtraCSS:           s.binding.ExtraCSS,
	}
}

func renderAdminTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := adminTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *httpdServer) renderMessagePage(w http.ResponseWriter, r *http.Request, title, body string, statusCode int,
	err error, message string,
) {
	var errorString string
	if body != "" {
		errorString = body + " "
	}
	if err != nil {
		errorString += err.Error()
	}
	data := messagePage{
		basePage: s.getBasePageData(title, "", r),
		Error:    errorString,
		Success:  message,
	}
	w.WriteHeader(statusCode)
	renderAdminTemplate(w, templateMessage, data)
}

func (s *httpdServer) renderInternalServerErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderMessagePage(w, r, page500Title, page500Body, http.StatusInternalServerError, err, "")
}

func (s *httpdServer) renderBadRequestPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderMessagePage(w, r, page400Title, "", http.StatusBadRequest, err, "")
}

func (s *httpdServer) renderForbiddenPage(w http.ResponseWriter, r *http.Request, body string) {
	s.renderMessagePage(w, r, page403Title, "", http.StatusForbidden, nil, body)
}

func (s *httpdServer) renderNotFoundPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderMessagePage(w, r, page404Title, page404Body, http.StatusNotFound, err, "")
}

func (s *httpdServer) renderForgotPwdPage(w http.ResponseWriter, error, ip string) {
	data := forgotPwdPage{
		CurrentURL: webAdminForgotPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Title:      pageForgotPwdTitle,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	renderAdminTemplate(w, templateForgotPassword, data)
}

func (s *httpdServer) renderResetPwdPage(w http.ResponseWriter, error, ip string) {
	data := resetPwdPage{
		CurrentURL: webAdminResetPwdPath,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		Title:      pageResetPwdTitle,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	renderAdminTemplate(w, templateResetPassword, data)
}

func (s *httpdServer) renderTwoFactorPage(w http.ResponseWriter, error, ip string) {
	data := twoFactorPage{
		CurrentURL:  webAdminTwoFactorPath,
		Version:     version.Get().Version,
		Error:       error,
		CSRFToken:   createCSRFToken(ip),
		StaticURL:   webStaticFilesPath,
		RecoveryURL: webAdminTwoFactorRecoveryPath,
		ExtraCSS:    s.binding.ExtraCSS,
	}
	renderAdminTemplate(w, templateTwoFactor, data)
}

func (s *httpdServer) renderTwoFactorRecoveryPage(w http.ResponseWriter, error, ip string) {
	data := twoFactorPage{
		CurrentURL: webAdminTwoFactorRecoveryPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	renderAdminTemplate(w, templateTwoFactorRecovery, data)
}

func (s *httpdServer) renderMFAPage(w http.ResponseWriter, r *http.Request) {
	data := mfaPage{
		basePage:        s.getBasePageData(pageMFATitle, webAdminMFAPath, r),
		TOTPConfigs:     mfa.GetAvailableTOTPConfigNames(),
		GenerateTOTPURL: webAdminTOTPGeneratePath,
		ValidateTOTPURL: webAdminTOTPValidatePath,
		SaveTOTPURL:     webAdminTOTPSavePath,
		RecCodesURL:     webAdminRecoveryCodesPath,
	}
	admin, err := dataprovider.AdminExists(data.LoggedAdmin.Username)
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	data.TOTPConfig = admin.Filters.TOTPConfig
	renderAdminTemplate(w, templateMFA, data)
}

func (s *httpdServer) renderProfilePage(w http.ResponseWriter, r *http.Request, error string) {
	data := profilePage{
		basePage: s.getBasePageData(pageProfileTitle, webAdminProfilePath, r),
		Error:    error,
	}
	admin, err := dataprovider.AdminExists(data.LoggedAdmin.Username)
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	data.AllowAPIKeyAuth = admin.Filters.AllowAPIKeyAuth
	data.Email = admin.Email
	data.Description = admin.Description

	renderAdminTemplate(w, templateProfile, data)
}

func (s *httpdServer) renderChangePasswordPage(w http.ResponseWriter, r *http.Request, error string) {
	data := changePasswordPage{
		basePage: s.getBasePageData(pageChangePwdTitle, webChangeAdminPwdPath, r),
		Error:    error,
	}

	renderAdminTemplate(w, templateChangePwd, data)
}

func (s *httpdServer) renderMaintenancePage(w http.ResponseWriter, r *http.Request, error string) {
	data := maintenancePage{
		basePage:    s.getBasePageData(pageMaintenanceTitle, webMaintenancePath, r),
		BackupPath:  webBackupPath,
		RestorePath: webRestorePath,
		Error:       error,
	}

	renderAdminTemplate(w, templateMaintenance, data)
}

func (s *httpdServer) renderAdminSetupPage(w http.ResponseWriter, r *http.Request, username, error string) {
	data := setupPage{
		basePage:             s.getBasePageData(pageSetupTitle, webAdminSetupPath, r),
		Username:             username,
		HasInstallationCode:  installationCode != "",
		InstallationCodeHint: installationCodeHint,
		Error:                error,
	}

	renderAdminTemplate(w, templateSetup, data)
}

func (s *httpdServer) renderAddUpdateAdminPage(w http.ResponseWriter, r *http.Request, admin *dataprovider.Admin,
	error string, isAdd bool) {
	currentURL := webAdminPath
	title := "Add a new admin"
	if !isAdd {
		currentURL = fmt.Sprintf("%v/%v", webAdminPath, url.PathEscape(admin.Username))
		title = "Update admin"
	}
	data := adminPage{
		basePage: s.getBasePageData(title, currentURL, r),
		Admin:    admin,
		Error:    error,
		IsAdd:    isAdd,
	}

	renderAdminTemplate(w, templateAdmin, data)
}

func (s *httpdServer) renderUserPage(w http.ResponseWriter, r *http.Request, user *dataprovider.User,
	mode userPageMode, error string,
) {
	folders, err := s.getWebVirtualFolders(w, r, defaultQueryLimit)
	if err != nil {
		return
	}
	user.SetEmptySecretsIfNil()
	var title, currentURL string
	switch mode {
	case userPageModeAdd:
		title = "Add a new user"
		currentURL = webUserPath
	case userPageModeUpdate:
		title = "Update user"
		currentURL = fmt.Sprintf("%v/%v", webUserPath, url.PathEscape(user.Username))
	case userPageModeTemplate:
		title = "User template"
		currentURL = webTemplateUser
	}
	if user.Password != "" && user.IsPasswordHashed() && mode == userPageModeUpdate {
		user.Password = redactedSecret
	}
	user.FsConfig.RedactedSecret = redactedSecret
	data := userPage{
		basePage:           s.getBasePageData(title, currentURL, r),
		Mode:               mode,
		Error:              error,
		User:               user,
		ValidPerms:         dataprovider.ValidPerms,
		ValidLoginMethods:  dataprovider.ValidLoginMethods,
		ValidProtocols:     dataprovider.ValidProtocols,
		TwoFactorProtocols: dataprovider.MFAProtocols,
		WebClientOptions:   sdk.WebClientOptions,
		RootDirPerms:       user.GetPermissionsForPath("/"),
		VirtualFolders:     folders,
		CanImpersonate:     os.Getuid() == 0,
		FsWrapper: fsWrapper{
			Filesystem:      user.FsConfig,
			IsUserPage:      true,
			HasUsersBaseDir: dataprovider.HasUsersBaseDir(),
			DirPath:         user.HomeDir,
		},
	}
	renderAdminTemplate(w, templateUser, data)
}

func (s *httpdServer) renderFolderPage(w http.ResponseWriter, r *http.Request, folder vfs.BaseVirtualFolder, mode folderPageMode, error string) {
	var title, currentURL string
	switch mode {
	case folderPageModeAdd:
		title = "Add a new folder"
		currentURL = webFolderPath
	case folderPageModeUpdate:
		title = "Update folder"
		currentURL = fmt.Sprintf("%v/%v", webFolderPath, url.PathEscape(folder.Name))
	case folderPageModeTemplate:
		title = "Folder template"
		currentURL = webTemplateFolder
	}
	folder.FsConfig.RedactedSecret = redactedSecret
	folder.FsConfig.SetEmptySecretsIfNil()

	data := folderPage{
		basePage: s.getBasePageData(title, currentURL, r),
		Error:    error,
		Folder:   folder,
		Mode:     mode,
		FsWrapper: fsWrapper{
			Filesystem:      folder.FsConfig,
			IsUserPage:      false,
			HasUsersBaseDir: false,
			DirPath:         folder.MappedPath,
		},
	}
	renderAdminTemplate(w, templateFolder, data)
}

func getFoldersForTemplate(r *http.Request) []string {
	var res []string
	folderNames := r.Form["tpl_foldername"]
	folders := make(map[string]bool)
	for _, name := range folderNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := folders[name]; ok {
			continue
		}
		folders[name] = true
		res = append(res, name)
	}
	return res
}

func getUsersForTemplate(r *http.Request) []userTemplateFields {
	var res []userTemplateFields
	tplUsernames := r.Form["tpl_username"]
	tplPasswords := r.Form["tpl_password"]
	tplPublicKeys := r.Form["tpl_public_keys"]

	users := make(map[string]bool)
	for idx, username := range tplUsernames {
		username = strings.TrimSpace(username)
		password := ""
		publicKey := ""
		if len(tplPasswords) > idx {
			password = strings.TrimSpace(tplPasswords[idx])
		}
		if len(tplPublicKeys) > idx {
			publicKey = strings.TrimSpace(tplPublicKeys[idx])
		}
		if username == "" {
			continue
		}
		if _, ok := users[username]; ok {
			continue
		}

		users[username] = true
		res = append(res, userTemplateFields{
			Username:   username,
			Password:   password,
			PublicKeys: []string{publicKey},
		})
	}

	return res
}

func getVirtualFoldersFromPostFields(r *http.Request) []vfs.VirtualFolder {
	var virtualFolders []vfs.VirtualFolder
	folderPaths := r.Form["vfolder_path"]
	folderNames := r.Form["vfolder_name"]
	folderQuotaSizes := r.Form["vfolder_quota_size"]
	folderQuotaFiles := r.Form["vfolder_quota_files"]
	for idx, p := range folderPaths {
		p = strings.TrimSpace(p)
		name := ""
		if len(folderNames) > idx {
			name = folderNames[idx]
		}
		if p != "" && name != "" {
			vfolder := vfs.VirtualFolder{
				BaseVirtualFolder: vfs.BaseVirtualFolder{
					Name: name,
				},
				VirtualPath: p,
				QuotaFiles:  -1,
				QuotaSize:   -1,
			}
			if len(folderQuotaSizes) > idx {
				quotaSize, err := strconv.ParseInt(strings.TrimSpace(folderQuotaSizes[idx]), 10, 64)
				if err == nil {
					vfolder.QuotaSize = quotaSize
				}
			}
			if len(folderQuotaFiles) > idx {
				quotaFiles, err := strconv.Atoi(strings.TrimSpace(folderQuotaFiles[idx]))
				if err == nil {
					vfolder.QuotaFiles = quotaFiles
				}
			}
			virtualFolders = append(virtualFolders, vfolder)
		}
	}

	return virtualFolders
}

func getUserPermissionsFromPostFields(r *http.Request) map[string][]string {
	permissions := make(map[string][]string)
	permissions["/"] = r.Form["permissions"]

	for k := range r.Form {
		if strings.HasPrefix(k, "sub_perm_path") {
			p := strings.TrimSpace(r.Form.Get(k))
			if p != "" {
				idx := strings.TrimPrefix(k, "sub_perm_path")
				permissions[p] = r.Form[fmt.Sprintf("sub_perm_permissions%v", idx)]
			}
		}
	}

	return permissions
}

func getDataTransferLimitsFromPostFields(r *http.Request) ([]sdk.DataTransferLimit, error) {
	var result []sdk.DataTransferLimit

	for k := range r.Form {
		if strings.HasPrefix(k, "data_transfer_limit_sources") {
			sources := getSliceFromDelimitedValues(r.Form.Get(k), ",")
			if len(sources) > 0 {
				dtLimit := sdk.DataTransferLimit{
					Sources: sources,
				}
				idx := strings.TrimPrefix(k, "data_transfer_limit_sources")
				ul := r.Form.Get(fmt.Sprintf("upload_data_transfer_source%v", idx))
				dl := r.Form.Get(fmt.Sprintf("download_data_transfer_source%v", idx))
				total := r.Form.Get(fmt.Sprintf("total_data_transfer_source%v", idx))
				if ul != "" {
					dataUL, err := strconv.ParseInt(ul, 10, 64)
					if err != nil {
						return result, fmt.Errorf("invalid upload_data_transfer_source%v %#v: %w", idx, ul, err)
					}
					dtLimit.UploadDataTransfer = dataUL
				}
				if dl != "" {
					dataDL, err := strconv.ParseInt(dl, 10, 64)
					if err != nil {
						return result, fmt.Errorf("invalid download_data_transfer_source%v %#v: %w", idx, dl, err)
					}
					dtLimit.DownloadDataTransfer = dataDL
				}
				if total != "" {
					dataTotal, err := strconv.ParseInt(total, 10, 64)
					if err != nil {
						return result, fmt.Errorf("invalid total_data_transfer_source%v %#v: %w", idx, total, err)
					}
					dtLimit.TotalDataTransfer = dataTotal
				}

				result = append(result, dtLimit)
			}
		}
	}

	return result, nil
}

func getBandwidthLimitsFromPostFields(r *http.Request) ([]sdk.BandwidthLimit, error) {
	var result []sdk.BandwidthLimit

	for k := range r.Form {
		if strings.HasPrefix(k, "bandwidth_limit_sources") {
			sources := getSliceFromDelimitedValues(r.Form.Get(k), ",")
			if len(sources) > 0 {
				bwLimit := sdk.BandwidthLimit{
					Sources: sources,
				}
				idx := strings.TrimPrefix(k, "bandwidth_limit_sources")
				ul := r.Form.Get(fmt.Sprintf("upload_bandwidth_source%v", idx))
				dl := r.Form.Get(fmt.Sprintf("download_bandwidth_source%v", idx))
				if ul != "" {
					bandwidthUL, err := strconv.ParseInt(ul, 10, 64)
					if err != nil {
						return result, fmt.Errorf("invalid upload_bandwidth_source%v %#v: %w", idx, ul, err)
					}
					bwLimit.UploadBandwidth = bandwidthUL
				}
				if dl != "" {
					bandwidthDL, err := strconv.ParseInt(dl, 10, 64)
					if err != nil {
						return result, fmt.Errorf("invalid download_bandwidth_source%v %#v: %w", idx, ul, err)
					}
					bwLimit.DownloadBandwidth = bandwidthDL
				}
				result = append(result, bwLimit)
			}
		}
	}

	return result, nil
}

func getPatterDenyPolicyFromString(policy string) int {
	denyPolicy := sdk.DenyPolicyDefault
	if policy == "1" {
		denyPolicy = sdk.DenyPolicyHide
	}
	return denyPolicy
}

func getFilePatternsFromPostField(r *http.Request) []sdk.PatternsFilter {
	var result []sdk.PatternsFilter

	allowedPatterns := make(map[string][]string)
	deniedPatterns := make(map[string][]string)
	patternPolicies := make(map[string]string)

	for k := range r.Form {
		if strings.HasPrefix(k, "pattern_path") {
			p := strings.TrimSpace(r.Form.Get(k))
			idx := strings.TrimPrefix(k, "pattern_path")
			filters := strings.TrimSpace(r.Form.Get(fmt.Sprintf("patterns%v", idx)))
			filters = strings.ReplaceAll(filters, " ", "")
			patternType := r.Form.Get(fmt.Sprintf("pattern_type%v", idx))
			patternPolicy := r.Form.Get(fmt.Sprintf("pattern_policy%v", idx))
			if p != "" && filters != "" {
				if patternType == "allowed" {
					allowedPatterns[p] = append(allowedPatterns[p], strings.Split(filters, ",")...)
				} else {
					deniedPatterns[p] = append(deniedPatterns[p], strings.Split(filters, ",")...)
				}
				if patternPolicy != "" && patternPolicy != "0" {
					patternPolicies[p] = patternPolicy
				}
			}
		}
	}

	for dirAllowed, allowPatterns := range allowedPatterns {
		filter := sdk.PatternsFilter{
			Path:            dirAllowed,
			AllowedPatterns: allowPatterns,
			DenyPolicy:      getPatterDenyPolicyFromString(patternPolicies[dirAllowed]),
		}
		for dirDenied, denPatterns := range deniedPatterns {
			if dirAllowed == dirDenied {
				filter.DeniedPatterns = denPatterns
				break
			}
		}
		result = append(result, filter)
	}
	for dirDenied, denPatterns := range deniedPatterns {
		found := false
		for _, res := range result {
			if res.Path == dirDenied {
				found = true
				break
			}
		}
		if !found {
			result = append(result, sdk.PatternsFilter{
				Path:           dirDenied,
				DeniedPatterns: denPatterns,
				DenyPolicy:     getPatterDenyPolicyFromString(patternPolicies[dirDenied]),
			})
		}
	}
	return result
}

func getFiltersFromUserPostFields(r *http.Request) (sdk.BaseUserFilters, error) {
	var filters sdk.BaseUserFilters
	bwLimits, err := getBandwidthLimitsFromPostFields(r)
	if err != nil {
		return filters, err
	}
	dtLimits, err := getDataTransferLimitsFromPostFields(r)
	if err != nil {
		return filters, err
	}
	filters.BandwidthLimits = bwLimits
	filters.DataTransferLimits = dtLimits
	filters.AllowedIP = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	filters.DeniedIP = getSliceFromDelimitedValues(r.Form.Get("denied_ip"), ",")
	filters.DeniedLoginMethods = r.Form["denied_login_methods"]
	filters.DeniedProtocols = r.Form["denied_protocols"]
	filters.TwoFactorAuthProtocols = r.Form["required_two_factor_protocols"]
	filters.FilePatterns = getFilePatternsFromPostField(r)
	filters.TLSUsername = sdk.TLSUsername(r.Form.Get("tls_username"))
	filters.WebClient = r.Form["web_client_options"]
	hooks := r.Form["hooks"]
	if util.IsStringInSlice("external_auth_disabled", hooks) {
		filters.Hooks.ExternalAuthDisabled = true
	}
	if util.IsStringInSlice("pre_login_disabled", hooks) {
		filters.Hooks.PreLoginDisabled = true
	}
	if util.IsStringInSlice("check_password_disabled", hooks) {
		filters.Hooks.CheckPasswordDisabled = true
	}
	filters.DisableFsChecks = len(r.Form.Get("disable_fs_checks")) > 0
	filters.AllowAPIKeyAuth = len(r.Form.Get("allow_api_key_auth")) > 0
	filters.ExternalAuthCacheTime, err = strconv.ParseInt(r.Form.Get("external_auth_cache_time"), 10, 64)
	filters.StartDirectory = r.Form.Get("start_directory")
	return filters, err
}

func getSecretFromFormField(r *http.Request, field string) *kms.Secret {
	secret := kms.NewPlainSecret(r.Form.Get(field))
	if strings.TrimSpace(secret.GetPayload()) == redactedSecret {
		secret.SetStatus(sdkkms.SecretStatusRedacted)
	}
	if strings.TrimSpace(secret.GetPayload()) == "" {
		secret.SetStatus("")
	}
	return secret
}

func getS3Config(r *http.Request) (vfs.S3FsConfig, error) {
	var err error
	config := vfs.S3FsConfig{}
	config.Bucket = r.Form.Get("s3_bucket")
	config.Region = r.Form.Get("s3_region")
	config.AccessKey = r.Form.Get("s3_access_key")
	config.RoleARN = r.Form.Get("s3_role_arn")
	config.AccessSecret = getSecretFromFormField(r, "s3_access_secret")
	config.Endpoint = r.Form.Get("s3_endpoint")
	config.StorageClass = r.Form.Get("s3_storage_class")
	config.ACL = r.Form.Get("s3_acl")
	config.KeyPrefix = r.Form.Get("s3_key_prefix")
	config.UploadPartSize, err = strconv.ParseInt(r.Form.Get("s3_upload_part_size"), 10, 64)
	if err != nil {
		return config, err
	}
	config.UploadConcurrency, err = strconv.Atoi(r.Form.Get("s3_upload_concurrency"))
	if err != nil {
		return config, err
	}
	config.DownloadPartSize, err = strconv.ParseInt(r.Form.Get("s3_download_part_size"), 10, 64)
	if err != nil {
		return config, err
	}
	config.DownloadConcurrency, err = strconv.Atoi(r.Form.Get("s3_download_concurrency"))
	if err != nil {
		return config, err
	}
	config.ForcePathStyle = r.Form.Get("s3_force_path_style") != ""
	config.DownloadPartMaxTime, err = strconv.Atoi(r.Form.Get("s3_download_part_max_time"))
	if err != nil {
		return config, err
	}
	config.UploadPartMaxTime, err = strconv.Atoi(r.Form.Get("s3_upload_part_max_time"))
	return config, err
}

func getGCSConfig(r *http.Request) (vfs.GCSFsConfig, error) {
	var err error
	config := vfs.GCSFsConfig{}

	config.Bucket = r.Form.Get("gcs_bucket")
	config.StorageClass = r.Form.Get("gcs_storage_class")
	config.ACL = r.Form.Get("gcs_acl")
	config.KeyPrefix = r.Form.Get("gcs_key_prefix")
	autoCredentials := r.Form.Get("gcs_auto_credentials")
	if autoCredentials != "" {
		config.AutomaticCredentials = 1
	} else {
		config.AutomaticCredentials = 0
	}
	credentials, _, err := r.FormFile("gcs_credential_file")
	if err == http.ErrMissingFile {
		return config, nil
	}
	if err != nil {
		return config, err
	}
	defer credentials.Close()
	fileBytes, err := io.ReadAll(credentials)
	if err != nil || len(fileBytes) == 0 {
		if len(fileBytes) == 0 {
			err = errors.New("credentials file size must be greater than 0")
		}
		return config, err
	}
	config.Credentials = kms.NewPlainSecret(string(fileBytes))
	config.AutomaticCredentials = 0
	return config, err
}

func getSFTPConfig(r *http.Request) (vfs.SFTPFsConfig, error) {
	var err error
	config := vfs.SFTPFsConfig{}
	config.Endpoint = r.Form.Get("sftp_endpoint")
	config.Username = r.Form.Get("sftp_username")
	config.Password = getSecretFromFormField(r, "sftp_password")
	config.PrivateKey = getSecretFromFormField(r, "sftp_private_key")
	fingerprintsFormValue := r.Form.Get("sftp_fingerprints")
	config.Fingerprints = getSliceFromDelimitedValues(fingerprintsFormValue, "\n")
	config.Prefix = r.Form.Get("sftp_prefix")
	config.DisableCouncurrentReads = len(r.Form.Get("sftp_disable_concurrent_reads")) > 0
	config.BufferSize, err = strconv.ParseInt(r.Form.Get("sftp_buffer_size"), 10, 64)
	return config, err
}

func getAzureConfig(r *http.Request) (vfs.AzBlobFsConfig, error) {
	var err error
	config := vfs.AzBlobFsConfig{}
	config.Container = r.Form.Get("az_container")
	config.AccountName = r.Form.Get("az_account_name")
	config.AccountKey = getSecretFromFormField(r, "az_account_key")
	config.SASURL = getSecretFromFormField(r, "az_sas_url")
	config.Endpoint = r.Form.Get("az_endpoint")
	config.KeyPrefix = r.Form.Get("az_key_prefix")
	config.AccessTier = r.Form.Get("az_access_tier")
	config.UseEmulator = len(r.Form.Get("az_use_emulator")) > 0
	config.UploadPartSize, err = strconv.ParseInt(r.Form.Get("az_upload_part_size"), 10, 64)
	if err != nil {
		return config, err
	}
	config.UploadConcurrency, err = strconv.Atoi(r.Form.Get("az_upload_concurrency"))
	if err != nil {
		return config, err
	}
	config.DownloadPartSize, err = strconv.ParseInt(r.Form.Get("az_download_part_size"), 10, 64)
	if err != nil {
		return config, err
	}
	config.DownloadConcurrency, err = strconv.Atoi(r.Form.Get("az_download_concurrency"))
	return config, err
}

func getFsConfigFromPostFields(r *http.Request) (vfs.Filesystem, error) {
	var fs vfs.Filesystem
	fs.Provider = sdk.GetProviderByName(r.Form.Get("fs_provider"))
	switch fs.Provider {
	case sdk.S3FilesystemProvider:
		config, err := getS3Config(r)
		if err != nil {
			return fs, err
		}
		fs.S3Config = config
	case sdk.AzureBlobFilesystemProvider:
		config, err := getAzureConfig(r)
		if err != nil {
			return fs, err
		}
		fs.AzBlobConfig = config
	case sdk.GCSFilesystemProvider:
		config, err := getGCSConfig(r)
		if err != nil {
			return fs, err
		}
		fs.GCSConfig = config
	case sdk.CryptedFilesystemProvider:
		fs.CryptConfig.Passphrase = getSecretFromFormField(r, "crypt_passphrase")
	case sdk.SFTPFilesystemProvider:
		config, err := getSFTPConfig(r)
		if err != nil {
			return fs, err
		}
		fs.SFTPConfig = config
	}
	return fs, nil
}

func getAdminFromPostFields(r *http.Request) (dataprovider.Admin, error) {
	var admin dataprovider.Admin
	err := r.ParseForm()
	if err != nil {
		return admin, err
	}
	status, err := strconv.Atoi(r.Form.Get("status"))
	if err != nil {
		return admin, err
	}
	admin.Username = r.Form.Get("username")
	admin.Password = r.Form.Get("password")
	admin.Permissions = r.Form["permissions"]
	admin.Email = r.Form.Get("email")
	admin.Status = status
	admin.Filters.AllowList = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	admin.Filters.AllowAPIKeyAuth = len(r.Form.Get("allow_api_key_auth")) > 0
	admin.AdditionalInfo = r.Form.Get("additional_info")
	admin.Description = r.Form.Get("description")
	return admin, nil
}

func replacePlaceholders(field string, replacements map[string]string) string {
	for k, v := range replacements {
		field = strings.ReplaceAll(field, k, v)
	}
	return field
}

func getFolderFromTemplate(folder vfs.BaseVirtualFolder, name string) vfs.BaseVirtualFolder {
	folder.Name = name
	replacements := make(map[string]string)
	replacements["%name%"] = folder.Name

	folder.MappedPath = replacePlaceholders(folder.MappedPath, replacements)
	folder.Description = replacePlaceholders(folder.Description, replacements)
	switch folder.FsConfig.Provider {
	case sdk.CryptedFilesystemProvider:
		folder.FsConfig.CryptConfig = getCryptFsFromTemplate(folder.FsConfig.CryptConfig, replacements)
	case sdk.S3FilesystemProvider:
		folder.FsConfig.S3Config = getS3FsFromTemplate(folder.FsConfig.S3Config, replacements)
	case sdk.GCSFilesystemProvider:
		folder.FsConfig.GCSConfig = getGCSFsFromTemplate(folder.FsConfig.GCSConfig, replacements)
	case sdk.AzureBlobFilesystemProvider:
		folder.FsConfig.AzBlobConfig = getAzBlobFsFromTemplate(folder.FsConfig.AzBlobConfig, replacements)
	case sdk.SFTPFilesystemProvider:
		folder.FsConfig.SFTPConfig = getSFTPFsFromTemplate(folder.FsConfig.SFTPConfig, replacements)
	}

	return folder
}

func getCryptFsFromTemplate(fsConfig vfs.CryptFsConfig, replacements map[string]string) vfs.CryptFsConfig {
	if fsConfig.Passphrase != nil {
		if fsConfig.Passphrase.IsPlain() {
			payload := replacePlaceholders(fsConfig.Passphrase.GetPayload(), replacements)
			fsConfig.Passphrase = kms.NewPlainSecret(payload)
		}
	}
	return fsConfig
}

func getS3FsFromTemplate(fsConfig vfs.S3FsConfig, replacements map[string]string) vfs.S3FsConfig {
	fsConfig.KeyPrefix = replacePlaceholders(fsConfig.KeyPrefix, replacements)
	fsConfig.AccessKey = replacePlaceholders(fsConfig.AccessKey, replacements)
	if fsConfig.AccessSecret != nil && fsConfig.AccessSecret.IsPlain() {
		payload := replacePlaceholders(fsConfig.AccessSecret.GetPayload(), replacements)
		fsConfig.AccessSecret = kms.NewPlainSecret(payload)
	}
	return fsConfig
}

func getGCSFsFromTemplate(fsConfig vfs.GCSFsConfig, replacements map[string]string) vfs.GCSFsConfig {
	fsConfig.KeyPrefix = replacePlaceholders(fsConfig.KeyPrefix, replacements)
	return fsConfig
}

func getAzBlobFsFromTemplate(fsConfig vfs.AzBlobFsConfig, replacements map[string]string) vfs.AzBlobFsConfig {
	fsConfig.KeyPrefix = replacePlaceholders(fsConfig.KeyPrefix, replacements)
	fsConfig.AccountName = replacePlaceholders(fsConfig.AccountName, replacements)
	if fsConfig.AccountKey != nil && fsConfig.AccountKey.IsPlain() {
		payload := replacePlaceholders(fsConfig.AccountKey.GetPayload(), replacements)
		fsConfig.AccountKey = kms.NewPlainSecret(payload)
	}
	return fsConfig
}

func getSFTPFsFromTemplate(fsConfig vfs.SFTPFsConfig, replacements map[string]string) vfs.SFTPFsConfig {
	fsConfig.Prefix = replacePlaceholders(fsConfig.Prefix, replacements)
	fsConfig.Username = replacePlaceholders(fsConfig.Username, replacements)
	if fsConfig.Password != nil && fsConfig.Password.IsPlain() {
		payload := replacePlaceholders(fsConfig.Password.GetPayload(), replacements)
		fsConfig.Password = kms.NewPlainSecret(payload)
	}
	return fsConfig
}

func getUserFromTemplate(user dataprovider.User, template userTemplateFields) dataprovider.User {
	user.Username = template.Username
	user.Password = template.Password
	user.PublicKeys = template.PublicKeys
	replacements := make(map[string]string)
	replacements["%username%"] = user.Username
	if user.Password != "" && !user.IsPasswordHashed() {
		user.Password = replacePlaceholders(user.Password, replacements)
		replacements["%password%"] = user.Password
	}

	user.HomeDir = replacePlaceholders(user.HomeDir, replacements)
	var vfolders []vfs.VirtualFolder
	for _, vfolder := range user.VirtualFolders {
		vfolder.Name = replacePlaceholders(vfolder.Name, replacements)
		vfolder.VirtualPath = replacePlaceholders(vfolder.VirtualPath, replacements)
		vfolders = append(vfolders, vfolder)
	}
	user.VirtualFolders = vfolders
	user.Description = replacePlaceholders(user.Description, replacements)
	user.AdditionalInfo = replacePlaceholders(user.AdditionalInfo, replacements)

	switch user.FsConfig.Provider {
	case sdk.CryptedFilesystemProvider:
		user.FsConfig.CryptConfig = getCryptFsFromTemplate(user.FsConfig.CryptConfig, replacements)
	case sdk.S3FilesystemProvider:
		user.FsConfig.S3Config = getS3FsFromTemplate(user.FsConfig.S3Config, replacements)
	case sdk.GCSFilesystemProvider:
		user.FsConfig.GCSConfig = getGCSFsFromTemplate(user.FsConfig.GCSConfig, replacements)
	case sdk.AzureBlobFilesystemProvider:
		user.FsConfig.AzBlobConfig = getAzBlobFsFromTemplate(user.FsConfig.AzBlobConfig, replacements)
	case sdk.SFTPFilesystemProvider:
		user.FsConfig.SFTPConfig = getSFTPFsFromTemplate(user.FsConfig.SFTPConfig, replacements)
	}

	return user
}

func getTransferLimits(r *http.Request) (int64, int64, int64, error) {
	dataTransferUL, err := strconv.ParseInt(r.Form.Get("upload_data_transfer"), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid upload data transfer: %w", err)
	}
	dataTransferDL, err := strconv.ParseInt(r.Form.Get("download_data_transfer"), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid download data transfer: %w", err)
	}
	dataTransferTotal, err := strconv.ParseInt(r.Form.Get("total_data_transfer"), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid total data transfer: %w", err)
	}
	return dataTransferUL, dataTransferDL, dataTransferTotal, nil
}

func getQuotaLimits(r *http.Request) (int64, int, error) {
	quotaSize, err := strconv.ParseInt(r.Form.Get("quota_size"), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid quota size: %w", err)
	}
	quotaFiles, err := strconv.Atoi(r.Form.Get("quota_files"))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid quota files: %w", err)
	}
	return quotaSize, quotaFiles, nil
}

func getUserFromPostFields(r *http.Request) (dataprovider.User, error) {
	var user dataprovider.User
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		return user, err
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck
	uid, err := strconv.Atoi(r.Form.Get("uid"))
	if err != nil {
		return user, fmt.Errorf("invalid uid: %w", err)
	}
	gid, err := strconv.Atoi(r.Form.Get("gid"))
	if err != nil {
		return user, fmt.Errorf("invalid uid: %w", err)
	}
	maxSessions, err := strconv.Atoi(r.Form.Get("max_sessions"))
	if err != nil {
		return user, fmt.Errorf("invalid max sessions: %w", err)
	}
	quotaSize, quotaFiles, err := getQuotaLimits(r)
	if err != nil {
		return user, err
	}
	bandwidthUL, err := strconv.ParseInt(r.Form.Get("upload_bandwidth"), 10, 64)
	if err != nil {
		return user, fmt.Errorf("invalid upload bandwidth: %w", err)
	}
	bandwidthDL, err := strconv.ParseInt(r.Form.Get("download_bandwidth"), 10, 64)
	if err != nil {
		return user, fmt.Errorf("invalid download bandwidth: %w", err)
	}
	dataTransferUL, dataTransferDL, dataTransferTotal, err := getTransferLimits(r)
	if err != nil {
		return user, err
	}
	status, err := strconv.Atoi(r.Form.Get("status"))
	if err != nil {
		return user, fmt.Errorf("invalid status: %w", err)
	}
	expirationDateMillis := int64(0)
	expirationDateString := r.Form.Get("expiration_date")
	if strings.TrimSpace(expirationDateString) != "" {
		expirationDate, err := time.Parse(webDateTimeFormat, expirationDateString)
		if err != nil {
			return user, err
		}
		expirationDateMillis = util.GetTimeAsMsSinceEpoch(expirationDate)
	}
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		return user, err
	}
	filters, err := getFiltersFromUserPostFields(r)
	if err != nil {
		return user, err
	}
	user = dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:             r.Form.Get("username"),
			Email:                r.Form.Get("email"),
			Password:             r.Form.Get("password"),
			PublicKeys:           r.Form["public_keys"],
			HomeDir:              r.Form.Get("home_dir"),
			UID:                  uid,
			GID:                  gid,
			Permissions:          getUserPermissionsFromPostFields(r),
			MaxSessions:          maxSessions,
			QuotaSize:            quotaSize,
			QuotaFiles:           quotaFiles,
			UploadBandwidth:      bandwidthUL,
			DownloadBandwidth:    bandwidthDL,
			UploadDataTransfer:   dataTransferUL,
			DownloadDataTransfer: dataTransferDL,
			TotalDataTransfer:    dataTransferTotal,
			Status:               status,
			ExpirationDate:       expirationDateMillis,
			AdditionalInfo:       r.Form.Get("additional_info"),
			Description:          r.Form.Get("description"),
		},
		Filters: dataprovider.UserFilters{
			BaseUserFilters: filters,
		},
		VirtualFolders: getVirtualFoldersFromPostFields(r),
		FsConfig:       fsConfig,
	}
	maxFileSize, err := strconv.ParseInt(r.Form.Get("max_upload_file_size"), 10, 64)
	if err != nil {
		return user, fmt.Errorf("invalid max upload file size: %w", err)
	}
	user.Filters.MaxUploadFileSize = maxFileSize
	return user, err
}

func (s *httpdServer) handleWebAdminForgotPwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if !smtp.IsEnabled() {
		s.renderNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderForgotPwdPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebAdminForgotPwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderForgotPwdPage(w, err.Error(), ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	err = handleForgotPassword(r, r.Form.Get("username"), true)
	if err != nil {
		if e, ok := err.(*util.ValidationError); ok {
			s.renderForgotPwdPage(w, e.GetErrorString(), ipAddr)
			return
		}
		s.renderForgotPwdPage(w, err.Error(), ipAddr)
		return
	}
	http.Redirect(w, r, webAdminResetPwdPath, http.StatusFound)
}

func (s *httpdServer) handleWebAdminPasswordReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !smtp.IsEnabled() {
		s.renderNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderResetPwdPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebAdminTwoFactor(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderTwoFactorPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebAdminTwoFactorRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderTwoFactorRecoveryPage(w, "", util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebAdminMFA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderMFAPage(w, r)
}

func (s *httpdServer) handleWebAdminProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderProfilePage(w, r, "")
}

func (s *httpdServer) handleWebAdminChangePwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderChangePasswordPage(w, r, "")
}

func (s *httpdServer) handleWebAdminProfilePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderProfilePage(w, r, err.Error())
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderProfilePage(w, r, "Invalid token claims")
		return
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		s.renderProfilePage(w, r, err.Error())
		return
	}
	admin.Filters.AllowAPIKeyAuth = len(r.Form.Get("allow_api_key_auth")) > 0
	admin.Email = r.Form.Get("email")
	admin.Description = r.Form.Get("description")
	err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr)
	if err != nil {
		s.renderProfilePage(w, r, err.Error())
		return
	}
	s.renderMessagePage(w, r, "Profile updated", "", http.StatusOK, nil,
		"Your profile has been successfully updated")
}

func (s *httpdServer) handleWebMaintenance(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderMaintenancePage(w, r, "")
}

func (s *httpdServer) handleWebRestore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRestoreSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderBadRequestPage(w, r, errors.New("invalid token claims"))
		return
	}
	err = r.ParseMultipartForm(MaxRestoreSize)
	if err != nil {
		s.renderMaintenancePage(w, r, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	restoreMode, err := strconv.Atoi(r.Form.Get("mode"))
	if err != nil {
		s.renderMaintenancePage(w, r, err.Error())
		return
	}
	scanQuota, err := strconv.Atoi(r.Form.Get("quota"))
	if err != nil {
		s.renderMaintenancePage(w, r, err.Error())
		return
	}
	backupFile, _, err := r.FormFile("backup_file")
	if err != nil {
		s.renderMaintenancePage(w, r, err.Error())
		return
	}
	defer backupFile.Close()

	backupContent, err := io.ReadAll(backupFile)
	if err != nil || len(backupContent) == 0 {
		if len(backupContent) == 0 {
			err = errors.New("backup file size must be greater than 0")
		}
		s.renderMaintenancePage(w, r, err.Error())
		return
	}

	if err := restoreBackup(backupContent, "", scanQuota, restoreMode, claims.Username, ipAddr); err != nil {
		s.renderMaintenancePage(w, r, err.Error())
		return
	}

	s.renderMessagePage(w, r, "Data restored", "", http.StatusOK, nil, "Your backup was successfully restored")
}

func (s *httpdServer) handleGetWebAdmins(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit := defaultQueryLimit
	if _, ok := r.URL.Query()["qlimit"]; ok {
		var err error
		limit, err = strconv.Atoi(r.URL.Query().Get("qlimit"))
		if err != nil {
			limit = defaultQueryLimit
		}
	}
	admins := make([]dataprovider.Admin, 0, limit)
	for {
		a, err := dataprovider.GetAdmins(limit, len(admins), dataprovider.OrderASC)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return
		}
		admins = append(admins, a...)
		if len(a) < limit {
			break
		}
	}
	data := adminsPage{
		basePage: s.getBasePageData(pageAdminsTitle, webAdminsPath, r),
		Admins:   admins,
	}
	renderAdminTemplate(w, templateAdmins, data)
}

func (s *httpdServer) handleWebAdminSetupGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
		return
	}
	s.renderAdminSetupPage(w, r, "", "")
}

func (s *httpdServer) handleWebAddAdminGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	admin := &dataprovider.Admin{Status: 1}
	s.renderAddUpdateAdminPage(w, r, admin, "", true)
}

func (s *httpdServer) handleWebUpdateAdminGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	admin, err := dataprovider.AdminExists(username)
	if err == nil {
		s.renderAddUpdateAdminPage(w, r, &admin, "", false)
	} else if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebAddAdminPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderBadRequestPage(w, r, errors.New("invalid token claims"))
		return
	}
	admin, err := getAdminFromPostFields(r)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &admin, err.Error(), true)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	err = dataprovider.AddAdmin(&admin, claims.Username, ipAddr)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &admin, err.Error(), true)
		return
	}
	http.Redirect(w, r, webAdminsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateAdminPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	username := getURLParam(r, "username")
	admin, err := dataprovider.AdminExists(username)
	if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}

	updatedAdmin, err := getAdminFromPostFields(r)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &updatedAdmin, err.Error(), false)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	updatedAdmin.ID = admin.ID
	updatedAdmin.Username = admin.Username
	if updatedAdmin.Password == "" {
		updatedAdmin.Password = admin.Password
	}
	updatedAdmin.Filters.TOTPConfig = admin.Filters.TOTPConfig
	updatedAdmin.Filters.RecoveryCodes = admin.Filters.RecoveryCodes
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderAddUpdateAdminPage(w, r, &updatedAdmin, "Invalid token claims", false)
		return
	}
	if username == claims.Username {
		if claims.isCriticalPermRemoved(updatedAdmin.Permissions) {
			s.renderAddUpdateAdminPage(w, r, &updatedAdmin, "You cannot remove these permissions to yourself", false)
			return
		}
		if updatedAdmin.Status == 0 {
			s.renderAddUpdateAdminPage(w, r, &updatedAdmin, "You cannot disable yourself", false)
			return
		}
	}
	err = dataprovider.UpdateAdmin(&updatedAdmin, claims.Username, ipAddr)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &admin, err.Error(), false)
		return
	}
	http.Redirect(w, r, webAdminsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebDefenderPage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	data := defenderHostsPage{
		basePage:         s.getBasePageData(pageDefenderTitle, webDefenderPath, r),
		DefenderHostsURL: webDefenderHostsPath,
	}

	renderAdminTemplate(w, templateDefender, data)
}

func (s *httpdServer) handleGetWebUsers(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var limit int
	if _, ok := r.URL.Query()["qlimit"]; ok {
		var err error
		limit, err = strconv.Atoi(r.URL.Query().Get("qlimit"))
		if err != nil {
			limit = defaultQueryLimit
		}
	} else {
		limit = defaultQueryLimit
	}
	users := make([]dataprovider.User, 0, limit)
	for {
		u, err := dataprovider.GetUsers(limit, len(users), dataprovider.OrderASC)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return
		}
		users = append(users, u...)
		if len(u) < limit {
			break
		}
	}
	data := usersPage{
		basePage: s.getBasePageData(pageUsersTitle, webUsersPath, r),
		Users:    users,
	}
	renderAdminTemplate(w, templateUsers, data)
}

func (s *httpdServer) handleWebTemplateFolderGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if r.URL.Query().Get("from") != "" {
		name := r.URL.Query().Get("from")
		folder, err := dataprovider.GetFolderByName(name)
		if err == nil {
			folder.FsConfig.SetEmptySecrets()
			s.renderFolderPage(w, r, folder, folderPageModeTemplate, "")
		} else if _, ok := err.(*util.RecordNotFoundError); ok {
			s.renderNotFoundPage(w, r, err)
		} else {
			s.renderInternalServerErrorPage(w, r, err)
		}
	} else {
		folder := vfs.BaseVirtualFolder{}
		s.renderFolderPage(w, r, folder, folderPageModeTemplate, "")
	}
}

func (s *httpdServer) handleWebTemplateFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderBadRequestPage(w, r, errors.New("invalid token claims"))
		return
	}
	templateFolder := vfs.BaseVirtualFolder{}
	err = r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		s.renderMessagePage(w, r, "Error parsing folders fields", "", http.StatusBadRequest, err, "")
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}

	templateFolder.MappedPath = r.Form.Get("mapped_path")
	templateFolder.Description = r.Form.Get("description")
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		s.renderMessagePage(w, r, "Error parsing folders fields", "", http.StatusBadRequest, err, "")
		return
	}
	templateFolder.FsConfig = fsConfig

	var dump dataprovider.BackupData
	dump.Version = dataprovider.DumpVersion

	foldersFields := getFoldersForTemplate(r)
	for _, tmpl := range foldersFields {
		f := getFolderFromTemplate(templateFolder, tmpl)
		if err := dataprovider.ValidateFolder(&f); err != nil {
			s.renderMessagePage(w, r, "Folder validation error", fmt.Sprintf("Error validating folder %#v", f.Name),
				http.StatusBadRequest, err, "")
			return
		}
		dump.Folders = append(dump.Folders, f)
	}

	if len(dump.Folders) == 0 {
		s.renderMessagePage(w, r, "No folders defined", "No valid folders defined, unable to complete the requested action",
			http.StatusBadRequest, nil, "")
		return
	}
	if r.Form.Get("form_action") == "export_from_template" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sftpgo-%v-folders-from-template.json\"",
			len(dump.Folders)))
		render.JSON(w, r, dump)
		return
	}
	if err = RestoreFolders(dump.Folders, "", 1, 0, claims.Username, ipAddr); err != nil {
		s.renderMessagePage(w, r, "Unable to save folders", "Cannot save the defined folders:",
			getRespStatus(err), err, "")
		return
	}
	http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebTemplateUserGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if r.URL.Query().Get("from") != "" {
		username := r.URL.Query().Get("from")
		user, err := dataprovider.UserExists(username)
		if err == nil {
			user.SetEmptySecrets()
			user.PublicKeys = nil
			user.Email = ""
			user.Description = ""
			s.renderUserPage(w, r, &user, userPageModeTemplate, "")
		} else if _, ok := err.(*util.RecordNotFoundError); ok {
			s.renderNotFoundPage(w, r, err)
		} else {
			s.renderInternalServerErrorPage(w, r, err)
		}
	} else {
		user := dataprovider.User{BaseUser: sdk.BaseUser{
			Status: 1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		}}
		s.renderUserPage(w, r, &user, userPageModeTemplate, "")
	}
}

func (s *httpdServer) handleWebTemplateUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderBadRequestPage(w, r, errors.New("invalid token claims"))
		return
	}
	templateUser, err := getUserFromPostFields(r)
	if err != nil {
		s.renderMessagePage(w, r, "Error parsing user fields", "", http.StatusBadRequest, err, "")
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}

	var dump dataprovider.BackupData
	dump.Version = dataprovider.DumpVersion

	userTmplFields := getUsersForTemplate(r)
	for _, tmpl := range userTmplFields {
		u := getUserFromTemplate(templateUser, tmpl)
		if err := dataprovider.ValidateUser(&u); err != nil {
			s.renderMessagePage(w, r, "User validation error", fmt.Sprintf("Error validating user %#v", u.Username),
				http.StatusBadRequest, err, "")
			return
		}
		dump.Users = append(dump.Users, u)
		for _, folder := range u.VirtualFolders {
			if !dump.HasFolder(folder.Name) {
				dump.Folders = append(dump.Folders, folder.BaseVirtualFolder)
			}
		}
	}

	if len(dump.Users) == 0 {
		s.renderMessagePage(w, r, "No users defined", "No valid users defined, unable to complete the requested action",
			http.StatusBadRequest, nil, "")
		return
	}
	if r.Form.Get("form_action") == "export_from_template" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sftpgo-%v-users-from-template.json\"",
			len(dump.Users)))
		render.JSON(w, r, dump)
		return
	}
	if err = RestoreUsers(dump.Users, "", 1, 0, claims.Username, ipAddr); err != nil {
		s.renderMessagePage(w, r, "Unable to save users", "Cannot save the defined users:",
			getRespStatus(err), err, "")
		return
	}
	http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebAddUserGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	user := dataprovider.User{BaseUser: sdk.BaseUser{
		Status: 1,
		Permissions: map[string][]string{
			"/": {dataprovider.PermAny},
		},
	}}
	s.renderUserPage(w, r, &user, userPageModeAdd, "")
}

func (s *httpdServer) handleWebUpdateUserGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username)
	if err == nil {
		s.renderUserPage(w, r, &user, userPageModeUpdate, "")
	} else if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebAddUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderBadRequestPage(w, r, errors.New("invalid token claims"))
		return
	}
	user, err := getUserFromPostFields(r)
	if err != nil {
		s.renderUserPage(w, r, &user, userPageModeAdd, err.Error())
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	user = getUserFromTemplate(user, userTemplateFields{
		Username:   user.Username,
		Password:   user.Password,
		PublicKeys: user.PublicKeys,
	})
	err = dataprovider.AddUser(&user, claims.Username, ipAddr)
	if err == nil {
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		s.renderUserPage(w, r, &user, userPageModeAdd, err.Error())
	}
}

func (s *httpdServer) handleWebUpdateUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderBadRequestPage(w, r, errors.New("invalid token claims"))
		return
	}
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username)
	if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	updatedUser, err := getUserFromPostFields(r)
	if err != nil {
		s.renderUserPage(w, r, &user, userPageModeUpdate, err.Error())
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	updatedUser.ID = user.ID
	updatedUser.Username = user.Username
	updatedUser.Filters.RecoveryCodes = user.Filters.RecoveryCodes
	updatedUser.Filters.TOTPConfig = user.Filters.TOTPConfig
	updatedUser.SetEmptySecretsIfNil()
	if updatedUser.Password == redactedSecret {
		updatedUser.Password = user.Password
	}
	updateEncryptedSecrets(&updatedUser.FsConfig, user.FsConfig.S3Config.AccessSecret, user.FsConfig.AzBlobConfig.AccountKey,
		user.FsConfig.AzBlobConfig.SASURL, user.FsConfig.GCSConfig.Credentials, user.FsConfig.CryptConfig.Passphrase,
		user.FsConfig.SFTPConfig.Password, user.FsConfig.SFTPConfig.PrivateKey)

	updatedUser = getUserFromTemplate(updatedUser, userTemplateFields{
		Username:   updatedUser.Username,
		Password:   updatedUser.Password,
		PublicKeys: updatedUser.PublicKeys,
	})

	err = dataprovider.UpdateUser(&updatedUser, claims.Username, ipAddr)
	if err == nil {
		if r.Form.Get("disconnect") != "" {
			disconnectUser(user.Username)
		}
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		s.renderUserPage(w, r, &user, userPageModeUpdate, err.Error())
	}
}

func (s *httpdServer) handleWebGetStatus(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	data := statusPage{
		basePage: s.getBasePageData(pageStatusTitle, webStatusPath, r),
		Status:   getServicesStatus(),
	}
	renderAdminTemplate(w, templateStatus, data)
}

func (s *httpdServer) handleWebGetConnections(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connectionStats := common.Connections.GetStats()
	data := connectionsPage{
		basePage:    s.getBasePageData(pageConnectionsTitle, webConnectionsPath, r),
		Connections: connectionStats,
	}
	renderAdminTemplate(w, templateConnections, data)
}

func (s *httpdServer) handleWebAddFolderGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderFolderPage(w, r, vfs.BaseVirtualFolder{}, folderPageModeAdd, "")
}

func (s *httpdServer) handleWebAddFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	folder := vfs.BaseVirtualFolder{}
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeAdd, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	folder.MappedPath = r.Form.Get("mapped_path")
	folder.Name = r.Form.Get("name")
	folder.Description = r.Form.Get("description")
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeAdd, err.Error())
		return
	}
	folder.FsConfig = fsConfig
	folder = getFolderFromTemplate(folder, folder.Name)

	err = dataprovider.AddFolder(&folder)
	if err == nil {
		http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
	} else {
		s.renderFolderPage(w, r, folder, folderPageModeAdd, err.Error())
	}
}

func (s *httpdServer) handleWebUpdateFolderGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if err == nil {
		s.renderFolderPage(w, r, folder, folderPageModeUpdate, "")
	} else if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebUpdateFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		s.renderBadRequestPage(w, r, errors.New("invalid token claims"))
		return
	}
	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if _, ok := err.(*util.RecordNotFoundError); ok {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}

	err = r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeUpdate, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeUpdate, err.Error())
		return
	}
	updatedFolder := vfs.BaseVirtualFolder{
		MappedPath:  r.Form.Get("mapped_path"),
		Description: r.Form.Get("description"),
	}
	updatedFolder.ID = folder.ID
	updatedFolder.Name = folder.Name
	updatedFolder.FsConfig = fsConfig
	updatedFolder.FsConfig.SetEmptySecretsIfNil()
	updateEncryptedSecrets(&updatedFolder.FsConfig, folder.FsConfig.S3Config.AccessSecret, folder.FsConfig.AzBlobConfig.AccountKey,
		folder.FsConfig.AzBlobConfig.SASURL, folder.FsConfig.GCSConfig.Credentials, folder.FsConfig.CryptConfig.Passphrase,
		folder.FsConfig.SFTPConfig.Password, folder.FsConfig.SFTPConfig.PrivateKey)

	updatedFolder = getFolderFromTemplate(updatedFolder, updatedFolder.Name)

	err = dataprovider.UpdateFolder(&updatedFolder, folder.Users, claims.Username, ipAddr)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeUpdate, err.Error())
		return
	}
	http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
}

func (s *httpdServer) getWebVirtualFolders(w http.ResponseWriter, r *http.Request, limit int) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	for {
		f, err := dataprovider.GetFolders(limit, len(folders), dataprovider.OrderASC)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return folders, err
		}
		folders = append(folders, f...)
		if len(f) < limit {
			break
		}
	}
	return folders, nil
}

func (s *httpdServer) handleWebGetFolders(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit := defaultQueryLimit
	if _, ok := r.URL.Query()["qlimit"]; ok {
		var err error
		limit, err = strconv.Atoi(r.URL.Query().Get("qlimit"))
		if err != nil {
			limit = defaultQueryLimit
		}
	}
	folders, err := s.getWebVirtualFolders(w, r, limit)
	if err != nil {
		return
	}

	data := foldersPage{
		basePage: s.getBasePageData(pageFoldersTitle, webFoldersPath, r),
		Folders:  folders,
	}
	renderAdminTemplate(w, templateFolders, data)
}
