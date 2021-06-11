package httpd

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
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
	templateChangePwd    = "changepwd.html"
	templateMaintenance  = "maintenance.html"
	templateSetup        = "adminsetup.html"
	pageUsersTitle       = "Users"
	pageAdminsTitle      = "Admins"
	pageConnectionsTitle = "Connections"
	pageStatusTitle      = "Status"
	pageFoldersTitle     = "Folders"
	pageChangePwdTitle   = "Change password"
	pageMaintenanceTitle = "Maintenance"
	pageDefenderTitle    = "Defender"
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
	ChangeAdminPwdURL  string
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
	LoggedAdmin        *dataprovider.Admin
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
	Connections []*common.ConnectionStatus
}

type statusPage struct {
	basePage
	Status ServicesStatus
}

type userPage struct {
	basePage
	User              *dataprovider.User
	RootPerms         []string
	Error             string
	ValidPerms        []string
	ValidLoginMethods []string
	ValidProtocols    []string
	WebClientOptions  []string
	RootDirPerms      []string
	RedactedSecret    string
	Mode              userPageMode
	VirtualFolders    []vfs.BaseVirtualFolder
}

type adminPage struct {
	basePage
	Admin *dataprovider.Admin
	Error string
	IsAdd bool
}

type changePwdPage struct {
	basePage
	Error string
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
	Username string
	Error    string
}

type folderPage struct {
	basePage
	Folder vfs.BaseVirtualFolder
	Error  string
	Mode   folderPageMode
}

type messagePage struct {
	basePage
	Error   string
	Success string
}

type userTemplateFields struct {
	Username  string
	Password  string
	PublicKey string
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
	changePwdPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateChangePwd),
	}
	connectionsPaths := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateConnections),
	}
	messagePath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateMessage),
	}
	foldersPath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFolders),
	}
	folderPath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFsConfig),
		filepath.Join(templatesPath, templateAdminDir, templateFolder),
	}
	statusPath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateStatus),
	}
	loginPath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateLogin),
	}
	maintenancePath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateMaintenance),
	}
	defenderPath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateDefender),
	}
	setupPath := []string{
		filepath.Join(templatesPath, templateAdminDir, templateSetup),
	}
	usersTmpl := utils.LoadTemplate(template.ParseFiles(usersPaths...))
	userTmpl := utils.LoadTemplate(template.ParseFiles(userPaths...))
	adminsTmpl := utils.LoadTemplate(template.ParseFiles(adminsPaths...))
	adminTmpl := utils.LoadTemplate(template.ParseFiles(adminPaths...))
	connectionsTmpl := utils.LoadTemplate(template.ParseFiles(connectionsPaths...))
	messageTmpl := utils.LoadTemplate(template.ParseFiles(messagePath...))
	foldersTmpl := utils.LoadTemplate(template.ParseFiles(foldersPath...))
	folderTmpl := utils.LoadTemplate(template.ParseFiles(folderPath...))
	statusTmpl := utils.LoadTemplate(template.ParseFiles(statusPath...))
	loginTmpl := utils.LoadTemplate(template.ParseFiles(loginPath...))
	changePwdTmpl := utils.LoadTemplate(template.ParseFiles(changePwdPaths...))
	maintenanceTmpl := utils.LoadTemplate(template.ParseFiles(maintenancePath...))
	defenderTmpl := utils.LoadTemplate(template.ParseFiles(defenderPath...))
	setupTmpl := utils.LoadTemplate(template.ParseFiles(setupPath...))

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
	adminTemplates[templateChangePwd] = changePwdTmpl
	adminTemplates[templateMaintenance] = maintenanceTmpl
	adminTemplates[templateDefender] = defenderTmpl
	adminTemplates[templateSetup] = setupTmpl
}

func getBasePageData(title, currentURL string, r *http.Request) basePage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken()
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
		ChangeAdminPwdURL:  webChangeAdminPwdPath,
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
		CSRFToken:          csrfToken,
	}
}

func renderAdminTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := adminTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderMessagePage(w http.ResponseWriter, r *http.Request, title, body string, statusCode int, err error, message string) {
	var errorString string
	if body != "" {
		errorString = body + " "
	}
	if err != nil {
		errorString += err.Error()
	}
	data := messagePage{
		basePage: getBasePageData(title, "", r),
		Error:    errorString,
		Success:  message,
	}
	w.WriteHeader(statusCode)
	renderAdminTemplate(w, templateMessage, data)
}

func renderInternalServerErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	renderMessagePage(w, r, page500Title, page500Body, http.StatusInternalServerError, err, "")
}

func renderBadRequestPage(w http.ResponseWriter, r *http.Request, err error) {
	renderMessagePage(w, r, page400Title, "", http.StatusBadRequest, err, "")
}

func renderForbiddenPage(w http.ResponseWriter, r *http.Request, body string) {
	renderMessagePage(w, r, page403Title, "", http.StatusForbidden, nil, body)
}

func renderNotFoundPage(w http.ResponseWriter, r *http.Request, err error) {
	renderMessagePage(w, r, page404Title, page404Body, http.StatusNotFound, err, "")
}

func renderChangePwdPage(w http.ResponseWriter, r *http.Request, error string) {
	data := changePwdPage{
		basePage: getBasePageData(pageChangePwdTitle, webChangeAdminPwdPath, r),
		Error:    error,
	}

	renderAdminTemplate(w, templateChangePwd, data)
}

func renderMaintenancePage(w http.ResponseWriter, r *http.Request, error string) {
	data := maintenancePage{
		basePage:    getBasePageData(pageMaintenanceTitle, webMaintenancePath, r),
		BackupPath:  webBackupPath,
		RestorePath: webRestorePath,
		Error:       error,
	}

	renderAdminTemplate(w, templateMaintenance, data)
}

func renderAdminSetupPage(w http.ResponseWriter, r *http.Request, username, error string) {
	data := setupPage{
		basePage: getBasePageData(pageSetupTitle, webAdminSetupPath, r),
		Username: username,
		Error:    error,
	}

	renderAdminTemplate(w, templateSetup, data)
}

func renderAddUpdateAdminPage(w http.ResponseWriter, r *http.Request, admin *dataprovider.Admin,
	error string, isAdd bool) {
	currentURL := webAdminPath
	if !isAdd {
		currentURL = fmt.Sprintf("%v/%v", webAdminPath, url.PathEscape(admin.Username))
	}
	data := adminPage{
		basePage: getBasePageData("Add a new user", currentURL, r),
		Admin:    admin,
		Error:    error,
		IsAdd:    isAdd,
	}

	renderAdminTemplate(w, templateAdmin, data)
}

func renderUserPage(w http.ResponseWriter, r *http.Request, user *dataprovider.User, mode userPageMode, error string) {
	folders, err := getWebVirtualFolders(w, r, defaultQueryLimit)
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
		basePage:          getBasePageData(title, currentURL, r),
		Mode:              mode,
		Error:             error,
		User:              user,
		ValidPerms:        dataprovider.ValidPerms,
		ValidLoginMethods: dataprovider.ValidLoginMethods,
		ValidProtocols:    dataprovider.ValidProtocols,
		WebClientOptions:  dataprovider.WebClientOptions,
		RootDirPerms:      user.GetPermissionsForPath("/"),
		VirtualFolders:    folders,
	}
	renderAdminTemplate(w, templateUser, data)
}

func renderFolderPage(w http.ResponseWriter, r *http.Request, folder vfs.BaseVirtualFolder, mode folderPageMode, error string) {
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
		basePage: getBasePageData(title, currentURL, r),
		Error:    error,
		Folder:   folder,
		Mode:     mode,
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
		if username == "" || (password == "" && publicKey == "") {
			continue
		}
		if _, ok := users[username]; ok {
			continue
		}

		users[username] = true
		res = append(res, userTemplateFields{
			Username:  username,
			Password:  password,
			PublicKey: publicKey,
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

func getFilePatternsFromPostField(r *http.Request) []dataprovider.PatternsFilter {
	var result []dataprovider.PatternsFilter

	allowedPatterns := make(map[string][]string)
	deniedPatterns := make(map[string][]string)

	for k := range r.Form {
		if strings.HasPrefix(k, "pattern_path") {
			p := strings.TrimSpace(r.Form.Get(k))
			idx := strings.TrimPrefix(k, "pattern_path")
			filters := strings.TrimSpace(r.Form.Get(fmt.Sprintf("patterns%v", idx)))
			filters = strings.ReplaceAll(filters, " ", "")
			patternType := r.Form.Get(fmt.Sprintf("pattern_type%v", idx))
			if p != "" && filters != "" {
				if patternType == "allowed" {
					allowedPatterns[p] = append(allowedPatterns[p], strings.Split(filters, ",")...)
				} else {
					deniedPatterns[p] = append(deniedPatterns[p], strings.Split(filters, ",")...)
				}
			}
		}
	}

	for dirAllowed, allowPatterns := range allowedPatterns {
		filter := dataprovider.PatternsFilter{
			Path:            dirAllowed,
			AllowedPatterns: utils.RemoveDuplicates(allowPatterns),
		}
		for dirDenied, denPatterns := range deniedPatterns {
			if dirAllowed == dirDenied {
				filter.DeniedPatterns = utils.RemoveDuplicates(denPatterns)
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
			result = append(result, dataprovider.PatternsFilter{
				Path:           dirDenied,
				DeniedPatterns: denPatterns,
			})
		}
	}
	return result
}

func getFiltersFromUserPostFields(r *http.Request) dataprovider.UserFilters {
	var filters dataprovider.UserFilters
	filters.AllowedIP = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	filters.DeniedIP = getSliceFromDelimitedValues(r.Form.Get("denied_ip"), ",")
	filters.DeniedLoginMethods = r.Form["ssh_login_methods"]
	filters.DeniedProtocols = r.Form["denied_protocols"]
	filters.FilePatterns = getFilePatternsFromPostField(r)
	filters.TLSUsername = dataprovider.TLSUsername(r.Form.Get("tls_username"))
	filters.WebClient = r.Form["web_client_options"]
	hooks := r.Form["hooks"]
	if utils.IsStringInSlice("external_auth_disabled", hooks) {
		filters.Hooks.ExternalAuthDisabled = true
	}
	if utils.IsStringInSlice("pre_login_disabled", hooks) {
		filters.Hooks.PreLoginDisabled = true
	}
	if utils.IsStringInSlice("check_password_disabled", hooks) {
		filters.Hooks.CheckPasswordDisabled = true
	}
	filters.DisableFsChecks = len(r.Form.Get("disable_fs_checks")) > 0
	return filters
}

func getSecretFromFormField(r *http.Request, field string) *kms.Secret {
	secret := kms.NewPlainSecret(r.Form.Get(field))
	if strings.TrimSpace(secret.GetPayload()) == redactedSecret {
		secret.SetStatus(kms.SecretStatusRedacted)
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
	config.AccessSecret = getSecretFromFormField(r, "s3_access_secret")
	config.Endpoint = r.Form.Get("s3_endpoint")
	config.StorageClass = r.Form.Get("s3_storage_class")
	config.KeyPrefix = r.Form.Get("s3_key_prefix")
	config.UploadPartSize, err = strconv.ParseInt(r.Form.Get("s3_upload_part_size"), 10, 64)
	if err != nil {
		return config, err
	}
	config.UploadConcurrency, err = strconv.Atoi(r.Form.Get("s3_upload_concurrency"))
	return config, err
}

func getGCSConfig(r *http.Request) (vfs.GCSFsConfig, error) {
	var err error
	config := vfs.GCSFsConfig{}

	config.Bucket = r.Form.Get("gcs_bucket")
	config.StorageClass = r.Form.Get("gcs_storage_class")
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
	return config, err
}

func getFsConfigFromPostFields(r *http.Request) (vfs.Filesystem, error) {
	var fs vfs.Filesystem
	provider, err := strconv.Atoi(r.Form.Get("fs_provider"))
	if err != nil {
		provider = int(vfs.LocalFilesystemProvider)
	}
	fs.Provider = vfs.FilesystemProvider(provider)
	switch fs.Provider {
	case vfs.S3FilesystemProvider:
		config, err := getS3Config(r)
		if err != nil {
			return fs, err
		}
		fs.S3Config = config
	case vfs.AzureBlobFilesystemProvider:
		config, err := getAzureConfig(r)
		if err != nil {
			return fs, err
		}
		fs.AzBlobConfig = config
	case vfs.GCSFilesystemProvider:
		config, err := getGCSConfig(r)
		if err != nil {
			return fs, err
		}
		fs.GCSConfig = config
	case vfs.CryptedFilesystemProvider:
		fs.CryptConfig.Passphrase = getSecretFromFormField(r, "crypt_passphrase")
	case vfs.SFTPFilesystemProvider:
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
	case vfs.CryptedFilesystemProvider:
		folder.FsConfig.CryptConfig = getCryptFsFromTemplate(folder.FsConfig.CryptConfig, replacements)
	case vfs.S3FilesystemProvider:
		folder.FsConfig.S3Config = getS3FsFromTemplate(folder.FsConfig.S3Config, replacements)
	case vfs.GCSFilesystemProvider:
		folder.FsConfig.GCSConfig = getGCSFsFromTemplate(folder.FsConfig.GCSConfig, replacements)
	case vfs.AzureBlobFilesystemProvider:
		folder.FsConfig.AzBlobConfig = getAzBlobFsFromTemplate(folder.FsConfig.AzBlobConfig, replacements)
	case vfs.SFTPFilesystemProvider:
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
	user.PublicKeys = nil
	if template.PublicKey != "" {
		user.PublicKeys = append(user.PublicKeys, template.PublicKey)
	}
	replacements := make(map[string]string)
	replacements["%username%"] = user.Username
	user.Password = replacePlaceholders(user.Password, replacements)
	replacements["%password%"] = user.Password

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
	case vfs.CryptedFilesystemProvider:
		user.FsConfig.CryptConfig = getCryptFsFromTemplate(user.FsConfig.CryptConfig, replacements)
	case vfs.S3FilesystemProvider:
		user.FsConfig.S3Config = getS3FsFromTemplate(user.FsConfig.S3Config, replacements)
	case vfs.GCSFilesystemProvider:
		user.FsConfig.GCSConfig = getGCSFsFromTemplate(user.FsConfig.GCSConfig, replacements)
	case vfs.AzureBlobFilesystemProvider:
		user.FsConfig.AzBlobConfig = getAzBlobFsFromTemplate(user.FsConfig.AzBlobConfig, replacements)
	case vfs.SFTPFilesystemProvider:
		user.FsConfig.SFTPConfig = getSFTPFsFromTemplate(user.FsConfig.SFTPConfig, replacements)
	}

	return user
}

func getUserFromPostFields(r *http.Request) (dataprovider.User, error) {
	var user dataprovider.User
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		return user, err
	}
	uid, err := strconv.Atoi(r.Form.Get("uid"))
	if err != nil {
		return user, err
	}
	gid, err := strconv.Atoi(r.Form.Get("gid"))
	if err != nil {
		return user, err
	}
	maxSessions, err := strconv.Atoi(r.Form.Get("max_sessions"))
	if err != nil {
		return user, err
	}
	quotaSize, err := strconv.ParseInt(r.Form.Get("quota_size"), 10, 64)
	if err != nil {
		return user, err
	}
	quotaFiles, err := strconv.Atoi(r.Form.Get("quota_files"))
	if err != nil {
		return user, err
	}
	bandwidthUL, err := strconv.ParseInt(r.Form.Get("upload_bandwidth"), 10, 64)
	if err != nil {
		return user, err
	}
	bandwidthDL, err := strconv.ParseInt(r.Form.Get("download_bandwidth"), 10, 64)
	if err != nil {
		return user, err
	}
	status, err := strconv.Atoi(r.Form.Get("status"))
	if err != nil {
		return user, err
	}
	expirationDateMillis := int64(0)
	expirationDateString := r.Form.Get("expiration_date")
	if len(strings.TrimSpace(expirationDateString)) > 0 {
		expirationDate, err := time.Parse(webDateTimeFormat, expirationDateString)
		if err != nil {
			return user, err
		}
		expirationDateMillis = utils.GetTimeAsMsSinceEpoch(expirationDate)
	}
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		return user, err
	}
	user = dataprovider.User{
		Username:          r.Form.Get("username"),
		Password:          r.Form.Get("password"),
		PublicKeys:        r.Form["public_keys"],
		HomeDir:           r.Form.Get("home_dir"),
		VirtualFolders:    getVirtualFoldersFromPostFields(r),
		UID:               uid,
		GID:               gid,
		Permissions:       getUserPermissionsFromPostFields(r),
		MaxSessions:       maxSessions,
		QuotaSize:         quotaSize,
		QuotaFiles:        quotaFiles,
		UploadBandwidth:   bandwidthUL,
		DownloadBandwidth: bandwidthDL,
		Status:            status,
		ExpirationDate:    expirationDateMillis,
		Filters:           getFiltersFromUserPostFields(r),
		FsConfig:          fsConfig,
		AdditionalInfo:    r.Form.Get("additional_info"),
		Description:       r.Form.Get("description"),
	}
	maxFileSize, err := strconv.ParseInt(r.Form.Get("max_upload_file_size"), 10, 64)
	user.Filters.MaxUploadFileSize = maxFileSize
	return user, err
}

func renderLoginPage(w http.ResponseWriter, error string) {
	data := loginPage{
		CurrentURL: webLoginPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(),
		StaticURL:  webStaticFilesPath,
	}
	renderAdminTemplate(w, templateLogin, data)
}

func handleWebAdminChangePwd(w http.ResponseWriter, r *http.Request) {
	renderChangePwdPage(w, r, "")
}

func handleWebAdminChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		renderChangePwdPage(w, r, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	err = doChangeAdminPassword(r, r.Form.Get("current_password"), r.Form.Get("new_password1"),
		r.Form.Get("new_password2"))
	if err != nil {
		renderChangePwdPage(w, r, err.Error())
		return
	}
	handleWebLogout(w, r)
}

func handleWebLogout(w http.ResponseWriter, r *http.Request) {
	c := jwtTokenClaims{}
	c.removeCookie(w, r, webBaseAdminPath)

	http.Redirect(w, r, webLoginPath, http.StatusFound)
}

func handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	renderLoginPage(w, "")
}

func handleWebMaintenance(w http.ResponseWriter, r *http.Request) {
	renderMaintenancePage(w, r, "")
}

func handleWebRestore(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(MaxRestoreSize)
	if err != nil {
		renderMaintenancePage(w, r, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	restoreMode, err := strconv.Atoi(r.Form.Get("mode"))
	if err != nil {
		renderMaintenancePage(w, r, err.Error())
		return
	}
	scanQuota, err := strconv.Atoi(r.Form.Get("quota"))
	if err != nil {
		renderMaintenancePage(w, r, err.Error())
		return
	}
	backupFile, _, err := r.FormFile("backup_file")
	if err != nil {
		renderMaintenancePage(w, r, err.Error())
		return
	}
	defer backupFile.Close()

	backupContent, err := io.ReadAll(backupFile)
	if err != nil || len(backupContent) == 0 {
		if len(backupContent) == 0 {
			err = errors.New("backup file size must be greater than 0")
		}
		renderMaintenancePage(w, r, err.Error())
		return
	}

	if err := restoreBackup(backupContent, "", scanQuota, restoreMode); err != nil {
		renderMaintenancePage(w, r, err.Error())
		return
	}

	renderMessagePage(w, r, "Data restored", "", http.StatusOK, nil, "Your backup was successfully restored")
}

func handleGetWebAdmins(w http.ResponseWriter, r *http.Request) {
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
			renderInternalServerErrorPage(w, r, err)
			return
		}
		admins = append(admins, a...)
		if len(a) < limit {
			break
		}
	}
	data := adminsPage{
		basePage: getBasePageData(pageAdminsTitle, webAdminsPath, r),
		Admins:   admins,
	}
	renderAdminTemplate(w, templateAdmins, data)
}

func handleWebAdminSetupGet(w http.ResponseWriter, r *http.Request) {
	if dataprovider.HasAdmin() {
		http.Redirect(w, r, webLoginPath, http.StatusFound)
		return
	}
	renderAdminSetupPage(w, r, "", "")
}

func handleWebAddAdminGet(w http.ResponseWriter, r *http.Request) {
	admin := &dataprovider.Admin{Status: 1}
	renderAddUpdateAdminPage(w, r, admin, "", true)
}

func handleWebUpdateAdminGet(w http.ResponseWriter, r *http.Request) {
	username := getURLParam(r, "username")
	admin, err := dataprovider.AdminExists(username)
	if err == nil {
		renderAddUpdateAdminPage(w, r, &admin, "", false)
	} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, r, err)
	} else {
		renderInternalServerErrorPage(w, r, err)
	}
}

func handleWebAddAdminPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	admin, err := getAdminFromPostFields(r)
	if err != nil {
		renderAddUpdateAdminPage(w, r, &admin, err.Error(), true)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	err = dataprovider.AddAdmin(&admin)
	if err != nil {
		renderAddUpdateAdminPage(w, r, &admin, err.Error(), true)
		return
	}
	http.Redirect(w, r, webAdminsPath, http.StatusSeeOther)
}

func handleWebUpdateAdminPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	username := getURLParam(r, "username")
	admin, err := dataprovider.AdminExists(username)
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		renderInternalServerErrorPage(w, r, err)
		return
	}

	updatedAdmin, err := getAdminFromPostFields(r)
	if err != nil {
		renderAddUpdateAdminPage(w, r, &updatedAdmin, err.Error(), false)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	updatedAdmin.ID = admin.ID
	updatedAdmin.Username = admin.Username
	if updatedAdmin.Password == "" {
		updatedAdmin.Password = admin.Password
	}
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		renderAddUpdateAdminPage(w, r, &updatedAdmin, fmt.Sprintf("Invalid token claims: %v", err), false)
		return
	}
	if username == claims.Username {
		if claims.isCriticalPermRemoved(updatedAdmin.Permissions) {
			renderAddUpdateAdminPage(w, r, &updatedAdmin, "You cannot remove these permissions to yourself", false)
			return
		}
		if updatedAdmin.Status == 0 {
			renderAddUpdateAdminPage(w, r, &updatedAdmin, "You cannot disable yourself", false)
			return
		}
	}
	err = dataprovider.UpdateAdmin(&updatedAdmin)
	if err != nil {
		renderAddUpdateAdminPage(w, r, &admin, err.Error(), false)
		return
	}
	http.Redirect(w, r, webAdminsPath, http.StatusSeeOther)
}

func handleWebDefenderPage(w http.ResponseWriter, r *http.Request) {
	data := defenderHostsPage{
		basePage:         getBasePageData(pageDefenderTitle, webDefenderPath, r),
		DefenderHostsURL: webDefenderHostsPath,
	}

	renderAdminTemplate(w, templateDefender, data)
}

func handleGetWebUsers(w http.ResponseWriter, r *http.Request) {
	limit := defaultQueryLimit
	if _, ok := r.URL.Query()["qlimit"]; ok {
		var err error
		limit, err = strconv.Atoi(r.URL.Query().Get("qlimit"))
		if err != nil {
			limit = defaultQueryLimit
		}
	}
	users := make([]dataprovider.User, 0, limit)
	for {
		u, err := dataprovider.GetUsers(limit, len(users), dataprovider.OrderASC)
		if err != nil {
			renderInternalServerErrorPage(w, r, err)
			return
		}
		users = append(users, u...)
		if len(u) < limit {
			break
		}
	}
	data := usersPage{
		basePage: getBasePageData(pageUsersTitle, webUsersPath, r),
		Users:    users,
	}
	renderAdminTemplate(w, templateUsers, data)
}

func handleWebTemplateFolderGet(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("from") != "" {
		name := r.URL.Query().Get("from")
		folder, err := dataprovider.GetFolderByName(name)
		if err == nil {
			renderFolderPage(w, r, folder, folderPageModeTemplate, "")
		} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
			renderNotFoundPage(w, r, err)
		} else {
			renderInternalServerErrorPage(w, r, err)
		}
	} else {
		folder := vfs.BaseVirtualFolder{}
		renderFolderPage(w, r, folder, folderPageModeTemplate, "")
	}
}

func handleWebTemplateFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	templateFolder := vfs.BaseVirtualFolder{}
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		renderMessagePage(w, r, "Error parsing folders fields", "", http.StatusBadRequest, err, "")
		return
	}

	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}

	templateFolder.MappedPath = r.Form.Get("mapped_path")
	templateFolder.Description = r.Form.Get("description")
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		renderMessagePage(w, r, "Error parsing folders fields", "", http.StatusBadRequest, err, "")
		return
	}
	templateFolder.FsConfig = fsConfig

	var dump dataprovider.BackupData
	dump.Version = dataprovider.DumpVersion

	foldersFields := getFoldersForTemplate(r)
	for _, tmpl := range foldersFields {
		f := getFolderFromTemplate(templateFolder, tmpl)
		if err := dataprovider.ValidateFolder(&f); err != nil {
			renderMessagePage(w, r, fmt.Sprintf("Error validating folder %#v", f.Name), "", http.StatusBadRequest, err, "")
			return
		}
		dump.Folders = append(dump.Folders, f)
	}

	if len(dump.Folders) == 0 {
		renderMessagePage(w, r, "No folders to export", "No valid folders found, export is not possible", http.StatusBadRequest, nil, "")
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sftpgo-%v-folders-from-template.json\"", len(dump.Folders)))
	render.JSON(w, r, dump)
}

func handleWebTemplateUserGet(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("from") != "" {
		username := r.URL.Query().Get("from")
		user, err := dataprovider.UserExists(username)
		if err == nil {
			user.SetEmptySecrets()
			renderUserPage(w, r, &user, userPageModeTemplate, "")
		} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
			renderNotFoundPage(w, r, err)
		} else {
			renderInternalServerErrorPage(w, r, err)
		}
	} else {
		user := dataprovider.User{Status: 1}
		renderUserPage(w, r, &user, userPageModeTemplate, "")
	}
}

func handleWebTemplateUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	templateUser, err := getUserFromPostFields(r)
	if err != nil {
		renderMessagePage(w, r, "Error parsing user fields", "", http.StatusBadRequest, err, "")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}

	var dump dataprovider.BackupData
	dump.Version = dataprovider.DumpVersion

	userTmplFields := getUsersForTemplate(r)
	for _, tmpl := range userTmplFields {
		u := getUserFromTemplate(templateUser, tmpl)
		if err := dataprovider.ValidateUser(&u); err != nil {
			renderMessagePage(w, r, fmt.Sprintf("Error validating user %#v", u.Username), "", http.StatusBadRequest, err, "")
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
		renderMessagePage(w, r, "No users to export", "No valid users found, export is not possible", http.StatusBadRequest, nil, "")
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sftpgo-%v-users-from-template.json\"", len(dump.Users)))
	render.JSON(w, r, dump)
}

func handleWebAddUserGet(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("clone-from") != "" {
		username := r.URL.Query().Get("clone-from")
		user, err := dataprovider.UserExists(username)
		if err == nil {
			user.ID = 0
			user.Username = ""
			user.Password = ""
			user.SetEmptySecrets()
			renderUserPage(w, r, &user, userPageModeAdd, "")
		} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
			renderNotFoundPage(w, r, err)
		} else {
			renderInternalServerErrorPage(w, r, err)
		}
	} else {
		user := dataprovider.User{Status: 1}
		renderUserPage(w, r, &user, userPageModeAdd, "")
	}
}

func handleWebUpdateUserGet(w http.ResponseWriter, r *http.Request) {
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username)
	if err == nil {
		renderUserPage(w, r, &user, userPageModeUpdate, "")
	} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, r, err)
	} else {
		renderInternalServerErrorPage(w, r, err)
	}
}

func handleWebAddUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	user, err := getUserFromPostFields(r)
	if err != nil {
		renderUserPage(w, r, &user, userPageModeAdd, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	err = dataprovider.AddUser(&user)
	if err == nil {
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		renderUserPage(w, r, &user, userPageModeAdd, err.Error())
	}
}

func handleWebUpdateUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username)
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		renderInternalServerErrorPage(w, r, err)
		return
	}
	updatedUser, err := getUserFromPostFields(r)
	if err != nil {
		renderUserPage(w, r, &user, userPageModeUpdate, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	updatedUser.ID = user.ID
	updatedUser.Username = user.Username
	updatedUser.SetEmptySecretsIfNil()
	if updatedUser.Password == redactedSecret {
		updatedUser.Password = user.Password
	}
	updateEncryptedSecrets(&updatedUser.FsConfig, user.FsConfig.S3Config.AccessSecret, user.FsConfig.AzBlobConfig.AccountKey,
		user.FsConfig.AzBlobConfig.SASURL, user.FsConfig.GCSConfig.Credentials, user.FsConfig.CryptConfig.Passphrase,
		user.FsConfig.SFTPConfig.Password, user.FsConfig.SFTPConfig.PrivateKey)

	err = dataprovider.UpdateUser(&updatedUser)
	if err == nil {
		if len(r.Form.Get("disconnect")) > 0 {
			disconnectUser(user.Username)
		}
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		renderUserPage(w, r, &user, userPageModeUpdate, err.Error())
	}
}

func handleWebGetStatus(w http.ResponseWriter, r *http.Request) {
	data := statusPage{
		basePage: getBasePageData(pageStatusTitle, webStatusPath, r),
		Status:   getServicesStatus(),
	}
	renderAdminTemplate(w, templateStatus, data)
}

func handleWebGetConnections(w http.ResponseWriter, r *http.Request) {
	connectionStats := common.Connections.GetStats()
	data := connectionsPage{
		basePage:    getBasePageData(pageConnectionsTitle, webConnectionsPath, r),
		Connections: connectionStats,
	}
	renderAdminTemplate(w, templateConnections, data)
}

func handleWebAddFolderGet(w http.ResponseWriter, r *http.Request) {
	renderFolderPage(w, r, vfs.BaseVirtualFolder{}, folderPageModeAdd, "")
}

func handleWebAddFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	folder := vfs.BaseVirtualFolder{}
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		renderFolderPage(w, r, folder, folderPageModeAdd, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	folder.MappedPath = r.Form.Get("mapped_path")
	folder.Name = r.Form.Get("name")
	folder.Description = r.Form.Get("description")
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		renderFolderPage(w, r, folder, folderPageModeAdd, err.Error())
		return
	}
	folder.FsConfig = fsConfig

	err = dataprovider.AddFolder(&folder)
	if err == nil {
		http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
	} else {
		renderFolderPage(w, r, folder, folderPageModeAdd, err.Error())
	}
}

func handleWebUpdateFolderGet(w http.ResponseWriter, r *http.Request) {
	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if err == nil {
		renderFolderPage(w, r, folder, folderPageModeUpdate, "")
	} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, r, err)
	} else {
		renderInternalServerErrorPage(w, r, err)
	}
}

func handleWebUpdateFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		renderInternalServerErrorPage(w, r, err)
		return
	}

	err = r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		renderFolderPage(w, r, folder, folderPageModeUpdate, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		renderFolderPage(w, r, folder, folderPageModeUpdate, err.Error())
		return
	}
	updatedFolder := &vfs.BaseVirtualFolder{
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

	err = dataprovider.UpdateFolder(updatedFolder, folder.Users)
	if err != nil {
		renderFolderPage(w, r, folder, folderPageModeUpdate, err.Error())
		return
	}
	http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
}

func getWebVirtualFolders(w http.ResponseWriter, r *http.Request, limit int) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	for {
		f, err := dataprovider.GetFolders(limit, len(folders), dataprovider.OrderASC)
		if err != nil {
			renderInternalServerErrorPage(w, r, err)
			return folders, err
		}
		folders = append(folders, f...)
		if len(f) < limit {
			break
		}
	}
	return folders, nil
}

func handleWebGetFolders(w http.ResponseWriter, r *http.Request) {
	limit := defaultQueryLimit
	if _, ok := r.URL.Query()["qlimit"]; ok {
		var err error
		limit, err = strconv.Atoi(r.URL.Query().Get("qlimit"))
		if err != nil {
			limit = defaultQueryLimit
		}
	}
	folders, err := getWebVirtualFolders(w, r, limit)
	if err != nil {
		return
	}

	data := foldersPage{
		basePage: getBasePageData(pageFoldersTitle, webFoldersPath, r),
		Folders:  folders,
	}
	renderAdminTemplate(w, templateFolders, data)
}
