package httpd

import (
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	templateBase         = "base.html"
	templateUsers        = "users.html"
	templateUser         = "user.html"
	templateConnections  = "connections.html"
	templateFolders      = "folders.html"
	templateFolder       = "folder.html"
	templateMessage      = "message.html"
	templateStatus       = "status.html"
	pageUsersTitle       = "Users"
	pageConnectionsTitle = "Connections"
	pageStatusTitle      = "Status"
	pageFoldersTitle     = "Folders"
	page400Title         = "Bad request"
	page404Title         = "Not found"
	page404Body          = "The page you are looking for does not exist."
	page500Title         = "Internal Server Error"
	page500Body          = "The server is unable to fulfill your request."
	defaultQueryLimit    = 500
	webDateTimeFormat    = "2006-01-02 15:04:05" // YYYY-MM-DD HH:MM:SS
	redactedSecret       = "[**redacted**]"
)

var (
	templates = make(map[string]*template.Template)
)

type basePage struct {
	Title                 string
	CurrentURL            string
	UsersURL              string
	UserURL               string
	APIUserURL            string
	APIConnectionsURL     string
	APIQuotaScanURL       string
	ConnectionsURL        string
	FoldersURL            string
	FolderURL             string
	APIFoldersURL         string
	APIFolderQuotaScanURL string
	StatusURL             string
	UsersTitle            string
	ConnectionsTitle      string
	FoldersTitle          string
	StatusTitle           string
	Version               string
}

type usersPage struct {
	basePage
	Users []dataprovider.User
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
	Status ServicesStatus
}

type userPage struct {
	basePage
	User                 dataprovider.User
	RootPerms            []string
	Error                string
	ValidPerms           []string
	ValidSSHLoginMethods []string
	ValidProtocols       []string
	RootDirPerms         []string
	RedactedSecret       string
	IsAdd                bool
}

type folderPage struct {
	basePage
	Folder vfs.BaseVirtualFolder
	Error  string
}

type messagePage struct {
	basePage
	Error   string
	Success string
}

func loadTemplates(templatesPath string) {
	usersPaths := []string{
		filepath.Join(templatesPath, templateBase),
		filepath.Join(templatesPath, templateUsers),
	}
	userPaths := []string{
		filepath.Join(templatesPath, templateBase),
		filepath.Join(templatesPath, templateUser),
	}
	connectionsPaths := []string{
		filepath.Join(templatesPath, templateBase),
		filepath.Join(templatesPath, templateConnections),
	}
	messagePath := []string{
		filepath.Join(templatesPath, templateBase),
		filepath.Join(templatesPath, templateMessage),
	}
	foldersPath := []string{
		filepath.Join(templatesPath, templateBase),
		filepath.Join(templatesPath, templateFolders),
	}
	folderPath := []string{
		filepath.Join(templatesPath, templateBase),
		filepath.Join(templatesPath, templateFolder),
	}
	statusPath := []string{
		filepath.Join(templatesPath, templateBase),
		filepath.Join(templatesPath, templateStatus),
	}
	usersTmpl := utils.LoadTemplate(template.ParseFiles(usersPaths...))
	userTmpl := utils.LoadTemplate(template.ParseFiles(userPaths...))
	connectionsTmpl := utils.LoadTemplate(template.ParseFiles(connectionsPaths...))
	messageTmpl := utils.LoadTemplate(template.ParseFiles(messagePath...))
	foldersTmpl := utils.LoadTemplate(template.ParseFiles(foldersPath...))
	folderTmpl := utils.LoadTemplate(template.ParseFiles(folderPath...))
	statusTmpl := utils.LoadTemplate(template.ParseFiles(statusPath...))

	templates[templateUsers] = usersTmpl
	templates[templateUser] = userTmpl
	templates[templateConnections] = connectionsTmpl
	templates[templateMessage] = messageTmpl
	templates[templateFolders] = foldersTmpl
	templates[templateFolder] = folderTmpl
	templates[templateStatus] = statusTmpl
}

func getBasePageData(title, currentURL string) basePage {
	return basePage{
		Title:                 title,
		CurrentURL:            currentURL,
		UsersURL:              webUsersPath,
		UserURL:               webUserPath,
		FoldersURL:            webFoldersPath,
		FolderURL:             webFolderPath,
		APIUserURL:            userPath,
		APIConnectionsURL:     activeConnectionsPath,
		APIQuotaScanURL:       quotaScanPath,
		APIFoldersURL:         folderPath,
		APIFolderQuotaScanURL: quotaScanVFolderPath,
		ConnectionsURL:        webConnectionsPath,
		StatusURL:             webStatusPath,
		UsersTitle:            pageUsersTitle,
		ConnectionsTitle:      pageConnectionsTitle,
		FoldersTitle:          pageFoldersTitle,
		StatusTitle:           pageStatusTitle,
		Version:               version.GetAsString(),
	}
}

func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	err := templates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderMessagePage(w http.ResponseWriter, title, body string, statusCode int, err error, message string) {
	var errorString string
	if len(body) > 0 {
		errorString = body + " "
	}
	if err != nil {
		errorString += err.Error()
	}
	data := messagePage{
		basePage: getBasePageData(title, ""),
		Error:    errorString,
		Success:  message,
	}
	w.WriteHeader(statusCode)
	renderTemplate(w, templateMessage, data)
}

func renderInternalServerErrorPage(w http.ResponseWriter, err error) {
	renderMessagePage(w, page500Title, page500Body, http.StatusInternalServerError, err, "")
}

func renderBadRequestPage(w http.ResponseWriter, err error) {
	renderMessagePage(w, page400Title, "", http.StatusBadRequest, err, "")
}

func renderNotFoundPage(w http.ResponseWriter, err error) {
	renderMessagePage(w, page404Title, page404Body, http.StatusNotFound, err, "")
}

func renderAddUserPage(w http.ResponseWriter, user dataprovider.User, error string) {
	user.SetEmptySecretsIfNil()
	data := userPage{
		basePage:             getBasePageData("Add a new user", webUserPath),
		IsAdd:                true,
		Error:                error,
		User:                 user,
		ValidPerms:           dataprovider.ValidPerms,
		ValidSSHLoginMethods: dataprovider.ValidSSHLoginMethods,
		ValidProtocols:       dataprovider.ValidProtocols,
		RootDirPerms:         user.GetPermissionsForPath("/"),
		RedactedSecret:       redactedSecret,
	}
	renderTemplate(w, templateUser, data)
}

func renderUpdateUserPage(w http.ResponseWriter, user dataprovider.User, error string) {
	user.SetEmptySecretsIfNil()
	data := userPage{
		basePage:             getBasePageData("Update user", fmt.Sprintf("%v/%v", webUserPath, user.ID)),
		IsAdd:                false,
		Error:                error,
		User:                 user,
		ValidPerms:           dataprovider.ValidPerms,
		ValidSSHLoginMethods: dataprovider.ValidSSHLoginMethods,
		ValidProtocols:       dataprovider.ValidProtocols,
		RootDirPerms:         user.GetPermissionsForPath("/"),
		RedactedSecret:       redactedSecret,
	}
	renderTemplate(w, templateUser, data)
}

func renderAddFolderPage(w http.ResponseWriter, folder vfs.BaseVirtualFolder, error string) {
	data := folderPage{
		basePage: getBasePageData("Add a new folder", webFolderPath),
		Error:    error,
		Folder:   folder,
	}
	renderTemplate(w, templateFolder, data)
}

func getVirtualFoldersFromPostFields(r *http.Request) []vfs.VirtualFolder {
	var virtualFolders []vfs.VirtualFolder
	formValue := r.Form.Get("virtual_folders")
	for _, cleaned := range getSliceFromDelimitedValues(formValue, "\n") {
		if strings.Contains(cleaned, "::") {
			mapping := strings.Split(cleaned, "::")
			if len(mapping) > 1 {
				vfolder := vfs.VirtualFolder{
					BaseVirtualFolder: vfs.BaseVirtualFolder{
						MappedPath: strings.TrimSpace(mapping[1]),
					},
					VirtualPath: strings.TrimSpace(mapping[0]),
					QuotaFiles:  -1,
					QuotaSize:   -1,
				}
				if len(mapping) > 2 {
					quotaFiles, err := strconv.Atoi(strings.TrimSpace(mapping[2]))
					if err == nil {
						vfolder.QuotaFiles = quotaFiles
					}
				}
				if len(mapping) > 3 {
					quotaSize, err := strconv.ParseInt(strings.TrimSpace(mapping[3]), 10, 64)
					if err == nil {
						vfolder.QuotaSize = quotaSize
					}
				}
				virtualFolders = append(virtualFolders, vfolder)
			}
		}
	}
	return virtualFolders
}

func getUserPermissionsFromPostFields(r *http.Request) map[string][]string {
	permissions := make(map[string][]string)
	permissions["/"] = r.Form["permissions"]
	subDirsPermsValue := r.Form.Get("sub_dirs_permissions")
	for _, cleaned := range getSliceFromDelimitedValues(subDirsPermsValue, "\n") {
		if strings.Contains(cleaned, "::") {
			dirPerms := strings.Split(cleaned, "::")
			if len(dirPerms) > 1 {
				dir := dirPerms[0]
				dir = strings.TrimSpace(dir)
				perms := []string{}
				for _, p := range strings.Split(dirPerms[1], ",") {
					cleanedPerm := strings.TrimSpace(p)
					if len(cleanedPerm) > 0 {
						perms = append(perms, cleanedPerm)
					}
				}
				if len(dir) > 0 {
					permissions[dir] = perms
				}
			}
		}
	}
	return permissions
}

func getSliceFromDelimitedValues(values, delimiter string) []string {
	result := []string{}
	for _, v := range strings.Split(values, delimiter) {
		cleaned := strings.TrimSpace(v)
		if len(cleaned) > 0 {
			result = append(result, cleaned)
		}
	}
	return result
}

func getListFromPostFields(value string) map[string][]string {
	result := make(map[string][]string)
	for _, cleaned := range getSliceFromDelimitedValues(value, "\n") {
		if strings.Contains(cleaned, "::") {
			dirExts := strings.Split(cleaned, "::")
			if len(dirExts) > 1 {
				dir := dirExts[0]
				dir = path.Clean(strings.TrimSpace(dir))
				exts := []string{}
				for _, e := range strings.Split(dirExts[1], ",") {
					cleanedExt := strings.TrimSpace(e)
					if cleanedExt != "" {
						exts = append(exts, cleanedExt)
					}
				}
				if dir != "" {
					if _, ok := result[dir]; ok {
						result[dir] = append(result[dir], exts...)
					} else {
						result[dir] = exts
					}
					result[dir] = utils.RemoveDuplicates(result[dir])
				}
			}
		}
	}
	return result
}

func getFilePatternsFromPostField(valueAllowed, valuesDenied string) []dataprovider.PatternsFilter {
	var result []dataprovider.PatternsFilter
	allowedPatterns := getListFromPostFields(valueAllowed)
	deniedPatterns := getListFromPostFields(valuesDenied)

	for dirAllowed, allowPatterns := range allowedPatterns {
		filter := dataprovider.PatternsFilter{
			Path:            dirAllowed,
			AllowedPatterns: allowPatterns,
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
			result = append(result, dataprovider.PatternsFilter{
				Path:           dirDenied,
				DeniedPatterns: denPatterns,
			})
		}
	}
	return result
}

func getFileExtensionsFromPostField(valueAllowed, valuesDenied string) []dataprovider.ExtensionsFilter {
	var result []dataprovider.ExtensionsFilter
	allowedExtensions := getListFromPostFields(valueAllowed)
	deniedExtensions := getListFromPostFields(valuesDenied)

	for dirAllowed, allowedExts := range allowedExtensions {
		filter := dataprovider.ExtensionsFilter{
			Path:              dirAllowed,
			AllowedExtensions: allowedExts,
		}
		for dirDenied, deniedExts := range deniedExtensions {
			if dirAllowed == dirDenied {
				filter.DeniedExtensions = deniedExts
				break
			}
		}
		result = append(result, filter)
	}
	for dirDenied, deniedExts := range deniedExtensions {
		found := false
		for _, res := range result {
			if res.Path == dirDenied {
				found = true
				break
			}
		}
		if !found {
			result = append(result, dataprovider.ExtensionsFilter{
				Path:             dirDenied,
				DeniedExtensions: deniedExts,
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
	filters.FileExtensions = getFileExtensionsFromPostField(r.Form.Get("allowed_extensions"), r.Form.Get("denied_extensions"))
	filters.FilePatterns = getFilePatternsFromPostField(r.Form.Get("allowed_patterns"), r.Form.Get("denied_patterns"))
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
	fileBytes, err := ioutil.ReadAll(credentials)
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

func getAzureConfig(r *http.Request) (vfs.AzBlobFsConfig, error) {
	var err error
	config := vfs.AzBlobFsConfig{}
	config.Container = r.Form.Get("az_container")
	config.AccountName = r.Form.Get("az_account_name")
	config.AccountKey = getSecretFromFormField(r, "az_account_key")
	config.SASURL = r.Form.Get("az_sas_url")
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

func getFsConfigFromUserPostFields(r *http.Request) (dataprovider.Filesystem, error) {
	var fs dataprovider.Filesystem
	provider, err := strconv.Atoi(r.Form.Get("fs_provider"))
	if err != nil {
		provider = int(dataprovider.LocalFilesystemProvider)
	}
	fs.Provider = dataprovider.FilesystemProvider(provider)
	if fs.Provider == dataprovider.S3FilesystemProvider {
		config, err := getS3Config(r)
		if err != nil {
			return fs, err
		}
		fs.S3Config = config
	} else if fs.Provider == dataprovider.GCSFilesystemProvider {
		config, err := getGCSConfig(r)
		if err != nil {
			return fs, err
		}
		fs.GCSConfig = config
	} else if fs.Provider == dataprovider.AzureBlobFilesystemProvider {
		config, err := getAzureConfig(r)
		if err != nil {
			return fs, err
		}
		fs.AzBlobConfig = config
	} else if fs.Provider == dataprovider.CryptedFilesystemProvider {
		fs.CryptConfig.Passphrase = getSecretFromFormField(r, "crypt_passphrase")
	}
	return fs, nil
}

func getUserFromPostFields(r *http.Request) (dataprovider.User, error) {
	var user dataprovider.User
	err := r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		return user, err
	}
	publicKeysFormValue := r.Form.Get("public_keys")
	publicKeys := getSliceFromDelimitedValues(publicKeysFormValue, "\n")
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
	fsConfig, err := getFsConfigFromUserPostFields(r)
	if err != nil {
		return user, err
	}
	user = dataprovider.User{
		Username:          r.Form.Get("username"),
		Password:          r.Form.Get("password"),
		PublicKeys:        publicKeys,
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
	}
	maxFileSize, err := strconv.ParseInt(r.Form.Get("max_upload_file_size"), 10, 64)
	user.Filters.MaxUploadFileSize = maxFileSize
	return user, err
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
		u, err := dataprovider.GetUsers(limit, len(users), dataprovider.OrderASC, "")
		if err != nil {
			renderInternalServerErrorPage(w, err)
			return
		}
		users = append(users, u...)
		if len(u) < limit {
			break
		}
	}
	data := usersPage{
		basePage: getBasePageData(pageUsersTitle, webUsersPath),
		Users:    users,
	}
	renderTemplate(w, templateUsers, data)
}

func handleWebAddUserGet(w http.ResponseWriter, r *http.Request) {
	renderAddUserPage(w, dataprovider.User{Status: 1}, "")
}

func handleWebUpdateUserGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil {
		renderBadRequestPage(w, err)
		return
	}
	user, err := dataprovider.GetUserByID(id)
	if err == nil {
		renderUpdateUserPage(w, user, "")
	} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, err)
	} else {
		renderInternalServerErrorPage(w, err)
	}
}

func handleWebAddUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	user, err := getUserFromPostFields(r)
	if err != nil {
		renderAddUserPage(w, user, err.Error())
		return
	}
	err = dataprovider.AddUser(user)
	if err == nil {
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		renderAddUserPage(w, user, err.Error())
	}
}

func handleWebUpdateUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	id, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil {
		renderBadRequestPage(w, err)
		return
	}
	user, err := dataprovider.GetUserByID(id)
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, err)
		return
	} else if err != nil {
		renderInternalServerErrorPage(w, err)
		return
	}
	updatedUser, err := getUserFromPostFields(r)
	if err != nil {
		renderUpdateUserPage(w, user, err.Error())
		return
	}
	updatedUser.ID = user.ID
	updatedUser.SetEmptySecretsIfNil()
	if len(updatedUser.Password) == 0 {
		updatedUser.Password = user.Password
	}
	if !updatedUser.FsConfig.S3Config.AccessSecret.IsPlain() && !updatedUser.FsConfig.S3Config.AccessSecret.IsEmpty() {
		updatedUser.FsConfig.S3Config.AccessSecret = user.FsConfig.S3Config.AccessSecret
	}
	if !updatedUser.FsConfig.AzBlobConfig.AccountKey.IsPlain() && !updatedUser.FsConfig.AzBlobConfig.AccountKey.IsEmpty() {
		updatedUser.FsConfig.AzBlobConfig.AccountKey = user.FsConfig.AzBlobConfig.AccountKey
	}
	if !updatedUser.FsConfig.CryptConfig.Passphrase.IsPlain() && !updatedUser.FsConfig.CryptConfig.Passphrase.IsEmpty() {
		updatedUser.FsConfig.CryptConfig.Passphrase = user.FsConfig.CryptConfig.Passphrase
	}
	err = dataprovider.UpdateUser(updatedUser)
	if err == nil {
		if len(r.Form.Get("disconnect")) > 0 {
			disconnectUser(user.Username)
		}
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		renderUpdateUserPage(w, user, err.Error())
	}
}

func handleWebGetStatus(w http.ResponseWriter, r *http.Request) {
	data := statusPage{
		basePage: getBasePageData(pageStatusTitle, webStatusPath),
		Status:   getServicesStatus(),
	}
	renderTemplate(w, templateStatus, data)
}

func handleWebGetConnections(w http.ResponseWriter, r *http.Request) {
	connectionStats := common.Connections.GetStats()
	data := connectionsPage{
		basePage:    getBasePageData(pageConnectionsTitle, webConnectionsPath),
		Connections: connectionStats,
	}
	renderTemplate(w, templateConnections, data)
}

func handleWebAddFolderGet(w http.ResponseWriter, r *http.Request) {
	renderAddFolderPage(w, vfs.BaseVirtualFolder{}, "")
}

func handleWebAddFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	folder := vfs.BaseVirtualFolder{}
	err := r.ParseForm()
	if err != nil {
		renderAddFolderPage(w, folder, err.Error())
		return
	}
	folder.MappedPath = r.Form.Get("mapped_path")

	err = dataprovider.AddFolder(folder)
	if err == nil {
		http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
	} else {
		renderAddFolderPage(w, folder, err.Error())
	}
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
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	for {
		f, err := dataprovider.GetFolders(limit, len(folders), dataprovider.OrderASC, "")
		if err != nil {
			renderInternalServerErrorPage(w, err)
			return
		}
		folders = append(folders, f...)
		if len(f) < limit {
			break
		}
	}

	data := foldersPage{
		basePage: getBasePageData(pageFoldersTitle, webFoldersPath),
		Folders:  folders,
	}
	renderTemplate(w, templateFolders, data)
}
