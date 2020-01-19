package httpd

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
)

const (
	templateBase           = "base.html"
	templateUsers          = "users.html"
	templateUser           = "user.html"
	templateConnections    = "connections.html"
	templateMessage        = "message.html"
	pageUsersTitle         = "Users"
	pageConnectionsTitle   = "Connections"
	page400Title           = "Bad request"
	page404Title           = "Not found"
	page404Body            = "The page you are looking for does not exist."
	page500Title           = "Internal Server Error"
	page500Body            = "The server is unable to fulfill your request."
	defaultUsersQueryLimit = 500
	webDateTimeFormat      = "2006-01-02 15:04:05" // YYYY-MM-DD HH:MM:SS
)

var (
	templates = make(map[string]*template.Template)
)

type basePage struct {
	Title             string
	CurrentURL        string
	UsersURL          string
	UserURL           string
	APIUserURL        string
	APIConnectionsURL string
	APIQuotaScanURL   string
	ConnectionsURL    string
	UsersTitle        string
	ConnectionsTitle  string
	Version           string
}

type usersPage struct {
	basePage
	Users []dataprovider.User
}

type connectionsPage struct {
	basePage
	Connections []sftpd.ConnectionStatus
}

type userPage struct {
	basePage
	IsAdd        bool
	User         dataprovider.User
	RootPerms    []string
	Error        string
	ValidPerms   []string
	RootDirPerms []string
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
	usersTmpl := template.Must(template.ParseFiles(usersPaths...))
	userTmpl := template.Must(template.ParseFiles(userPaths...))
	connectionsTmpl := template.Must(template.ParseFiles(connectionsPaths...))
	messageTmpl := template.Must(template.ParseFiles(messagePath...))

	templates[templateUsers] = usersTmpl
	templates[templateUser] = userTmpl
	templates[templateConnections] = connectionsTmpl
	templates[templateMessage] = messageTmpl
}

func getBasePageData(title, currentURL string) basePage {
	version := utils.GetAppVersion()
	return basePage{
		Title:             title,
		CurrentURL:        currentURL,
		UsersURL:          webUsersPath,
		UserURL:           webUserPath,
		APIUserURL:        userPath,
		APIConnectionsURL: activeConnectionsPath,
		APIQuotaScanURL:   quotaScanPath,
		ConnectionsURL:    webConnectionsPath,
		UsersTitle:        pageUsersTitle,
		ConnectionsTitle:  pageConnectionsTitle,
		Version:           version.GetVersionAsString(),
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
	renderMessagePage(w, page500Title, page400Title, http.StatusInternalServerError, err, "")
}

func renderBadRequestPage(w http.ResponseWriter, err error) {
	renderMessagePage(w, page400Title, "", http.StatusBadRequest, err, "")
}

func renderNotFoundPage(w http.ResponseWriter, err error) {
	renderMessagePage(w, page404Title, page404Body, http.StatusNotFound, err, "")
}

func renderAddUserPage(w http.ResponseWriter, user dataprovider.User, error string) {
	data := userPage{
		basePage:     getBasePageData("Add a new user", webUserPath),
		IsAdd:        true,
		Error:        error,
		User:         user,
		ValidPerms:   dataprovider.ValidPerms,
		RootDirPerms: user.GetPermissionsForPath("/"),
	}
	renderTemplate(w, templateUser, data)
}

func renderUpdateUserPage(w http.ResponseWriter, user dataprovider.User, error string) {
	data := userPage{
		basePage:     getBasePageData("Update user", fmt.Sprintf("%v/%v", webUserPath, user.ID)),
		IsAdd:        false,
		Error:        error,
		User:         user,
		ValidPerms:   dataprovider.ValidPerms,
		RootDirPerms: user.GetPermissionsForPath("/"),
	}
	renderTemplate(w, templateUser, data)
}

func getUserPermissionsFromPostFields(r *http.Request) map[string][]string {
	permissions := make(map[string][]string)
	permissions["/"] = r.Form["permissions"]
	subDirsPermsValue := r.Form.Get("sub_dirs_permissions")
	for _, cleaned := range getSliceFromDelimitedValues(subDirsPermsValue, "\n") {
		if strings.ContainsRune(cleaned, ':') {
			dirPerms := strings.Split(cleaned, ":")
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
				if len(dir) > 0 && len(perms) > 0 {
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

func getFiltersFromUserPostFields(r *http.Request) dataprovider.UserFilters {
	var filters dataprovider.UserFilters
	filters.AllowedIP = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	filters.DeniedIP = getSliceFromDelimitedValues(r.Form.Get("denied_ip"), ",")
	return filters
}

func getFsConfigFromUserPostFields(r *http.Request) dataprovider.Filesystem {
	var fs dataprovider.Filesystem
	provider, err := strconv.Atoi(r.Form.Get("fs_provider"))
	if err != nil {
		provider = 0
	}
	fs.Provider = provider
	if fs.Provider == 1 {
		fs.S3Config.Bucket = r.Form.Get("s3_bucket")
		fs.S3Config.Region = r.Form.Get("s3_region")
		fs.S3Config.AccessKey = r.Form.Get("s3_access_key")
		fs.S3Config.AccessSecret = r.Form.Get("s3_access_secret")
		fs.S3Config.Endpoint = r.Form.Get("s3_endpoint")
		fs.S3Config.StorageClass = r.Form.Get("s3_storage_class")
	}
	return fs
}

func getUserFromPostFields(r *http.Request) (dataprovider.User, error) {
	var user dataprovider.User
	err := r.ParseForm()
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
	user = dataprovider.User{
		Username:          r.Form.Get("username"),
		Password:          r.Form.Get("password"),
		PublicKeys:        publicKeys,
		HomeDir:           r.Form.Get("home_dir"),
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
		FsConfig:          getFsConfigFromUserPostFields(r),
	}
	return user, err
}

func handleGetWebUsers(w http.ResponseWriter, r *http.Request) {
	limit := defaultUsersQueryLimit
	if _, ok := r.URL.Query()["qlimit"]; ok {
		var err error
		limit, err = strconv.Atoi(r.URL.Query().Get("qlimit"))
		if err != nil {
			limit = defaultUsersQueryLimit
		}
	}
	var users []dataprovider.User
	u, err := dataprovider.GetUsers(dataProvider, limit, 0, "ASC", "")
	users = append(users, u...)
	for len(u) == limit {
		u, err = dataprovider.GetUsers(dataProvider, limit, len(users), "ASC", "")
		if err == nil && len(u) > 0 {
			users = append(users, u...)
		} else {
			break
		}
	}
	if err != nil {
		renderInternalServerErrorPage(w, err)
		return
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

func handleWebUpdateUserGet(userID string, w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		renderBadRequestPage(w, err)
		return
	}
	user, err := dataprovider.GetUserByID(dataProvider, id)
	if err == nil {
		renderUpdateUserPage(w, user, "")
	} else if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		renderNotFoundPage(w, err)
	} else {
		renderInternalServerErrorPage(w, err)
	}
}

func handleWebAddUserPost(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromPostFields(r)
	if err != nil {
		renderAddUserPage(w, user, err.Error())
		return
	}
	err = dataprovider.AddUser(dataProvider, user)
	if err == nil {
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		renderAddUserPage(w, user, err.Error())
	}
}

func handleWebUpdateUserPost(userID string, w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		renderBadRequestPage(w, err)
		return
	}
	user, err := dataprovider.GetUserByID(dataProvider, id)
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
	if len(updatedUser.Password) == 0 {
		updatedUser.Password = user.Password
	}
	err = dataprovider.UpdateUser(dataProvider, updatedUser)
	if err == nil {
		http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
	} else {
		renderUpdateUserPage(w, user, err.Error())
	}
}

func handleWebGetConnections(w http.ResponseWriter, r *http.Request) {
	connectionStats := sftpd.GetConnectionsStats()
	data := connectionsPage{
		basePage:    getBasePageData(pageConnectionsTitle, webConnectionsPath),
		Connections: connectionStats,
	}
	renderTemplate(w, templateConnections, data)
}
