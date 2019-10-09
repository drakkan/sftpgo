package httpd

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/sftpd"
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
	ConnectionsURL    string
	UsersTitle        string
	ConnectionsTitle  string
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
	IsAdd      bool
	User       dataprovider.User
	Error      string
	ValidPerms []string
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
	return basePage{
		Title:             title,
		CurrentURL:        currentURL,
		UsersURL:          webUsersPath,
		UserURL:           webUserPath,
		APIUserURL:        userPath,
		APIConnectionsURL: activeConnectionsPath,
		ConnectionsURL:    webConnectionsPath,
		UsersTitle:        pageUsersTitle,
		ConnectionsTitle:  pageConnectionsTitle,
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
		basePage:   getBasePageData("Add a new user", webUserPath),
		IsAdd:      true,
		Error:      error,
		User:       user,
		ValidPerms: dataprovider.ValidPerms,
	}
	renderTemplate(w, templateUser, data)
}

func renderUpdateUserPage(w http.ResponseWriter, user dataprovider.User, error string) {
	data := userPage{
		basePage:   getBasePageData("Update user", fmt.Sprintf("%v/%v", webUserPath, user.ID)),
		IsAdd:      false,
		Error:      error,
		User:       user,
		ValidPerms: dataprovider.ValidPerms,
	}
	renderTemplate(w, templateUser, data)
}

func getUserFromPostFields(r *http.Request) (dataprovider.User, error) {
	var user dataprovider.User
	err := r.ParseForm()
	if err != nil {
		return user, err
	}
	publicKeysFormValue := r.Form.Get("public_keys")
	publicKeys := []string{}
	for _, v := range strings.Split(publicKeysFormValue, "\n") {
		cleaned := strings.TrimSpace(v)
		if len(cleaned) > 0 {
			publicKeys = append(publicKeys, cleaned)
		}
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
	user = dataprovider.User{
		Username:          r.Form.Get("username"),
		Password:          r.Form.Get("password"),
		PublicKeys:        publicKeys,
		HomeDir:           r.Form.Get("home_dir"),
		UID:               uid,
		GID:               gid,
		Permissions:       r.Form["permissions"],
		MaxSessions:       maxSessions,
		QuotaSize:         quotaSize,
		QuotaFiles:        quotaFiles,
		UploadBandwidth:   bandwidthUL,
		DownloadBandwidth: bandwidthDL,
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
	renderAddUserPage(w, dataprovider.User{}, "")
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
