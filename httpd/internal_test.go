package httpd

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

const (
	invalidURL  = "http://foo\x7f.com/"
	inactiveURL = "http://127.0.0.1:12345"
)

func TestGetRespStatus(t *testing.T) {
	var err error
	err = &dataprovider.MethodDisabledError{}
	respStatus := getRespStatus(err)
	assert.Equal(t, http.StatusForbidden, respStatus)
	err = fmt.Errorf("generic error")
	respStatus = getRespStatus(err)
	assert.Equal(t, http.StatusInternalServerError, respStatus)
}

func TestCheckResponse(t *testing.T) {
	err := checkResponse(http.StatusOK, http.StatusCreated)
	assert.Error(t, err)
	err = checkResponse(http.StatusBadRequest, http.StatusBadRequest)
	assert.NoError(t, err)
}

func TestCheckUser(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	actual.Password = "password"
	err := checkUser(expected, actual)
	assert.Error(t, err)
	actual.Password = ""
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.ID = 1
	actual.ID = 2
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.ID = 2
	actual.ID = 2
	expected.Permissions = make(map[string][]string)
	expected.Permissions["/"] = []string{dataprovider.PermCreateDirs, dataprovider.PermDelete, dataprovider.PermDownload}
	actual.Permissions = make(map[string][]string)
	err = checkUser(expected, actual)
	assert.Error(t, err)
	actual.Permissions["/"] = []string{dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Permissions["/"] = append(expected.Permissions["/"], dataprovider.PermRename)
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Permissions = make(map[string][]string)
	expected.Permissions["/somedir"] = []string{dataprovider.PermAny}
	actual.Permissions = make(map[string][]string)
	actual.Permissions["/otherdir"] = []string{dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Permissions = make(map[string][]string)
	actual.Permissions = make(map[string][]string)
	actual.FsConfig.Provider = 1
	err = checkUser(expected, actual)
	assert.Error(t, err)
	actual.FsConfig.Provider = 0
	expected.VirtualFolders = append(expected.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir",
		MappedPath:  os.TempDir(),
	})
	err = checkUser(expected, actual)
	assert.Error(t, err)
	actual.VirtualFolders = append(actual.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: "/vdir1",
		MappedPath:  os.TempDir(),
	})
	err = checkUser(expected, actual)
	assert.Error(t, err)
}

func TestCompareUserFilters(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	actual.ID = 1
	expected.ID = 1
	expected.Filters.AllowedIP = []string{}
	actual.Filters.AllowedIP = []string{"192.168.1.2/32"}
	err := checkUser(expected, actual)
	assert.Error(t, err)
	expected.Filters.AllowedIP = []string{"192.168.1.3/32"}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Filters.AllowedIP = []string{}
	actual.Filters.AllowedIP = []string{}
	expected.Filters.DeniedIP = []string{}
	actual.Filters.DeniedIP = []string{"192.168.1.2/32"}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Filters.DeniedIP = []string{"192.168.1.3/32"}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Filters.DeniedIP = []string{}
	actual.Filters.DeniedIP = []string{}
	expected.Filters.DeniedLoginMethods = []string{}
	actual.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPassword}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	expected.Filters.DeniedLoginMethods = []string{}
	actual.Filters.DeniedLoginMethods = []string{}
	expected.Filters.FileExtensions = append(expected.Filters.FileExtensions, dataprovider.ExtensionsFilter{
		Path:              "/",
		AllowedExtensions: []string{".jpg", ".png"},
		DeniedExtensions:  []string{".zip", ".rar"},
	})
	err = checkUser(expected, actual)
	assert.Error(t, err)
	actual.Filters.FileExtensions = append(actual.Filters.FileExtensions, dataprovider.ExtensionsFilter{
		Path:              "/sub",
		AllowedExtensions: []string{".jpg", ".png"},
		DeniedExtensions:  []string{".zip", ".rar"},
	})
	err = checkUser(expected, actual)
	assert.Error(t, err)
	actual.Filters.FileExtensions[0] = dataprovider.ExtensionsFilter{
		Path:              "/",
		AllowedExtensions: []string{".jpg"},
		DeniedExtensions:  []string{".zip", ".rar"},
	}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	actual.Filters.FileExtensions[0] = dataprovider.ExtensionsFilter{
		Path:              "/",
		AllowedExtensions: []string{".tiff", ".png"},
		DeniedExtensions:  []string{".zip", ".rar"},
	}
	err = checkUser(expected, actual)
	assert.Error(t, err)
	actual.Filters.FileExtensions[0] = dataprovider.ExtensionsFilter{
		Path:              "/",
		AllowedExtensions: []string{".jpg", ".png"},
		DeniedExtensions:  []string{".tar.gz", ".rar"},
	}
	err = checkUser(expected, actual)
	assert.Error(t, err)
}

func TestCompareUserFields(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	expected.Permissions = make(map[string][]string)
	actual.Permissions = make(map[string][]string)
	expected.Username = "test"
	err := compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.Username = ""
	expected.HomeDir = "homedir"
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.HomeDir = ""
	expected.UID = 1
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.UID = 0
	expected.GID = 1
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.GID = 0
	expected.MaxSessions = 2
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.MaxSessions = 0
	expected.QuotaSize = 4096
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.QuotaSize = 0
	expected.QuotaFiles = 2
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.QuotaFiles = 0
	expected.Permissions["/"] = []string{dataprovider.PermCreateDirs}
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.Permissions = nil
	expected.UploadBandwidth = 64
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.UploadBandwidth = 0
	expected.DownloadBandwidth = 128
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.DownloadBandwidth = 0
	expected.Status = 1
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
	expected.Status = 0
	expected.ExpirationDate = 123
	err = compareEqualsUserFields(expected, actual)
	assert.Error(t, err)
}

func TestCompareUserFsConfig(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	expected.FsConfig.Provider = 1
	err := compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.Provider = 0
	expected.FsConfig.S3Config.Bucket = "bucket"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.Bucket = ""
	expected.FsConfig.S3Config.Region = "region"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.Region = ""
	expected.FsConfig.S3Config.AccessKey = "access key"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.AccessKey = ""
	actual.FsConfig.S3Config.AccessSecret = "access secret"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	secret, _ := utils.EncryptData("access secret")
	actual.FsConfig.S3Config.AccessSecret = ""
	expected.FsConfig.S3Config.AccessSecret = secret
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.AccessSecret = utils.RemoveDecryptionKey(secret)
	actual.FsConfig.S3Config.AccessSecret = utils.RemoveDecryptionKey(secret) + "a"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.AccessSecret = "test"
	actual.FsConfig.S3Config.AccessSecret = ""
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.AccessSecret = ""
	actual.FsConfig.S3Config.AccessSecret = ""
	expected.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.Endpoint = ""
	expected.FsConfig.S3Config.StorageClass = "Standard"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.StorageClass = ""
	expected.FsConfig.S3Config.KeyPrefix = "somedir/subdir"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.KeyPrefix = ""
	expected.FsConfig.S3Config.UploadPartSize = 10
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.S3Config.UploadPartSize = 0
	expected.FsConfig.S3Config.UploadConcurrency = 3
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
}

func TestCompareUserGCSConfig(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	expected.FsConfig.GCSConfig.KeyPrefix = "somedir/subdir"
	err := compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.GCSConfig.KeyPrefix = ""
	expected.FsConfig.GCSConfig.Bucket = "bucket"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.GCSConfig.Bucket = ""
	expected.FsConfig.GCSConfig.StorageClass = "Standard"
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.GCSConfig.StorageClass = ""
	expected.FsConfig.GCSConfig.AutomaticCredentials = 1
	err = compareUserFsConfig(expected, actual)
	assert.Error(t, err)
	expected.FsConfig.GCSConfig.AutomaticCredentials = 0
}

func TestGCSWebInvalidFormFile(t *testing.T) {
	form := make(url.Values)
	form.Set("username", "test_username")
	form.Set("fs_provider", "2")
	req, _ := http.NewRequest(http.MethodPost, webUserPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	_, err := getFsConfigFromUserPostFields(req)
	assert.EqualError(t, err, http.ErrNotMultipart.Error())
}

func TestApiCallsWithBadURL(t *testing.T) {
	oldBaseURL := httpBaseURL
	oldAuthUsername := authUsername
	oldAuthPassword := authPassword
	SetBaseURLAndCredentials(invalidURL, oldAuthUsername, oldAuthPassword)
	u := dataprovider.User{}
	_, _, err := UpdateUser(u, http.StatusBadRequest)
	assert.Error(t, err)
	_, err = RemoveUser(u, http.StatusNotFound)
	assert.Error(t, err)
	_, _, err = GetUsers(1, 0, "", http.StatusBadRequest)
	assert.Error(t, err)
	_, err = CloseConnection("non_existent_id", http.StatusNotFound)
	assert.Error(t, err)
	_, _, err = Dumpdata("backup.json", "", http.StatusBadRequest)
	assert.Error(t, err)
	_, _, err = Loaddata("/tmp/backup.json", "", "", http.StatusBadRequest)
	assert.Error(t, err)
	SetBaseURLAndCredentials(oldBaseURL, oldAuthUsername, oldAuthPassword)
}

func TestApiCallToNotListeningServer(t *testing.T) {
	oldBaseURL := httpBaseURL
	oldAuthUsername := authUsername
	oldAuthPassword := authPassword
	SetBaseURLAndCredentials(inactiveURL, oldAuthUsername, oldAuthPassword)
	u := dataprovider.User{}
	_, _, err := AddUser(u, http.StatusBadRequest)
	assert.Error(t, err)
	_, _, err = UpdateUser(u, http.StatusNotFound)
	assert.Error(t, err)
	_, err = RemoveUser(u, http.StatusNotFound)
	assert.Error(t, err)
	_, _, err = GetUserByID(-1, http.StatusNotFound)
	assert.Error(t, err)
	_, _, err = GetUsers(100, 0, "", http.StatusOK)
	assert.Error(t, err)
	_, _, err = GetQuotaScans(http.StatusOK)
	assert.Error(t, err)
	_, err = StartQuotaScan(u, http.StatusNotFound)
	assert.Error(t, err)
	_, _, err = GetConnections(http.StatusOK)
	assert.Error(t, err)
	_, err = CloseConnection("non_existent_id", http.StatusNotFound)
	assert.Error(t, err)
	_, _, err = GetVersion(http.StatusOK)
	assert.Error(t, err)
	_, _, err = GetProviderStatus(http.StatusOK)
	assert.Error(t, err)
	_, _, err = Dumpdata("backup.json", "0", http.StatusOK)
	assert.Error(t, err)
	_, _, err = Loaddata("/tmp/backup.json", "", "", http.StatusOK)
	assert.Error(t, err)
	SetBaseURLAndCredentials(oldBaseURL, oldAuthUsername, oldAuthPassword)
}

func TestBasicAuth(t *testing.T) {
	oldAuthUsername := authUsername
	oldAuthPassword := authPassword
	authUserFile := filepath.Join(os.TempDir(), "http_users.txt")
	authUserData := []byte("test1:$2y$05$bcHSED7aO1cfLto6ZdDBOOKzlwftslVhtpIkRhAtSa4GuLmk5mola\n")
	ioutil.WriteFile(authUserFile, authUserData, 0666)
	httpAuth, _ = newBasicAuthProvider(authUserFile)
	_, _, err := GetVersion(http.StatusUnauthorized)
	assert.NoError(t, err)
	SetBaseURLAndCredentials(httpBaseURL, "test1", "password1")
	_, _, err = GetVersion(http.StatusOK)
	assert.NoError(t, err)
	SetBaseURLAndCredentials(httpBaseURL, "test1", "wrong_password")
	resp, _ := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(metricsPath), nil, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	authUserData = append(authUserData, []byte("test2:$apr1$gLnIkRIf$Xr/6aJfmIrihP4b2N2tcs/\n")...)
	err = ioutil.WriteFile(authUserFile, authUserData, 0666)
	assert.NoError(t, err)
	SetBaseURLAndCredentials(httpBaseURL, "test2", "password2")
	_, _, err = GetVersion(http.StatusOK)
	assert.NoError(t, err)
	SetBaseURLAndCredentials(httpBaseURL, "test2", "wrong_password")
	_, _, err = GetVersion(http.StatusOK)
	assert.Error(t, err)
	authUserData = append(authUserData, []byte("test3:$apr1$gLnIkRIf$Xr/6$aJfmIr$ihP4b2N2tcs/\n")...)
	ioutil.WriteFile(authUserFile, authUserData, 0666)
	SetBaseURLAndCredentials(httpBaseURL, "test3", "wrong_password")
	_, _, err = GetVersion(http.StatusUnauthorized)
	assert.NoError(t, err)
	authUserData = append(authUserData, []byte("test4:$invalid$gLnIkRIf$Xr/6$aJfmIr$ihP4b2N2tcs/\n")...)
	ioutil.WriteFile(authUserFile, authUserData, 0666)
	SetBaseURLAndCredentials(httpBaseURL, "test3", "password2")
	_, _, err = GetVersion(http.StatusUnauthorized)
	assert.NoError(t, err)
	if runtime.GOOS != "windows" {
		authUserData = append(authUserData, []byte("test5:$apr1$gLnIkRIf$Xr/6aJfmIrihP4b2N2tcs/\n")...)
		err = ioutil.WriteFile(authUserFile, authUserData, 0666)
		assert.NoError(t, err)
		err = os.Chmod(authUserFile, 0001)
		assert.NoError(t, err)
		SetBaseURLAndCredentials(httpBaseURL, "test5", "password2")
		_, _, err = GetVersion(http.StatusUnauthorized)
		assert.NoError(t, err)
		err = os.Chmod(authUserFile, 0666)
		assert.NoError(t, err)
	}
	authUserData = append(authUserData, []byte("\"foo\"bar\"\r\n")...)
	err = ioutil.WriteFile(authUserFile, authUserData, 0666)
	assert.NoError(t, err)
	SetBaseURLAndCredentials(httpBaseURL, "test2", "password2")
	_, _, err = GetVersion(http.StatusUnauthorized)
	assert.NoError(t, err)
	err = os.Remove(authUserFile)
	assert.NoError(t, err)
	SetBaseURLAndCredentials(httpBaseURL, oldAuthUsername, oldAuthPassword)
	httpAuth, _ = newBasicAuthProvider("")
}

func TestCloseConnectionHandler(t *testing.T) {
	req, _ := http.NewRequest(http.MethodDelete, activeConnectionsPath+"/connectionID", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("connectionID", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	handleCloseConnection(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRenderInvalidTemplate(t *testing.T) {
	tmpl, err := template.New("test").Parse("{{.Count}}")
	if assert.NoError(t, err) {
		templates["no_match"] = tmpl
		rw := httptest.NewRecorder()
		renderTemplate(rw, "no_match", map[string]string{})
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	}
}

func TestQuotaScanInvalidFs(t *testing.T) {
	user := dataprovider.User{
		Username: "test",
		HomeDir:  os.TempDir(),
		FsConfig: dataprovider.Filesystem{
			Provider: 1,
		},
	}
	sftpd.AddQuotaScan(user.Username)
	err := doQuotaScan(user)
	assert.Error(t, err)
}
