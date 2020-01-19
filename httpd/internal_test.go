package httpd

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/go-chi/chi"
)

const (
	invalidURL  = "http://foo\x7f.com/"
	inactiveURL = "http://127.0.0.1:12345"
)

func TestGetRespStatus(t *testing.T) {
	var err error
	err = &dataprovider.MethodDisabledError{}
	respStatus := getRespStatus(err)
	if respStatus != http.StatusForbidden {
		t.Errorf("wrong resp status extected: %d got: %d", http.StatusForbidden, respStatus)
	}
	err = fmt.Errorf("generic error")
	respStatus = getRespStatus(err)
	if respStatus != http.StatusInternalServerError {
		t.Errorf("wrong resp status extected: %d got: %d", http.StatusInternalServerError, respStatus)
	}
}

func TestCheckResponse(t *testing.T) {
	err := checkResponse(http.StatusOK, http.StatusCreated)
	if err == nil {
		t.Errorf("check must fail")
	}
	err = checkResponse(http.StatusBadRequest, http.StatusBadRequest)
	if err != nil {
		t.Errorf("test must succeed, error: %v", err)
	}
}

func TestCheckUser(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	actual.Password = "password"
	err := checkUser(expected, actual)
	if err == nil {
		t.Errorf("actual password must be nil")
	}
	actual.Password = ""
	actual.PublicKeys = []string{"pub key"}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("actual public key must be nil")
	}
	actual.PublicKeys = []string{}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("actual ID must be > 0")
	}
	expected.ID = 1
	actual.ID = 2
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("actual ID must be equal to expected ID")
	}
	expected.ID = 2
	actual.ID = 2
	expected.Permissions = make(map[string][]string)
	expected.Permissions["/"] = []string{dataprovider.PermCreateDirs, dataprovider.PermDelete, dataprovider.PermDownload}
	actual.Permissions = make(map[string][]string)
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("Permissions are not equal")
	}
	actual.Permissions["/"] = []string{dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("Permissions are not equal")
	}
	expected.Permissions["/"] = append(expected.Permissions["/"], dataprovider.PermRename)
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("Permissions are not equal")
	}
	expected.Permissions = make(map[string][]string)
	expected.Permissions["/somedir"] = []string{dataprovider.PermAny}
	actual.Permissions = make(map[string][]string)
	actual.Permissions["/otherdir"] = []string{dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("Permissions are not equal")
	}
	expected.Permissions = make(map[string][]string)
	actual.Permissions = make(map[string][]string)
	expected.Filters.AllowedIP = []string{}
	actual.Filters.AllowedIP = []string{"192.168.1.2/32"}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("AllowedIP are not equal")
	}
	expected.Filters.AllowedIP = []string{"192.168.1.3/32"}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("AllowedIP contents are not equal")
	}
	expected.Filters.AllowedIP = []string{}
	actual.Filters.AllowedIP = []string{}
	expected.Filters.DeniedIP = []string{}
	actual.Filters.DeniedIP = []string{"192.168.1.2/32"}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("DeniedIP are not equal")
	}
	expected.Filters.DeniedIP = []string{"192.168.1.3/32"}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("DeniedIP contents are not equal")
	}
	expected.Filters.DeniedIP = []string{}
	actual.Filters.DeniedIP = []string{}
	actual.FsConfig.Provider = 1
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("Fs providers are not equal")
	}
}

func TestCompareUserFields(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	expected.Permissions = make(map[string][]string)
	actual.Permissions = make(map[string][]string)
	expected.Username = "test"
	err := compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("Username does not match")
	}
	expected.Username = ""
	expected.HomeDir = "homedir"
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("HomeDir does not match")
	}
	expected.HomeDir = ""
	expected.UID = 1
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("UID does not match")
	}
	expected.UID = 0
	expected.GID = 1
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("GID does not match")
	}
	expected.GID = 0
	expected.MaxSessions = 2
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("MaxSessions do not match")
	}
	expected.MaxSessions = 0
	expected.QuotaSize = 4096
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("QuotaSize does not match")
	}
	expected.QuotaSize = 0
	expected.QuotaFiles = 2
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("QuotaFiles do not match")
	}
	expected.QuotaFiles = 0
	expected.Permissions["/"] = []string{dataprovider.PermCreateDirs}
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("Permissions are not equal")
	}
	expected.Permissions = nil
	expected.UploadBandwidth = 64
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("UploadBandwidth does not match")
	}
	expected.UploadBandwidth = 0
	expected.DownloadBandwidth = 128
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("DownloadBandwidth does not match")
	}
	expected.DownloadBandwidth = 0
	expected.Status = 1
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("Status does not match")
	}
	expected.Status = 0
	expected.ExpirationDate = 123
	err = compareEqualsUserFields(expected, actual)
	if err == nil {
		t.Errorf("Expiration date does not match")
	}
}

func TestCompareUserFsConfig(t *testing.T) {
	expected := &dataprovider.User{}
	actual := &dataprovider.User{}
	expected.FsConfig.Provider = 1
	err := compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("Provider does not match")
	}
	expected.FsConfig.Provider = 0
	expected.FsConfig.S3Config.Bucket = "bucket"
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 bucket does not match")
	}
	expected.FsConfig.S3Config.Bucket = ""
	expected.FsConfig.S3Config.Region = "region"
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 region does not match")
	}
	expected.FsConfig.S3Config.Region = ""
	expected.FsConfig.S3Config.AccessKey = "access key"
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 access key does not match")
	}
	expected.FsConfig.S3Config.AccessKey = ""
	actual.FsConfig.S3Config.AccessSecret = "access secret"
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 access secret does not match")
	}
	secret, _ := utils.EncryptData("access secret")
	actual.FsConfig.S3Config.AccessSecret = ""
	expected.FsConfig.S3Config.AccessSecret = secret
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 access secret does not match")
	}
	expected.FsConfig.S3Config.AccessSecret = utils.RemoveDecryptionKey(secret)
	actual.FsConfig.S3Config.AccessSecret = utils.RemoveDecryptionKey(secret) + "a"
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 access secret does not match")
	}
	expected.FsConfig.S3Config.AccessSecret = "test"
	actual.FsConfig.S3Config.AccessSecret = ""
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 access secret does not match")
	}
	expected.FsConfig.S3Config.AccessSecret = ""
	actual.FsConfig.S3Config.AccessSecret = ""
	expected.FsConfig.S3Config.Endpoint = "http://127.0.0.1:9000/"
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 endpoint does not match")
	}
	expected.FsConfig.S3Config.Endpoint = ""
	expected.FsConfig.S3Config.StorageClass = "Standard"
	err = compareUserFsConfig(expected, actual)
	if err == nil {
		t.Errorf("S3 storage class does not match")
	}
}

func TestApiCallsWithBadURL(t *testing.T) {
	oldBaseURL := httpBaseURL
	SetBaseURL(invalidURL)
	u := dataprovider.User{}
	_, _, err := UpdateUser(u, http.StatusBadRequest)
	if err == nil {
		t.Error("request with invalid URL must fail")
	}
	_, err = RemoveUser(u, http.StatusNotFound)
	if err == nil {
		t.Error("request with invalid URL must fail")
	}
	_, _, err = GetUsers(1, 0, "", http.StatusBadRequest)
	if err == nil {
		t.Error("request with invalid URL must fail")
	}
	_, err = CloseConnection("non_existent_id", http.StatusNotFound)
	if err == nil {
		t.Error("request with invalid URL must fail")
	}
	_, _, err = Dumpdata("backup.json", http.StatusBadRequest)
	if err == nil {
		t.Error("request with invalid URL must fail")
	}
	_, _, err = Loaddata("/tmp/backup.json", "", http.StatusBadRequest)
	if err == nil {
		t.Error("request with invalid URL must fail")
	}
	SetBaseURL(oldBaseURL)
}

func TestApiCallToNotListeningServer(t *testing.T) {
	oldBaseURL := httpBaseURL
	SetBaseURL(inactiveURL)
	u := dataprovider.User{}
	_, _, err := AddUser(u, http.StatusBadRequest)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = UpdateUser(u, http.StatusNotFound)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, err = RemoveUser(u, http.StatusNotFound)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = GetUserByID(-1, http.StatusNotFound)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = GetUsers(100, 0, "", http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = GetQuotaScans(http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, err = StartQuotaScan(u, http.StatusNotFound)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = GetConnections(http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, err = CloseConnection("non_existent_id", http.StatusNotFound)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = GetVersion(http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = GetProviderStatus(http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = Dumpdata("backup.json", http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = Loaddata("/tmp/backup.json", "", http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	SetBaseURL(oldBaseURL)
}

func TestCloseConnectionHandler(t *testing.T) {
	req, _ := http.NewRequest(http.MethodDelete, activeConnectionsPath+"/connectionID", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("connectionID", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	handleCloseConnection(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected response code 400. Got %d", rr.Code)
	}
}

func TestRenderInvalidTemplate(t *testing.T) {
	tmpl, err := template.New("test").Parse("{{.Count}}")
	if err != nil {
		t.Errorf("error making test template: %v", err)
	} else {
		templates["no_match"] = tmpl
		rw := httptest.NewRecorder()
		renderTemplate(rw, "no_match", map[string]string{})
		if rw.Code != http.StatusInternalServerError {
			t.Errorf("invalid template rendering must fail")
		}
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
	if err == nil {
		t.Error("quota scan with bad fs must fail")
	}
}
