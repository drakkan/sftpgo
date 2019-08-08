package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/drakkan/sftpgo/dataprovider"
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
	expected := dataprovider.User{}
	actual := dataprovider.User{}
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
	expected.Permissions = []string{dataprovider.PermCreateDirs, dataprovider.PermDelete, dataprovider.PermDownload}
	actual.Permissions = []string{dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("Permissions are not equal")
	}
	expected.Permissions = append(expected.Permissions, dataprovider.PermRename)
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("Permissions are not equal")
	}
}

func TestCompareUserFields(t *testing.T) {
	expected := dataprovider.User{}
	actual := dataprovider.User{}
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
	expected.Permissions = []string{dataprovider.PermCreateDirs}
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
}

func TestApiCallsWithBadURL(t *testing.T) {
	oldBaseURL := httpBaseURL
	SetBaseURL(invalidURL)
	u := dataprovider.User{}
	_, _, err := UpdateUser(u, http.StatusBadRequest)
	if err == nil {
		t.Errorf("request with invalid URL must fail")
	}
	_, err = RemoveUser(u, http.StatusNotFound)
	if err == nil {
		t.Errorf("request with invalid URL must fail")
	}
	_, _, err = GetUsers(1, 0, "", http.StatusBadRequest)
	if err == nil {
		t.Errorf("request with invalid URL must fail")
	}
	_, err = CloseSFTPConnection("non_existent_id", http.StatusNotFound)
	if err == nil {
		t.Errorf("request with invalid URL must fail")
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
	_, _, err = GetSFTPConnections(http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, err = CloseSFTPConnection("non_existent_id", http.StatusNotFound)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	_, _, err = GetVersion(http.StatusOK)
	if err == nil {
		t.Errorf("request to an inactive URL must fail")
	}
	SetBaseURL(oldBaseURL)
}
