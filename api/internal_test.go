package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/drakkan/sftpgo/dataprovider"
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
	err := checkResponse(200, 201, nil)
	if err == nil {
		t.Errorf("check must fail")
	}
	err = checkResponse(400, 400, nil)
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
	actual.PublicKey = "pub key"
	err = checkUser(expected, actual)
	if err == nil {
		t.Errorf("actual public key must be nil")
	}
	actual.PublicKey = ""
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
