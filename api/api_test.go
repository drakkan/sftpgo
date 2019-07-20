package api_test

import (
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/dataprovider"
)

// To run test cases you need to manually start sftpgo using port 2022 for sftp and 8080 for http API

const (
	defaultUsername = "test_user"
	defaultPassword = "test_password"
	testPubKey      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
)

var (
	defaultPerms = []string{dataprovider.PermAny}
	homeBasePath string
)

func init() {
	if runtime.GOOS == "windows" {
		homeBasePath = "C:\\"
	} else {
		homeBasePath = "/tmp"
	}
}

func getTestUser() dataprovider.User {
	return dataprovider.User{
		Username:    defaultUsername,
		Password:    defaultPassword,
		HomeDir:     filepath.Join(homeBasePath, defaultUsername),
		Permissions: defaultPerms,
	}
}

func TestBasicUserHandling(t *testing.T) {
	user, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.MaxSessions = 10
	user.QuotaSize = 4096
	user.QuotaFiles = 2
	user.UploadBandwidth = 128
	user.DownloadBandwidth = 64
	user, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	users, err := api.GetUsers(0, 0, defaultUsername, http.StatusOK)
	if err != nil {
		t.Errorf("unable to get users: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("number of users mismatch, expected: 1, actual: %v", len(users))
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
}

func TestAddUserNoCredentials(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	u.PublicKey = ""
	_, err := api.AddUser(u, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error adding user with no credentials: %v", err)
	}
}

func TestAddUserNoUsername(t *testing.T) {
	u := getTestUser()
	u.Username = ""
	_, err := api.AddUser(u, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error adding user with no home dir: %v", err)
	}
}

func TestAddUserNoHomeDir(t *testing.T) {
	u := getTestUser()
	u.HomeDir = ""
	_, err := api.AddUser(u, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error adding user with no home dir: %v", err)
	}
}

func TestAddUserInvalidHomeDir(t *testing.T) {
	u := getTestUser()
	u.HomeDir = "relative_path"
	_, err := api.AddUser(u, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error adding user with invalid home dir: %v", err)
	}
}

func TestAddUserNoPerms(t *testing.T) {
	u := getTestUser()
	u.Permissions = []string{}
	_, err := api.AddUser(u, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error adding user with no perms: %v", err)
	}
}

func TestAddUserInvalidPerms(t *testing.T) {
	u := getTestUser()
	u.Permissions = []string{"invalidPerm"}
	_, err := api.AddUser(u, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error adding user with no perms: %v", err)
	}
}

func TestUpdateUser(t *testing.T) {
	user, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.HomeDir = filepath.Join(homeBasePath, "testmod")
	user.UID = 33
	user.GID = 101
	user.MaxSessions = 10
	user.QuotaSize = 4096
	user.QuotaFiles = 2
	user.Permissions = []string{dataprovider.PermCreateDirs, dataprovider.PermDelete, dataprovider.PermDownload}
	user.UploadBandwidth = 1024
	user.DownloadBandwidth = 512
	user, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
}

func TestUpdateUserNoCredentials(t *testing.T) {
	user, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = ""
	user.PublicKey = ""
	// password and public key will be ommitted from json serialization if empty and so they will remain unchanged
	// and no validation error will be raised
	_, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unexpected error updating user with no credentials: %v", err)
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
}

func TestUpdateUserEmptyHomeDir(t *testing.T) {
	user, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.HomeDir = ""
	_, err = api.UpdateUser(user, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error updating user with empty home dir: %v", err)
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
}

func TestUpdateUserInvalidHomeDir(t *testing.T) {
	user, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.HomeDir = "relative_path"
	_, err = api.UpdateUser(user, http.StatusBadRequest)
	if err != nil {
		t.Errorf("unexpected error updating user with empty home dir: %v", err)
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
}

func TestUpdateNonExistentUser(t *testing.T) {
	_, err := api.UpdateUser(getTestUser(), http.StatusNotFound)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
}

func TestGetNonExistentUser(t *testing.T) {
	_, err := api.GetUserByID(0, http.StatusNotFound)
	if err != nil {
		t.Errorf("unable to get user: %v", err)
	}
}

func TestDeleteNonExistentUser(t *testing.T) {
	err := api.RemoveUser(getTestUser(), http.StatusNotFound)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestAddDuplicateUser(t *testing.T) {
	user, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	_, err = api.AddUser(getTestUser(), http.StatusInternalServerError)
	if err != nil {
		t.Errorf("unable to add second user: %v", err)
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestGetUsers(t *testing.T) {
	user1, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	u := getTestUser()
	u.Username = defaultUsername + "1"
	user2, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add second user: %v", err)
	}
	users, err := api.GetUsers(0, 0, "", http.StatusOK)
	if err != nil {
		t.Errorf("unable to get users: %v", err)
	}
	if len(users) < 2 {
		t.Errorf("at least 2 users are expected")
	}
	users, err = api.GetUsers(1, 0, "", http.StatusOK)
	if len(users) != 1 {
		t.Errorf("1 user are expected")
	}
	users, err = api.GetUsers(1, 1, "", http.StatusOK)
	if len(users) != 1 {
		t.Errorf("1 user are expected")
	}
	err = api.RemoveUser(user1, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	err = api.RemoveUser(user2, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestGetQuotaScans(t *testing.T) {
	_, err := api.GetQuotaScans(http.StatusOK)
	if err != nil {
		t.Errorf("unable to get quota scans: %v", err)
	}
}

func TestStartQuotaScan(t *testing.T) {
	user, err := api.AddUser(getTestUser(), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	err = api.StartQuotaScan(user, http.StatusCreated)
	if err != nil {
		t.Errorf("unable to start quota scan: %v", err)
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}
