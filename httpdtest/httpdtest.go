// Package httpdtest provides utilities for testing the exposed REST API.
package httpdtest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/httpd"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	tokenPath             = "/api/v2/token"
	activeConnectionsPath = "/api/v2/connections"
	quotasBasePath        = "/api/v2/quotas"
	quotaScanPath         = "/api/v2/quotas/users/scans"
	quotaScanVFolderPath  = "/api/v2/quotas/folders/scans"
	userPath              = "/api/v2/users"
	versionPath           = "/api/v2/version"
	folderPath            = "/api/v2/folders"
	serverStatusPath      = "/api/v2/status"
	dumpDataPath          = "/api/v2/dumpdata"
	loadDataPath          = "/api/v2/loaddata"
	defenderHosts         = "/api/v2/defender/hosts"
	defenderBanTime       = "/api/v2/defender/bantime"
	defenderUnban         = "/api/v2/defender/unban"
	defenderScore         = "/api/v2/defender/score"
	adminPath             = "/api/v2/admins"
	adminPwdPath          = "/api/v2/admin/changepwd"
	apiKeysPath           = "/api/v2/apikeys"
	retentionBasePath     = "/api/v2/retention/users"
	retentionChecksPath   = "/api/v2/retention/users/checks"
)

const (
	defaultTokenAuthUser = "admin"
	defaultTokenAuthPass = "password"
)

var (
	httpBaseURL = "http://127.0.0.1:8080"
	jwtToken    = ""
)

// SetBaseURL sets the base url to use for HTTP requests.
// Default URL is "http://127.0.0.1:8080"
func SetBaseURL(url string) {
	httpBaseURL = url
}

// SetJWTToken sets the JWT token to use
func SetJWTToken(token string) {
	jwtToken = token
}

func sendHTTPRequest(method, url string, body io.Reader, contentType, token string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))
	}
	return httpclient.GetHTTPClient().Do(req)
}

func buildURLRelativeToBase(paths ...string) string {
	// we need to use path.Join and not filepath.Join
	// since filepath.Join will use backslash separator on Windows
	p := path.Join(paths...)
	return fmt.Sprintf("%s/%s", strings.TrimRight(httpBaseURL, "/"), strings.TrimLeft(p, "/"))
}

// GetToken tries to return a JWT token
func GetToken(username, password string) (string, map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, buildURLRelativeToBase(tokenPath), nil)
	if err != nil {
		return "", nil, err
	}
	req.SetBasicAuth(username, password)
	resp, err := httpclient.GetHTTPClient().Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	err = checkResponse(resp.StatusCode, http.StatusOK)
	if err != nil {
		return "", nil, err
	}
	responseHolder := make(map[string]interface{})
	err = render.DecodeJSON(resp.Body, &responseHolder)
	if err != nil {
		return "", nil, err
	}
	return responseHolder["access_token"].(string), responseHolder, nil
}

func getDefaultToken() string {
	if jwtToken != "" {
		return jwtToken
	}
	token, _, err := GetToken(defaultTokenAuthUser, defaultTokenAuthPass)
	if err != nil {
		return ""
	}
	return token
}

// AddUser adds a new user and checks the received HTTP Status code against expectedStatusCode.
func AddUser(user dataprovider.User, expectedStatusCode int) (dataprovider.User, []byte, error) {
	var newUser dataprovider.User
	var body []byte
	userAsJSON, _ := json.Marshal(user)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(userPath), bytes.NewBuffer(userAsJSON),
		"application/json", getDefaultToken())
	if err != nil {
		return newUser, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusCreated {
		body, _ = getResponseBody(resp)
		return newUser, body, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newUser)
	} else {
		body, _ = getResponseBody(resp)
	}
	if err == nil {
		err = checkUser(&user, &newUser)
	}
	return newUser, body, err
}

// UpdateUserWithJSON update a user using the provided JSON as POST body
func UpdateUserWithJSON(user dataprovider.User, expectedStatusCode int, disconnect string, userAsJSON []byte) (dataprovider.User, []byte, error) {
	var newUser dataprovider.User
	var body []byte
	url, err := addDisconnectQueryParam(buildURLRelativeToBase(userPath, url.PathEscape(user.Username)), disconnect)
	if err != nil {
		return user, body, err
	}
	resp, err := sendHTTPRequest(http.MethodPut, url.String(), bytes.NewBuffer(userAsJSON), "application/json",
		getDefaultToken())
	if err != nil {
		return user, body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		return newUser, body, err
	}
	if err == nil {
		newUser, body, err = GetUserByUsername(user.Username, expectedStatusCode)
	}
	if err == nil {
		err = checkUser(&user, &newUser)
	}
	return newUser, body, err
}

// UpdateUser updates an existing user and checks the received HTTP Status code against expectedStatusCode.
func UpdateUser(user dataprovider.User, expectedStatusCode int, disconnect string) (dataprovider.User, []byte, error) {
	userAsJSON, _ := json.Marshal(user)
	return UpdateUserWithJSON(user, expectedStatusCode, disconnect, userAsJSON)
}

// RemoveUser removes an existing user and checks the received HTTP Status code against expectedStatusCode.
func RemoveUser(user dataprovider.User, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(userPath, url.PathEscape(user.Username)),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetUserByUsername gets a user by username and checks the received HTTP Status code against expectedStatusCode.
func GetUserByUsername(username string, expectedStatusCode int) (dataprovider.User, []byte, error) {
	var user dataprovider.User
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(userPath, url.PathEscape(username)),
		nil, "", getDefaultToken())
	if err != nil {
		return user, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &user)
	} else {
		body, _ = getResponseBody(resp)
	}
	return user, body, err
}

// GetUsers returns a list of users and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
func GetUsers(limit, offset int64, expectedStatusCode int) ([]dataprovider.User, []byte, error) {
	var users []dataprovider.User
	var body []byte
	url, err := addLimitAndOffsetQueryParams(buildURLRelativeToBase(userPath), limit, offset)
	if err != nil {
		return users, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return users, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &users)
	} else {
		body, _ = getResponseBody(resp)
	}
	return users, body, err
}

// AddAdmin adds a new admin and checks the received HTTP Status code against expectedStatusCode.
func AddAdmin(admin dataprovider.Admin, expectedStatusCode int) (dataprovider.Admin, []byte, error) {
	var newAdmin dataprovider.Admin
	var body []byte
	asJSON, _ := json.Marshal(admin)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(adminPath), bytes.NewBuffer(asJSON),
		"application/json", getDefaultToken())
	if err != nil {
		return newAdmin, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusCreated {
		body, _ = getResponseBody(resp)
		return newAdmin, body, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newAdmin)
	} else {
		body, _ = getResponseBody(resp)
	}
	if err == nil {
		err = checkAdmin(&admin, &newAdmin)
	}
	return newAdmin, body, err
}

// UpdateAdmin updates an existing admin and checks the received HTTP Status code against expectedStatusCode
func UpdateAdmin(admin dataprovider.Admin, expectedStatusCode int) (dataprovider.Admin, []byte, error) {
	var newAdmin dataprovider.Admin
	var body []byte

	asJSON, _ := json.Marshal(admin)
	resp, err := sendHTTPRequest(http.MethodPut, buildURLRelativeToBase(adminPath, url.PathEscape(admin.Username)),
		bytes.NewBuffer(asJSON), "application/json", getDefaultToken())
	if err != nil {
		return newAdmin, body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		return newAdmin, body, err
	}
	if err == nil {
		newAdmin, body, err = GetAdminByUsername(admin.Username, expectedStatusCode)
	}
	if err == nil {
		err = checkAdmin(&admin, &newAdmin)
	}
	return newAdmin, body, err
}

// RemoveAdmin removes an existing admin and checks the received HTTP Status code against expectedStatusCode.
func RemoveAdmin(admin dataprovider.Admin, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(adminPath, url.PathEscape(admin.Username)),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetAdminByUsername gets an admin by username and checks the received HTTP Status code against expectedStatusCode.
func GetAdminByUsername(username string, expectedStatusCode int) (dataprovider.Admin, []byte, error) {
	var admin dataprovider.Admin
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(adminPath, url.PathEscape(username)),
		nil, "", getDefaultToken())
	if err != nil {
		return admin, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &admin)
	} else {
		body, _ = getResponseBody(resp)
	}
	return admin, body, err
}

// GetAdmins returns a list of admins and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
func GetAdmins(limit, offset int64, expectedStatusCode int) ([]dataprovider.Admin, []byte, error) {
	var admins []dataprovider.Admin
	var body []byte
	url, err := addLimitAndOffsetQueryParams(buildURLRelativeToBase(adminPath), limit, offset)
	if err != nil {
		return admins, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return admins, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &admins)
	} else {
		body, _ = getResponseBody(resp)
	}
	return admins, body, err
}

// ChangeAdminPassword changes the password for an existing admin
func ChangeAdminPassword(currentPassword, newPassword string, expectedStatusCode int) ([]byte, error) {
	var body []byte

	pwdChange := make(map[string]string)
	pwdChange["current_password"] = currentPassword
	pwdChange["new_password"] = newPassword

	asJSON, _ := json.Marshal(&pwdChange)
	resp, err := sendHTTPRequest(http.MethodPut, buildURLRelativeToBase(adminPwdPath),
		bytes.NewBuffer(asJSON), "application/json", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()

	err = checkResponse(resp.StatusCode, expectedStatusCode)
	body, _ = getResponseBody(resp)

	return body, err
}

// GetAPIKeys returns a list of API keys and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
func GetAPIKeys(limit, offset int64, expectedStatusCode int) ([]dataprovider.APIKey, []byte, error) {
	var apiKeys []dataprovider.APIKey
	var body []byte
	url, err := addLimitAndOffsetQueryParams(buildURLRelativeToBase(apiKeysPath), limit, offset)
	if err != nil {
		return apiKeys, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return apiKeys, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &apiKeys)
	} else {
		body, _ = getResponseBody(resp)
	}
	return apiKeys, body, err
}

// AddAPIKey adds a new API key and checks the received HTTP Status code against expectedStatusCode.
func AddAPIKey(apiKey dataprovider.APIKey, expectedStatusCode int) (dataprovider.APIKey, []byte, error) {
	var newAPIKey dataprovider.APIKey
	var body []byte
	asJSON, _ := json.Marshal(apiKey)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(apiKeysPath), bytes.NewBuffer(asJSON),
		"application/json", getDefaultToken())
	if err != nil {
		return newAPIKey, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusCreated {
		body, _ = getResponseBody(resp)
		return newAPIKey, body, err
	}
	if err != nil {
		body, _ = getResponseBody(resp)
		return newAPIKey, body, err
	}
	response := make(map[string]string)
	err = render.DecodeJSON(resp.Body, &response)
	if err == nil {
		newAPIKey, body, err = GetAPIKeyByID(resp.Header.Get("X-Object-ID"), http.StatusOK)
	}
	if err == nil {
		err = checkAPIKey(&apiKey, &newAPIKey)
	}
	newAPIKey.Key = response["key"]

	return newAPIKey, body, err
}

// UpdateAPIKey updates an existing API key and checks the received HTTP Status code against expectedStatusCode
func UpdateAPIKey(apiKey dataprovider.APIKey, expectedStatusCode int) (dataprovider.APIKey, []byte, error) {
	var newAPIKey dataprovider.APIKey
	var body []byte

	asJSON, _ := json.Marshal(apiKey)
	resp, err := sendHTTPRequest(http.MethodPut, buildURLRelativeToBase(apiKeysPath, url.PathEscape(apiKey.KeyID)),
		bytes.NewBuffer(asJSON), "application/json", getDefaultToken())
	if err != nil {
		return newAPIKey, body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		return newAPIKey, body, err
	}
	if err == nil {
		newAPIKey, body, err = GetAPIKeyByID(apiKey.KeyID, expectedStatusCode)
	}
	if err == nil {
		err = checkAPIKey(&apiKey, &newAPIKey)
	}
	return newAPIKey, body, err
}

// RemoveAPIKey removes an existing API key and checks the received HTTP Status code against expectedStatusCode.
func RemoveAPIKey(apiKey dataprovider.APIKey, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(apiKeysPath, url.PathEscape(apiKey.KeyID)),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetAPIKeyByID gets a API key by ID and checks the received HTTP Status code against expectedStatusCode.
func GetAPIKeyByID(keyID string, expectedStatusCode int) (dataprovider.APIKey, []byte, error) {
	var apiKey dataprovider.APIKey
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(apiKeysPath, url.PathEscape(keyID)),
		nil, "", getDefaultToken())
	if err != nil {
		return apiKey, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &apiKey)
	} else {
		body, _ = getResponseBody(resp)
	}
	return apiKey, body, err
}

// GetQuotaScans gets active quota scans for users and checks the received HTTP Status code against expectedStatusCode.
func GetQuotaScans(expectedStatusCode int) ([]common.ActiveQuotaScan, []byte, error) {
	var quotaScans []common.ActiveQuotaScan
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(quotaScanPath), nil, "", getDefaultToken())
	if err != nil {
		return quotaScans, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &quotaScans)
	} else {
		body, _ = getResponseBody(resp)
	}
	return quotaScans, body, err
}

// StartQuotaScan starts a new quota scan for the given user and checks the received HTTP Status code against expectedStatusCode.
func StartQuotaScan(user dataprovider.User, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(quotasBasePath, "users", user.Username, "scan"),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// UpdateQuotaUsage updates the user used quota limits and checks the received
// HTTP Status code against expectedStatusCode.
func UpdateQuotaUsage(user dataprovider.User, mode string, expectedStatusCode int) ([]byte, error) {
	var body []byte
	userAsJSON, _ := json.Marshal(user)
	url, err := addModeQueryParam(buildURLRelativeToBase(quotasBasePath, "users", user.Username, "usage"), mode)
	if err != nil {
		return body, err
	}
	resp, err := sendHTTPRequest(http.MethodPut, url.String(), bytes.NewBuffer(userAsJSON), "application/json",
		getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// UpdateTransferQuotaUsage updates the user used transfer quota limits and checks the received
// HTTP Status code against expectedStatusCode.
func UpdateTransferQuotaUsage(user dataprovider.User, mode string, expectedStatusCode int) ([]byte, error) {
	var body []byte
	userAsJSON, _ := json.Marshal(user)
	url, err := addModeQueryParam(buildURLRelativeToBase(quotasBasePath, "users", user.Username, "transfer-usage"), mode)
	if err != nil {
		return body, err
	}
	resp, err := sendHTTPRequest(http.MethodPut, url.String(), bytes.NewBuffer(userAsJSON), "application/json",
		getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetRetentionChecks returns the active retention checks
func GetRetentionChecks(expectedStatusCode int) ([]common.ActiveRetentionChecks, []byte, error) {
	var checks []common.ActiveRetentionChecks
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(retentionChecksPath), nil, "", getDefaultToken())
	if err != nil {
		return checks, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &checks)
	} else {
		body, _ = getResponseBody(resp)
	}
	return checks, body, err
}

// StartRetentionCheck starts a new retention check
func StartRetentionCheck(username string, retention []common.FolderRetention, expectedStatusCode int) ([]byte, error) {
	var body []byte
	asJSON, _ := json.Marshal(retention)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(retentionBasePath, username, "check"),
		bytes.NewBuffer(asJSON), "application/json", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetConnections returns status and stats for active SFTP/SCP connections
func GetConnections(expectedStatusCode int) ([]common.ConnectionStatus, []byte, error) {
	var connections []common.ConnectionStatus
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(activeConnectionsPath), nil, "", getDefaultToken())
	if err != nil {
		return connections, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &connections)
	} else {
		body, _ = getResponseBody(resp)
	}
	return connections, body, err
}

// CloseConnection closes an active  connection identified by connectionID
func CloseConnection(connectionID string, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(activeConnectionsPath, connectionID),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	body, _ = getResponseBody(resp)
	return body, err
}

// AddFolder adds a new folder and checks the received HTTP Status code against expectedStatusCode
func AddFolder(folder vfs.BaseVirtualFolder, expectedStatusCode int) (vfs.BaseVirtualFolder, []byte, error) {
	var newFolder vfs.BaseVirtualFolder
	var body []byte
	folderAsJSON, _ := json.Marshal(folder)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(folderPath), bytes.NewBuffer(folderAsJSON),
		"application/json", getDefaultToken())
	if err != nil {
		return newFolder, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusCreated {
		body, _ = getResponseBody(resp)
		return newFolder, body, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newFolder)
	} else {
		body, _ = getResponseBody(resp)
	}
	if err == nil {
		err = checkFolder(&folder, &newFolder)
	}
	return newFolder, body, err
}

// UpdateFolder updates an existing folder and checks the received HTTP Status code against expectedStatusCode.
func UpdateFolder(folder vfs.BaseVirtualFolder, expectedStatusCode int) (vfs.BaseVirtualFolder, []byte, error) {
	var updatedFolder vfs.BaseVirtualFolder
	var body []byte

	folderAsJSON, _ := json.Marshal(folder)
	resp, err := sendHTTPRequest(http.MethodPut, buildURLRelativeToBase(folderPath, url.PathEscape(folder.Name)),
		bytes.NewBuffer(folderAsJSON), "application/json", getDefaultToken())
	if err != nil {
		return updatedFolder, body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)

	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		return updatedFolder, body, err
	}
	if err == nil {
		updatedFolder, body, err = GetFolderByName(folder.Name, expectedStatusCode)
	}
	if err == nil {
		err = checkFolder(&folder, &updatedFolder)
	}
	return updatedFolder, body, err
}

// RemoveFolder removes an existing user and checks the received HTTP Status code against expectedStatusCode.
func RemoveFolder(folder vfs.BaseVirtualFolder, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(folderPath, url.PathEscape(folder.Name)),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetFolderByName gets a folder by name and checks the received HTTP Status code against expectedStatusCode.
func GetFolderByName(name string, expectedStatusCode int) (vfs.BaseVirtualFolder, []byte, error) {
	var folder vfs.BaseVirtualFolder
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(folderPath, url.PathEscape(name)),
		nil, "", getDefaultToken())
	if err != nil {
		return folder, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &folder)
	} else {
		body, _ = getResponseBody(resp)
	}
	return folder, body, err
}

// GetFolders returns a list of folders and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
// The results can be filtered specifying a folder path, the folder path filter is an exact match
func GetFolders(limit int64, offset int64, expectedStatusCode int) ([]vfs.BaseVirtualFolder, []byte, error) {
	var folders []vfs.BaseVirtualFolder
	var body []byte
	url, err := addLimitAndOffsetQueryParams(buildURLRelativeToBase(folderPath), limit, offset)
	if err != nil {
		return folders, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return folders, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &folders)
	} else {
		body, _ = getResponseBody(resp)
	}
	return folders, body, err
}

// GetFoldersQuotaScans gets active quota scans for folders and checks the received HTTP Status code against expectedStatusCode.
func GetFoldersQuotaScans(expectedStatusCode int) ([]common.ActiveVirtualFolderQuotaScan, []byte, error) {
	var quotaScans []common.ActiveVirtualFolderQuotaScan
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(quotaScanVFolderPath), nil, "", getDefaultToken())
	if err != nil {
		return quotaScans, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &quotaScans)
	} else {
		body, _ = getResponseBody(resp)
	}
	return quotaScans, body, err
}

// StartFolderQuotaScan start a new quota scan for the given folder and checks the received HTTP Status code against expectedStatusCode.
func StartFolderQuotaScan(folder vfs.BaseVirtualFolder, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(quotasBasePath, "folders", folder.Name, "scan"),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// UpdateFolderQuotaUsage updates the folder used quota limits and checks the received HTTP Status code against expectedStatusCode.
func UpdateFolderQuotaUsage(folder vfs.BaseVirtualFolder, mode string, expectedStatusCode int) ([]byte, error) {
	var body []byte
	folderAsJSON, _ := json.Marshal(folder)
	url, err := addModeQueryParam(buildURLRelativeToBase(quotasBasePath, "folders", folder.Name, "usage"), mode)
	if err != nil {
		return body, err
	}
	resp, err := sendHTTPRequest(http.MethodPut, url.String(), bytes.NewBuffer(folderAsJSON), "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetVersion returns version details
func GetVersion(expectedStatusCode int) (version.Info, []byte, error) {
	var appVersion version.Info
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(versionPath), nil, "", getDefaultToken())
	if err != nil {
		return appVersion, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &appVersion)
	} else {
		body, _ = getResponseBody(resp)
	}
	return appVersion, body, err
}

// GetStatus returns the server status
func GetStatus(expectedStatusCode int) (httpd.ServicesStatus, []byte, error) {
	var response httpd.ServicesStatus
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(serverStatusPath), nil, "", getDefaultToken())
	if err != nil {
		return response, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && (expectedStatusCode == http.StatusOK) {
		err = render.DecodeJSON(resp.Body, &response)
	} else {
		body, _ = getResponseBody(resp)
	}
	return response, body, err
}

// GetDefenderHosts returns hosts that are banned or for which some violations have been detected
func GetDefenderHosts(expectedStatusCode int) ([]dataprovider.DefenderEntry, []byte, error) {
	var response []dataprovider.DefenderEntry
	var body []byte
	url, err := url.Parse(buildURLRelativeToBase(defenderHosts))
	if err != nil {
		return response, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return response, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &response)
	} else {
		body, _ = getResponseBody(resp)
	}
	return response, body, err
}

// GetDefenderHostByIP returns the host with the given IP, if it exists
func GetDefenderHostByIP(ip string, expectedStatusCode int) (dataprovider.DefenderEntry, []byte, error) {
	var host dataprovider.DefenderEntry
	var body []byte
	id := hex.EncodeToString([]byte(ip))
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(defenderHosts, id),
		nil, "", getDefaultToken())
	if err != nil {
		return host, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &host)
	} else {
		body, _ = getResponseBody(resp)
	}
	return host, body, err
}

// RemoveDefenderHostByIP removes the host with the given IP from the defender list
func RemoveDefenderHostByIP(ip string, expectedStatusCode int) ([]byte, error) {
	var body []byte
	id := hex.EncodeToString([]byte(ip))
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(defenderHosts, id), nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetBanTime returns the ban time for the given IP address
func GetBanTime(ip string, expectedStatusCode int) (map[string]interface{}, []byte, error) {
	var response map[string]interface{}
	var body []byte
	url, err := url.Parse(buildURLRelativeToBase(defenderBanTime))
	if err != nil {
		return response, body, err
	}
	q := url.Query()
	q.Add("ip", ip)
	url.RawQuery = q.Encode()
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return response, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &response)
	} else {
		body, _ = getResponseBody(resp)
	}
	return response, body, err
}

// GetScore returns the score for the given IP address
func GetScore(ip string, expectedStatusCode int) (map[string]interface{}, []byte, error) {
	var response map[string]interface{}
	var body []byte
	url, err := url.Parse(buildURLRelativeToBase(defenderScore))
	if err != nil {
		return response, body, err
	}
	q := url.Query()
	q.Add("ip", ip)
	url.RawQuery = q.Encode()
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return response, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &response)
	} else {
		body, _ = getResponseBody(resp)
	}
	return response, body, err
}

// UnbanIP unbans the given IP address
func UnbanIP(ip string, expectedStatusCode int) error {
	postBody := make(map[string]string)
	postBody["ip"] = ip
	asJSON, _ := json.Marshal(postBody)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(defenderUnban), bytes.NewBuffer(asJSON),
		"", getDefaultToken())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResponse(resp.StatusCode, expectedStatusCode)
}

// Dumpdata requests a backup to outputFile.
// outputFile is relative to the configured backups_path
func Dumpdata(outputFile, outputData, indent string, expectedStatusCode int) (map[string]interface{}, []byte, error) {
	var response map[string]interface{}
	var body []byte
	url, err := url.Parse(buildURLRelativeToBase(dumpDataPath))
	if err != nil {
		return response, body, err
	}
	q := url.Query()
	if outputData != "" {
		q.Add("output-data", outputData)
	}
	if outputFile != "" {
		q.Add("output-file", outputFile)
	}
	if indent != "" {
		q.Add("indent", indent)
	}
	url.RawQuery = q.Encode()
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return response, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &response)
	} else {
		body, _ = getResponseBody(resp)
	}
	return response, body, err
}

// Loaddata restores a backup.
func Loaddata(inputFile, scanQuota, mode string, expectedStatusCode int) (map[string]interface{}, []byte, error) {
	var response map[string]interface{}
	var body []byte
	url, err := url.Parse(buildURLRelativeToBase(loadDataPath))
	if err != nil {
		return response, body, err
	}
	q := url.Query()
	q.Add("input-file", inputFile)
	if scanQuota != "" {
		q.Add("scan-quota", scanQuota)
	}
	if mode != "" {
		q.Add("mode", mode)
	}
	url.RawQuery = q.Encode()
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return response, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &response)
	} else {
		body, _ = getResponseBody(resp)
	}
	return response, body, err
}

// LoaddataFromPostBody restores a backup
func LoaddataFromPostBody(data []byte, scanQuota, mode string, expectedStatusCode int) (map[string]interface{}, []byte, error) {
	var response map[string]interface{}
	var body []byte
	url, err := url.Parse(buildURLRelativeToBase(loadDataPath))
	if err != nil {
		return response, body, err
	}
	q := url.Query()
	if scanQuota != "" {
		q.Add("scan-quota", scanQuota)
	}
	if mode != "" {
		q.Add("mode", mode)
	}
	url.RawQuery = q.Encode()
	resp, err := sendHTTPRequest(http.MethodPost, url.String(), bytes.NewReader(data), "", getDefaultToken())
	if err != nil {
		return response, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &response)
	} else {
		body, _ = getResponseBody(resp)
	}
	return response, body, err
}

func checkResponse(actual int, expected int) error {
	if expected != actual {
		return fmt.Errorf("wrong status code: got %v want %v", actual, expected)
	}
	return nil
}

func getResponseBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(resp.Body)
}

func checkFolder(expected *vfs.BaseVirtualFolder, actual *vfs.BaseVirtualFolder) error {
	if expected.ID <= 0 {
		if actual.ID <= 0 {
			return errors.New("actual folder ID must be > 0")
		}
	} else {
		if actual.ID != expected.ID {
			return errors.New("folder ID mismatch")
		}
	}
	if dataprovider.ConvertName(expected.Name) != actual.Name {
		return errors.New("name mismatch")
	}
	if expected.MappedPath != actual.MappedPath {
		return errors.New("mapped path mismatch")
	}
	if expected.Description != actual.Description {
		return errors.New("description mismatch")
	}
	return compareFsConfig(&expected.FsConfig, &actual.FsConfig)
}

func checkAPIKey(expected, actual *dataprovider.APIKey) error {
	if actual.Key != "" {
		return errors.New("key must not be visible")
	}
	if actual.KeyID == "" {
		return errors.New("actual key_id cannot be empty")
	}
	if expected.Name != actual.Name {
		return errors.New("name mismatch")
	}
	if expected.Scope != actual.Scope {
		return errors.New("scope mismatch")
	}
	if actual.CreatedAt == 0 {
		return errors.New("created_at cannot be 0")
	}
	if actual.UpdatedAt == 0 {
		return errors.New("updated_at cannot be 0")
	}
	if expected.ExpiresAt != actual.ExpiresAt {
		return errors.New("expires_at mismatch")
	}
	if expected.Description != actual.Description {
		return errors.New("description mismatch")
	}
	if expected.User != actual.User {
		return errors.New("user mismatch")
	}
	if expected.Admin != actual.Admin {
		return errors.New("admin mismatch")
	}

	return nil
}

func checkAdmin(expected, actual *dataprovider.Admin) error {
	if actual.Password != "" {
		return errors.New("admin password must not be visible")
	}
	if expected.ID <= 0 {
		if actual.ID <= 0 {
			return errors.New("actual admin ID must be > 0")
		}
	} else {
		if actual.ID != expected.ID {
			return errors.New("admin ID mismatch")
		}
	}
	if expected.CreatedAt > 0 {
		if expected.CreatedAt != actual.CreatedAt {
			return fmt.Errorf("created_at mismatch %v != %v", expected.CreatedAt, actual.CreatedAt)
		}
	}
	if err := compareAdminEqualFields(expected, actual); err != nil {
		return err
	}
	if len(expected.Permissions) != len(actual.Permissions) {
		return errors.New("permissions mismatch")
	}
	for _, p := range expected.Permissions {
		if !util.IsStringInSlice(p, actual.Permissions) {
			return errors.New("permissions content mismatch")
		}
	}
	if len(expected.Filters.AllowList) != len(actual.Filters.AllowList) {
		return errors.New("allow list mismatch")
	}
	if expected.Filters.AllowAPIKeyAuth != actual.Filters.AllowAPIKeyAuth {
		return errors.New("allow_api_key_auth mismatch")
	}
	for _, v := range expected.Filters.AllowList {
		if !util.IsStringInSlice(v, actual.Filters.AllowList) {
			return errors.New("allow list content mismatch")
		}
	}

	return nil
}

func compareAdminEqualFields(expected *dataprovider.Admin, actual *dataprovider.Admin) error {
	if dataprovider.ConvertName(expected.Username) != actual.Username {
		return errors.New("sername mismatch")
	}
	if expected.Email != actual.Email {
		return errors.New("email mismatch")
	}
	if expected.Status != actual.Status {
		return errors.New("status mismatch")
	}
	if expected.Description != actual.Description {
		return errors.New("description mismatch")
	}
	if expected.AdditionalInfo != actual.AdditionalInfo {
		return errors.New("additional info mismatch")
	}
	return nil
}

func checkUser(expected *dataprovider.User, actual *dataprovider.User) error {
	if actual.Password != "" {
		return errors.New("user password must not be visible")
	}
	if expected.ID <= 0 {
		if actual.ID <= 0 {
			return errors.New("actual user ID must be > 0")
		}
	} else {
		if actual.ID != expected.ID {
			return errors.New("user ID mismatch")
		}
	}
	if expected.CreatedAt > 0 {
		if expected.CreatedAt != actual.CreatedAt {
			return fmt.Errorf("created_at mismatch %v != %v", expected.CreatedAt, actual.CreatedAt)
		}
	}

	if expected.Email != actual.Email {
		return errors.New("email mismatch")
	}
	if err := compareUserPermissions(expected, actual); err != nil {
		return err
	}
	if err := compareUserFilters(expected, actual); err != nil {
		return err
	}
	if err := compareFsConfig(&expected.FsConfig, &actual.FsConfig); err != nil {
		return err
	}
	if err := compareUserVirtualFolders(expected, actual); err != nil {
		return err
	}
	return compareEqualsUserFields(expected, actual)
}

func compareUserPermissions(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Permissions) != len(actual.Permissions) {
		return errors.New("permissions mismatch")
	}
	for dir, perms := range expected.Permissions {
		if actualPerms, ok := actual.Permissions[dir]; ok {
			for _, v := range actualPerms {
				if !util.IsStringInSlice(v, perms) {
					return errors.New("permissions contents mismatch")
				}
			}
		} else {
			return errors.New("permissions directories mismatch")
		}
	}
	return nil
}

func compareUserVirtualFolders(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(actual.VirtualFolders) != len(expected.VirtualFolders) {
		return errors.New("virtual folders len mismatch")
	}
	for _, v := range actual.VirtualFolders {
		found := false
		for _, v1 := range expected.VirtualFolders {
			if path.Clean(v.VirtualPath) == path.Clean(v1.VirtualPath) {
				if err := checkFolder(&v1.BaseVirtualFolder, &v.BaseVirtualFolder); err != nil {
					return err
				}
				if v.QuotaSize != v1.QuotaSize {
					return errors.New("vfolder quota size mismatch")
				}
				if (v.QuotaFiles) != (v1.QuotaFiles) {
					return errors.New("vfolder quota files mismatch")
				}
				found = true
				break
			}
		}
		if !found {
			return errors.New("virtual folders mismatch")
		}
	}
	return nil
}

func compareFsConfig(expected *vfs.Filesystem, actual *vfs.Filesystem) error {
	if expected.Provider != actual.Provider {
		return errors.New("fs provider mismatch")
	}
	if err := compareS3Config(expected, actual); err != nil {
		return err
	}
	if err := compareGCSConfig(expected, actual); err != nil {
		return err
	}
	if err := compareAzBlobConfig(expected, actual); err != nil {
		return err
	}
	if err := checkEncryptedSecret(expected.CryptConfig.Passphrase, actual.CryptConfig.Passphrase); err != nil {
		return err
	}
	return compareSFTPFsConfig(expected, actual)
}

func compareS3Config(expected *vfs.Filesystem, actual *vfs.Filesystem) error { //nolint:gocyclo
	if expected.S3Config.Bucket != actual.S3Config.Bucket {
		return errors.New("fs S3 bucket mismatch")
	}
	if expected.S3Config.Region != actual.S3Config.Region {
		return errors.New("fs S3 region mismatch")
	}
	if expected.S3Config.AccessKey != actual.S3Config.AccessKey {
		return errors.New("fs S3 access key mismatch")
	}
	if expected.S3Config.RoleARN != actual.S3Config.RoleARN {
		return errors.New("fs S3 role ARN mismatch")
	}
	if err := checkEncryptedSecret(expected.S3Config.AccessSecret, actual.S3Config.AccessSecret); err != nil {
		return fmt.Errorf("fs S3 access secret mismatch: %v", err)
	}
	if expected.S3Config.Endpoint != actual.S3Config.Endpoint {
		return errors.New("fs S3 endpoint mismatch")
	}
	if expected.S3Config.StorageClass != actual.S3Config.StorageClass {
		return errors.New("fs S3 storage class mismatch")
	}
	if expected.S3Config.ACL != actual.S3Config.ACL {
		return errors.New("fs S3 ACL mismatch")
	}
	if expected.S3Config.UploadPartSize != actual.S3Config.UploadPartSize {
		return errors.New("fs S3 upload part size mismatch")
	}
	if expected.S3Config.UploadConcurrency != actual.S3Config.UploadConcurrency {
		return errors.New("fs S3 upload concurrency mismatch")
	}
	if expected.S3Config.DownloadPartSize != actual.S3Config.DownloadPartSize {
		return errors.New("fs S3 download part size mismatch")
	}
	if expected.S3Config.DownloadConcurrency != actual.S3Config.DownloadConcurrency {
		return errors.New("fs S3 download concurrency mismatch")
	}
	if expected.S3Config.ForcePathStyle != actual.S3Config.ForcePathStyle {
		return errors.New("fs S3 force path style mismatch")
	}
	if expected.S3Config.DownloadPartMaxTime != actual.S3Config.DownloadPartMaxTime {
		return errors.New("fs S3 download part max time mismatch")
	}
	if expected.S3Config.UploadPartMaxTime != actual.S3Config.UploadPartMaxTime {
		return errors.New("fs S3 upload part max time mismatch")
	}
	if expected.S3Config.KeyPrefix != actual.S3Config.KeyPrefix &&
		expected.S3Config.KeyPrefix+"/" != actual.S3Config.KeyPrefix {
		return errors.New("fs S3 key prefix mismatch")
	}
	return nil
}

func compareGCSConfig(expected *vfs.Filesystem, actual *vfs.Filesystem) error {
	if expected.GCSConfig.Bucket != actual.GCSConfig.Bucket {
		return errors.New("GCS bucket mismatch")
	}
	if expected.GCSConfig.StorageClass != actual.GCSConfig.StorageClass {
		return errors.New("GCS storage class mismatch")
	}
	if expected.GCSConfig.ACL != actual.GCSConfig.ACL {
		return errors.New("GCS ACL mismatch")
	}
	if expected.GCSConfig.KeyPrefix != actual.GCSConfig.KeyPrefix &&
		expected.GCSConfig.KeyPrefix+"/" != actual.GCSConfig.KeyPrefix {
		return errors.New("GCS key prefix mismatch")
	}
	if expected.GCSConfig.AutomaticCredentials != actual.GCSConfig.AutomaticCredentials {
		return errors.New("GCS automatic credentials mismatch")
	}
	return nil
}

func compareSFTPFsConfig(expected *vfs.Filesystem, actual *vfs.Filesystem) error {
	if expected.SFTPConfig.Endpoint != actual.SFTPConfig.Endpoint {
		return errors.New("SFTPFs endpoint mismatch")
	}
	if expected.SFTPConfig.Username != actual.SFTPConfig.Username {
		return errors.New("SFTPFs username mismatch")
	}
	if expected.SFTPConfig.DisableCouncurrentReads != actual.SFTPConfig.DisableCouncurrentReads {
		return errors.New("SFTPFs disable_concurrent_reads mismatch")
	}
	if expected.SFTPConfig.BufferSize != actual.SFTPConfig.BufferSize {
		return errors.New("SFTPFs buffer_size mismatch")
	}
	if err := checkEncryptedSecret(expected.SFTPConfig.Password, actual.SFTPConfig.Password); err != nil {
		return fmt.Errorf("SFTPFs password mismatch: %v", err)
	}
	if err := checkEncryptedSecret(expected.SFTPConfig.PrivateKey, actual.SFTPConfig.PrivateKey); err != nil {
		return fmt.Errorf("SFTPFs private key mismatch: %v", err)
	}
	if expected.SFTPConfig.Prefix != actual.SFTPConfig.Prefix {
		if expected.SFTPConfig.Prefix != "" && actual.SFTPConfig.Prefix != "/" {
			return errors.New("SFTPFs prefix mismatch")
		}
	}
	if len(expected.SFTPConfig.Fingerprints) != len(actual.SFTPConfig.Fingerprints) {
		return errors.New("SFTPFs fingerprints mismatch")
	}
	for _, value := range actual.SFTPConfig.Fingerprints {
		if !util.IsStringInSlice(value, expected.SFTPConfig.Fingerprints) {
			return errors.New("SFTPFs fingerprints mismatch")
		}
	}
	return nil
}

func compareAzBlobConfig(expected *vfs.Filesystem, actual *vfs.Filesystem) error {
	if expected.AzBlobConfig.Container != actual.AzBlobConfig.Container {
		return errors.New("azure Blob container mismatch")
	}
	if expected.AzBlobConfig.AccountName != actual.AzBlobConfig.AccountName {
		return errors.New("azure Blob account name mismatch")
	}
	if err := checkEncryptedSecret(expected.AzBlobConfig.AccountKey, actual.AzBlobConfig.AccountKey); err != nil {
		return fmt.Errorf("azure Blob account key mismatch: %v", err)
	}
	if expected.AzBlobConfig.Endpoint != actual.AzBlobConfig.Endpoint {
		return errors.New("azure Blob endpoint mismatch")
	}
	if err := checkEncryptedSecret(expected.AzBlobConfig.SASURL, actual.AzBlobConfig.SASURL); err != nil {
		return fmt.Errorf("azure Blob SAS URL mismatch: %v", err)
	}
	if expected.AzBlobConfig.UploadPartSize != actual.AzBlobConfig.UploadPartSize {
		return errors.New("azure Blob upload part size mismatch")
	}
	if expected.AzBlobConfig.UploadConcurrency != actual.AzBlobConfig.UploadConcurrency {
		return errors.New("azure Blob upload concurrency mismatch")
	}
	if expected.AzBlobConfig.DownloadPartSize != actual.AzBlobConfig.DownloadPartSize {
		return errors.New("azure Blob download part size mismatch")
	}
	if expected.AzBlobConfig.DownloadConcurrency != actual.AzBlobConfig.DownloadConcurrency {
		return errors.New("azure Blob download concurrency mismatch")
	}
	if expected.AzBlobConfig.KeyPrefix != actual.AzBlobConfig.KeyPrefix &&
		expected.AzBlobConfig.KeyPrefix+"/" != actual.AzBlobConfig.KeyPrefix {
		return errors.New("azure Blob key prefix mismatch")
	}
	if expected.AzBlobConfig.UseEmulator != actual.AzBlobConfig.UseEmulator {
		return errors.New("azure Blob use emulator mismatch")
	}
	if expected.AzBlobConfig.AccessTier != actual.AzBlobConfig.AccessTier {
		return errors.New("azure Blob access tier mismatch")
	}
	return nil
}

func areSecretEquals(expected, actual *kms.Secret) bool {
	if expected == nil && actual == nil {
		return true
	}
	if expected != nil && expected.IsEmpty() && actual == nil {
		return true
	}
	if actual != nil && actual.IsEmpty() && expected == nil {
		return true
	}
	return false
}

func checkEncryptedSecret(expected, actual *kms.Secret) error {
	if areSecretEquals(expected, actual) {
		return nil
	}
	if expected == nil && actual != nil && !actual.IsEmpty() {
		return errors.New("secret mismatch")
	}
	if actual == nil && expected != nil && !expected.IsEmpty() {
		return errors.New("secret mismatch")
	}
	if expected.IsPlain() && actual.IsEncrypted() {
		if actual.GetPayload() == "" {
			return errors.New("invalid secret payload")
		}
		if actual.GetAdditionalData() != "" {
			return errors.New("invalid secret additional data")
		}
		if actual.GetKey() != "" {
			return errors.New("invalid secret key")
		}
	} else {
		if expected.GetStatus() != actual.GetStatus() || expected.GetPayload() != actual.GetPayload() {
			return errors.New("secret mismatch")
		}
	}
	return nil
}

func compareUserFilterSubStructs(expected *dataprovider.User, actual *dataprovider.User) error {
	for _, IPMask := range expected.Filters.AllowedIP {
		if !util.IsStringInSlice(IPMask, actual.Filters.AllowedIP) {
			return errors.New("allowed IP contents mismatch")
		}
	}
	for _, IPMask := range expected.Filters.DeniedIP {
		if !util.IsStringInSlice(IPMask, actual.Filters.DeniedIP) {
			return errors.New("denied IP contents mismatch")
		}
	}
	for _, method := range expected.Filters.DeniedLoginMethods {
		if !util.IsStringInSlice(method, actual.Filters.DeniedLoginMethods) {
			return errors.New("denied login methods contents mismatch")
		}
	}
	for _, protocol := range expected.Filters.DeniedProtocols {
		if !util.IsStringInSlice(protocol, actual.Filters.DeniedProtocols) {
			return errors.New("denied protocols contents mismatch")
		}
	}
	for _, options := range expected.Filters.WebClient {
		if !util.IsStringInSlice(options, actual.Filters.WebClient) {
			return errors.New("web client options contents mismatch")
		}
	}
	return compareUserFiltersEqualFields(expected, actual)
}

func compareUserFiltersEqualFields(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.Filters.Hooks.ExternalAuthDisabled != actual.Filters.Hooks.ExternalAuthDisabled {
		return errors.New("external_auth_disabled hook mismatch")
	}
	if expected.Filters.Hooks.PreLoginDisabled != actual.Filters.Hooks.PreLoginDisabled {
		return errors.New("pre_login_disabled hook mismatch")
	}
	if expected.Filters.Hooks.CheckPasswordDisabled != actual.Filters.Hooks.CheckPasswordDisabled {
		return errors.New("check_password_disabled hook mismatch")
	}
	if expected.Filters.DisableFsChecks != actual.Filters.DisableFsChecks {
		return errors.New("disable_fs_checks mismatch")
	}
	if expected.Filters.StartDirectory != actual.Filters.StartDirectory {
		return errors.New("start_directory mismatch")
	}
	return nil
}

func compareUserFilters(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Filters.AllowedIP) != len(actual.Filters.AllowedIP) {
		return errors.New("allowed IP mismatch")
	}
	if len(expected.Filters.DeniedIP) != len(actual.Filters.DeniedIP) {
		return errors.New("denied IP mismatch")
	}
	if len(expected.Filters.DeniedLoginMethods) != len(actual.Filters.DeniedLoginMethods) {
		return errors.New("denied login methods mismatch")
	}
	if len(expected.Filters.DeniedProtocols) != len(actual.Filters.DeniedProtocols) {
		return errors.New("denied protocols mismatch")
	}
	if expected.Filters.MaxUploadFileSize != actual.Filters.MaxUploadFileSize {
		return errors.New("max upload file size mismatch")
	}
	if expected.Filters.TLSUsername != actual.Filters.TLSUsername {
		return errors.New("TLSUsername mismatch")
	}
	if len(expected.Filters.WebClient) != len(actual.Filters.WebClient) {
		return errors.New("WebClient filter mismatch")
	}
	if expected.Filters.AllowAPIKeyAuth != actual.Filters.AllowAPIKeyAuth {
		return errors.New("allow_api_key_auth mismatch")
	}
	if expected.Filters.ExternalAuthCacheTime != actual.Filters.ExternalAuthCacheTime {
		return errors.New("external_auth_cache_time mismatch")
	}
	if err := compareUserFilterSubStructs(expected, actual); err != nil {
		return err
	}
	if err := compareUserBandwidthLimitFilters(expected, actual); err != nil {
		return err
	}
	if err := compareUserDataTransferLimitFilters(expected, actual); err != nil {
		return err
	}
	return compareUserFilePatternsFilters(expected, actual)
}

func checkFilterMatch(expected []string, actual []string) bool {
	if len(expected) != len(actual) {
		return false
	}
	for _, e := range expected {
		if !util.IsStringInSlice(strings.ToLower(e), actual) {
			return false
		}
	}
	return true
}

func compareUserDataTransferLimitFilters(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Filters.DataTransferLimits) != len(actual.Filters.DataTransferLimits) {
		return errors.New("data transfer limits filters mismatch")
	}
	for idx, l := range expected.Filters.DataTransferLimits {
		if actual.Filters.DataTransferLimits[idx].UploadDataTransfer != l.UploadDataTransfer {
			return errors.New("data transfer limit upload_data_transfer mismatch")
		}
		if actual.Filters.DataTransferLimits[idx].DownloadDataTransfer != l.DownloadDataTransfer {
			return errors.New("data transfer limit download_data_transfer mismatch")
		}
		if actual.Filters.DataTransferLimits[idx].TotalDataTransfer != l.TotalDataTransfer {
			return errors.New("data transfer limit total_data_transfer mismatch")
		}
		for _, source := range actual.Filters.DataTransferLimits[idx].Sources {
			if !util.IsStringInSlice(source, l.Sources) {
				return errors.New("data transfer limit source mismatch")
			}
		}
	}

	return nil
}

func compareUserBandwidthLimitFilters(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Filters.BandwidthLimits) != len(actual.Filters.BandwidthLimits) {
		return errors.New("bandwidth limits filters mismatch")
	}

	for idx, l := range expected.Filters.BandwidthLimits {
		if actual.Filters.BandwidthLimits[idx].UploadBandwidth != l.UploadBandwidth {
			return errors.New("bandwidth filters upload_bandwidth mismatch")
		}
		if actual.Filters.BandwidthLimits[idx].DownloadBandwidth != l.DownloadBandwidth {
			return errors.New("bandwidth filters download_bandwidth mismatch")
		}
		if len(actual.Filters.BandwidthLimits[idx].Sources) != len(l.Sources) {
			return errors.New("bandwidth filters sources mismatch")
		}
		for _, source := range actual.Filters.BandwidthLimits[idx].Sources {
			if !util.IsStringInSlice(source, l.Sources) {
				return errors.New("bandwidth filters source mismatch")
			}
		}
	}

	return nil
}

func compareUserFilePatternsFilters(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Filters.FilePatterns) != len(actual.Filters.FilePatterns) {
		return errors.New("file patterns mismatch")
	}
	for _, f := range expected.Filters.FilePatterns {
		found := false
		for _, f1 := range actual.Filters.FilePatterns {
			if path.Clean(f.Path) == path.Clean(f1.Path) && f.DenyPolicy == f1.DenyPolicy {
				if !checkFilterMatch(f.AllowedPatterns, f1.AllowedPatterns) ||
					!checkFilterMatch(f.DeniedPatterns, f1.DeniedPatterns) {
					return errors.New("file patterns contents mismatch")
				}
				found = true
			}
		}
		if !found {
			return errors.New("file patterns contents mismatch")
		}
	}
	return nil
}

func compareEqualsUserFields(expected *dataprovider.User, actual *dataprovider.User) error {
	if dataprovider.ConvertName(expected.Username) != actual.Username {
		return errors.New("username mismatch")
	}
	if expected.HomeDir != actual.HomeDir {
		return errors.New("home dir mismatch")
	}
	if expected.UID != actual.UID {
		return errors.New("UID mismatch")
	}
	if expected.GID != actual.GID {
		return errors.New("GID mismatch")
	}
	if expected.MaxSessions != actual.MaxSessions {
		return errors.New("MaxSessions mismatch")
	}
	if len(expected.Permissions) != len(actual.Permissions) {
		return errors.New("permissions mismatch")
	}
	if expected.UploadBandwidth != actual.UploadBandwidth {
		return errors.New("UploadBandwidth mismatch")
	}
	if expected.DownloadBandwidth != actual.DownloadBandwidth {
		return errors.New("DownloadBandwidth mismatch")
	}
	if expected.Status != actual.Status {
		return errors.New("status mismatch")
	}
	if expected.ExpirationDate != actual.ExpirationDate {
		return errors.New("ExpirationDate mismatch")
	}
	if expected.AdditionalInfo != actual.AdditionalInfo {
		return errors.New("AdditionalInfo mismatch")
	}
	if expected.Description != actual.Description {
		return errors.New("description mismatch")
	}
	return compareQuotaUserFields(expected, actual)
}

func compareQuotaUserFields(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.QuotaSize != actual.QuotaSize {
		return errors.New("QuotaSize mismatch")
	}
	if expected.QuotaFiles != actual.QuotaFiles {
		return errors.New("QuotaFiles mismatch")
	}
	if expected.UploadDataTransfer != actual.UploadDataTransfer {
		return errors.New("upload_data_transfer mismatch")
	}
	if expected.DownloadDataTransfer != actual.DownloadDataTransfer {
		return errors.New("download_data_transfer mismatch")
	}
	if expected.TotalDataTransfer != actual.TotalDataTransfer {
		return errors.New("total_data_transfer mismatch")
	}
	return nil
}

func addLimitAndOffsetQueryParams(rawurl string, limit, offset int64) (*url.URL, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	q := url.Query()
	if limit > 0 {
		q.Add("limit", strconv.FormatInt(limit, 10))
	}
	if offset > 0 {
		q.Add("offset", strconv.FormatInt(offset, 10))
	}
	url.RawQuery = q.Encode()
	return url, err
}

func addModeQueryParam(rawurl, mode string) (*url.URL, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	q := url.Query()
	if len(mode) > 0 {
		q.Add("mode", mode)
	}
	url.RawQuery = q.Encode()
	return url, err
}

func addDisconnectQueryParam(rawurl, disconnect string) (*url.URL, error) {
	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	q := url.Query()
	if len(disconnect) > 0 {
		q.Add("disconnect", disconnect)
	}
	url.RawQuery = q.Encode()
	return url, err
}
