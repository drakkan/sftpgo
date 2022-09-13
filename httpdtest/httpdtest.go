// Package httpdtest provides utilities for testing the exposed REST API.
package httpdtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	tokenPath                 = "/api/v2/token"
	activeConnectionsPath     = "/api/v2/connections"
	quotaScanPath             = "/api/v2/quota-scans"
	quotaScanVFolderPath      = "/api/v2/folder-quota-scans"
	userPath                  = "/api/v2/users"
	versionPath               = "/api/v2/version"
	folderPath                = "/api/v2/folders"
	serverStatusPath          = "/api/v2/status"
	dumpDataPath              = "/api/v2/dumpdata"
	loadDataPath              = "/api/v2/loaddata"
	updateUsedQuotaPath       = "/api/v2/quota-update"
	updateFolderUsedQuotaPath = "/api/v2/folder-quota-update"
	defenderBanTime           = "/api/v2/defender/bantime"
	defenderUnban             = "/api/v2/defender/unban"
	defenderScore             = "/api/v2/defender/score"
	adminPath                 = "/api/v2/admins"
	adminPwdPath              = "/api/v2/changepwd/admin"
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

// AddAdmin adds a new user and checks the received HTTP Status code against expectedStatusCode.
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
	userAsJSON, _ := json.Marshal(user)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(quotaScanPath), bytes.NewBuffer(userAsJSON),
		"", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// UpdateQuotaUsage updates the user used quota limits and checks the received HTTP Status code against expectedStatusCode.
func UpdateQuotaUsage(user dataprovider.User, mode string, expectedStatusCode int) ([]byte, error) {
	var body []byte
	userAsJSON, _ := json.Marshal(user)
	url, err := addModeQueryParam(buildURLRelativeToBase(updateUsedQuotaPath), mode)
	if err != nil {
		return body, err
	}
	resp, err := sendHTTPRequest(http.MethodPut, url.String(), bytes.NewBuffer(userAsJSON), "", getDefaultToken())
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
	folderAsJSON, _ := json.Marshal(folder)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(quotaScanVFolderPath),
		bytes.NewBuffer(folderAsJSON), "", getDefaultToken())
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
	url, err := addModeQueryParam(buildURLRelativeToBase(updateFolderUsedQuotaPath), mode)
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
	return ioutil.ReadAll(resp.Body)
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
	if expected.Name != actual.Name {
		return errors.New("name mismatch")
	}
	if expected.MappedPath != actual.MappedPath {
		return errors.New("mapped path mismatch")
	}
	if expected.LastQuotaUpdate != actual.LastQuotaUpdate {
		return errors.New("last quota update mismatch")
	}
	if expected.UsedQuotaSize != actual.UsedQuotaSize {
		return errors.New("used quota size mismatch")
	}
	if expected.UsedQuotaFiles != actual.UsedQuotaFiles {
		return errors.New("used quota files mismatch")
	}
	if len(expected.Users) != len(actual.Users) {
		return errors.New("folder users mismatch")
	}
	for _, u := range actual.Users {
		if !utils.IsStringInSlice(u, expected.Users) {
			return errors.New("folder users mismatch")
		}
	}
	return nil
}

func checkAdmin(expected *dataprovider.Admin, actual *dataprovider.Admin) error {
	if actual.Password != "" {
		return errors.New("Admin password must not be visible")
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
	if expected.Username != actual.Username {
		return errors.New("Username mismatch")
	}
	if expected.Email != actual.Email {
		return errors.New("Email mismatch")
	}
	if expected.Status != actual.Status {
		return errors.New("Status mismatch")
	}
	if expected.AdditionalInfo != actual.AdditionalInfo {
		return errors.New("AdditionalInfo mismatch")
	}
	if len(expected.Permissions) != len(actual.Permissions) {
		return errors.New("Permissions mismatch")
	}
	for _, p := range expected.Permissions {
		if !utils.IsStringInSlice(p, actual.Permissions) {
			return errors.New("Permissions content mismatch")
		}
	}
	if len(expected.Filters.AllowList) != len(actual.Filters.AllowList) {
		return errors.New("AllowList mismatch")
	}
	for _, v := range expected.Filters.AllowList {
		if !utils.IsStringInSlice(v, actual.Filters.AllowList) {
			return errors.New("AllowList content mismatch")
		}
	}

	return nil
}

func checkUser(expected *dataprovider.User, actual *dataprovider.User) error {
	if actual.Password != "" {
		return errors.New("User password must not be visible")
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
	if len(expected.Permissions) != len(actual.Permissions) {
		return errors.New("Permissions mismatch")
	}
	for dir, perms := range expected.Permissions {
		if actualPerms, ok := actual.Permissions[dir]; ok {
			for _, v := range actualPerms {
				if !utils.IsStringInSlice(v, perms) {
					return errors.New("Permissions contents mismatch")
				}
			}
		} else {
			return errors.New("Permissions directories mismatch")
		}
	}
	if err := compareUserFilters(expected, actual); err != nil {
		return err
	}
	if err := compareUserFsConfig(expected, actual); err != nil {
		return err
	}
	if err := compareUserVirtualFolders(expected, actual); err != nil {
		return err
	}
	return compareEqualsUserFields(expected, actual)
}

func compareUserVirtualFolders(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(actual.VirtualFolders) != len(expected.VirtualFolders) {
		return errors.New("Virtual folders mismatch")
	}
	for _, v := range actual.VirtualFolders {
		found := false
		for _, v1 := range expected.VirtualFolders {
			if path.Clean(v.VirtualPath) == path.Clean(v1.VirtualPath) &&
				filepath.Clean(v.MappedPath) == filepath.Clean(v1.MappedPath) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("Virtual folders mismatch")
		}
	}
	return nil
}

func compareUserFsConfig(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.FsConfig.Provider != actual.FsConfig.Provider {
		return errors.New("Fs provider mismatch")
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
	if err := checkEncryptedSecret(expected.FsConfig.CryptConfig.Passphrase, actual.FsConfig.CryptConfig.Passphrase); err != nil {
		return err
	}
	if err := compareSFTPFsConfig(expected, actual); err != nil {
		return err
	}
	return nil
}

func compareS3Config(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.FsConfig.S3Config.Bucket != actual.FsConfig.S3Config.Bucket {
		return errors.New("S3 bucket mismatch")
	}
	if expected.FsConfig.S3Config.Region != actual.FsConfig.S3Config.Region {
		return errors.New("S3 region mismatch")
	}
	if expected.FsConfig.S3Config.AccessKey != actual.FsConfig.S3Config.AccessKey {
		return errors.New("S3 access key mismatch")
	}
	if err := checkEncryptedSecret(expected.FsConfig.S3Config.AccessSecret, actual.FsConfig.S3Config.AccessSecret); err != nil {
		return fmt.Errorf("S3 access secret mismatch: %v", err)
	}
	if expected.FsConfig.S3Config.Endpoint != actual.FsConfig.S3Config.Endpoint {
		return errors.New("S3 endpoint mismatch")
	}
	if expected.FsConfig.S3Config.StorageClass != actual.FsConfig.S3Config.StorageClass {
		return errors.New("S3 storage class mismatch")
	}
	if expected.FsConfig.S3Config.UploadPartSize != actual.FsConfig.S3Config.UploadPartSize {
		return errors.New("S3 upload part size mismatch")
	}
	if expected.FsConfig.S3Config.UploadConcurrency != actual.FsConfig.S3Config.UploadConcurrency {
		return errors.New("S3 upload concurrency mismatch")
	}
	if expected.FsConfig.S3Config.UploadPartMaxTime != actual.FsConfig.S3Config.UploadPartMaxTime {
		return errors.New("S3 upload part max time mismatch")
	}
	if expected.FsConfig.S3Config.DownloadPartSize != actual.FsConfig.S3Config.DownloadPartSize {
		return errors.New("S3 download part size mismatch")
	}
	if expected.FsConfig.S3Config.DownloadConcurrency != actual.FsConfig.S3Config.DownloadConcurrency {
		return errors.New("S3 download concurrency mismatch")
	}
	if expected.FsConfig.S3Config.DownloadPartMaxTime != actual.FsConfig.S3Config.DownloadPartMaxTime {
		return errors.New("S3 download part max time mismatch")
	}
	if expected.FsConfig.S3Config.KeyPrefix != actual.FsConfig.S3Config.KeyPrefix &&
		expected.FsConfig.S3Config.KeyPrefix+"/" != actual.FsConfig.S3Config.KeyPrefix {
		return errors.New("S3 key prefix mismatch")
	}
	return nil
}

func compareGCSConfig(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.FsConfig.GCSConfig.Bucket != actual.FsConfig.GCSConfig.Bucket {
		return errors.New("GCS bucket mismatch")
	}
	if expected.FsConfig.GCSConfig.StorageClass != actual.FsConfig.GCSConfig.StorageClass {
		return errors.New("GCS storage class mismatch")
	}
	if expected.FsConfig.GCSConfig.KeyPrefix != actual.FsConfig.GCSConfig.KeyPrefix &&
		expected.FsConfig.GCSConfig.KeyPrefix+"/" != actual.FsConfig.GCSConfig.KeyPrefix {
		return errors.New("GCS key prefix mismatch")
	}
	if expected.FsConfig.GCSConfig.AutomaticCredentials != actual.FsConfig.GCSConfig.AutomaticCredentials {
		return errors.New("GCS automatic credentials mismatch")
	}
	return nil
}

func compareSFTPFsConfig(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.FsConfig.SFTPConfig.Endpoint != actual.FsConfig.SFTPConfig.Endpoint {
		return errors.New("SFTPFs endpoint mismatch")
	}
	if expected.FsConfig.SFTPConfig.Username != actual.FsConfig.SFTPConfig.Username {
		return errors.New("SFTPFs username mismatch")
	}
	if err := checkEncryptedSecret(expected.FsConfig.SFTPConfig.Password, actual.FsConfig.SFTPConfig.Password); err != nil {
		return fmt.Errorf("SFTPFs password mismatch: %v", err)
	}
	if err := checkEncryptedSecret(expected.FsConfig.SFTPConfig.PrivateKey, actual.FsConfig.SFTPConfig.PrivateKey); err != nil {
		return fmt.Errorf("SFTPFs private key mismatch: %v", err)
	}
	if expected.FsConfig.SFTPConfig.Prefix != actual.FsConfig.SFTPConfig.Prefix {
		if expected.FsConfig.SFTPConfig.Prefix != "" && actual.FsConfig.SFTPConfig.Prefix != "/" {
			return errors.New("SFTPFs prefix mismatch")
		}
	}
	if len(expected.FsConfig.SFTPConfig.Fingerprints) != len(actual.FsConfig.SFTPConfig.Fingerprints) {
		return errors.New("SFTPFs fingerprints mismatch")
	}
	for _, value := range actual.FsConfig.SFTPConfig.Fingerprints {
		if !utils.IsStringInSlice(value, expected.FsConfig.SFTPConfig.Fingerprints) {
			return errors.New("SFTPFs fingerprints mismatch")
		}
	}
	return nil
}

func compareAzBlobConfig(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.FsConfig.AzBlobConfig.Container != actual.FsConfig.AzBlobConfig.Container {
		return errors.New("Azure Blob container mismatch")
	}
	if expected.FsConfig.AzBlobConfig.AccountName != actual.FsConfig.AzBlobConfig.AccountName {
		return errors.New("Azure Blob account name mismatch")
	}
	if err := checkEncryptedSecret(expected.FsConfig.AzBlobConfig.AccountKey, actual.FsConfig.AzBlobConfig.AccountKey); err != nil {
		return fmt.Errorf("Azure Blob account key mismatch: %v", err)
	}
	if expected.FsConfig.AzBlobConfig.Endpoint != actual.FsConfig.AzBlobConfig.Endpoint {
		return errors.New("Azure Blob endpoint mismatch")
	}
	if expected.FsConfig.AzBlobConfig.SASURL != actual.FsConfig.AzBlobConfig.SASURL {
		return errors.New("Azure Blob SASL URL mismatch")
	}
	if expected.FsConfig.AzBlobConfig.UploadPartSize != actual.FsConfig.AzBlobConfig.UploadPartSize {
		return errors.New("Azure Blob upload part size mismatch")
	}
	if expected.FsConfig.AzBlobConfig.UploadConcurrency != actual.FsConfig.AzBlobConfig.UploadConcurrency {
		return errors.New("Azure Blob upload concurrency mismatch")
	}
	if expected.FsConfig.AzBlobConfig.KeyPrefix != actual.FsConfig.AzBlobConfig.KeyPrefix &&
		expected.FsConfig.AzBlobConfig.KeyPrefix+"/" != actual.FsConfig.AzBlobConfig.KeyPrefix {
		return errors.New("Azure Blob key prefix mismatch")
	}
	if expected.FsConfig.AzBlobConfig.UseEmulator != actual.FsConfig.AzBlobConfig.UseEmulator {
		return errors.New("Azure Blob use emulator mismatch")
	}
	if expected.FsConfig.AzBlobConfig.AccessTier != actual.FsConfig.AzBlobConfig.AccessTier {
		return errors.New("Azure Blob access tier mismatch")
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

func compareUserFilters(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Filters.AllowedIP) != len(actual.Filters.AllowedIP) {
		return errors.New("AllowedIP mismatch")
	}
	if len(expected.Filters.DeniedIP) != len(actual.Filters.DeniedIP) {
		return errors.New("DeniedIP mismatch")
	}
	if len(expected.Filters.DeniedLoginMethods) != len(actual.Filters.DeniedLoginMethods) {
		return errors.New("Denied login methods mismatch")
	}
	if len(expected.Filters.DeniedProtocols) != len(actual.Filters.DeniedProtocols) {
		return errors.New("Denied protocols mismatch")
	}
	if expected.Filters.MaxUploadFileSize != actual.Filters.MaxUploadFileSize {
		return errors.New("Max upload file size mismatch")
	}
	for _, IPMask := range expected.Filters.AllowedIP {
		if !utils.IsStringInSlice(IPMask, actual.Filters.AllowedIP) {
			return errors.New("AllowedIP contents mismatch")
		}
	}
	for _, IPMask := range expected.Filters.DeniedIP {
		if !utils.IsStringInSlice(IPMask, actual.Filters.DeniedIP) {
			return errors.New("DeniedIP contents mismatch")
		}
	}
	for _, method := range expected.Filters.DeniedLoginMethods {
		if !utils.IsStringInSlice(method, actual.Filters.DeniedLoginMethods) {
			return errors.New("Denied login methods contents mismatch")
		}
	}
	for _, protocol := range expected.Filters.DeniedProtocols {
		if !utils.IsStringInSlice(protocol, actual.Filters.DeniedProtocols) {
			return errors.New("Denied protocols contents mismatch")
		}
	}
	if err := compareUserFileExtensionsFilters(expected, actual); err != nil {
		return err
	}
	return compareUserFilePatternsFilters(expected, actual)
}

func checkFilterMatch(expected []string, actual []string) bool {
	if len(expected) != len(actual) {
		return false
	}
	for _, e := range expected {
		if !utils.IsStringInSlice(strings.ToLower(e), actual) {
			return false
		}
	}
	return true
}

func compareUserFilePatternsFilters(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Filters.FilePatterns) != len(actual.Filters.FilePatterns) {
		return errors.New("file patterns mismatch")
	}
	for _, f := range expected.Filters.FilePatterns {
		found := false
		for _, f1 := range actual.Filters.FilePatterns {
			if path.Clean(f.Path) == path.Clean(f1.Path) {
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

func compareUserFileExtensionsFilters(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(expected.Filters.FileExtensions) != len(actual.Filters.FileExtensions) {
		return errors.New("file extensions mismatch")
	}
	for _, f := range expected.Filters.FileExtensions {
		found := false
		for _, f1 := range actual.Filters.FileExtensions {
			if path.Clean(f.Path) == path.Clean(f1.Path) {
				if !checkFilterMatch(f.AllowedExtensions, f1.AllowedExtensions) ||
					!checkFilterMatch(f.DeniedExtensions, f1.DeniedExtensions) {
					return errors.New("file extensions contents mismatch")
				}
				found = true
			}
		}
		if !found {
			return errors.New("file extensions contents mismatch")
		}
	}
	return nil
}

func compareEqualsUserFields(expected *dataprovider.User, actual *dataprovider.User) error {
	if expected.Username != actual.Username {
		return errors.New("Username mismatch")
	}
	if expected.HomeDir != actual.HomeDir {
		return errors.New("HomeDir mismatch")
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
	if expected.QuotaSize != actual.QuotaSize {
		return errors.New("QuotaSize mismatch")
	}
	if expected.QuotaFiles != actual.QuotaFiles {
		return errors.New("QuotaFiles mismatch")
	}
	if len(expected.Permissions) != len(actual.Permissions) {
		return errors.New("Permissions mismatch")
	}
	if expected.UploadBandwidth != actual.UploadBandwidth {
		return errors.New("UploadBandwidth mismatch")
	}
	if expected.DownloadBandwidth != actual.DownloadBandwidth {
		return errors.New("DownloadBandwidth mismatch")
	}
	if expected.Status != actual.Status {
		return errors.New("Status mismatch")
	}
	if expected.ExpirationDate != actual.ExpirationDate {
		return errors.New("ExpirationDate mismatch")
	}
	if expected.AdditionalInfo != actual.AdditionalInfo {
		return errors.New("AdditionalInfo mismatch")
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
