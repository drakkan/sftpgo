// Copyright (C) 2019-2022  Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/httpd"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	tokenPath             = "/api/v2/token"
	activeConnectionsPath = "/api/v2/connections"
	quotasBasePath        = "/api/v2/quotas"
	quotaScanPath         = "/api/v2/quotas/users/scans"
	quotaScanVFolderPath  = "/api/v2/quotas/folders/scans"
	userPath              = "/api/v2/users"
	groupPath             = "/api/v2/groups"
	versionPath           = "/api/v2/version"
	folderPath            = "/api/v2/folders"
	serverStatusPath      = "/api/v2/status"
	dumpDataPath          = "/api/v2/dumpdata"
	loadDataPath          = "/api/v2/loaddata"
	defenderHosts         = "/api/v2/defender/hosts"
	adminPath             = "/api/v2/admins"
	adminPwdPath          = "/api/v2/admin/changepwd"
	apiKeysPath           = "/api/v2/apikeys"
	retentionBasePath     = "/api/v2/retention/users"
	retentionChecksPath   = "/api/v2/retention/users/checks"
	eventActionsPath      = "/api/v2/eventactions"
	eventRulesPath        = "/api/v2/eventrules"
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
func GetToken(username, password string) (string, map[string]any, error) {
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
	responseHolder := make(map[string]any)
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

// AddGroup adds a new group and checks the received HTTP Status code against expectedStatusCode.
func AddGroup(group dataprovider.Group, expectedStatusCode int) (dataprovider.Group, []byte, error) {
	var newGroup dataprovider.Group
	var body []byte
	asJSON, _ := json.Marshal(group)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(groupPath), bytes.NewBuffer(asJSON),
		"application/json", getDefaultToken())
	if err != nil {
		return newGroup, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusCreated {
		body, _ = getResponseBody(resp)
		return newGroup, body, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newGroup)
	} else {
		body, _ = getResponseBody(resp)
	}
	if err == nil {
		err = checkGroup(group, newGroup)
	}
	return newGroup, body, err
}

// UpdateGroup updates an existing group and checks the received HTTP Status code against expectedStatusCode
func UpdateGroup(group dataprovider.Group, expectedStatusCode int) (dataprovider.Group, []byte, error) {
	var newGroup dataprovider.Group
	var body []byte

	asJSON, _ := json.Marshal(group)
	resp, err := sendHTTPRequest(http.MethodPut, buildURLRelativeToBase(groupPath, url.PathEscape(group.Name)),
		bytes.NewBuffer(asJSON), "application/json", getDefaultToken())
	if err != nil {
		return newGroup, body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		return newGroup, body, err
	}
	if err == nil {
		newGroup, body, err = GetGroupByName(group.Name, expectedStatusCode)
	}
	if err == nil {
		err = checkGroup(group, newGroup)
	}
	return newGroup, body, err
}

// RemoveGroup removes an existing group and checks the received HTTP Status code against expectedStatusCode.
func RemoveGroup(group dataprovider.Group, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(groupPath, url.PathEscape(group.Name)),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetGroupByName gets a group by name and checks the received HTTP Status code against expectedStatusCode.
func GetGroupByName(name string, expectedStatusCode int) (dataprovider.Group, []byte, error) {
	var group dataprovider.Group
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(groupPath, url.PathEscape(name)),
		nil, "", getDefaultToken())
	if err != nil {
		return group, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &group)
	} else {
		body, _ = getResponseBody(resp)
	}
	return group, body, err
}

// GetGroups returns a list of groups and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
func GetGroups(limit, offset int64, expectedStatusCode int) ([]dataprovider.Group, []byte, error) {
	var groups []dataprovider.Group
	var body []byte
	url, err := addLimitAndOffsetQueryParams(buildURLRelativeToBase(groupPath), limit, offset)
	if err != nil {
		return groups, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return groups, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &groups)
	} else {
		body, _ = getResponseBody(resp)
	}
	return groups, body, err
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

// AddEventAction adds a new event action
func AddEventAction(action dataprovider.BaseEventAction, expectedStatusCode int) (dataprovider.BaseEventAction, []byte, error) {
	var newAction dataprovider.BaseEventAction
	var body []byte
	asJSON, _ := json.Marshal(action)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(eventActionsPath), bytes.NewBuffer(asJSON),
		"application/json", getDefaultToken())
	if err != nil {
		return newAction, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusCreated {
		body, _ = getResponseBody(resp)
		return newAction, body, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newAction)
	} else {
		body, _ = getResponseBody(resp)
	}
	if err == nil {
		err = checkEventAction(action, newAction)
	}
	return newAction, body, err
}

// UpdateEventAction updates an existing event action
func UpdateEventAction(action dataprovider.BaseEventAction, expectedStatusCode int) (dataprovider.BaseEventAction, []byte, error) {
	var newAction dataprovider.BaseEventAction
	var body []byte

	asJSON, _ := json.Marshal(action)
	resp, err := sendHTTPRequest(http.MethodPut, buildURLRelativeToBase(eventActionsPath, url.PathEscape(action.Name)),
		bytes.NewBuffer(asJSON), "application/json", getDefaultToken())
	if err != nil {
		return newAction, body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		return newAction, body, err
	}
	if err == nil {
		newAction, body, err = GetEventActionByName(action.Name, expectedStatusCode)
	}
	if err == nil {
		err = checkEventAction(action, newAction)
	}
	return newAction, body, err
}

// RemoveEventAction removes an existing action and checks the received HTTP Status code against expectedStatusCode.
func RemoveEventAction(action dataprovider.BaseEventAction, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(eventActionsPath, url.PathEscape(action.Name)),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetEventActionByName gets an event action by name and checks the received HTTP Status code against expectedStatusCode.
func GetEventActionByName(name string, expectedStatusCode int) (dataprovider.BaseEventAction, []byte, error) {
	var action dataprovider.BaseEventAction
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(eventActionsPath, url.PathEscape(name)),
		nil, "", getDefaultToken())
	if err != nil {
		return action, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &action)
	} else {
		body, _ = getResponseBody(resp)
	}
	return action, body, err
}

// GetEventActions returns a list of event actions and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
func GetEventActions(limit, offset int64, expectedStatusCode int) ([]dataprovider.BaseEventAction, []byte, error) {
	var actions []dataprovider.BaseEventAction
	var body []byte
	url, err := addLimitAndOffsetQueryParams(buildURLRelativeToBase(eventActionsPath), limit, offset)
	if err != nil {
		return actions, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return actions, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &actions)
	} else {
		body, _ = getResponseBody(resp)
	}
	return actions, body, err
}

// AddEventRule adds a new event rule
func AddEventRule(rule dataprovider.EventRule, expectedStatusCode int) (dataprovider.EventRule, []byte, error) {
	var newRule dataprovider.EventRule
	var body []byte
	asJSON, _ := json.Marshal(rule)
	resp, err := sendHTTPRequest(http.MethodPost, buildURLRelativeToBase(eventRulesPath), bytes.NewBuffer(asJSON),
		"application/json", getDefaultToken())
	if err != nil {
		return newRule, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusCreated {
		body, _ = getResponseBody(resp)
		return newRule, body, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newRule)
	} else {
		body, _ = getResponseBody(resp)
	}
	if err == nil {
		err = checkEventRule(rule, newRule)
	}
	return newRule, body, err
}

// UpdateEventRule updates an existing event rule
func UpdateEventRule(rule dataprovider.EventRule, expectedStatusCode int) (dataprovider.EventRule, []byte, error) {
	var newRule dataprovider.EventRule
	var body []byte

	asJSON, _ := json.Marshal(rule)
	resp, err := sendHTTPRequest(http.MethodPut, buildURLRelativeToBase(eventRulesPath, url.PathEscape(rule.Name)),
		bytes.NewBuffer(asJSON), "application/json", getDefaultToken())
	if err != nil {
		return newRule, body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		return newRule, body, err
	}
	if err == nil {
		newRule, body, err = GetEventRuleByName(rule.Name, expectedStatusCode)
	}
	if err == nil {
		err = checkEventRule(rule, newRule)
	}
	return newRule, body, err
}

// RemoveEventRule removes an existing rule and checks the received HTTP Status code against expectedStatusCode.
func RemoveEventRule(rule dataprovider.EventRule, expectedStatusCode int) ([]byte, error) {
	var body []byte
	resp, err := sendHTTPRequest(http.MethodDelete, buildURLRelativeToBase(eventRulesPath, url.PathEscape(rule.Name)),
		nil, "", getDefaultToken())
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetEventRuleByName gets an event rule by name and checks the received HTTP Status code against expectedStatusCode.
func GetEventRuleByName(name string, expectedStatusCode int) (dataprovider.EventRule, []byte, error) {
	var rule dataprovider.EventRule
	var body []byte
	resp, err := sendHTTPRequest(http.MethodGet, buildURLRelativeToBase(eventRulesPath, url.PathEscape(name)),
		nil, "", getDefaultToken())
	if err != nil {
		return rule, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &rule)
	} else {
		body, _ = getResponseBody(resp)
	}
	return rule, body, err
}

// GetEventRules returns a list of event rules and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
func GetEventRules(limit, offset int64, expectedStatusCode int) ([]dataprovider.EventRule, []byte, error) {
	var rules []dataprovider.EventRule
	var body []byte
	url, err := addLimitAndOffsetQueryParams(buildURLRelativeToBase(eventRulesPath), limit, offset)
	if err != nil {
		return rules, body, err
	}
	resp, err := sendHTTPRequest(http.MethodGet, url.String(), nil, "", getDefaultToken())
	if err != nil {
		return rules, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &rules)
	} else {
		body, _ = getResponseBody(resp)
	}
	return rules, body, err
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
func StartRetentionCheck(username string, retention []dataprovider.FolderRetention, expectedStatusCode int) ([]byte, error) {
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

// Dumpdata requests a backup to outputFile.
// outputFile is relative to the configured backups_path
func Dumpdata(outputFile, outputData, indent string, expectedStatusCode int) (map[string]any, []byte, error) {
	var response map[string]any
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
func Loaddata(inputFile, scanQuota, mode string, expectedStatusCode int) (map[string]any, []byte, error) {
	var response map[string]any
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
func LoaddataFromPostBody(data []byte, scanQuota, mode string, expectedStatusCode int) (map[string]any, []byte, error) {
	var response map[string]any
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

func checkEventAction(expected, actual dataprovider.BaseEventAction) error {
	if expected.ID <= 0 {
		if actual.ID <= 0 {
			return errors.New("actual action ID must be > 0")
		}
	} else {
		if actual.ID != expected.ID {
			return errors.New("action ID mismatch")
		}
	}
	if dataprovider.ConvertName(expected.Name) != actual.Name {
		return errors.New("name mismatch")
	}
	if expected.Description != actual.Description {
		return errors.New("description mismatch")
	}
	if expected.Type != actual.Type {
		return errors.New("type mismatch")
	}
	if err := compareEventActionCmdConfigFields(expected.Options.CmdConfig, actual.Options.CmdConfig); err != nil {
		return err
	}
	if err := compareEventActionEmailConfigFields(expected.Options.EmailConfig, actual.Options.EmailConfig); err != nil {
		return err
	}
	if err := compareEventActionDataRetentionFields(expected.Options.RetentionConfig, actual.Options.RetentionConfig); err != nil {
		return err
	}
	if err := compareEventActionFsConfigFields(expected.Options.FsConfig, actual.Options.FsConfig); err != nil {
		return err
	}
	return compareEventActionHTTPConfigFields(expected.Options.HTTPConfig, actual.Options.HTTPConfig)
}

func checkEventSchedules(expected, actual []dataprovider.Schedule) error {
	if len(expected) != len(actual) {
		return errors.New("schedules mismatch")
	}
	for _, ex := range expected {
		found := false
		for _, ac := range actual {
			if ac.DayOfMonth == ex.DayOfMonth && ac.DayOfWeek == ex.DayOfWeek && ac.Hours == ex.Hours && ac.Month == ex.Month {
				found = true
				break
			}
		}
		if !found {
			return errors.New("schedules content mismatch")
		}
	}
	return nil
}

func compareConditionPatternOptions(expected, actual []dataprovider.ConditionPattern) error {
	if len(expected) != len(actual) {
		return errors.New("condition pattern mismatch")
	}
	for _, ex := range expected {
		found := false
		for _, ac := range actual {
			if ac.Pattern == ex.Pattern && ac.InverseMatch == ex.InverseMatch {
				found = true
				break
			}
		}
		if !found {
			return errors.New("condition pattern content mismatch")
		}
	}
	return nil
}

func checkEventConditionOptions(expected, actual dataprovider.ConditionOptions) error {
	if err := compareConditionPatternOptions(expected.Names, actual.Names); err != nil {
		return errors.New("condition names mismatch")
	}
	if err := compareConditionPatternOptions(expected.GroupNames, actual.GroupNames); err != nil {
		return errors.New("condition group names mismatch")
	}
	if err := compareConditionPatternOptions(expected.FsPaths, actual.FsPaths); err != nil {
		return errors.New("condition fs_paths mismatch")
	}
	if len(expected.Protocols) != len(actual.Protocols) {
		return errors.New("condition protocols mismatch")
	}
	for _, v := range expected.Protocols {
		if !util.Contains(actual.Protocols, v) {
			return errors.New("condition protocols content mismatch")
		}
	}
	if len(expected.ProviderObjects) != len(actual.ProviderObjects) {
		return errors.New("condition provider objects mismatch")
	}
	for _, v := range expected.ProviderObjects {
		if !util.Contains(actual.ProviderObjects, v) {
			return errors.New("condition provider objects content mismatch")
		}
	}
	if expected.MinFileSize != actual.MinFileSize {
		return errors.New("condition min file size mismatch")
	}
	if expected.MaxFileSize != actual.MaxFileSize {
		return errors.New("condition max file size mismatch")
	}
	return nil
}

func checkEventConditions(expected, actual dataprovider.EventConditions) error {
	if len(expected.FsEvents) != len(actual.FsEvents) {
		return errors.New("fs events mismatch")
	}
	for _, v := range expected.FsEvents {
		if !util.Contains(actual.FsEvents, v) {
			return errors.New("fs events content mismatch")
		}
	}
	if len(expected.ProviderEvents) != len(actual.ProviderEvents) {
		return errors.New("provider events mismatch")
	}
	for _, v := range expected.ProviderEvents {
		if !util.Contains(actual.ProviderEvents, v) {
			return errors.New("provider events content mismatch")
		}
	}
	if err := checkEventConditionOptions(expected.Options, actual.Options); err != nil {
		return err
	}

	return checkEventSchedules(expected.Schedules, actual.Schedules)
}

func checkEventRuleActions(expected, actual []dataprovider.EventAction) error {
	if len(expected) != len(actual) {
		return errors.New("actions mismatch")
	}
	for _, ex := range expected {
		found := false
		for _, ac := range actual {
			if ex.Name == ac.Name && ex.Order == ac.Order && ex.Options.ExecuteSync == ac.Options.ExecuteSync &&
				ex.Options.IsFailureAction == ac.Options.IsFailureAction && ex.Options.StopOnFailure == ac.Options.StopOnFailure {
				found = true
				break
			}
		}
		if !found {
			return errors.New("actions contents mismatch")
		}
	}
	return nil
}

func checkEventRule(expected, actual dataprovider.EventRule) error {
	if expected.ID <= 0 {
		if actual.ID <= 0 {
			return errors.New("actual group ID must be > 0")
		}
	} else {
		if actual.ID != expected.ID {
			return errors.New("group ID mismatch")
		}
	}
	if dataprovider.ConvertName(expected.Name) != actual.Name {
		return errors.New("name mismatch")
	}
	if expected.Description != actual.Description {
		return errors.New("description mismatch")
	}
	if actual.CreatedAt == 0 {
		return errors.New("created_at unset")
	}
	if actual.UpdatedAt == 0 {
		return errors.New("updated_at unset")
	}
	if expected.Trigger != actual.Trigger {
		return errors.New("trigger mismatch")
	}
	if err := checkEventConditions(expected.Conditions, actual.Conditions); err != nil {
		return err
	}
	return checkEventRuleActions(expected.Actions, actual.Actions)
}

func checkGroup(expected, actual dataprovider.Group) error {
	if expected.ID <= 0 {
		if actual.ID <= 0 {
			return errors.New("actual group ID must be > 0")
		}
	} else {
		if actual.ID != expected.ID {
			return errors.New("group ID mismatch")
		}
	}
	if dataprovider.ConvertName(expected.Name) != actual.Name {
		return errors.New("name mismatch")
	}
	if expected.Description != actual.Description {
		return errors.New("description mismatch")
	}
	if actual.CreatedAt == 0 {
		return errors.New("created_at unset")
	}
	if actual.UpdatedAt == 0 {
		return errors.New("updated_at unset")
	}
	if err := compareEqualGroupSettingsFields(expected.UserSettings.BaseGroupUserSettings,
		actual.UserSettings.BaseGroupUserSettings); err != nil {
		return err
	}
	if err := compareVirtualFolders(expected.VirtualFolders, actual.VirtualFolders); err != nil {
		return err
	}
	if err := compareUserFilters(expected.UserSettings.Filters, actual.UserSettings.Filters); err != nil {
		return err
	}
	return compareFsConfig(&expected.UserSettings.FsConfig, &actual.UserSettings.FsConfig)
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
		if !util.Contains(actual.Permissions, p) {
			return errors.New("permissions content mismatch")
		}
	}
	if err := compareAdminFilters(expected.Filters, actual.Filters); err != nil {
		return err
	}
	return compareAdminGroups(expected, actual)
}

func compareAdminFilters(expected, actual dataprovider.AdminFilters) error {
	if expected.AllowAPIKeyAuth != actual.AllowAPIKeyAuth {
		return errors.New("allow_api_key_auth mismatch")
	}
	if len(expected.AllowList) != len(actual.AllowList) {
		return errors.New("allow list mismatch")
	}
	for _, v := range expected.AllowList {
		if !util.Contains(actual.AllowList, v) {
			return errors.New("allow list content mismatch")
		}
	}
	if expected.Preferences.HideUserPageSections != actual.Preferences.HideUserPageSections {
		return errors.New("hide user page sections mismatch")
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
	if err := compareUserPermissions(expected.Permissions, actual.Permissions); err != nil {
		return err
	}
	if err := compareUserFilters(expected.Filters.BaseUserFilters, actual.Filters.BaseUserFilters); err != nil {
		return err
	}
	if err := compareFsConfig(&expected.FsConfig, &actual.FsConfig); err != nil {
		return err
	}
	if err := compareUserGroups(expected, actual); err != nil {
		return err
	}
	if err := compareVirtualFolders(expected.VirtualFolders, actual.VirtualFolders); err != nil {
		return err
	}
	return compareEqualsUserFields(expected, actual)
}

func compareUserPermissions(expected map[string][]string, actual map[string][]string) error {
	if len(expected) != len(actual) {
		return errors.New("permissions mismatch")
	}
	for dir, perms := range expected {
		if actualPerms, ok := actual[dir]; ok {
			for _, v := range actualPerms {
				if !util.Contains(perms, v) {
					return errors.New("permissions contents mismatch")
				}
			}
		} else {
			return errors.New("permissions directories mismatch")
		}
	}
	return nil
}

func compareAdminGroups(expected *dataprovider.Admin, actual *dataprovider.Admin) error {
	if len(actual.Groups) != len(expected.Groups) {
		return errors.New("groups len mismatch")
	}
	for _, g := range actual.Groups {
		found := false
		for _, g1 := range expected.Groups {
			if g1.Name == g.Name {
				found = true
				if g1.Options.AddToUsersAs != g.Options.AddToUsersAs {
					return fmt.Errorf("add to users as field mismatch for group %s", g.Name)
				}
			}
		}
		if !found {
			return errors.New("groups mismatch")
		}
	}
	return nil
}

func compareUserGroups(expected *dataprovider.User, actual *dataprovider.User) error {
	if len(actual.Groups) != len(expected.Groups) {
		return errors.New("groups len mismatch")
	}
	for _, g := range actual.Groups {
		found := false
		for _, g1 := range expected.Groups {
			if g1.Name == g.Name {
				found = true
				if g1.Type != g.Type {
					return fmt.Errorf("type mismatch for group %s", g.Name)
				}
			}
		}
		if !found {
			return errors.New("groups mismatch")
		}
	}
	return nil
}

func compareVirtualFolders(expected []vfs.VirtualFolder, actual []vfs.VirtualFolder) error {
	if len(actual) != len(expected) {
		return errors.New("virtual folders len mismatch")
	}
	for _, v := range actual {
		found := false
		for _, v1 := range expected {
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
	if err := compareSFTPFsConfig(expected, actual); err != nil {
		return err
	}
	return compareHTTPFsConfig(expected, actual)
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

func compareHTTPFsConfig(expected *vfs.Filesystem, actual *vfs.Filesystem) error {
	if expected.HTTPConfig.Endpoint != actual.HTTPConfig.Endpoint {
		return errors.New("HTTPFs endpoint mismatch")
	}
	if expected.HTTPConfig.Username != actual.HTTPConfig.Username {
		return errors.New("HTTPFs username mismatch")
	}
	if expected.HTTPConfig.SkipTLSVerify != actual.HTTPConfig.SkipTLSVerify {
		return errors.New("HTTPFs skip_tls_verify mismatch")
	}
	if expected.SFTPConfig.EqualityCheckMode != actual.SFTPConfig.EqualityCheckMode {
		return errors.New("HTTPFs equality_check_mode mismatch")
	}
	if err := checkEncryptedSecret(expected.HTTPConfig.Password, actual.HTTPConfig.Password); err != nil {
		return fmt.Errorf("HTTPFs password mismatch: %v", err)
	}
	if err := checkEncryptedSecret(expected.HTTPConfig.APIKey, actual.HTTPConfig.APIKey); err != nil {
		return fmt.Errorf("HTTPFs API key mismatch: %v", err)
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
	if expected.SFTPConfig.EqualityCheckMode != actual.SFTPConfig.EqualityCheckMode {
		return errors.New("SFTPFs equality_check_mode mismatch")
	}
	if err := checkEncryptedSecret(expected.SFTPConfig.Password, actual.SFTPConfig.Password); err != nil {
		return fmt.Errorf("SFTPFs password mismatch: %v", err)
	}
	if err := checkEncryptedSecret(expected.SFTPConfig.PrivateKey, actual.SFTPConfig.PrivateKey); err != nil {
		return fmt.Errorf("SFTPFs private key mismatch: %v", err)
	}
	if err := checkEncryptedSecret(expected.SFTPConfig.KeyPassphrase, actual.SFTPConfig.KeyPassphrase); err != nil {
		return fmt.Errorf("SFTPFs private key passphrase mismatch: %v", err)
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
		if !util.Contains(expected.SFTPConfig.Fingerprints, value) {
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

func compareUserFilterSubStructs(expected sdk.BaseUserFilters, actual sdk.BaseUserFilters) error {
	for _, IPMask := range expected.AllowedIP {
		if !util.Contains(actual.AllowedIP, IPMask) {
			return errors.New("allowed IP contents mismatch")
		}
	}
	for _, IPMask := range expected.DeniedIP {
		if !util.Contains(actual.DeniedIP, IPMask) {
			return errors.New("denied IP contents mismatch")
		}
	}
	for _, method := range expected.DeniedLoginMethods {
		if !util.Contains(actual.DeniedLoginMethods, method) {
			return errors.New("denied login methods contents mismatch")
		}
	}
	for _, protocol := range expected.DeniedProtocols {
		if !util.Contains(actual.DeniedProtocols, protocol) {
			return errors.New("denied protocols contents mismatch")
		}
	}
	for _, options := range expected.WebClient {
		if !util.Contains(actual.WebClient, options) {
			return errors.New("web client options contents mismatch")
		}
	}
	return compareUserFiltersEqualFields(expected, actual)
}

func compareUserFiltersEqualFields(expected sdk.BaseUserFilters, actual sdk.BaseUserFilters) error {
	if expected.Hooks.ExternalAuthDisabled != actual.Hooks.ExternalAuthDisabled {
		return errors.New("external_auth_disabled hook mismatch")
	}
	if expected.Hooks.PreLoginDisabled != actual.Hooks.PreLoginDisabled {
		return errors.New("pre_login_disabled hook mismatch")
	}
	if expected.Hooks.CheckPasswordDisabled != actual.Hooks.CheckPasswordDisabled {
		return errors.New("check_password_disabled hook mismatch")
	}
	if expected.DisableFsChecks != actual.DisableFsChecks {
		return errors.New("disable_fs_checks mismatch")
	}
	if expected.StartDirectory != actual.StartDirectory {
		return errors.New("start_directory mismatch")
	}
	return nil
}

func compareBaseUserFilters(expected sdk.BaseUserFilters, actual sdk.BaseUserFilters) error {
	if len(expected.AllowedIP) != len(actual.AllowedIP) {
		return errors.New("allowed IP mismatch")
	}
	if len(expected.DeniedIP) != len(actual.DeniedIP) {
		return errors.New("denied IP mismatch")
	}
	if len(expected.DeniedLoginMethods) != len(actual.DeniedLoginMethods) {
		return errors.New("denied login methods mismatch")
	}
	if len(expected.DeniedProtocols) != len(actual.DeniedProtocols) {
		return errors.New("denied protocols mismatch")
	}
	if expected.MaxUploadFileSize != actual.MaxUploadFileSize {
		return errors.New("max upload file size mismatch")
	}
	if expected.TLSUsername != actual.TLSUsername {
		return errors.New("TLSUsername mismatch")
	}
	if len(expected.WebClient) != len(actual.WebClient) {
		return errors.New("WebClient filter mismatch")
	}
	if expected.AllowAPIKeyAuth != actual.AllowAPIKeyAuth {
		return errors.New("allow_api_key_auth mismatch")
	}
	if expected.ExternalAuthCacheTime != actual.ExternalAuthCacheTime {
		return errors.New("external_auth_cache_time mismatch")
	}
	if expected.FTPSecurity != actual.FTPSecurity {
		return errors.New("ftp_security mismatch")
	}
	if expected.IsAnonymous != actual.IsAnonymous {
		return errors.New("is_anonymous mismatch")
	}
	if expected.DefaultSharesExpiration != actual.DefaultSharesExpiration {
		return errors.New("default_shares_expiration mismatch")
	}
	return nil
}

func compareUserFilters(expected sdk.BaseUserFilters, actual sdk.BaseUserFilters) error {
	if err := compareBaseUserFilters(expected, actual); err != nil {
		return err
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
		if !util.Contains(actual, strings.ToLower(e)) {
			return false
		}
	}
	return true
}

func compareUserDataTransferLimitFilters(expected sdk.BaseUserFilters, actual sdk.BaseUserFilters) error {
	if len(expected.DataTransferLimits) != len(actual.DataTransferLimits) {
		return errors.New("data transfer limits filters mismatch")
	}
	for idx, l := range expected.DataTransferLimits {
		if actual.DataTransferLimits[idx].UploadDataTransfer != l.UploadDataTransfer {
			return errors.New("data transfer limit upload_data_transfer mismatch")
		}
		if actual.DataTransferLimits[idx].DownloadDataTransfer != l.DownloadDataTransfer {
			return errors.New("data transfer limit download_data_transfer mismatch")
		}
		if actual.DataTransferLimits[idx].TotalDataTransfer != l.TotalDataTransfer {
			return errors.New("data transfer limit total_data_transfer mismatch")
		}
		for _, source := range actual.DataTransferLimits[idx].Sources {
			if !util.Contains(l.Sources, source) {
				return errors.New("data transfer limit source mismatch")
			}
		}
	}

	return nil
}

func compareUserBandwidthLimitFilters(expected sdk.BaseUserFilters, actual sdk.BaseUserFilters) error {
	if len(expected.BandwidthLimits) != len(actual.BandwidthLimits) {
		return errors.New("bandwidth limits filters mismatch")
	}

	for idx, l := range expected.BandwidthLimits {
		if actual.BandwidthLimits[idx].UploadBandwidth != l.UploadBandwidth {
			return errors.New("bandwidth filters upload_bandwidth mismatch")
		}
		if actual.BandwidthLimits[idx].DownloadBandwidth != l.DownloadBandwidth {
			return errors.New("bandwidth filters download_bandwidth mismatch")
		}
		if len(actual.BandwidthLimits[idx].Sources) != len(l.Sources) {
			return errors.New("bandwidth filters sources mismatch")
		}
		for _, source := range actual.BandwidthLimits[idx].Sources {
			if !util.Contains(l.Sources, source) {
				return errors.New("bandwidth filters source mismatch")
			}
		}
	}

	return nil
}

func compareUserFilePatternsFilters(expected sdk.BaseUserFilters, actual sdk.BaseUserFilters) error {
	if len(expected.FilePatterns) != len(actual.FilePatterns) {
		return errors.New("file patterns mismatch")
	}
	for _, f := range expected.FilePatterns {
		found := false
		for _, f1 := range actual.FilePatterns {
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

func compareKeyValues(expected, actual []dataprovider.KeyValue) error {
	if len(expected) != len(actual) {
		return errors.New("kay values mismatch")
	}
	for _, ex := range expected {
		found := false
		for _, ac := range actual {
			if ac.Key == ex.Key && ac.Value == ex.Value {
				found = true
				break
			}
		}
		if !found {
			return errors.New("kay values mismatch")
		}
	}
	return nil
}

func compareHTTPparts(expected, actual []dataprovider.HTTPPart) error {
	for _, p1 := range expected {
		found := false
		for _, p2 := range actual {
			if p1.Name == p2.Name {
				found = true
				if err := compareKeyValues(p1.Headers, p2.Headers); err != nil {
					return fmt.Errorf("http headers mismatch for part %q", p1.Name)
				}
				if p1.Body != p2.Body || p1.Filepath != p2.Filepath {
					return fmt.Errorf("http part %q mismatch", p1.Name)
				}
			}
		}
		if !found {
			return fmt.Errorf("expected http part %q not found", p1.Name)
		}
	}
	return nil
}

func compareEventActionHTTPConfigFields(expected, actual dataprovider.EventActionHTTPConfig) error {
	if expected.Endpoint != actual.Endpoint {
		return errors.New("http endpoint mismatch")
	}
	if expected.Username != actual.Username {
		return errors.New("http username mismatch")
	}
	if err := checkEncryptedSecret(expected.Password, actual.Password); err != nil {
		return err
	}
	if err := compareKeyValues(expected.Headers, actual.Headers); err != nil {
		return errors.New("http headers mismatch")
	}
	if expected.Timeout != actual.Timeout {
		return errors.New("http timeout mismatch")
	}
	if expected.SkipTLSVerify != actual.SkipTLSVerify {
		return errors.New("http skip TLS verify mismatch")
	}
	if expected.Method != actual.Method {
		return errors.New("http method mismatch")
	}
	if err := compareKeyValues(expected.QueryParameters, actual.QueryParameters); err != nil {
		return errors.New("http query parameters mismatch")
	}
	if expected.Body != actual.Body {
		return errors.New("http body mismatch")
	}
	if len(expected.Parts) != len(actual.Parts) {
		return errors.New("http parts mismatch")
	}
	return compareHTTPparts(expected.Parts, actual.Parts)
}

func compareEventActionEmailConfigFields(expected, actual dataprovider.EventActionEmailConfig) error {
	if len(expected.Recipients) != len(actual.Recipients) {
		return errors.New("email recipients mismatch")
	}
	for _, v := range expected.Recipients {
		if !util.Contains(actual.Recipients, v) {
			return errors.New("email recipients content mismatch")
		}
	}
	if expected.Subject != actual.Subject {
		return errors.New("email subject mismatch")
	}
	if expected.Body != actual.Body {
		return errors.New("email body mismatch")
	}
	if len(expected.Attachments) != len(actual.Attachments) {
		return errors.New("email attachments mismatch")
	}
	for _, v := range expected.Attachments {
		if !util.Contains(actual.Attachments, v) {
			return errors.New("email attachments content mismatch")
		}
	}
	return nil
}

func compareEventActionFsConfigFields(expected, actual dataprovider.EventActionFilesystemConfig) error {
	if expected.Type != actual.Type {
		return errors.New("fs type mismatch")
	}
	if err := compareKeyValues(expected.Renames, actual.Renames); err != nil {
		return errors.New("fs renames mismatch")
	}
	if len(expected.Deletes) != len(actual.Deletes) {
		return errors.New("fs deletes mismatch")
	}
	for _, v := range expected.Deletes {
		if !util.Contains(actual.Deletes, v) {
			return errors.New("fs deletes content mismatch")
		}
	}
	if len(expected.MkDirs) != len(actual.MkDirs) {
		return errors.New("fs mkdirs mismatch")
	}
	for _, v := range expected.MkDirs {
		if !util.Contains(actual.MkDirs, v) {
			return errors.New("fs mkdir content mismatch")
		}
	}
	if len(expected.Exist) != len(actual.Exist) {
		return errors.New("fs exist mismatch")
	}
	for _, v := range expected.Exist {
		if !util.Contains(actual.Exist, v) {
			return errors.New("fs exist content mismatch")
		}
	}
	return nil
}

func compareEventActionCmdConfigFields(expected, actual dataprovider.EventActionCommandConfig) error {
	if expected.Cmd != actual.Cmd {
		return errors.New("command mismatch")
	}
	if expected.Timeout != actual.Timeout {
		return errors.New("cmd timeout mismatch")
	}
	if len(expected.Args) != len(actual.Args) {
		return errors.New("cmd args mismatch")
	}
	for _, v := range expected.Args {
		if !util.Contains(actual.Args, v) {
			return errors.New("cmd args content mismatch")
		}
	}
	if err := compareKeyValues(expected.EnvVars, actual.EnvVars); err != nil {
		return errors.New("cmd env vars mismatch")
	}
	return nil
}

func compareEventActionDataRetentionFields(expected, actual dataprovider.EventActionDataRetentionConfig) error {
	if len(expected.Folders) != len(actual.Folders) {
		return errors.New("retention folders mismatch")
	}
	for _, f1 := range expected.Folders {
		found := false
		for _, f2 := range actual.Folders {
			if f1.Path == f2.Path {
				found = true
				if f1.Retention != f2.Retention {
					return fmt.Errorf("retention mismatch for folder %s", f1.Path)
				}
				if f1.DeleteEmptyDirs != f2.DeleteEmptyDirs {
					return fmt.Errorf("delete_empty_dirs mismatch for folder %s", f1.Path)
				}
				if f1.IgnoreUserPermissions != f2.IgnoreUserPermissions {
					return fmt.Errorf("ignore_user_permissions mismatch for folder %s", f1.Path)
				}
				break
			}
		}
		if !found {
			return errors.New("retention folders mismatch")
		}
	}
	return nil
}

func compareEqualGroupSettingsFields(expected sdk.BaseGroupUserSettings, actual sdk.BaseGroupUserSettings) error {
	if expected.HomeDir != actual.HomeDir {
		return errors.New("home dir mismatch")
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
	if expected.UploadBandwidth != actual.UploadBandwidth {
		return errors.New("UploadBandwidth mismatch")
	}
	if expected.DownloadBandwidth != actual.DownloadBandwidth {
		return errors.New("DownloadBandwidth mismatch")
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
	return compareUserPermissions(expected.Permissions, actual.Permissions)
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
