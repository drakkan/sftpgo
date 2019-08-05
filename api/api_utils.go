package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/go-chi/render"
)

var (
	httpBaseURL = "http://127.0.0.1:8080"
)

// SetBaseURL sets the base url to use for HTTP requests, default is "http://127.0.0.1:8080"
func SetBaseURL(url string) {
	httpBaseURL = url
}

// gets an HTTP Client with a timeout
func getHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
	}
}

func buildURLRelativeToBase(paths ...string) string {
	// we need to use path.Join and not filepath.Join
	// since filepath.Join will use backslash separator on Windows
	p := path.Join(paths...)
	return fmt.Sprintf("%s/%s", strings.TrimRight(httpBaseURL, "/"), strings.TrimLeft(p, "/"))
}

// AddUser adds a new user and checks the received HTTP Status code against expectedStatusCode.
func AddUser(user dataprovider.User, expectedStatusCode int) (dataprovider.User, []byte, error) {
	var newUser dataprovider.User
	var body []byte
	userAsJSON, err := json.Marshal(user)
	if err != nil {
		return newUser, body, err
	}
	resp, err := getHTTPClient().Post(buildURLRelativeToBase(userPath), "application/json", bytes.NewBuffer(userAsJSON))
	if err != nil {
		return newUser, body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	if expectedStatusCode != http.StatusOK {
		body, _ = getResponseBody(resp)
		return newUser, body, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newUser)
	} else {
		body, _ = getResponseBody(resp)
	}
	if err == nil {
		err = checkUser(user, newUser)
	}
	return newUser, body, err
}

// UpdateUser updates an existing user and checks the received HTTP Status code against expectedStatusCode.
func UpdateUser(user dataprovider.User, expectedStatusCode int) (dataprovider.User, []byte, error) {
	var newUser dataprovider.User
	var body []byte
	userAsJSON, err := json.Marshal(user)
	if err != nil {
		return user, body, err
	}
	req, err := http.NewRequest(http.MethodPut, buildURLRelativeToBase(userPath, strconv.FormatInt(user.ID, 10)),
		bytes.NewBuffer(userAsJSON))
	if err != nil {
		return user, body, err
	}
	resp, err := getHTTPClient().Do(req)
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
		newUser, body, err = GetUserByID(user.ID, expectedStatusCode)
	}
	if err == nil {
		err = checkUser(user, newUser)
	}
	return newUser, body, err
}

// RemoveUser removes an existing user and checks the received HTTP Status code against expectedStatusCode.
func RemoveUser(user dataprovider.User, expectedStatusCode int) ([]byte, error) {
	var body []byte
	req, err := http.NewRequest(http.MethodDelete, buildURLRelativeToBase(userPath, strconv.FormatInt(user.ID, 10)), nil)
	if err != nil {
		return body, err
	}
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetUserByID gets an user by database id and checks the received HTTP Status code against expectedStatusCode.
func GetUserByID(userID int64, expectedStatusCode int) (dataprovider.User, []byte, error) {
	var user dataprovider.User
	var body []byte
	resp, err := getHTTPClient().Get(buildURLRelativeToBase(userPath, strconv.FormatInt(userID, 10)))
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

// GetUsers allows to get a list of users and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
// The results can be filtered specifying an username, the username filter is an exact match
func GetUsers(limit int64, offset int64, username string, expectedStatusCode int) ([]dataprovider.User, []byte, error) {
	var users []dataprovider.User
	var body []byte
	url, err := url.Parse(buildURLRelativeToBase(userPath))
	if err != nil {
		return users, body, err
	}
	q := url.Query()
	if limit > 0 {
		q.Add("limit", strconv.FormatInt(limit, 10))
	}
	if offset > 0 {
		q.Add("offset", strconv.FormatInt(offset, 10))
	}
	if len(username) > 0 {
		q.Add("username", username)
	}
	url.RawQuery = q.Encode()
	resp, err := getHTTPClient().Get(url.String())
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

// GetQuotaScans gets active quota scans and checks the received HTTP Status code against expectedStatusCode.
func GetQuotaScans(expectedStatusCode int) ([]sftpd.ActiveQuotaScan, []byte, error) {
	var quotaScans []sftpd.ActiveQuotaScan
	var body []byte
	resp, err := getHTTPClient().Get(buildURLRelativeToBase(quotaScanPath))
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

// StartQuotaScan start a new quota scan for the given user and checks the received HTTP Status code against expectedStatusCode.
func StartQuotaScan(user dataprovider.User, expectedStatusCode int) ([]byte, error) {
	var body []byte
	userAsJSON, err := json.Marshal(user)
	if err != nil {
		return body, err
	}
	resp, err := getHTTPClient().Post(buildURLRelativeToBase(quotaScanPath), "application/json", bytes.NewBuffer(userAsJSON))
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	body, _ = getResponseBody(resp)
	return body, checkResponse(resp.StatusCode, expectedStatusCode)
}

// GetSFTPConnections returns status and stats for active SFTP connections
func GetSFTPConnections(expectedStatusCode int) ([]sftpd.ConnectionStatus, []byte, error) {
	var connections []sftpd.ConnectionStatus
	var body []byte
	resp, err := getHTTPClient().Get(buildURLRelativeToBase(activeConnectionsPath))
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

// CloseSFTPConnection closes an active SFTP connection identified by connectionID
func CloseSFTPConnection(connectionID string, expectedStatusCode int) ([]byte, error) {
	var body []byte
	req, err := http.NewRequest(http.MethodDelete, buildURLRelativeToBase(activeConnectionsPath, connectionID), nil)
	if err != nil {
		return body, err
	}
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return body, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode)
	body, _ = getResponseBody(resp)
	return body, err
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

func checkUser(expected dataprovider.User, actual dataprovider.User) error {
	if len(actual.Password) > 0 {
		return errors.New("User password must not be visible")
	}
	if len(actual.PublicKey) > 0 {
		return errors.New("User public key must not be visible")
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
	for _, v := range expected.Permissions {
		if !utils.IsStringInSlice(v, actual.Permissions) {
			return errors.New("Permissions contents mismatch")
		}
	}
	return compareEqualsUserFields(expected, actual)
}

func compareEqualsUserFields(expected dataprovider.User, actual dataprovider.User) error {
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
	return nil
}
