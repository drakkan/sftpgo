package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/go-chi/render"
)

var (
	defaultPerms = []string{dataprovider.PermAny}
	httpBaseURL  = "http://127.0.0.1:8080"
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

// AddUser adds a new user and checks the received HTTP Status code against expectedStatusCode.
func AddUser(user dataprovider.User, expectedStatusCode int) (dataprovider.User, error) {
	var newUser dataprovider.User
	userAsJSON, err := json.Marshal(user)
	if err != nil {
		return newUser, err
	}
	resp, err := getHTTPClient().Post(httpBaseURL+userPath, "application/json", bytes.NewBuffer(userAsJSON))
	if err != nil {
		return newUser, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode, resp)
	if expectedStatusCode != http.StatusOK {
		return newUser, err
	}
	if err == nil {
		err = render.DecodeJSON(resp.Body, &newUser)
	}
	if err == nil {
		err = checkUser(user, newUser)
	}
	return newUser, err
}

// UpdateUser updates an existing user and checks the received HTTP Status code against expectedStatusCode.
func UpdateUser(user dataprovider.User, expectedStatusCode int) (dataprovider.User, error) {
	var newUser dataprovider.User
	userAsJSON, err := json.Marshal(user)
	if err != nil {
		return user, err
	}
	req, err := http.NewRequest(http.MethodPut, httpBaseURL+userPath+"/"+strconv.FormatInt(user.ID, 10), bytes.NewBuffer(userAsJSON))
	if err != nil {
		return user, err
	}
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode, resp)
	if expectedStatusCode != http.StatusOK {
		return newUser, err
	}
	if err == nil {
		newUser, err = GetUserByID(user.ID, expectedStatusCode)
	}
	if err == nil {
		err = checkUser(user, newUser)
	}
	return newUser, err
}

// RemoveUser removes an existing user and checks the received HTTP Status code against expectedStatusCode.
func RemoveUser(user dataprovider.User, expectedStatusCode int) error {
	req, err := http.NewRequest(http.MethodDelete, httpBaseURL+userPath+"/"+strconv.FormatInt(user.ID, 10), nil)
	if err != nil {
		return err
	}
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResponse(resp.StatusCode, expectedStatusCode, resp)
}

// GetUserByID gets an user by database id and checks the received HTTP Status code against expectedStatusCode.
func GetUserByID(userID int64, expectedStatusCode int) (dataprovider.User, error) {
	var user dataprovider.User
	resp, err := getHTTPClient().Get(httpBaseURL + userPath + "/" + strconv.FormatInt(userID, 10))
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode, resp)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &user)
	}
	return user, err
}

// GetUsers allows to get a list of users and checks the received HTTP Status code against expectedStatusCode.
// The number of results can be limited specifying a limit.
// Some results can be skipped specifying an offset.
// The results can be filtered specifying an username, the username filter is an exact match
func GetUsers(limit int64, offset int64, username string, expectedStatusCode int) ([]dataprovider.User, error) {
	var users []dataprovider.User
	url, err := url.Parse(httpBaseURL + userPath)
	if err != nil {
		return users, err
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
		return users, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode, resp)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &users)
	}
	return users, err
}

// GetQuotaScans gets active quota scans and checks the received HTTP Status code against expectedStatusCode.
func GetQuotaScans(expectedStatusCode int) ([]sftpd.ActiveQuotaScan, error) {
	var quotaScans []sftpd.ActiveQuotaScan
	resp, err := getHTTPClient().Get(httpBaseURL + quotaScanPath)
	if err != nil {
		return quotaScans, err
	}
	defer resp.Body.Close()
	err = checkResponse(resp.StatusCode, expectedStatusCode, resp)
	if err == nil && expectedStatusCode == http.StatusOK {
		err = render.DecodeJSON(resp.Body, &quotaScans)
	}
	return quotaScans, err
}

// StartQuotaScan start a new quota scan for the given user and checks the received HTTP Status code against expectedStatusCode.
func StartQuotaScan(user dataprovider.User, expectedStatusCode int) error {
	userAsJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	resp, err := getHTTPClient().Post(httpBaseURL+quotaScanPath, "application/json", bytes.NewBuffer(userAsJSON))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkResponse(resp.StatusCode, expectedStatusCode, resp)
}

func checkResponse(actual int, expected int, resp *http.Response) error {
	if expected != actual {
		return fmt.Errorf("wrong status code: got %v want %v", actual, expected)
	}
	if expected != http.StatusOK && resp != nil {
		b, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			fmt.Printf("request: %v, response body: %v", resp.Request.URL, string(b))
		}
	}
	return nil
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
