package httpd_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd/s3translate"
	"github.com/drakkan/sftpgo/httpdtest"
	"github.com/drakkan/sftpgo/vfs"
)

func TestS3Translate(t *testing.T) {
	basicUser := getTestUser()
	basicUser.FsConfig.Provider = dataprovider.S3FilesystemProvider
	basicUser.FsConfig.S3Config = vfs.S3FsConfig{
		Region:    `local`,
		Bucket:    `bucket1`,
		KeyPrefix: `users/test1`,
	}

	user, _, err := httpdtest.AddUser(basicUser, http.StatusCreated)
	assert.NoError(t, err)

	// successful response
	translated, err := httpdtest.UsersS3Translate(s3translate.Request{
		Username: defaultUsername,
		Password: defaultPassword,
		FilePath: `test.txt`,
	}, http.StatusOK)

	assert.NoError(t, err)
	assert.Equal(t, s3translate.Response{
		Region: `local`,
		Bucket: `bucket1`,
		Key:    `/users/test1/test.txt`,
	}, translated)

	// validation exception
	_, err = httpdtest.UsersS3Translate(s3translate.Request{
		Username: defaultUsername,
		Password: defaultPassword,
	}, http.StatusBadRequest)

	assert.Equal(t, httpdtest.APIError{Err: `filepath is required`}, err)

	// user not found
	_, err = httpdtest.UsersS3Translate(s3translate.Request{
		Username: defaultUsername + `1`,
		Password: defaultPassword,
		FilePath: `test.txt`,
	}, http.StatusNotFound)

	assert.Error(t, err)

	// invalid credentials
	_, err = httpdtest.UsersS3Translate(s3translate.Request{
		Username: defaultUsername,
		Password: defaultPassword + `1`,
		FilePath: `test.txt`,
	}, http.StatusForbidden)

	assert.Equal(t, httpdtest.APIError{
		Message: `Access Denied`,
		Err:     `invalid credentials`,
	}, err)

	// invalid transversal error
	_, err = httpdtest.UsersS3Translate(s3translate.Request{
		Username: defaultUsername,
		Password: defaultPassword,
		FilePath: `/../user/test.txt`,
	}, http.StatusBadRequest)

	assert.Equal(t, httpdtest.APIError{
		Err: `filepath is invalid`,
	}, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestTranslateS3InvalidJsonMock(t *testing.T) {
	token, err := getJWTAPITokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, "/api/v2/users-s3/translate-path", bytes.NewBuffer([]byte("invalid json")))
	setBearerForReq(req, token)
	rr := executeRequest(req)
	checkResponseCode(t, http.StatusBadRequest, rr)
}
