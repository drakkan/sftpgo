package s3translate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/vfs"
)

func TestRequestValidation(t *testing.T) {
	Req := Request{}
	assert.Equal(t, ErrUsernameRequired, Req.Validate())
	Req.Username = `user1`
	assert.Equal(t, ErrPasswordRequired, Req.Validate())
	Req.Password = `pass1`
	assert.Equal(t, ErrFilePathRequired, Req.Validate())
	Req.FilePath = `/`
	assert.Equal(t, ErrFilePathInvalid, Req.Validate())
	Req.FilePath = `test.txt`
	assert.Nil(t, Req.Validate())
}

func TestResolvePathNotS3(t *testing.T) {
	Req := Request{}
	Resp, err := Req.ResolvePath(dataprovider.Filesystem{})
	assert.Equal(t, Response{}, Resp)
	assert.Equal(t, ErrFileSystemNotS3, err)
}

func TestResolvePathTransversal(t *testing.T) {
	Req := Request{FilePath: `/../user/test.csv`}
	Resp, err := Req.ResolvePath(dataprovider.Filesystem{
		Provider: dataprovider.S3FilesystemProvider,
		S3Config: vfs.S3FsConfig{
			KeyPrefix: `users/user1/`,
		},
	})
	assert.Equal(t, Response{}, Resp)
	assert.Equal(t, ErrFilePathInvalid, err)
}

func TestResolvePath(t *testing.T) {
	Req := Request{FilePath: `test.csv`}
	Resp, err := Req.ResolvePath(dataprovider.Filesystem{
		Provider: dataprovider.S3FilesystemProvider,
		S3Config: vfs.S3FsConfig{
			Region:    `us-east-1`,
			Bucket:    `bucket1`,
			KeyPrefix: `users/user1/`,
		},
	})
	assert.Equal(t, Response{
		Region: `us-east-1`,
		Bucket: `bucket1`,
		Key:    `/users/user1/test.csv`,
	}, Resp)
	assert.Nil(t, err)
}
