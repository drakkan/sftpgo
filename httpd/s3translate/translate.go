package s3translate

import (
	"errors"
	"path"
	"strings"

	"github.com/drakkan/sftpgo/dataprovider"
)

var (
	ErrUsernameRequired = errors.New(`username is required`)
	ErrPasswordRequired = errors.New(`password is required`)
	ErrFilePathRequired = errors.New(`filepath is required`)
	ErrFilePathInvalid  = errors.New(`filepath is invalid`)
	ErrFileSystemNotS3  = errors.New(`filesystem is not s3`)
)

type Request struct {
	Username string `json:"username"`
	Password string `json:"password"`
	FilePath string `json:"filepath"`
}

type Response struct {
	Region string `json:"region"`
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

func (req *Request) Validate() error {
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	req.FilePath = strings.TrimSpace(req.FilePath)

	if req.Username == `` {
		return ErrUsernameRequired
	}
	if req.Password == `` {
		return ErrPasswordRequired
	}
	if req.FilePath == `` {
		return ErrFilePathRequired
	}
	if req.FilePath == `/` || req.FilePath == `.` {
		return ErrFilePathInvalid
	}

	return nil
}

func (req *Request) ResolvePath(fs dataprovider.Filesystem) (Response, error) {
	if fs.Provider != dataprovider.S3FilesystemProvider {
		return Response{}, ErrFileSystemNotS3
	}
	if !path.IsAbs(req.FilePath) {
		req.FilePath = path.Clean("/" + req.FilePath)
	}
	// prevent path transversal outside of users key prefix
	Key := path.Join("/", fs.S3Config.KeyPrefix, req.FilePath)
	if !strings.HasPrefix(Key, path.Clean(`/`+fs.S3Config.KeyPrefix)+`/`) {
		return Response{}, ErrFilePathInvalid
	}
	return Response{
		Region: fs.S3Config.Region,
		Bucket: fs.S3Config.Bucket,
		Key:    Key,
	}, nil
}
