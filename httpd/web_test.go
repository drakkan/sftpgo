package httpd

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/vfs"
)

func TestGetS3Config(t *testing.T) {
	fs := vfs.S3FsConfig{
		Bucket:              "bucket",
		KeyPrefix:           "key1/",
		Region:              "us-east-1",
		Endpoint:            "http://127.0.0.1:9000",
		UploadPartSize:      1,
		UploadConcurrency:   2,
		UploadPartMaxTime:   3,
		DownloadPartSize:    4,
		DownloadConcurrency: 5,
		DownloadPartMaxTime: 6,
	}

	r := &http.Request{Form: make(url.Values)}
	r.Form.Set(`s3_bucket`, fs.Bucket)
	r.Form.Set(`s3_region`, fs.Region)
	r.Form.Set(`s3_endpoint`, fs.Endpoint)
	r.Form.Set(`s3_key_prefix`, fs.KeyPrefix)
	r.Form.Set(`s3_upload_part_size`, strconv.FormatInt(fs.UploadPartSize, 10))
	r.Form.Set(`s3_upload_concurrency`, strconv.Itoa(fs.UploadConcurrency))
	r.Form.Set(`s3_upload_part_max_time`, strconv.Itoa(fs.UploadPartMaxTime))
	r.Form.Set(`s3_download_part_size`, strconv.FormatInt(fs.DownloadPartSize, 10))
	r.Form.Set(`s3_download_concurrency`, strconv.Itoa(fs.DownloadConcurrency))
	r.Form.Set(`s3_download_part_max_time`, strconv.Itoa(fs.DownloadPartMaxTime))
	r.Form.Set(`s3_timeout`, strconv.Itoa(fs.Timeout))

	parsed, err := getS3Config(r)
	assert.Nil(t, err)
	assert.Equal(t, fs.Bucket, parsed.Bucket)
	assert.Equal(t, fs.Region, parsed.Region)
	assert.Equal(t, fs.Endpoint, parsed.Endpoint)
	assert.Equal(t, fs.KeyPrefix, parsed.KeyPrefix)
	assert.Equal(t, fs.UploadPartSize, parsed.UploadPartSize)
	assert.Equal(t, fs.UploadConcurrency, parsed.UploadConcurrency)
	assert.Equal(t, fs.UploadPartMaxTime, parsed.UploadPartMaxTime)
	assert.Equal(t, fs.DownloadPartSize, parsed.DownloadPartSize)
	assert.Equal(t, fs.DownloadConcurrency, parsed.DownloadConcurrency)
	assert.Equal(t, fs.DownloadPartMaxTime, parsed.DownloadPartMaxTime)

	// test errors in reverse parse order
	r.Form.Set(`s3_download_part_max_time`, `a`)
	_, err = getS3Config(r)
	assert.EqualError(t, err, `strconv.Atoi: parsing "a": invalid syntax`)

	r.Form.Set(`s3_download_concurrency`, `b`)
	_, err = getS3Config(r)
	assert.EqualError(t, err, `strconv.Atoi: parsing "b": invalid syntax`)

	r.Form.Set(`s3_download_part_size`, `c`)
	_, err = getS3Config(r)
	assert.EqualError(t, err, `strconv.ParseInt: parsing "c": invalid syntax`)

	r.Form.Set(`s3_upload_part_max_time`, `d`)
	_, err = getS3Config(r)
	assert.EqualError(t, err, `strconv.Atoi: parsing "d": invalid syntax`)

	r.Form.Set(`s3_upload_concurrency`, `e`)
	_, err = getS3Config(r)
	assert.EqualError(t, err, `strconv.Atoi: parsing "e": invalid syntax`)

	r.Form.Set(`s3_upload_part_size`, `f`)
	_, err = getS3Config(r)
	assert.EqualError(t, err, `strconv.ParseInt: parsing "f": invalid syntax`)
}
