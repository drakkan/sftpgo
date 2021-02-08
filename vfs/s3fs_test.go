package vfs

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/fsmeta"
	"github.com/drakkan/sftpgo/vfs/mocks"
)

func TestFSMetaStat(t *testing.T) {
	EnabledRestore := fsmeta.Enabled
	t.Cleanup(func() {
		fsmeta.Enabled = EnabledRestore
	})

	MockCtl := gomock.NewController(t)
	defer MockCtl.Finish()

	StoreTime := time.Unix(time.Now().Unix(), 0)
	LastModified := StoreTime.Add(time.Hour * -24)
	Meta := make(map[string]*string)
	Meta[fsmeta.S3MetaKey] = aws.String(LastModified.Format(time.RFC3339))

	S3 := mocks.NewMockS3API(MockCtl)
	S3.EXPECT().HeadObjectWithContext(gomock.Any(), &s3.HeadObjectInput{
		Bucket: aws.String(`sftpgo`),
		Key:    aws.String(`users/test1/test.txt`),
	}).Return(&s3.HeadObjectOutput{
		ContentLength: aws.Int64(145),
		LastModified:  aws.Time(StoreTime),
		Metadata:      Meta,
	}, nil).MinTimes(2).MaxTimes(2)

	Fs := &S3Fs{
		svc: S3,
		config: &S3FsConfig{
			KeyPrefix: `users/test1/`,
			Bucket:    `sftpgo`,
		},
	}

	// FS Meta Enabled.
	fsmeta.Enabled = true
	FileInfo, err := Fs.Stat(`users/test1/test.txt`)
	assert.Nil(t, err)
	assert.False(t, FileInfo.IsDir())
	assert.True(t, LastModified.Equal(FileInfo.ModTime()),
		`Expected: %s, Actual: %s`, LastModified, FileInfo.ModTime())
	assert.Equal(t, `test.txt`, FileInfo.Name())
	assert.Equal(t, int64(145), FileInfo.Size())

	// FS Meta Enabled (Default to Stored Time)
	fsmeta.Enabled = false
	FileInfo, err = Fs.Stat(`users/test1/test.txt`)
	assert.Nil(t, err)
	assert.True(t, StoreTime.Equal(FileInfo.ModTime()),
		`Expected: %s, Actual: %s`, StoreTime, FileInfo.ModTime())
}
