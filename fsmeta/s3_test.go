package fsmeta

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"

	"github.com/drakkan/sftpgo/vfs/mocks"
)

type S3Suite struct {
	suite.Suite
	MockCtl *gomock.Controller
}

func (Suite *S3Suite) BeforeTest(_, _ string) {
	Suite.MockCtl = gomock.NewController(Suite.T())
}

func (Suite *S3Suite) AfterTest(_, _ string) {
	Suite.MockCtl.Finish()
}

func (Suite *S3Suite) TestNilMetadata() {
	Ctx := context.Background()
	S3Mock := mocks.NewMockS3API(Suite.MockCtl)
	S3Mock.EXPECT().HeadObjectWithContext(Ctx, &s3.HeadObjectInput{
		Bucket: aws.String(`sftpgo`),
		Key:    aws.String(`users/test1/test.csv`),
	}).Return(&s3.HeadObjectOutput{}, nil)

	StoreTime := time.Date(2020, time.February, 23, 13, 45, 21, 0, time.UTC)

	S3Provider := NewS3Provider(S3Mock, "sftpgo")

	Key := Key{
		Path:      `users/test1/test.csv`,
		ETag:      "9b99c17f7943a02a250fc6ca7d10efcd",
		StoreTime: StoreTime,
		Size:      100,
	}
	Actual, err := S3Provider.Get(Ctx, Key)
	Suite.Nil(err)
	Suite.Equal(Meta{
		Key:          Key,
		LastModified: Key.StoreTime,
	}, Actual)
}

func (Suite *S3Suite) TestKeyNotFound() {
	Ctx := context.Background()

	S3Mock := mocks.NewMockS3API(Suite.MockCtl)
	S3Mock.EXPECT().HeadObjectWithContext(Ctx, &s3.HeadObjectInput{
		Bucket: aws.String(`sftpgo`),
		Key:    aws.String(`users/test1/test.csv`),
	}).Return(nil, awserr.New(s3.ErrCodeNoSuchKey, `NoSuchKey`, nil))

	S3Provider := NewS3Provider(S3Mock, "sftpgo")
	StoreTime := time.Date(2020, time.February, 23, 13, 45, 21, 0, time.UTC)

	Key := Key{
		Path:      `users/test1/test.csv`,
		ETag:      "9b99c17f7943a02a250fc6ca7d10efcd",
		StoreTime: StoreTime,
		Size:      100,
	}
	Actual, err := S3Provider.Get(Ctx, Key)
	Suite.Nil(err)
	Suite.Equal(Meta{
		Key:          Key,
		LastModified: Key.StoreTime,
	}, Actual)
}

func TestS3Suite(t *testing.T) {
	suite.Run(t, new(S3Suite))
}
