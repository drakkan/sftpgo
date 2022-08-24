package vfs

import (
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"

	"github.com/drakkan/sftpgo/fsmeta"
	"github.com/drakkan/sftpgo/vfs/mocks"
)

type S3FsSuite struct {
	suite.Suite
	MockCtl *gomock.Controller
	S3      *mocks.MockS3API
	DB      *sql.DB
	SQLMock sqlmock.Sqlmock
	Fs      *S3Fs
}

func (Suite *S3FsSuite) BeforeTest(_, _ string) {
	EnabledRestore := fsmeta.Enabled
	CurrentBuckets := fsmeta.Buckets
	Suite.T().Cleanup(func() {
		fsmeta.Enabled = EnabledRestore
		fsmeta.Buckets = CurrentBuckets
	})

	Suite.MockCtl = gomock.NewController(Suite.T())
	Suite.S3 = mocks.NewMockS3API(Suite.MockCtl)
	DB, Mock, err := sqlmock.New()
	if err != nil {
		Suite.FailNowf(`sqlmock`, `failed to setup db: %s`, err)
	}
	Suite.SQLMock = Mock
	Suite.DB = DB

	fsmeta.DefaultFactory = fsmeta.NewPostgresS3Factory(Suite.DB)

	Suite.Fs = &S3Fs{
		svc: Suite.S3,
		config: &S3FsConfig{
			KeyPrefix: `users/test1/`,
			Bucket:    `sftpgo`,
		},
		ctxTimeout:     30 * time.Second,
		ctxLongTimeout: 300 * time.Second,
	}
}

func (Suite *S3FsSuite) AfterTest(_, _ string) {
	Suite.MockCtl.Finish()
	_ = Suite.DB.Close()
	if err := Suite.SQLMock.ExpectationsWereMet(); err != nil {
		Suite.FailNowf(`sqlmock`, `unfulfilled expectations: %s`, err)
	}
}

func (Suite *S3FsSuite) TestStat() {
	StoreTime := time.Unix(time.Now().Unix(), 0)
	LastModified := StoreTime.Add(time.Hour * -24)
	Meta := make(map[string]*string)
	Meta[fsmeta.S3MetaKey] = aws.String(LastModified.Format(time.RFC3339))

	Suite.S3.EXPECT().HeadObjectWithContext(gomock.Any(), &s3.HeadObjectInput{
		Bucket: aws.String(`sftpgo`),
		Key:    aws.String(`users/test1/test.txt`),
	}).Return(&s3.HeadObjectOutput{
		ContentLength: aws.Int64(145),
		LastModified:  aws.Time(StoreTime),
		Metadata:      Meta,
	}, nil).MinTimes(3).MaxTimes(3)

	// FS Meta Enabled.
	fsmeta.Enabled = true
	FileInfo, err := Suite.Fs.Stat(`users/test1/test.txt`)
	Suite.Nil(err)
	Suite.False(FileInfo.IsDir())
	Suite.True(LastModified.Equal(FileInfo.ModTime()),
		`Expected: %s, Actual: %s`, LastModified, FileInfo.ModTime())
	Suite.Equal(`test.txt`, FileInfo.Name())
	Suite.Equal(int64(145), FileInfo.Size())

	// FS Meta Disabled (Default to Stored Time)
	fsmeta.Enabled = false
	FileInfo, err = Suite.Fs.Stat(`users/test1/test.txt`)
	Suite.Nil(err)
	Suite.True(StoreTime.Equal(FileInfo.ModTime()),
		`Expected: %s, Actual: %s`, StoreTime, FileInfo.ModTime())

	// FS Meta Enabled, Wrong Bucket (Default to Stored Time)
	fsmeta.Enabled = true
	fsmeta.Buckets = []string{`bucket`}
	FileInfo, err = Suite.Fs.Stat(`users/test1/test.txt`)
	Suite.Nil(err)
	Suite.True(StoreTime.Equal(FileInfo.ModTime()),
		`Expected: %s, Actual: %s`, StoreTime, FileInfo.ModTime())
}

func (Suite *S3FsSuite) TestDirectoryListingWithFSMetaPreload() {
	// Note: this test does not assert the results due to the callback function
	// parameter to ListObjectsV2PagesWithContext, only checks fsmeta preload SQL calls
	fsmeta.Buckets = []string{`sftpgo`}
	fsmeta.Enabled = true

	Suite.SQLMock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM fsmeta_folders WHERE path=$1`)).
		WithArgs(`s3://sftpgo/files/`).
		WillReturnRows(sqlmock.NewRows([]string{`id`}).AddRow(int64(12345)))

	Suite.SQLMock.ExpectQuery(regexp.QuoteMeta(`SELECT filename, filesize, uploaded, etag, last_modified FROM fsmeta_files WHERE folder_id = $1`)).
		WithArgs(int64(12345)).
		WillReturnRows(sqlmock.NewRows([]string{`filename`, `filesize`, `uploaded`, `etag`, `last_modified`}).
			AddRow(`file.txt`, 1234, time.Now(), `etag1`, time.Now()))

	Suite.S3.EXPECT().ListObjectsV2PagesWithContext(gomock.Any(), &s3.ListObjectsV2Input{
		Bucket:    aws.String(`sftpgo`),
		Prefix:    aws.String(`files/`),
		Delimiter: aws.String(`/`),
	}, gomock.Any()).Return(nil)

	Info, err := Suite.Fs.ReadDir(`files/`)
	Suite.Nil(err)
	Suite.Empty(Info)
}

func (Suite *S3FsSuite) TestDirectoryListingDisabledFSMetaBucket() {
	// Note: this test does not assert the results due to the callback function
	// parameter to ListObjectsV2PagesWithContext, SQLMock.ExpectationsWereMet()
	// assert that no fsmeta preload queries were made
	fsmeta.Buckets = []string{`random`}
	fsmeta.Enabled = true

	Suite.S3.EXPECT().ListObjectsV2PagesWithContext(gomock.Any(), &s3.ListObjectsV2Input{
		Bucket:    aws.String(`sftpgo`),
		Prefix:    aws.String(`files2/`),
		Delimiter: aws.String(`/`),
	}, gomock.Any()).Return(nil)

	Info, err := Suite.Fs.ReadDir(`files2/`)
	Suite.Nil(err)
	Suite.Empty(Info)
}

func (Suite *S3FsSuite) TestDirectoryListSingleFile() {
	StoreTime := time.Unix(time.Now().Unix(), 0)
	LastModified := StoreTime.Add(time.Hour * -24)
	Meta := make(map[string]*string)
	Meta[fsmeta.S3MetaKey] = aws.String(LastModified.Format(time.RFC3339))

	Suite.S3.EXPECT().HeadObjectWithContext(gomock.Any(), &s3.HeadObjectInput{
		Bucket: aws.String(`sftpgo`),
		Key:    aws.String(`users/test1/test.txt`),
	}).Return(&s3.HeadObjectOutput{
		ContentLength: aws.Int64(145),
		LastModified:  aws.Time(StoreTime),
		Metadata:      Meta,
	}, nil).MinTimes(3).MaxTimes(3)

	fsmeta.Enabled = false
	fsmeta.Buckets = []string{`sftpgo`}
	Files, err := Suite.Fs.ReadDir(`users/test1/test.txt`)
	Suite.Nil(err)
	Suite.Require().Len(Files, 1)
	Suite.True(StoreTime.Equal(Files[0].ModTime()),
		`Expected: %s, Actual: %s`, StoreTime, Files[0].ModTime())
	Suite.Equal(int64(145), Files[0].Size())
	Suite.Equal(`test.txt`, Files[0].Name())

	fsmeta.Enabled = true
	fsmeta.Buckets = []string{`sftpgo`}
	Files, err = Suite.Fs.ReadDir(`users/test1/test.txt`)
	Suite.Nil(err)
	Suite.Require().Len(Files, 1)
	Suite.True(LastModified.Equal(Files[0].ModTime()),
		`Expected: %s, Actual: %s`, LastModified, Files[0].ModTime())
	Suite.Equal(int64(145), Files[0].Size())
	Suite.Equal(`test.txt`, Files[0].Name())

	fsmeta.Enabled = true
	fsmeta.Buckets = []string{`bucket1`}
	Files, err = Suite.Fs.ReadDir(`users/test1/test.txt`)
	Suite.Nil(err)
	Suite.Require().Len(Files, 1)
	Suite.True(StoreTime.Equal(Files[0].ModTime()),
		`Expected: %s, Actual: %s`, StoreTime, Files[0].ModTime())
	Suite.Equal(int64(145), Files[0].Size())
	Suite.Equal(`test.txt`, Files[0].Name())
}

func TestFSMetaSuite(t *testing.T) {
	suite.Run(t, new(S3FsSuite))
}
