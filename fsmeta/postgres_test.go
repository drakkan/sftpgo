package fsmeta

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"

	"github.com/drakkan/sftpgo/vfs/mocks"
)

type PostgresSuite struct {
	suite.Suite
	DB      *sql.DB
	SQLMock sqlmock.Sqlmock
	MockCtl *gomock.Controller
}

func (Suite *PostgresSuite) BeforeTest(_, _ string) {
	DB, Mock, err := sqlmock.New()
	if err != nil {
		Suite.FailNowf(`sqlmock`, `failed to setup db: %s`, err)
	}
	Suite.SQLMock = Mock
	Suite.DB = DB
	Suite.MockCtl = gomock.NewController(Suite.T())
}

func (Suite *PostgresSuite) AfterTest(_, _ string) {
	Suite.MockCtl.Finish()
	_ = Suite.DB.Close()
	if err := Suite.SQLMock.ExpectationsWereMet(); err != nil {
		Suite.FailNowf(`sqlmock`, `unfulfilled expectations: %s`, err)
	}
}

func (Suite *PostgresSuite) TestGetFolderID() {
	Provider := &fsMetaPostgres{
		DB:            Suite.DB,
		Bucket:        "sftpgo",
		folderIDCache: make(map[string]uint64),
	}

	Suite.mockFolderIDQuery(`s3://sftpgo/users/test1/`, 153)

	ID, err := Provider.getFolderID(context.Background(), `users/test1/`)
	Suite.Equal(uint64(153), ID)
	Suite.Nil(err)
}

func (Suite *PostgresSuite) TestCreateFolderNoConflict() {
	Provider := &fsMetaPostgres{
		DB:            Suite.DB,
		Bucket:        "sftpgo",
		folderIDCache: make(map[string]uint64),
	}

	Suite.mockCreateFolderQuery(`s3://sftpgo/users/test1/`, 187)

	ID, err := Provider.createFolder(context.Background(), `users/test1/`)
	Suite.Equal(uint64(187), ID)
	Suite.Nil(err)
}

func (Suite *PostgresSuite) TestCreateFolderConflict() {
	Provider := &fsMetaPostgres{
		DB:            Suite.DB,
		Bucket:        "sftpgo",
		folderIDCache: make(map[string]uint64),
	}

	Suite.mockCreateFolderQuery(`s3://sftpgo/users/test1/`)
	Suite.mockFolderIDQuery(`s3://sftpgo/users/test1/`, 187)

	ID, err := Provider.createFolder(context.Background(), `users/test1/`)
	Suite.Equal(uint64(187), ID)
	Suite.Nil(err)
}

func (Suite *PostgresSuite) TestPreload() {
	// Setup Mock Providers
	S3 := mocks.NewMockS3API(Suite.MockCtl)
	Factory := NewPostgresS3Factory(Suite.DB)
	Provider := Factory.New(S3, `sftpgo`)

	// Generate Sample Data
	UploadTime1 := time.Date(2020, time.February, 15, 12, 34, 56, 0, time.UTC)
	UploadTime2 := UploadTime1.Add(time.Minute * 100)
	UploadTime3 := UploadTime1.Add(time.Minute * 200)

	LastModified1 := time.Date(2020, time.March, 32, 11, 57, 43, 0, time.UTC)
	LastModified2 := LastModified1.Add(time.Minute * 100)
	LastModified3 := LastModified1.Add(time.Minute * 200)

	Key1 := Key{Path: `users/test2/test1.csv`, ETag: `etag1`, StoreTime: UploadTime1, Size: 12345}
	Key2 := Key{Path: `users/test2/test2.csv`, ETag: `etag2`, StoreTime: UploadTime2, Size: 67890}
	Key3 := Key{Path: `users/test2/test3.csv`, ETag: `etag3`, StoreTime: UploadTime3, Size: 9782}

	S3Meta2 := make(map[string]*string)
	S3Meta2[S3MetaKey] = aws.String(LastModified2.Format(time.RFC3339))

	S3Meta3 := make(map[string]*string)
	S3Meta3[strings.ToLower(S3MetaKey)] = aws.String(LastModified3.Format(time.RFC3339))

	Ctx := context.Background()

	// Setup Mocked Requests
	// First row is proper cached match
	// Second row is invalid / expired cache match - cause S3 lookup
	// Third test3.csv not returned (cache miss) - cause S3 lookup
	Rows := sqlmock.NewRows([]string{`filename`, `filesize`, `uploaded`, `etag`, `last_modified`}).
		AddRow(`test1.csv`, 12345, UploadTime1, `etag1`, LastModified1).
		AddRow(`test2.csv`, 12345, UploadTime2, `not_etag2`, LastModified2)
	Suite.mockFolderIDQuery(`s3://sftpgo/users/test2/`, 15)
	Suite.SQLMock.ExpectQuery(regexp.QuoteMeta(`SELECT filename, filesize, uploaded, etag, last_modified ` +
		`FROM fsmeta_files WHERE folder_id = $1`)).
		WithArgs(15).
		//Suite.SQLMock.ExpectQuery(regexp.QuoteMeta(`SELECT filename, filesize, uploaded, etag, last_modified `+
		//	`FROM fsmeta_files WHERE folder_id = $1 AND filename >= $2 AND filename <= $3`)).
		//	WithArgs(15, `test1.csv`, `test3.csv`).
		WillReturnRows(Rows)

	// Database Mocks for test2.csv
	Suite.SQLMock.ExpectExec(regexp.QuoteMeta(`INSERT INTO fsmeta_files `+
		`(folder_id, filename, uploaded, filesize, etag, last_modified) VALUES ($1, $2, $3, $4, $5, $6) `+
		`ON CONFLICT (folder_id, filename) DO UPDATE `+
		`SET uploaded=$3, filesize=$4, etag=$5, last_modified=$6`)).
		WithArgs(15, `test2.csv`, UploadTime2, Key2.Size, `etag2`, LastModified2).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Database Mocks for test3.csv
	Suite.SQLMock.ExpectExec(regexp.QuoteMeta(`INSERT INTO fsmeta_files `+
		`(folder_id, filename, uploaded, filesize, etag, last_modified) VALUES ($1, $2, $3, $4, $5, $6) `+
		`ON CONFLICT (folder_id, filename) DO UPDATE `+
		`SET uploaded=$3, filesize=$4, etag=$5, last_modified=$6`)).
		WithArgs(15, `test3.csv`, UploadTime3, Key3.Size, `etag3`, LastModified3).
		WillReturnResult(sqlmock.NewResult(0, 1))

	S3.EXPECT().HeadObjectWithContext(Ctx, &s3.HeadObjectInput{
		Key:    aws.String(Key2.Path),
		Bucket: aws.String(`sftpgo`),
	}).Return(&s3.HeadObjectOutput{
		Metadata: S3Meta2,
	}, nil)

	S3.EXPECT().HeadObjectWithContext(Ctx, &s3.HeadObjectInput{
		Key:    aws.String(Key3.Path),
		Bucket: aws.String(`sftpgo`),
	}).Return(&s3.HeadObjectOutput{
		Metadata: S3Meta3,
	}, nil)

	Suite.Nil(Provider.Preload(Ctx, `users/test2/`))

	// assertions
	Actual1, err1 := Provider.Get(Ctx, Key1)
	Suite.Equal(Meta{Key: Key1, LastModified: LastModified1}, Actual1)
	Suite.Nil(err1)

	Actual2, err2 := Provider.Get(Ctx, Key2)
	Suite.Equal(Meta{Key: Key2, LastModified: LastModified2}, Actual2)
	Suite.Nil(err2)

	Actual3, err3 := Provider.Get(Ctx, Key3)
	Suite.Equal(Meta{Key: Key3, LastModified: LastModified3}, Actual3)
	Suite.Nil(err3)
}

func (Suite *PostgresSuite) mockFolderIDQuery(FolderArg string, IDs ...int) {
	Rows := sqlmock.NewRows([]string{`id`})
	for _, ID := range IDs {
		Rows.AddRow(ID)
	}
	Suite.SQLMock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM fsmeta_folders WHERE path=$1`)).
		WithArgs(FolderArg).
		WillReturnRows(Rows)
}

func (Suite *PostgresSuite) mockCreateFolderQuery(FolderArg string, IDs ...int) {
	Rows := sqlmock.NewRows([]string{`id`})
	for _, ID := range IDs {
		Rows.AddRow(ID)
	}
	Suite.SQLMock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO fsmeta_folders (path) VALUES ($1) ON CONFLICT (path) DO NOTHING RETURNING id`)).
		WithArgs(FolderArg).
		WillReturnRows(Rows)
}

func TestPostgresSuite(t *testing.T) {
	suite.Run(t, new(PostgresSuite))
}
