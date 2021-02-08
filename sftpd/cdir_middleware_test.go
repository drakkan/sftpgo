package sftpd

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/suite"

	"github.com/drakkan/sftpgo/sftpd/mocks"
	"github.com/drakkan/sftpgo/vfs"
)

type CDirMiddlewareSuite struct {
	suite.Suite
	MockCtl *gomock.Controller
}

func (Suite *CDirMiddlewareSuite) BeforeTest(_, _ string) {
	Suite.MockCtl = gomock.NewController(Suite.T())
}

func (Suite *CDirMiddlewareSuite) AfterTest(_, _ string) {
	Suite.MockCtl.Finish()
}

// verify unmodified pass through calls.
func (Suite *CDirMiddlewareSuite) TestPassthru() {
	Next := mocks.NewMockMiddleware(Suite.MockCtl)

	Middleware := NewCurrentDirMiddleware(Next)

	Req := &sftp.Request{Filepath: "/files/data.csv"}
	Next.EXPECT().Fileread(Req).Return(nil, nil)
	Next.EXPECT().Filecmd(Req).Return(nil)
	Next.EXPECT().Filewrite(Req).Return(nil, nil)
	Next.EXPECT().Lstat(Req).Return(nil, nil)
	Next.EXPECT().OpenFile(Req).Return(nil, nil)

	ReaderAt, err := Middleware.Fileread(Req)
	Suite.Nil(ReaderAt)
	Suite.Nil(err)

	WriterAt, err := Middleware.Filewrite(Req)
	Suite.Nil(WriterAt)
	Suite.Nil(err)

	ListerAt, err := Middleware.Lstat(Req)
	Suite.Nil(ListerAt)
	Suite.Nil(err)

	WriterReaderAt, err := Middleware.OpenFile(Req)
	Suite.Nil(WriterReaderAt)
	Suite.Nil(err)

	Suite.Nil(Middleware.Filecmd(Req))
}

func (Suite *CDirMiddlewareSuite) TestFilelist() {
	Next := mocks.NewMockMiddleware(Suite.MockCtl)

	Now := time.Now()
	listWithDot := listerAt{
		vfs.NewFileInfo(`.`, true, 0, Now, false),
		vfs.NewFileInfo(`files`, true, 0, Now, false),
	}
	listWithoutDot := listWithDot[1:]

	Req := &sftp.Request{Method: methodList, Filepath: "/files"}

	// Add current directory.
	Next.EXPECT().Filelist(Req).Return(listWithoutDot, nil)
	Middleware := NewCurrentDirMiddleware(Next)
	ListerAt, err := Middleware.Filelist(Req)
	Suite.Equal(listWithDot, ListerAt)
	Suite.Nil(err)

	// Current directory already listed.
	Next.EXPECT().Filelist(Req).Return(listWithDot, nil)
	ListerAt, err = Middleware.Filelist(Req)
	Suite.Equal(listWithDot, ListerAt)
	Suite.Nil(err)

	Next.EXPECT().Filelist(Req).Return(nil, sftp.ErrSSHFxPermissionDenied)
	ListerAt, err = Middleware.Filelist(Req)
	Suite.Nil(ListerAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)
}

func TestCDirMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(CDirMiddlewareSuite))
}
