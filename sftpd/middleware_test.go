package sftpd

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/suite"

	"github.com/drakkan/sftpgo/v2/sftpd/mocks"
)

type PrefixMiddlewareSuite struct {
	suite.Suite
	MockCtl *gomock.Controller
}

func (Suite *PrefixMiddlewareSuite) BeforeTest(_, _ string) {
	Suite.MockCtl = gomock.NewController(Suite.T())
}

func (Suite *PrefixMiddlewareSuite) AfterTest(_, _ string) {
	Suite.MockCtl.Finish()
}

func (Suite *PrefixMiddlewareSuite) TestFileWriter() {
	prefix := prefixMiddleware{prefix: `/files`}

	// parent of prefix
	WriterAt, err := prefix.Filewrite(&sftp.Request{Filepath: `/`})
	Suite.Nil(WriterAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	// file path and prefix are unrelated
	WriterAt, err = prefix.Filewrite(&sftp.Request{Filepath: `/random`})
	Suite.Nil(WriterAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	// file path is sub path of configured prefix
	// mocked returns are not import, just the call to the next file writer
	mockedWriter := mocks.NewMockMiddleware(Suite.MockCtl)
	mockedWriter.EXPECT().
		Filewrite(&sftp.Request{Filepath: `/data`}).
		Return(nil, nil)
	prefix.next = mockedWriter
	WriterAt, err = prefix.Filewrite(&sftp.Request{Filepath: `/files/data`})
	Suite.Nil(err)
	Suite.Nil(WriterAt)
}

func (Suite *PrefixMiddlewareSuite) TestFileReader() {
	middleware := prefixMiddleware{prefix: `/files`}

	// parent of prefix
	ReaderAt, err := middleware.Fileread(&sftp.Request{Filepath: `/`})
	Suite.Nil(ReaderAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	// file path and prefix are unrelated
	ReaderAt, err = middleware.Fileread(&sftp.Request{Filepath: `/random`})
	Suite.Nil(ReaderAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	// file path is sub path of configured prefix
	// mocked returns are not import, just the call to the next file writer
	mockedReader := mocks.NewMockMiddleware(Suite.MockCtl)
	mockedReader.EXPECT().
		Fileread(&sftp.Request{Filepath: `/data`}).
		Return(nil, nil)
	middleware.next = mockedReader
	ReaderAt, err = middleware.Fileread(&sftp.Request{Filepath: `/files/data`})
	Suite.Nil(err)
	Suite.Nil(ReaderAt)
}

func (Suite *PrefixMiddlewareSuite) TestOpenFile() {
	middleware := prefixMiddleware{prefix: `/files`}

	ReadWriteAt, err := middleware.OpenFile(&sftp.Request{Filepath: `/`})
	Suite.Nil(ReadWriteAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	// file path and prefix are unrelated
	ReadWriteAt, err = middleware.OpenFile(&sftp.Request{Filepath: `/random`})
	Suite.Nil(ReadWriteAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	var tests = []struct {
		RequestPath string
		NextPath    string
	}{
		// test normalization of various request paths
		{RequestPath: `/files/data.csv`, NextPath: `/data.csv`},
		{RequestPath: `files/data.csv`, NextPath: `/data.csv`},
		{RequestPath: `//files/./data.csv`, NextPath: `/data.csv`},
	}

	for _, test := range tests {
		OpenFileMock := mocks.NewMockMiddleware(Suite.MockCtl)
		OpenFileMock.EXPECT().
			OpenFile(&sftp.Request{Filepath: test.NextPath}).
			Return(nil, nil)
		middleware.next = OpenFileMock

		ReadWriteAt, err = middleware.OpenFile(&sftp.Request{Filepath: test.RequestPath})
		Suite.Nil(ReadWriteAt)
		Suite.Nil(err)
	}
}

func (Suite *PrefixMiddlewareSuite) TestStatVFS() {
	prefix := prefixMiddleware{prefix: `/files`}

	// parent of prefix
	res, err := prefix.StatVFS(&sftp.Request{Filepath: `/`})
	Suite.Nil(res)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	// file path and prefix are unrelated
	res, err = prefix.StatVFS(&sftp.Request{Filepath: `/random`})
	Suite.Nil(res)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	// file path is sub path of configured prefix
	// mocked returns are not import, just the call to the next file writer
	statVFSMock := mocks.NewMockMiddleware(Suite.MockCtl)
	statVFSMock.EXPECT().
		StatVFS(&sftp.Request{Filepath: `/data`}).
		Return(nil, nil)
	prefix.next = statVFSMock
	res, err = prefix.StatVFS(&sftp.Request{Filepath: `/files/data`})
	Suite.Nil(err)
	Suite.Nil(res)
}

func (Suite *PrefixMiddlewareSuite) TestFileListForwarding() {
	var tests = []struct {
		Method   string
		FilePath string
		FwdPath  string
	}{
		{Method: `List`, FilePath: `/files/data`, FwdPath: `/data`},
		{Method: `List`, FilePath: `/./files/data`, FwdPath: `/data`},
		{Method: `List`, FilePath: `files/data`, FwdPath: `/data`},
	}

	for _, test := range tests {
		FileListMock := mocks.NewMockMiddleware(Suite.MockCtl)
		FileListMock.EXPECT().
			Filelist(&sftp.Request{
				Method:   test.Method,
				Filepath: test.FwdPath,
			}).Return(nil, nil)

		handlers := newPrefixMiddleware(`/files`, FileListMock)
		ListerAt, err := handlers.Filelist(&sftp.Request{
			Method:   test.Method,
			Filepath: test.FilePath,
		})
		Suite.Nil(ListerAt)
		Suite.Nil(err)
	}
}

func (Suite *PrefixMiddlewareSuite) TestFileList() {
	var tests = []struct {
		Method        string
		FilePath      string
		ExpectedErr   error
		ExpectedPath  string
		ExpectedItems int
	}{
		{Method: `List`, FilePath: `/random`, ExpectedErr: sftp.ErrSSHFxPermissionDenied, ExpectedItems: 0},
		{Method: `List`, FilePath: `/`, ExpectedPath: `files`, ExpectedItems: 2},
		{Method: `Stat`, FilePath: `/`, ExpectedPath: `/`, ExpectedItems: 1},
		{Method: `NotAnOp`, ExpectedErr: sftp.ErrSSHFxOpUnsupported},
	}

	for _, test := range tests {
		middleware := prefixMiddleware{prefix: `/files`}
		ListerAt, err := middleware.Filelist(&sftp.Request{
			Method:   test.Method,
			Filepath: test.FilePath,
		})
		if test.ExpectedErr != nil {
			Suite.Equal(test.ExpectedErr, err)
			Suite.Nil(ListerAt)
		} else {
			Suite.Nil(err)
			Suite.IsType(listerAt{}, ListerAt)
			if directList, ok := ListerAt.(listerAt); ok {
				Suite.Len(directList, test.ExpectedItems)
				if test.ExpectedItems > 1 {
					Suite.Equal(".", directList[0].Name())
				}
				Suite.Equal(test.ExpectedPath, directList[test.ExpectedItems-1].Name())
				Suite.InDelta(time.Now().Unix(), directList[test.ExpectedItems-1].ModTime().Unix(), 1)
				Suite.True(directList[test.ExpectedItems-1].IsDir())
			}
		}
	}
}

func (Suite *PrefixMiddlewareSuite) TestLstat() {
	middleware := prefixMiddleware{prefix: `/files`}
	ListerAt, err := middleware.Lstat(&sftp.Request{Filepath: `/`})
	Suite.Nil(err)
	Suite.IsType(listerAt{}, ListerAt)
	if directList, ok := ListerAt.(listerAt); ok {
		Suite.Len(directList, 1)
		Suite.Equal(`/`, directList[0].Name())
		Suite.InDelta(time.Now().Unix(), directList[0].ModTime().Unix(), 1)
		Suite.True(directList[0].IsDir())
	}

	middleware = prefixMiddleware{prefix: `/files`}
	ListerAt, err = middleware.Lstat(&sftp.Request{Filepath: `/random`})
	Suite.Nil(ListerAt)
	Suite.Equal(sftp.ErrSSHFxPermissionDenied, err)

	MockLstat := mocks.NewMockMiddleware(Suite.MockCtl)
	MockLstat.EXPECT().
		Lstat(&sftp.Request{Filepath: "/data"}).
		Return(nil, nil)
	middleware = prefixMiddleware{prefix: `/files`}
	middleware.next = MockLstat

	ListerAt, err = middleware.Lstat(&sftp.Request{Filepath: `/files/data`})
	Suite.Nil(err)
	Suite.Nil(ListerAt)
}

func (Suite *PrefixMiddlewareSuite) TestFileCmdForwarding() {
	var tests = []struct {
		Method        string
		FilePath      string
		TargetPath    string
		FwdFilePath   string
		FwdTargetPath string
	}{
		{Method: `Rename`, FilePath: `/files/data.csv`, TargetPath: `/files/new-data.csv`, FwdFilePath: `/data.csv`, FwdTargetPath: `/new-data.csv`},
		{Method: `Rename`, FilePath: `files/data.csv`, TargetPath: `files/new-data.csv`, FwdFilePath: `/data.csv`, FwdTargetPath: `/new-data.csv`},
		{Method: `Symlink`, FilePath: `/./files/data.csv`, TargetPath: `files/new-data.csv`, FwdFilePath: `/data.csv`, FwdTargetPath: `/new-data.csv`},

		{Method: `Setstat`, FilePath: `files/data.csv`, FwdFilePath: `/data.csv`},
		{Method: `Remove`, FilePath: `/./files/data.csv`, FwdFilePath: `/data.csv`},
		{Method: `Rmdir`, FilePath: `files/data`, FwdFilePath: `/data`},
		{Method: `Mkdir`, FilePath: `/./files/data`, FwdFilePath: `/data`},
	}

	for _, test := range tests {
		FileCmdMock := mocks.NewMockMiddleware(Suite.MockCtl)
		FileCmdMock.EXPECT().
			Filecmd(&sftp.Request{
				Method:   test.Method,
				Filepath: test.FwdFilePath,
				Target:   test.FwdTargetPath,
			}).Return(nil)

		middleware := prefixMiddleware{
			prefix: `/files`,
			next:   FileCmdMock,
		}

		Suite.Nil(middleware.Filecmd(&sftp.Request{
			Method:   test.Method,
			Filepath: test.FilePath,
			Target:   test.TargetPath,
		}))
	}
}

func (Suite *PrefixMiddlewareSuite) TestFileCmdErrors() {
	middleware := prefixMiddleware{prefix: `/files`}

	var tests = []struct {
		Method      string
		RequestPath string
		TargetPath  string
		ExpectedErr error
	}{
		// two path methods
		{Method: `Rename`, RequestPath: `/`, TargetPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Rename`, RequestPath: `/random`, TargetPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Rename`, RequestPath: `/random`, TargetPath: `/files`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Symlink`, RequestPath: `/`, TargetPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Symlink`, RequestPath: `/random`, TargetPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Symlink`, RequestPath: `/random`, TargetPath: `/files`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},

		// single path methods
		{Method: `Setstat`, RequestPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Setstat`, RequestPath: `/unrelated`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Rmdir`, RequestPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Rmdir`, RequestPath: `/unrelated`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Mkdir`, RequestPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Mkdir`, RequestPath: `/unrelated`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Remove`, RequestPath: `/`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},
		{Method: `Remove`, RequestPath: `/unrelated`, ExpectedErr: sftp.ErrSSHFxPermissionDenied},

		{Method: `NotACmd`, ExpectedErr: sftp.ErrSSHFxOpUnsupported},
	}

	for _, test := range tests {
		err := middleware.Filecmd(&sftp.Request{
			Method:   test.Method,
			Filepath: test.RequestPath,
			Target:   test.TargetPath,
		})
		Suite.Equal(test.ExpectedErr, err)
	}
}

func (Suite *PrefixMiddlewareSuite) TestNextFolder() {
	prefix := prefixMiddleware{prefix: `/files/data`}
	Suite.Equal(`files`, prefix.nextListFolder(`/`))
	Suite.Equal(`files`, prefix.nextListFolder(``))
	Suite.Equal(`data`, prefix.nextListFolder(`/files`))
	Suite.Equal(`data`, prefix.nextListFolder(`files`))
	Suite.Equal(`data`, prefix.nextListFolder(`files/`))

	prefix = prefixMiddleware{prefix: `files/data`}
	Suite.Equal(`files`, prefix.nextListFolder(`/`))
	Suite.Equal(`files`, prefix.nextListFolder(``))
	Suite.Equal(`data`, prefix.nextListFolder(`/files`))
	Suite.Equal(`data`, prefix.nextListFolder(`files`))
	Suite.Equal(`data`, prefix.nextListFolder(`files/`))
}

func (Suite *PrefixMiddlewareSuite) TestContainsPrefix() {
	prefix := prefixMiddleware{prefix: `/`}
	Suite.True(prefix.containsPrefix(`/data`))
	Suite.True(prefix.containsPrefix(`/`))

	prefix = prefixMiddleware{prefix: `/files`}
	Suite.True(prefix.containsPrefix(`files`))
}

func (Suite *PrefixMiddlewareSuite) TestRemoveFolderPrefix() {
	prefix := prefixMiddleware{prefix: `/`}
	path, ok := prefix.removeFolderPrefix(`/files`)
	Suite.Equal(`/files`, path)
	Suite.True(ok)

	prefix = prefixMiddleware{prefix: `/files`}
	path, ok = prefix.removeFolderPrefix(`files`)
	Suite.Equal(`/`, path)
	Suite.True(ok)

	path, ok = prefix.removeFolderPrefix(`/random`)
	Suite.Equal(`/random`, path)
	Suite.False(ok)
}

func TestFolderPrefixSuite(t *testing.T) {
	suite.Run(t, new(PrefixMiddlewareSuite))
}
