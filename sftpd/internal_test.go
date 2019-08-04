package sftpd

import (
	"os"
	"runtime"
	"testing"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/pkg/sftp"
)

func TestWrongActions(t *testing.T) {
	actionsCopy := actions
	badCommand := "/bad/command"
	if runtime.GOOS == "windows" {
		badCommand = "C:\\bad\\command"
	}
	actions = Actions{
		ExecuteOn:           []string{operationDownload},
		Command:             badCommand,
		HTTPNotificationURL: "",
	}
	err := executeAction(operationDownload, "username", "path", "")
	if err == nil {
		t.Errorf("action with bad command must fail")
	}
	err = executeAction(operationDelete, "username", "path", "")
	if err != nil {
		t.Errorf("action not configured must silently fail")
	}
	actions.Command = ""
	actions.HTTPNotificationURL = "http://foo\x7f.com/"
	err = executeAction(operationDownload, "username", "path", "")
	if err == nil {
		t.Errorf("action with bad url must fail")
	}
	actions = actionsCopy
}

func TestRemoveNonexistentTransfer(t *testing.T) {
	transfer := Transfer{}
	err := removeTransfer(&transfer)
	if err == nil {
		t.Errorf("remove nonexistent transfer must fail")
	}
}

func TestRemoveNonexistentQuotaScan(t *testing.T) {
	err := RemoveQuotaScan("username")
	if err == nil {
		t.Errorf("remove nonexistent transfer must fail")
	}
}

func TestGetOSOpenFlags(t *testing.T) {
	var flags sftp.FileOpenFlags
	flags.Write = true
	flags.Append = true
	flags.Excl = true
	osFlags := getOSOpenFlags(flags)
	if osFlags&os.O_WRONLY == 0 || osFlags&os.O_APPEND == 0 || osFlags&os.O_EXCL == 0 {
		t.Errorf("error getting os flags from sftp file open flags")
	}
}

func TestUploadResume(t *testing.T) {
	c := Connection{}
	var flags sftp.FileOpenFlags
	_, err := c.handleSFTPUploadToExistingFile(flags, "", "", 0)
	if err != sftp.ErrSshFxOpUnsupported {
		t.Errorf("file resume is not supported")
	}
}

func TestUploadFiles(t *testing.T) {
	oldUploadMode := uploadMode
	uploadMode = uploadModeAtomic
	c := Connection{}
	var flags sftp.FileOpenFlags
	flags.Write = true
	flags.Trunc = true
	_, err := c.handleSFTPUploadToExistingFile(flags, "missing_path", "other_missing_path", 0)
	if err == nil {
		t.Errorf("upload to existing file must fail if one or both paths are invalid")
	}
	uploadMode = uploadModeStandard
	_, err = c.handleSFTPUploadToExistingFile(flags, "missing_path", "other_missing_path", 0)
	if err == nil {
		t.Errorf("upload to existing file must fail if one or both paths are invalid")
	}
	missingFile := "missing/relative/file.txt"
	if runtime.GOOS == "windows" {
		missingFile = "missing\\relative\\file.txt"
	}
	_, err = c.handleSFTPUploadToNewFile(".", missingFile)
	if err == nil {
		t.Errorf("upload new file in missing path must fail")
	}
	uploadMode = oldUploadMode
}

func TestLoginWithInvalidHome(t *testing.T) {
	u := dataprovider.User{}
	u.HomeDir = "home_rel_path"
	_, err := loginUser(u)
	if err == nil {
		t.Errorf("login a user with an invalid home_dir must fail")
	}
}
