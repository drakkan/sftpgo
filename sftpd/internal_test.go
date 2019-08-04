package sftpd

import (
	"os"
	"runtime"
	"testing"

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
