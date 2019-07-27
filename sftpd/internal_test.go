package sftpd

import (
	"runtime"
	"testing"
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
