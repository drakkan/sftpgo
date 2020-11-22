package httpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

func dumpData(w http.ResponseWriter, r *http.Request) {
	var outputFile, indent string
	if _, ok := r.URL.Query()["output_file"]; ok {
		outputFile = strings.TrimSpace(r.URL.Query().Get("output_file"))
	}
	if _, ok := r.URL.Query()["indent"]; ok {
		indent = strings.TrimSpace(r.URL.Query().Get("indent"))
	}
	if len(outputFile) == 0 {
		sendAPIResponse(w, r, errors.New("Invalid or missing output_file"), "", http.StatusBadRequest)
		return
	}
	if filepath.IsAbs(outputFile) {
		sendAPIResponse(w, r, fmt.Errorf("Invalid output_file %#v: it must be a relative path", outputFile), "", http.StatusBadRequest)
		return
	}
	if strings.Contains(outputFile, "..") {
		sendAPIResponse(w, r, fmt.Errorf("Invalid output_file %#v", outputFile), "", http.StatusBadRequest)
		return
	}
	outputFile = filepath.Join(backupsPath, outputFile)
	err := os.MkdirAll(filepath.Dir(outputFile), 0700)
	if err != nil {
		logger.Warn(logSender, "", "dumping data error: %v, output file: %#v", err, outputFile)
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	logger.Debug(logSender, "", "dumping data to: %#v", outputFile)

	backup, err := dataprovider.DumpData()
	if err != nil {
		logger.Warn(logSender, "", "dumping data error: %v, output file: %#v", err, outputFile)
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	var dump []byte
	if indent == "1" {
		dump, err = json.MarshalIndent(backup, "", "  ")
	} else {
		dump, err = json.Marshal(backup)
	}
	if err == nil {
		err = ioutil.WriteFile(outputFile, dump, 0600)
	}
	if err != nil {
		logger.Warn(logSender, "", "dumping data error: %v, output file: %#v", err, outputFile)
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	logger.Debug(logSender, "", "dumping data completed, output file: %#v, error: %v", outputFile, err)
	sendAPIResponse(w, r, err, "Data saved", http.StatusOK)
}

func loadData(w http.ResponseWriter, r *http.Request) {
	inputFile, scanQuota, mode, err := getLoaddataOptions(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if !filepath.IsAbs(inputFile) {
		sendAPIResponse(w, r, fmt.Errorf("Invalid input_file %#v: it must be an absolute path", inputFile), "", http.StatusBadRequest)
		return
	}
	fi, err := os.Stat(inputFile)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if fi.Size() > MaxRestoreSize {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to restore input file: %#v size too big: %v/%v bytes",
			inputFile, fi.Size(), MaxRestoreSize), http.StatusBadRequest)
		return
	}

	content, err := ioutil.ReadFile(inputFile)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	dump, err := dataprovider.ParseDumpData(content)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to parse input file: %#v", inputFile), http.StatusBadRequest)
		return
	}

	if err = RestoreFolders(dump.Folders, inputFile, scanQuota); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	if err = RestoreUsers(dump.Users, inputFile, mode, scanQuota); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	logger.Debug(logSender, "", "backup restored, users: %v", len(dump.Users))
	sendAPIResponse(w, r, err, "Data restored", http.StatusOK)
}

func getLoaddataOptions(r *http.Request) (string, int, int, error) {
	var inputFile string
	var err error
	scanQuota := 0
	restoreMode := 0
	if _, ok := r.URL.Query()["input_file"]; ok {
		inputFile = strings.TrimSpace(r.URL.Query().Get("input_file"))
	}
	if _, ok := r.URL.Query()["scan_quota"]; ok {
		scanQuota, err = strconv.Atoi(r.URL.Query().Get("scan_quota"))
		if err != nil {
			err = fmt.Errorf("invalid scan_quota: %v", err)
		}
	}
	if _, ok := r.URL.Query()["mode"]; ok {
		restoreMode, err = strconv.Atoi(r.URL.Query().Get("mode"))
		if err != nil {
			err = fmt.Errorf("invalid mode: %v", err)
		}
	}
	return inputFile, scanQuota, restoreMode, err
}

// RestoreFolders restores the specified folders
func RestoreFolders(folders []vfs.BaseVirtualFolder, inputFile string, scanQuota int) error {
	for _, folder := range folders {
		_, err := dataprovider.GetFolderByPath(folder.MappedPath)
		if err == nil {
			logger.Debug(logSender, "", "folder %#v already exists, restore not needed", folder.MappedPath)
			continue
		}
		folder.Users = nil
		err = dataprovider.AddFolder(folder)
		logger.Debug(logSender, "", "adding new folder: %+v, dump file: %#v, error: %v", folder, inputFile, err)
		if err != nil {
			return err
		}
		if scanQuota >= 1 {
			if common.QuotaScans.AddVFolderQuotaScan(folder.MappedPath) {
				logger.Debug(logSender, "", "starting quota scan for restored folder: %#v", folder.MappedPath)
				go doFolderQuotaScan(folder) //nolint:errcheck
			}
		}
	}
	return nil
}

// RestoreUsers restores the specified users
func RestoreUsers(users []dataprovider.User, inputFile string, mode, scanQuota int) error {
	for _, user := range users {
		u, err := dataprovider.UserExists(user.Username)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing user %#v not updated", u.Username)
				continue
			}
			user.ID = u.ID
			err = dataprovider.UpdateUser(user)
			user.Password = "[redacted]"
			logger.Debug(logSender, "", "restoring existing user: %+v, dump file: %#v, error: %v", user, inputFile, err)
			if mode == 2 && err == nil {
				disconnectUser(user.Username)
			}
		} else {
			err = dataprovider.AddUser(user)
			user.Password = "[redacted]"
			logger.Debug(logSender, "", "adding new user: %+v, dump file: %#v, error: %v", user, inputFile, err)
		}
		if err != nil {
			return err
		}
		if scanQuota == 1 || (scanQuota == 2 && user.HasQuotaRestrictions()) {
			if common.QuotaScans.AddUserQuotaScan(user.Username) {
				logger.Debug(logSender, "", "starting quota scan for restored user: %#v", user.Username)
				go doQuotaScan(user) //nolint:errcheck
			}
		}
	}
	return nil
}
