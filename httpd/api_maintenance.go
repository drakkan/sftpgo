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

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
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
	logger.Debug(logSender, "", "dumping data to: %#v", outputFile)

	users, err := dataprovider.DumpUsers(dataProvider)
	if err != nil {
		logger.Warn(logSender, "", "dumping data error: %v, output file: %#v", err, outputFile)
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	var dump []byte
	if indent == "1" {
		dump, err = json.MarshalIndent(dataprovider.BackupData{
			Users: users,
		}, "", "  ")
	} else {
		dump, err = json.Marshal(dataprovider.BackupData{
			Users: users,
		})
	}
	if err == nil {
		os.MkdirAll(filepath.Dir(outputFile), 0700)
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
	if fi.Size() > maxRestoreSize {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to restore input file: %#v size too big: %v/%v bytes",
			inputFile, fi.Size(), maxRestoreSize), http.StatusBadRequest)
		return
	}

	content, err := ioutil.ReadFile(inputFile)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	var dump dataprovider.BackupData
	err = json.Unmarshal(content, &dump)
	if err != nil {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to parse input file: %#v", inputFile), http.StatusBadRequest)
		return
	}

	for _, user := range dump.Users {
		u, err := dataprovider.UserExists(dataProvider, user.Username)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing user %#v not updated", u.Username)
				continue
			}
			user.ID = u.ID
			user.LastLogin = u.LastLogin
			user.UsedQuotaSize = u.UsedQuotaSize
			user.UsedQuotaFiles = u.UsedQuotaFiles
			err = dataprovider.UpdateUser(dataProvider, user)
			user.Password = "[redacted]"
			logger.Debug(logSender, "", "restoring existing user: %+v, dump file: %#v, error: %v", user, inputFile, err)
		} else {
			user.LastLogin = 0
			user.UsedQuotaSize = 0
			user.UsedQuotaFiles = 0
			err = dataprovider.AddUser(dataProvider, user)
			user.Password = "[redacted]"
			logger.Debug(logSender, "", "adding new user: %+v, dump file: %#v, error: %v", user, inputFile, err)
		}
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if needQuotaScan(scanQuota, &user) {
			if sftpd.AddQuotaScan(user.Username) {
				logger.Debug(logSender, "", "starting quota scan for restored user: %#v", user.Username)
				go doQuotaScan(user)
			}
		}
	}
	logger.Debug(logSender, "", "backup restored, users: %v", len(dump.Users))
	sendAPIResponse(w, r, err, "Data restored", http.StatusOK)
}

func needQuotaScan(scanQuota int, user *dataprovider.User) bool {
	return scanQuota == 1 || (scanQuota == 2 && user.HasQuotaRestrictions())
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
