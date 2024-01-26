// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package httpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func validateBackupFile(outputFile string) (string, error) {
	if outputFile == "" {
		return "", errors.New("invalid or missing output-file")
	}
	if filepath.IsAbs(outputFile) {
		return "", fmt.Errorf("invalid output-file %q: it must be a relative path", outputFile)
	}
	if strings.Contains(outputFile, "..") {
		return "", fmt.Errorf("invalid output-file %q", outputFile)
	}
	outputFile = filepath.Join(dataprovider.GetBackupsPath(), outputFile)
	return outputFile, nil
}

func dumpData(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var outputFile, outputData, indent string
	var scopes []string
	if _, ok := r.URL.Query()["output-file"]; ok {
		outputFile = strings.TrimSpace(r.URL.Query().Get("output-file"))
	}
	if _, ok := r.URL.Query()["output-data"]; ok {
		outputData = strings.TrimSpace(r.URL.Query().Get("output-data"))
	}
	if _, ok := r.URL.Query()["indent"]; ok {
		indent = strings.TrimSpace(r.URL.Query().Get("indent"))
	}
	if _, ok := r.URL.Query()["scopes"]; ok {
		scopes = getCommaSeparatedQueryParam(r, "scopes")
	}

	if outputData != "1" {
		var err error
		outputFile, err = validateBackupFile(outputFile)
		if err != nil {
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}

		err = os.MkdirAll(filepath.Dir(outputFile), 0700)
		if err != nil {
			logger.Error(logSender, "", "dumping data error: %v, output file: %q", err, outputFile)
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		logger.Debug(logSender, "", "dumping data to: %q", outputFile)
	}

	backup, err := dataprovider.DumpData(scopes)
	if err != nil {
		logger.Error(logSender, "", "dumping data error: %v, output file: %q", err, outputFile)
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	if outputData == "1" {
		w.Header().Set("Content-Disposition", "attachment; filename=\"sftpgo-backup.json\"")
		render.JSON(w, r, backup)
		return
	}

	var dump []byte
	if indent == "1" {
		dump, err = json.MarshalIndent(backup, "", "  ")
	} else {
		dump, err = json.Marshal(backup)
	}
	if err == nil {
		err = os.WriteFile(outputFile, dump, 0600)
	}
	if err != nil {
		logger.Warn(logSender, "", "dumping data error: %v, output file: %q", err, outputFile)
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	logger.Debug(logSender, "", "dumping data completed, output file: %q, error: %v", outputFile, err)
	sendAPIResponse(w, r, err, "Data saved", http.StatusOK)
}

func loadDataFromRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRestoreSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	_, scanQuota, mode, err := getLoaddataOptions(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil || len(content) == 0 {
		if len(content) == 0 {
			err = util.NewValidationError("request body is required")
		}
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if err := restoreBackup(content, "", scanQuota, mode, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Data restored", http.StatusOK)
}

func loadData(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	inputFile, scanQuota, mode, err := getLoaddataOptions(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if !filepath.IsAbs(inputFile) {
		sendAPIResponse(w, r, fmt.Errorf("invalid input_file %q: it must be an absolute path", inputFile), "",
			http.StatusBadRequest)
		return
	}
	fi, err := os.Stat(inputFile)
	if err != nil {
		sendAPIResponse(w, r, fmt.Errorf("invalid input_file %q", inputFile), "", http.StatusBadRequest)
		return
	}
	if fi.Size() > MaxRestoreSize {
		sendAPIResponse(w, r, err, fmt.Sprintf("Unable to restore input file: %q size too big: %d/%d bytes",
			inputFile, fi.Size(), MaxRestoreSize), http.StatusBadRequest)
		return
	}

	content, err := os.ReadFile(inputFile)
	if err != nil {
		sendAPIResponse(w, r, fmt.Errorf("invalid input_file %q", inputFile), "", http.StatusBadRequest)
		return
	}
	if err := restoreBackup(content, inputFile, scanQuota, mode, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Data restored", http.StatusOK)
}

func restoreBackup(content []byte, inputFile string, scanQuota, mode int, executor, ipAddress, role string) error {
	dump, err := dataprovider.ParseDumpData(content)
	if err != nil {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("invalid input_file %q", inputFile)),
			util.I18nErrorBackupFile,
		)
	}

	if err = RestoreConfigs(dump.Configs, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreIPListEntries(dump.IPLists, inputFile, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreRoles(dump.Roles, inputFile, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreFolders(dump.Folders, inputFile, mode, scanQuota, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreGroups(dump.Groups, inputFile, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreUsers(dump.Users, inputFile, mode, scanQuota, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreAdmins(dump.Admins, inputFile, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreAPIKeys(dump.APIKeys, inputFile, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreShares(dump.Shares, inputFile, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreEventActions(dump.EventActions, inputFile, mode, executor, ipAddress, role); err != nil {
		return err
	}

	if err = RestoreEventRules(dump.EventRules, inputFile, mode, executor, ipAddress, role, dump.Version); err != nil {
		return err
	}
	logger.Debug(logSender, "", "backup restored")

	return nil
}

func getLoaddataOptions(r *http.Request) (string, int, int, error) {
	var inputFile string
	var err error
	scanQuota := 0
	restoreMode := 0
	if _, ok := r.URL.Query()["input-file"]; ok {
		inputFile = strings.TrimSpace(r.URL.Query().Get("input-file"))
	}
	if _, ok := r.URL.Query()["scan-quota"]; ok {
		scanQuota, err = strconv.Atoi(r.URL.Query().Get("scan-quota"))
		if err != nil {
			err = fmt.Errorf("invalid scan_quota: %v", err)
			return inputFile, scanQuota, restoreMode, err
		}
	}
	if _, ok := r.URL.Query()["mode"]; ok {
		restoreMode, err = strconv.Atoi(r.URL.Query().Get("mode"))
		if err != nil {
			err = fmt.Errorf("invalid mode: %v", err)
			return inputFile, scanQuota, restoreMode, err
		}
	}
	return inputFile, scanQuota, restoreMode, err
}

// RestoreFolders restores the specified folders
func RestoreFolders(folders []vfs.BaseVirtualFolder, inputFile string, mode, scanQuota int, executor, ipAddress, role string) error {
	for idx := range folders {
		folder := folders[idx]
		f, err := dataprovider.GetFolderByName(folder.Name)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing folder %q not updated", folder.Name)
				continue
			}
			folder.ID = f.ID
			folder.Name = f.Name
			err = dataprovider.UpdateFolder(&folder, f.Users, f.Groups, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring existing folder %q, dump file: %q, error: %v", folder.Name, inputFile, err)
		} else {
			folder.Users = nil
			err = dataprovider.AddFolder(&folder, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new folder %q, dump file: %q, error: %v", folder.Name, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore folder %q: %w", folder.Name, err)
		}
		if scanQuota >= 1 {
			if common.QuotaScans.AddVFolderQuotaScan(folder.Name) {
				logger.Debug(logSender, "", "starting quota scan for restored folder: %q", folder.Name)
				go doFolderQuotaScan(folder) //nolint:errcheck
			}
		}
	}
	return nil
}

// RestoreShares restores the specified shares
func RestoreShares(shares []dataprovider.Share, inputFile string, mode int, executor,
	ipAddress, role string,
) error {
	for idx := range shares {
		share := shares[idx]
		share.IsRestore = true
		s, err := dataprovider.ShareExists(share.ShareID, "")
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing share %q not updated", share.ShareID)
				continue
			}
			share.ID = s.ID
			err = dataprovider.UpdateShare(&share, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring existing share %q, dump file: %q, error: %v", share.ShareID, inputFile, err)
		} else {
			err = dataprovider.AddShare(&share, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new share %q, dump file: %q, error: %v", share.ShareID, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore share %q: %w", share.ShareID, err)
		}
	}
	return nil
}

// RestoreEventActions restores the specified event actions
func RestoreEventActions(actions []dataprovider.BaseEventAction, inputFile string, mode int, executor, ipAddress, role string) error {
	for idx := range actions {
		action := actions[idx]
		a, err := dataprovider.EventActionExists(action.Name)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing event action %q not updated", a.Name)
				continue
			}
			action.ID = a.ID
			err = dataprovider.UpdateEventAction(&action, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring event action %q, dump file: %q, error: %v", action.Name, inputFile, err)
		} else {
			err = dataprovider.AddEventAction(&action, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new event action %q, dump file: %q, error: %v", action.Name, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore event action %q: %w", action.Name, err)
		}
	}
	return nil
}

// RestoreEventRules restores the specified event rules
func RestoreEventRules(rules []dataprovider.EventRule, inputFile string, mode int, executor, ipAddress,
	role string, dumpVersion int,
) error {
	for idx := range rules {
		rule := rules[idx]
		if dumpVersion < 15 {
			rule.Status = 1
		}
		r, err := dataprovider.EventRuleExists(rule.Name)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing event rule %q not updated", r.Name)
				continue
			}
			rule.ID = r.ID
			err = dataprovider.UpdateEventRule(&rule, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring event rule %q, dump file: %q, error: %v", rule.Name, inputFile, err)
		} else {
			err = dataprovider.AddEventRule(&rule, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new event rule %q, dump file: %q, error: %v", rule.Name, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore event rule %q: %w", rule.Name, err)
		}
	}
	return nil
}

// RestoreAPIKeys restores the specified API keys
func RestoreAPIKeys(apiKeys []dataprovider.APIKey, inputFile string, mode int, executor, ipAddress, role string) error {
	for idx := range apiKeys {
		apiKey := apiKeys[idx]
		if apiKey.Key == "" {
			logger.Warn(logSender, "", "cannot restore empty API key")
			return fmt.Errorf("cannot restore an empty API key: %+v", apiKey)
		}
		k, err := dataprovider.APIKeyExists(apiKey.KeyID)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing API key %q not updated", apiKey.KeyID)
				continue
			}
			apiKey.ID = k.ID
			err = dataprovider.UpdateAPIKey(&apiKey, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring existing API key %q, dump file: %q, error: %v", apiKey.KeyID, inputFile, err)
		} else {
			err = dataprovider.AddAPIKey(&apiKey, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new API key %q, dump file: %q, error: %v", apiKey.KeyID, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore API key %q: %w", apiKey.KeyID, err)
		}
	}
	return nil
}

// RestoreAdmins restores the specified admins
func RestoreAdmins(admins []dataprovider.Admin, inputFile string, mode int, executor, ipAddress, role string) error {
	for idx := range admins {
		admin := admins[idx]
		a, err := dataprovider.AdminExists(admin.Username)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing admin %q not updated", a.Username)
				continue
			}
			admin.ID = a.ID
			admin.Username = a.Username
			err = dataprovider.UpdateAdmin(&admin, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring existing admin %q, dump file: %q, error: %v", admin.Username, inputFile, err)
		} else {
			err = dataprovider.AddAdmin(&admin, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new admin %q, dump file: %q, error: %v", admin.Username, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore admin %q: %w", admin.Username, err)
		}
	}

	return nil
}

// RestoreConfigs restores the specified provider configs
func RestoreConfigs(configs *dataprovider.Configs, mode int, executor, ipAddress,
	executorRole string,
) error {
	if configs == nil {
		return nil
	}
	c, err := dataprovider.GetConfigs()
	if err != nil {
		return fmt.Errorf("unable to restore configs, error loading existing from db: %w", err)
	}
	if c.UpdatedAt > 0 {
		if mode == 1 {
			logger.Debug(logSender, "", "loaddata mode 1, existing configs not updated")
			return nil
		}
	}
	return dataprovider.UpdateConfigs(configs, executor, ipAddress, executorRole)
}

// RestoreIPListEntries restores the specified IP list entries
func RestoreIPListEntries(entries []dataprovider.IPListEntry, inputFile string, mode int, executor, ipAddress,
	executorRole string,
) error {
	for idx := range entries {
		entry := entries[idx]
		e, err := dataprovider.IPListEntryExists(entry.IPOrNet, entry.Type)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing IP list entry %s-%s not updated",
					e.Type.AsString(), e.IPOrNet)
				continue
			}
			err = dataprovider.UpdateIPListEntry(&entry, executor, ipAddress, executorRole)
			logger.Debug(logSender, "", "restoring existing IP list entry: %s-%s, dump file: %q, error: %v",
				entry.Type.AsString(), entry.IPOrNet, inputFile, err)
		} else {
			err = dataprovider.AddIPListEntry(&entry, executor, ipAddress, executorRole)
			logger.Debug(logSender, "", "adding new IP list entry %s-%s, dump file: %q, error: %v",
				entry.Type.AsString(), entry.IPOrNet, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore IP list entry %s-%s: %w", entry.Type.AsString(), entry.IPOrNet, err)
		}
	}
	return nil
}

// RestoreRoles restores the specified roles
func RestoreRoles(roles []dataprovider.Role, inputFile string, mode int, executor, ipAddress, executorRole string) error {
	for idx := range roles {
		role := roles[idx]
		r, err := dataprovider.RoleExists(role.Name)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing role %q not updated", r.Name)
				continue
			}
			role.ID = r.ID
			err = dataprovider.UpdateRole(&role, executor, ipAddress, executorRole)
			logger.Debug(logSender, "", "restoring existing role: %q, dump file: %q, error: %v", role.Name, inputFile, err)
		} else {
			err = dataprovider.AddRole(&role, executor, ipAddress, executorRole)
			logger.Debug(logSender, "", "adding new role: %q, dump file: %q, error: %v", role.Name, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore role %q: %w", role.Name, err)
		}
	}
	return nil
}

// RestoreGroups restores the specified groups
func RestoreGroups(groups []dataprovider.Group, inputFile string, mode int, executor, ipAddress, role string) error {
	for idx := range groups {
		group := groups[idx]
		g, err := dataprovider.GroupExists(group.Name)
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing group %q not updated", g.Name)
				continue
			}
			group.ID = g.ID
			group.Name = g.Name
			err = dataprovider.UpdateGroup(&group, g.Users, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring existing group: %q, dump file: %q, error: %v", group.Name, inputFile, err)
		} else {
			err = dataprovider.AddGroup(&group, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new group: %q, dump file: %q, error: %v", group.Name, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore group %q: %w", group.Name, err)
		}
	}
	return nil
}

// RestoreUsers restores the specified users
func RestoreUsers(users []dataprovider.User, inputFile string, mode, scanQuota int, executor, ipAddress, role string) error {
	for idx := range users {
		user := users[idx]
		u, err := dataprovider.UserExists(user.Username, "")
		if err == nil {
			if mode == 1 {
				logger.Debug(logSender, "", "loaddata mode 1, existing user %q not updated", u.Username)
				continue
			}
			user.ID = u.ID
			user.Username = u.Username
			err = dataprovider.UpdateUser(&user, executor, ipAddress, role)
			logger.Debug(logSender, "", "restoring existing user: %q, dump file: %q, error: %v", user.Username, inputFile, err)
			if mode == 2 && err == nil {
				disconnectUser(user.Username, executor, role)
			}
		} else {
			err = dataprovider.AddUser(&user, executor, ipAddress, role)
			logger.Debug(logSender, "", "adding new user: %q, dump file: %q, error: %v", user.Username, inputFile, err)
		}
		if err != nil {
			return fmt.Errorf("unable to restore user %q: %w", user.Username, err)
		}
		if scanQuota == 1 || (scanQuota == 2 && user.HasQuotaRestrictions()) {
			if common.QuotaScans.AddUserQuotaScan(user.Username, user.Role) {
				logger.Debug(logSender, "", "starting quota scan for restored user: %q", user.Username)
				go doUserQuotaScan(user) //nolint:errcheck
			}
		}
	}
	return nil
}
