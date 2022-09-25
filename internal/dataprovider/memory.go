// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

var (
	errMemoryProviderClosed = errors.New("memory provider is closed")
)

type memoryProviderHandle struct {
	// configuration file to use for loading users
	configFile string
	sync.Mutex
	isClosed bool
	// slice with ordered usernames
	usernames []string
	// map for users, username is the key
	users map[string]User
	// slice with ordered group names
	groupnames []string
	// map for group, group name is the key
	groups map[string]Group
	// map for virtual folders, folder name is the key
	vfolders map[string]vfs.BaseVirtualFolder
	// slice with ordered folder names
	vfoldersNames []string
	// map for admins, username is the key
	admins map[string]Admin
	// slice with ordered admins
	adminsUsernames []string
	// map for API keys, keyID is the key
	apiKeys map[string]APIKey
	// slice with ordered API keys KeyID
	apiKeysIDs []string
	// map for shares, shareID is the key
	shares map[string]Share
	// slice with ordered shares shareID
	sharesIDs []string
	// map for event actions, name is the key
	actions map[string]BaseEventAction
	// slice with ordered actions
	actionsNames []string
	// map for event actions, name is the key
	rules map[string]EventRule
	// slice with ordered rules
	rulesNames []string
}

// MemoryProvider defines the auth provider for a memory store
type MemoryProvider struct {
	dbHandle *memoryProviderHandle
}

func initializeMemoryProvider(basePath string) {
	configFile := ""
	if util.IsFileInputValid(config.Name) {
		configFile = config.Name
		if !filepath.IsAbs(configFile) {
			configFile = filepath.Join(basePath, configFile)
		}
	}
	provider = &MemoryProvider{
		dbHandle: &memoryProviderHandle{
			isClosed:        false,
			usernames:       []string{},
			users:           make(map[string]User),
			groupnames:      []string{},
			groups:          make(map[string]Group),
			vfolders:        make(map[string]vfs.BaseVirtualFolder),
			vfoldersNames:   []string{},
			admins:          make(map[string]Admin),
			adminsUsernames: []string{},
			apiKeys:         make(map[string]APIKey),
			apiKeysIDs:      []string{},
			shares:          make(map[string]Share),
			sharesIDs:       []string{},
			actions:         make(map[string]BaseEventAction),
			actionsNames:    []string{},
			rules:           make(map[string]EventRule),
			rulesNames:      []string{},
			configFile:      configFile,
		},
	}
	if err := provider.reloadConfig(); err != nil {
		logger.Error(logSender, "", "unable to load initial data: %v", err)
		logger.ErrorToConsole("unable to load initial data: %v", err)
	}
}

func (p *MemoryProvider) checkAvailability() error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	return nil
}

func (p *MemoryProvider) close() error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	p.dbHandle.isClosed = true
	return nil
}

func (p *MemoryProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	var user User
	if tlsCert == nil {
		return user, errors.New("TLS certificate cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, err
	}
	return checkUserAndTLSCertificate(&user, protocol, tlsCert)
}

func (p *MemoryProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, err
	}
	return checkUserAndPass(&user, password, ip, protocol)
}

func (p *MemoryProvider) validateUserAndPubKey(username string, pubKey []byte, isSSHCert bool) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey, isSSHCert)
}

func (p *MemoryProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	admin, err := p.adminExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating admin %#v: %v", username, err)
		return admin, ErrInvalidCredentials
	}
	err = admin.checkUserAndPass(password, ip)
	return admin, err
}

func (p *MemoryProvider) updateAPIKeyLastUse(keyID string) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	apiKey, err := p.apiKeyExistsInternal(keyID)
	if err != nil {
		return err
	}
	apiKey.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.apiKeys[apiKey.KeyID] = apiKey
	return nil
}

func (p *MemoryProvider) setUpdatedAt(username string) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return
	}
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.users[user.Username] = user
	setLastUserUpdate()
}

func (p *MemoryProvider) updateLastLogin(username string) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return err
	}
	user.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p *MemoryProvider) updateAdminLastLogin(username string) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	admin, err := p.adminExistsInternal(username)
	if err != nil {
		return err
	}
	admin.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.admins[admin.Username] = admin
	return nil
}

func (p *MemoryProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		providerLog(logger.LevelError, "unable to update transfer quota for user %#v error: %v", username, err)
		return err
	}
	if reset {
		user.UsedUploadDataTransfer = uploadSize
		user.UsedDownloadDataTransfer = downloadSize
	} else {
		user.UsedUploadDataTransfer += uploadSize
		user.UsedDownloadDataTransfer += downloadSize
	}
	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	providerLog(logger.LevelDebug, "transfer quota updated for user %#v, ul increment: %v dl increment: %v is reset? %v",
		username, uploadSize, downloadSize, reset)
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p *MemoryProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		providerLog(logger.LevelError, "unable to update quota for user %#v error: %v", username, err)
		return err
	}
	if reset {
		user.UsedQuotaSize = sizeAdd
		user.UsedQuotaFiles = filesAdd
	} else {
		user.UsedQuotaSize += sizeAdd
		user.UsedQuotaFiles += filesAdd
	}
	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	providerLog(logger.LevelDebug, "quota updated for user %#v, files increment: %v size increment: %v is reset? %v",
		username, filesAdd, sizeAdd, reset)
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p *MemoryProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return 0, 0, 0, 0, errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for user %#v error: %v", username, err)
		return 0, 0, 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, user.UsedUploadDataTransfer, user.UsedDownloadDataTransfer, err
}

func (p *MemoryProvider) addUser(user *User) error {
	// we can query virtual folder while validating a user
	// so we have to check without holding the lock
	err := ValidateUser(user)
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err = p.userExistsInternal(user.Username)
	if err == nil {
		return fmt.Errorf("username %#v already exists", user.Username)
	}
	user.ID = p.getNextID()
	user.LastQuotaUpdate = 0
	user.UsedQuotaSize = 0
	user.UsedQuotaFiles = 0
	user.UsedUploadDataTransfer = 0
	user.UsedDownloadDataTransfer = 0
	user.LastLogin = 0
	user.FirstUpload = 0
	user.FirstDownload = 0
	user.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	var mappedGroups []string
	for idx := range user.Groups {
		if err = p.addUserToGroupMapping(user.Username, user.Groups[idx].Name); err != nil {
			// try to remove group mapping
			for _, g := range mappedGroups {
				p.removeUserFromGroupMapping(user.Username, g)
			}
			return err
		}
		mappedGroups = append(mappedGroups, user.Groups[idx].Name)
	}
	user.VirtualFolders = p.joinUserVirtualFoldersFields(user)
	p.dbHandle.users[user.Username] = user.getACopy()
	p.dbHandle.usernames = append(p.dbHandle.usernames, user.Username)
	sort.Strings(p.dbHandle.usernames)
	return nil
}

func (p *MemoryProvider) updateUser(user *User) error {
	// we can query virtual folder while validating a user
	// so we have to check without holding the lock
	err := ValidateUser(user)
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	u, err := p.userExistsInternal(user.Username)
	if err != nil {
		return err
	}
	for idx := range u.Groups {
		p.removeUserFromGroupMapping(u.Username, u.Groups[idx].Name)
	}
	for idx := range user.Groups {
		if err = p.addUserToGroupMapping(user.Username, user.Groups[idx].Name); err != nil {
			// try to add old mapping
			for _, g := range u.Groups {
				if errRollback := p.addUserToGroupMapping(user.Username, g.Name); errRollback != nil {
					providerLog(logger.LevelError, "unable to rollback old group mapping %q for user %q, error: %v",
						g.Name, user.Username, errRollback)
				}
			}
			return err
		}
	}
	for _, oldFolder := range u.VirtualFolders {
		p.removeRelationFromFolderMapping(oldFolder.Name, u.Username, "")
	}
	user.VirtualFolders = p.joinUserVirtualFoldersFields(user)
	user.LastQuotaUpdate = u.LastQuotaUpdate
	user.UsedQuotaSize = u.UsedQuotaSize
	user.UsedQuotaFiles = u.UsedQuotaFiles
	user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
	user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
	user.LastLogin = u.LastLogin
	user.FirstDownload = u.FirstDownload
	user.FirstUpload = u.FirstUpload
	user.CreatedAt = u.CreatedAt
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	user.ID = u.ID
	// pre-login and external auth hook will use the passed *user so save a copy
	p.dbHandle.users[user.Username] = user.getACopy()
	setLastUserUpdate()
	return nil
}

func (p *MemoryProvider) deleteUser(user User, softDelete bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	u, err := p.userExistsInternal(user.Username)
	if err != nil {
		return err
	}
	for _, oldFolder := range u.VirtualFolders {
		p.removeRelationFromFolderMapping(oldFolder.Name, u.Username, "")
	}
	for idx := range u.Groups {
		p.removeUserFromGroupMapping(u.Username, u.Groups[idx].Name)
	}
	delete(p.dbHandle.users, user.Username)
	// this could be more efficient
	p.dbHandle.usernames = make([]string, 0, len(p.dbHandle.users))
	for username := range p.dbHandle.users {
		p.dbHandle.usernames = append(p.dbHandle.usernames, username)
	}
	sort.Strings(p.dbHandle.usernames)
	p.deleteAPIKeysWithUser(user.Username)
	p.deleteSharesWithUser(user.Username)
	return nil
}

func (p *MemoryProvider) updateUserPassword(username, password string) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	user, err := p.userExistsInternal(username)
	if err != nil {
		return err
	}
	user.Password = password
	p.dbHandle.users[username] = user
	return nil
}

func (p *MemoryProvider) dumpUsers() ([]User, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	users := make([]User, 0, len(p.dbHandle.usernames))
	var err error
	if p.dbHandle.isClosed {
		return users, errMemoryProviderClosed
	}
	for _, username := range p.dbHandle.usernames {
		u := p.dbHandle.users[username]
		user := u.getACopy()
		p.addVirtualFoldersToUser(&user)
		users = append(users, user)
	}
	return users, err
}

func (p *MemoryProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	folders := make([]vfs.BaseVirtualFolder, 0, len(p.dbHandle.vfoldersNames))
	if p.dbHandle.isClosed {
		return folders, errMemoryProviderClosed
	}
	for _, f := range p.dbHandle.vfolders {
		folders = append(folders, f)
	}
	return folders, nil
}

func (p *MemoryProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	if getLastUserUpdate() < after {
		return nil, nil
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	users := make([]User, 0, 10)
	for _, username := range p.dbHandle.usernames {
		u := p.dbHandle.users[username]
		if u.UpdatedAt < after {
			continue
		}
		user := u.getACopy()
		p.addVirtualFoldersToUser(&user)
		if len(user.Groups) > 0 {
			groupMapping := make(map[string]Group)
			for idx := range user.Groups {
				group, err := p.groupExistsInternal(user.Groups[idx].Name)
				if err != nil {
					continue
				}
				groupMapping[group.Name] = group
			}
			user.applyGroupSettings(groupMapping)
		}

		user.SetEmptySecretsIfNil()
		users = append(users, user)
	}

	return users, nil
}

func (p *MemoryProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	users := make([]User, 0, 30)
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return users, errMemoryProviderClosed
	}
	for _, username := range p.dbHandle.usernames {
		if needFolders, ok := toFetch[username]; ok {
			u := p.dbHandle.users[username]
			user := u.getACopy()
			if needFolders {
				p.addVirtualFoldersToUser(&user)
			}
			if len(user.Groups) > 0 {
				groupMapping := make(map[string]Group)
				for idx := range user.Groups {
					group, err := p.groupExistsInternal(user.Groups[idx].Name)
					if err != nil {
						continue
					}
					groupMapping[group.Name] = group
				}
				user.applyGroupSettings(groupMapping)
			}
			user.SetEmptySecretsIfNil()
			user.PrepareForRendering()
			users = append(users, user)
		}
	}

	return users, nil
}

func (p *MemoryProvider) getUsers(limit int, offset int, order string) ([]User, error) {
	users := make([]User, 0, limit)
	var err error
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return users, errMemoryProviderClosed
	}
	if limit <= 0 {
		return users, err
	}
	itNum := 0
	if order == OrderASC {
		for _, username := range p.dbHandle.usernames {
			itNum++
			if itNum <= offset {
				continue
			}
			u := p.dbHandle.users[username]
			user := u.getACopy()
			p.addVirtualFoldersToUser(&user)
			user.PrepareForRendering()
			users = append(users, user)
			if len(users) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.usernames) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			username := p.dbHandle.usernames[i]
			u := p.dbHandle.users[username]
			user := u.getACopy()
			p.addVirtualFoldersToUser(&user)
			user.PrepareForRendering()
			users = append(users, user)
			if len(users) >= limit {
				break
			}
		}
	}
	return users, err
}

func (p *MemoryProvider) userExists(username string) (User, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return user, err
	}
	p.addVirtualFoldersToUser(&user)
	return user, nil
}

func (p *MemoryProvider) userExistsInternal(username string) (User, error) {
	if val, ok := p.dbHandle.users[username]; ok {
		return val.getACopy(), nil
	}
	return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
}

func (p *MemoryProvider) groupExistsInternal(name string) (Group, error) {
	if val, ok := p.dbHandle.groups[name]; ok {
		return val.getACopy(), nil
	}
	return Group{}, util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", name))
}

func (p *MemoryProvider) actionExistsInternal(name string) (BaseEventAction, error) {
	if val, ok := p.dbHandle.actions[name]; ok {
		return val.getACopy(), nil
	}
	return BaseEventAction{}, util.NewRecordNotFoundError(fmt.Sprintf("event action %q does not exist", name))
}

func (p *MemoryProvider) ruleExistsInternal(name string) (EventRule, error) {
	if val, ok := p.dbHandle.rules[name]; ok {
		return val.getACopy(), nil
	}
	return EventRule{}, util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", name))
}

func (p *MemoryProvider) addAdmin(admin *Admin) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	err := admin.validate()
	if err != nil {
		return err
	}
	_, err = p.adminExistsInternal(admin.Username)
	if err == nil {
		return fmt.Errorf("admin %#v already exists", admin.Username)
	}
	admin.ID = p.getNextAdminID()
	admin.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	admin.LastLogin = 0
	var mappedAdmins []string
	for idx := range admin.Groups {
		if err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name); err != nil {
			// try to remove group mapping
			for _, g := range mappedAdmins {
				p.removeAdminFromGroupMapping(admin.Username, g)
			}
			return err
		}
		mappedAdmins = append(mappedAdmins, admin.Groups[idx].Name)
	}
	p.dbHandle.admins[admin.Username] = admin.getACopy()
	p.dbHandle.adminsUsernames = append(p.dbHandle.adminsUsernames, admin.Username)
	sort.Strings(p.dbHandle.adminsUsernames)
	return nil
}

func (p *MemoryProvider) updateAdmin(admin *Admin) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	err := admin.validate()
	if err != nil {
		return err
	}
	a, err := p.adminExistsInternal(admin.Username)
	if err != nil {
		return err
	}
	for idx := range a.Groups {
		p.removeAdminFromGroupMapping(a.Username, a.Groups[idx].Name)
	}
	for idx := range admin.Groups {
		if err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name); err != nil {
			// try to add old mapping
			for _, oldGroup := range a.Groups {
				if errRollback := p.addAdminToGroupMapping(a.Username, oldGroup.Name); errRollback != nil {
					providerLog(logger.LevelError, "unable to rollback old group mapping %q for admin %q, error: %v",
						oldGroup.Name, a.Username, errRollback)
				}
			}
			return err
		}
	}
	admin.ID = a.ID
	admin.CreatedAt = a.CreatedAt
	admin.LastLogin = a.LastLogin
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.admins[admin.Username] = admin.getACopy()
	return nil
}

func (p *MemoryProvider) deleteAdmin(admin Admin) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	a, err := p.adminExistsInternal(admin.Username)
	if err != nil {
		return err
	}
	for idx := range a.Groups {
		p.removeAdminFromGroupMapping(a.Username, a.Groups[idx].Name)
	}

	delete(p.dbHandle.admins, admin.Username)
	// this could be more efficient
	p.dbHandle.adminsUsernames = make([]string, 0, len(p.dbHandle.admins))
	for username := range p.dbHandle.admins {
		p.dbHandle.adminsUsernames = append(p.dbHandle.adminsUsernames, username)
	}
	sort.Strings(p.dbHandle.adminsUsernames)
	p.deleteAPIKeysWithAdmin(admin.Username)
	return nil
}

func (p *MemoryProvider) adminExists(username string) (Admin, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return Admin{}, errMemoryProviderClosed
	}
	return p.adminExistsInternal(username)
}

func (p *MemoryProvider) adminExistsInternal(username string) (Admin, error) {
	if val, ok := p.dbHandle.admins[username]; ok {
		return val.getACopy(), nil
	}
	return Admin{}, util.NewRecordNotFoundError(fmt.Sprintf("admin %#v does not exist", username))
}

func (p *MemoryProvider) dumpAdmins() ([]Admin, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	admins := make([]Admin, 0, len(p.dbHandle.admins))
	if p.dbHandle.isClosed {
		return admins, errMemoryProviderClosed
	}
	for _, admin := range p.dbHandle.admins {
		admins = append(admins, admin)
	}
	return admins, nil
}

func (p *MemoryProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	admins := make([]Admin, 0, limit)

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return admins, errMemoryProviderClosed
	}
	if limit <= 0 {
		return admins, nil
	}
	itNum := 0
	if order == OrderASC {
		for _, username := range p.dbHandle.adminsUsernames {
			itNum++
			if itNum <= offset {
				continue
			}
			a := p.dbHandle.admins[username]
			admin := a.getACopy()
			admin.HideConfidentialData()
			admins = append(admins, admin)
			if len(admins) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.adminsUsernames) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			username := p.dbHandle.adminsUsernames[i]
			a := p.dbHandle.admins[username]
			admin := a.getACopy()
			admin.HideConfidentialData()
			admins = append(admins, admin)
			if len(admins) >= limit {
				break
			}
		}
	}

	return admins, nil
}

func (p *MemoryProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	folder, err := p.folderExistsInternal(name)
	if err != nil {
		providerLog(logger.LevelError, "unable to update quota for folder %#v error: %v", name, err)
		return err
	}
	if reset {
		folder.UsedQuotaSize = sizeAdd
		folder.UsedQuotaFiles = filesAdd
	} else {
		folder.UsedQuotaSize += sizeAdd
		folder.UsedQuotaFiles += filesAdd
	}
	folder.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.vfolders[name] = folder
	return nil
}

func (p *MemoryProvider) getGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	if limit <= 0 {
		return nil, nil
	}
	groups := make([]Group, 0, limit)
	itNum := 0
	if order == OrderASC {
		for _, name := range p.dbHandle.groupnames {
			itNum++
			if itNum <= offset {
				continue
			}
			g := p.dbHandle.groups[name]
			group := g.getACopy()
			p.addVirtualFoldersToGroup(&group)
			group.PrepareForRendering()
			groups = append(groups, group)
			if len(groups) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.groupnames) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			name := p.dbHandle.groupnames[i]
			g := p.dbHandle.groups[name]
			group := g.getACopy()
			p.addVirtualFoldersToGroup(&group)
			group.PrepareForRendering()
			groups = append(groups, group)
			if len(groups) >= limit {
				break
			}
		}
	}
	return groups, nil
}

func (p *MemoryProvider) getGroupsWithNames(names []string) ([]Group, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	groups := make([]Group, 0, len(names))
	for _, name := range names {
		if val, ok := p.dbHandle.groups[name]; ok {
			group := val.getACopy()
			p.addVirtualFoldersToGroup(&group)
			groups = append(groups, group)
		}
	}

	return groups, nil
}

func (p *MemoryProvider) getUsersInGroups(names []string) ([]string, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	var users []string
	for _, name := range names {
		if val, ok := p.dbHandle.groups[name]; ok {
			group := val.getACopy()
			users = append(users, group.Users...)
		}
	}

	return users, nil
}

func (p *MemoryProvider) groupExists(name string) (Group, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return Group{}, errMemoryProviderClosed
	}
	group, err := p.groupExistsInternal(name)
	if err != nil {
		return group, err
	}
	p.addVirtualFoldersToGroup(&group)
	return group, nil
}

func (p *MemoryProvider) addGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err := p.groupExistsInternal(group.Name)
	if err == nil {
		return fmt.Errorf("group %#v already exists", group.Name)
	}
	group.ID = p.getNextGroupID()
	group.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	group.Users = nil
	group.Admins = nil
	group.VirtualFolders = p.joinGroupVirtualFoldersFields(group)
	p.dbHandle.groups[group.Name] = group.getACopy()
	p.dbHandle.groupnames = append(p.dbHandle.groupnames, group.Name)
	sort.Strings(p.dbHandle.groupnames)
	return nil
}

func (p *MemoryProvider) updateGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	g, err := p.groupExistsInternal(group.Name)
	if err != nil {
		return err
	}
	for _, oldFolder := range g.VirtualFolders {
		p.removeRelationFromFolderMapping(oldFolder.Name, "", g.Name)
	}
	group.VirtualFolders = p.joinGroupVirtualFoldersFields(group)
	group.CreatedAt = g.CreatedAt
	group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	group.ID = g.ID
	group.Users = g.Users
	group.Admins = g.Admins
	p.dbHandle.groups[group.Name] = group.getACopy()
	return nil
}

func (p *MemoryProvider) deleteGroup(group Group) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	g, err := p.groupExistsInternal(group.Name)
	if err != nil {
		return err
	}
	if len(g.Users) > 0 {
		return util.NewValidationError(fmt.Sprintf("the group %#v is referenced, it cannot be removed", group.Name))
	}
	for _, oldFolder := range g.VirtualFolders {
		p.removeRelationFromFolderMapping(oldFolder.Name, "", g.Name)
	}
	for _, a := range g.Admins {
		p.removeGroupFromAdminMapping(g.Name, a)
	}
	delete(p.dbHandle.groups, group.Name)
	// this could be more efficient
	p.dbHandle.groupnames = make([]string, 0, len(p.dbHandle.groups))
	for name := range p.dbHandle.groups {
		p.dbHandle.groupnames = append(p.dbHandle.groupnames, name)
	}
	sort.Strings(p.dbHandle.groupnames)
	return nil
}

func (p *MemoryProvider) dumpGroups() ([]Group, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	groups := make([]Group, 0, len(p.dbHandle.groups))
	var err error
	if p.dbHandle.isClosed {
		return groups, errMemoryProviderClosed
	}
	for _, name := range p.dbHandle.groupnames {
		g := p.dbHandle.groups[name]
		group := g.getACopy()
		p.addVirtualFoldersToGroup(&group)
		groups = append(groups, group)
	}
	return groups, err
}

func (p *MemoryProvider) getUsedFolderQuota(name string) (int, int64, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return 0, 0, errMemoryProviderClosed
	}
	folder, err := p.folderExistsInternal(name)
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for folder %#v error: %v", name, err)
		return 0, 0, err
	}
	return folder.UsedQuotaFiles, folder.UsedQuotaSize, err
}

func (p *MemoryProvider) joinGroupVirtualFoldersFields(group *Group) []vfs.VirtualFolder {
	var folders []vfs.VirtualFolder
	for idx := range group.VirtualFolders {
		folder := &group.VirtualFolders[idx]
		f, err := p.addOrUpdateFolderInternal(&folder.BaseVirtualFolder, "", group.Name, 0, 0, 0)
		if err == nil {
			folder.BaseVirtualFolder = f
			folders = append(folders, *folder)
		}
	}
	return folders
}

func (p *MemoryProvider) addVirtualFoldersToGroup(group *Group) {
	if len(group.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range group.VirtualFolders {
			folder := &group.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name)
			if err != nil {
				continue
			}
			folder.BaseVirtualFolder = baseFolder.GetACopy()
			folders = append(folders, *folder)
		}
		group.VirtualFolders = folders
	}
}

func (p *MemoryProvider) addActionsToRule(rule *EventRule) {
	var actions []EventAction
	for idx := range rule.Actions {
		action := &rule.Actions[idx]
		baseAction, err := p.actionExistsInternal(action.Name)
		if err != nil {
			continue
		}
		baseAction.Options.SetEmptySecretsIfNil()
		action.BaseEventAction = baseAction
		actions = append(actions, *action)
	}
	rule.Actions = actions
}

func (p *MemoryProvider) addRuleToActionMapping(ruleName, actionName string) error {
	a, err := p.actionExistsInternal(actionName)
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("action %q does not exist", actionName))
	}
	if !util.Contains(a.Rules, ruleName) {
		a.Rules = append(a.Rules, ruleName)
		p.dbHandle.actions[actionName] = a
	}
	return nil
}

func (p *MemoryProvider) removeRuleFromActionMapping(ruleName, actionName string) {
	a, err := p.actionExistsInternal(actionName)
	if err != nil {
		providerLog(logger.LevelWarn, "action %q does not exist, cannot remove from mapping", actionName)
		return
	}
	if util.Contains(a.Rules, ruleName) {
		var rules []string
		for _, r := range a.Rules {
			if r != ruleName {
				rules = append(rules, r)
			}
		}
		a.Rules = rules
		p.dbHandle.actions[actionName] = a
	}
}

func (p *MemoryProvider) addAdminToGroupMapping(username, groupname string) error {
	g, err := p.groupExistsInternal(groupname)
	if err != nil {
		return err
	}
	if !util.Contains(g.Admins, username) {
		g.Admins = append(g.Admins, username)
		p.dbHandle.groups[groupname] = g
	}
	return nil
}

func (p *MemoryProvider) removeAdminFromGroupMapping(username, groupname string) {
	g, err := p.groupExistsInternal(groupname)
	if err != nil {
		return
	}
	var admins []string
	for _, a := range g.Admins {
		if a != username {
			admins = append(admins, a)
		}
	}
	g.Admins = admins
	p.dbHandle.groups[groupname] = g
}

func (p *MemoryProvider) removeGroupFromAdminMapping(groupname, username string) {
	admin, err := p.adminExistsInternal(username)
	if err != nil {
		// the admin does not exist so there is no associated group
		return
	}
	var newGroups []AdminGroupMapping
	for _, g := range admin.Groups {
		if g.Name != groupname {
			newGroups = append(newGroups, g)
		}
	}
	admin.Groups = newGroups
	p.dbHandle.admins[admin.Username] = admin
}

func (p *MemoryProvider) addUserToGroupMapping(username, groupname string) error {
	g, err := p.groupExistsInternal(groupname)
	if err != nil {
		return err
	}
	if !util.Contains(g.Users, username) {
		g.Users = append(g.Users, username)
		p.dbHandle.groups[groupname] = g
	}
	return nil
}

func (p *MemoryProvider) removeUserFromGroupMapping(username, groupname string) {
	g, err := p.groupExistsInternal(groupname)
	if err != nil {
		return
	}
	var users []string
	for _, u := range g.Users {
		if u != username {
			users = append(users, u)
		}
	}
	g.Users = users
	p.dbHandle.groups[groupname] = g
}

func (p *MemoryProvider) joinUserVirtualFoldersFields(user *User) []vfs.VirtualFolder {
	var folders []vfs.VirtualFolder
	for idx := range user.VirtualFolders {
		folder := &user.VirtualFolders[idx]
		f, err := p.addOrUpdateFolderInternal(&folder.BaseVirtualFolder, user.Username, "", 0, 0, 0)
		if err == nil {
			folder.BaseVirtualFolder = f
			folders = append(folders, *folder)
		}
	}
	return folders
}

func (p *MemoryProvider) addVirtualFoldersToUser(user *User) {
	if len(user.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range user.VirtualFolders {
			folder := &user.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name)
			if err != nil {
				continue
			}
			folder.BaseVirtualFolder = baseFolder.GetACopy()
			folders = append(folders, *folder)
		}
		user.VirtualFolders = folders
	}
}

func (p *MemoryProvider) removeRelationFromFolderMapping(folderName, username, groupname string) {
	folder, err := p.folderExistsInternal(folderName)
	if err == nil {
		if username != "" {
			var usernames []string
			for _, user := range folder.Users {
				if user != username {
					usernames = append(usernames, user)
				}
			}
			folder.Users = usernames
		}
		if groupname != "" {
			var groups []string
			for _, group := range folder.Groups {
				if group != groupname {
					groups = append(groups, group)
				}
			}
			folder.Groups = groups
		}
		p.dbHandle.vfolders[folder.Name] = folder
	}
}

func (p *MemoryProvider) updateFoldersMappingInternal(folder vfs.BaseVirtualFolder) {
	p.dbHandle.vfolders[folder.Name] = folder
	if !util.Contains(p.dbHandle.vfoldersNames, folder.Name) {
		p.dbHandle.vfoldersNames = append(p.dbHandle.vfoldersNames, folder.Name)
		sort.Strings(p.dbHandle.vfoldersNames)
	}
}

func (p *MemoryProvider) addOrUpdateFolderInternal(baseFolder *vfs.BaseVirtualFolder, username, groupname string,
	usedQuotaSize int64, usedQuotaFiles int, lastQuotaUpdate int64,
) (vfs.BaseVirtualFolder, error) {
	folder, err := p.folderExistsInternal(baseFolder.Name)
	if err == nil {
		// exists
		folder.MappedPath = baseFolder.MappedPath
		folder.Description = baseFolder.Description
		folder.FsConfig = baseFolder.FsConfig.GetACopy()
		if username != "" && !util.Contains(folder.Users, username) {
			folder.Users = append(folder.Users, username)
		}
		if groupname != "" && !util.Contains(folder.Groups, groupname) {
			folder.Groups = append(folder.Groups, groupname)
		}
		p.updateFoldersMappingInternal(folder)
		return folder, nil
	}
	if _, ok := err.(*util.RecordNotFoundError); ok {
		folder = baseFolder.GetACopy()
		folder.ID = p.getNextFolderID()
		folder.UsedQuotaSize = usedQuotaSize
		folder.UsedQuotaFiles = usedQuotaFiles
		folder.LastQuotaUpdate = lastQuotaUpdate
		if username != "" {
			folder.Users = []string{username}
		}
		if groupname != "" {
			folder.Groups = []string{groupname}
		}
		p.updateFoldersMappingInternal(folder)
		return folder, nil
	}
	return folder, err
}

func (p *MemoryProvider) folderExistsInternal(name string) (vfs.BaseVirtualFolder, error) {
	if val, ok := p.dbHandle.vfolders[name]; ok {
		return val, nil
	}
	return vfs.BaseVirtualFolder{}, util.NewRecordNotFoundError(fmt.Sprintf("folder %#v does not exist", name))
}

func (p *MemoryProvider) getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	var err error
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return folders, errMemoryProviderClosed
	}
	if limit <= 0 {
		return folders, err
	}
	itNum := 0
	if order == OrderASC {
		for _, name := range p.dbHandle.vfoldersNames {
			itNum++
			if itNum <= offset {
				continue
			}
			f := p.dbHandle.vfolders[name]
			folder := f.GetACopy()
			folder.PrepareForRendering()
			folders = append(folders, folder)
			if len(folders) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.vfoldersNames) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			name := p.dbHandle.vfoldersNames[i]
			f := p.dbHandle.vfolders[name]
			folder := f.GetACopy()
			folder.PrepareForRendering()
			folders = append(folders, folder)
			if len(folders) >= limit {
				break
			}
		}
	}
	return folders, err
}

func (p *MemoryProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return vfs.BaseVirtualFolder{}, errMemoryProviderClosed
	}
	folder, err := p.folderExistsInternal(name)
	if err != nil {
		return vfs.BaseVirtualFolder{}, err
	}
	return folder.GetACopy(), nil
}

func (p *MemoryProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	err := ValidateFolder(folder)
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err = p.folderExistsInternal(folder.Name)
	if err == nil {
		return fmt.Errorf("folder %#v already exists", folder.Name)
	}
	folder.ID = p.getNextFolderID()
	folder.Users = nil
	folder.Groups = nil
	p.dbHandle.vfolders[folder.Name] = folder.GetACopy()
	p.dbHandle.vfoldersNames = append(p.dbHandle.vfoldersNames, folder.Name)
	sort.Strings(p.dbHandle.vfoldersNames)
	return nil
}

func (p *MemoryProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	err := ValidateFolder(folder)
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	f, err := p.folderExistsInternal(folder.Name)
	if err != nil {
		return err
	}
	folder.ID = f.ID
	folder.LastQuotaUpdate = f.LastQuotaUpdate
	folder.UsedQuotaFiles = f.UsedQuotaFiles
	folder.UsedQuotaSize = f.UsedQuotaSize
	folder.Users = f.Users
	folder.Groups = f.Groups
	p.dbHandle.vfolders[folder.Name] = folder.GetACopy()
	// now update the related users
	for _, username := range folder.Users {
		user, err := p.userExistsInternal(username)
		if err == nil {
			var folders []vfs.VirtualFolder
			for idx := range user.VirtualFolders {
				userFolder := &user.VirtualFolders[idx]
				if folder.Name == userFolder.Name {
					userFolder.BaseVirtualFolder = folder.GetACopy()
				}
				folders = append(folders, *userFolder)
			}
			user.VirtualFolders = folders
			p.dbHandle.users[user.Username] = user
		}
	}
	return nil
}

func (p *MemoryProvider) deleteFolder(f vfs.BaseVirtualFolder) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	folder, err := p.folderExistsInternal(f.Name)
	if err != nil {
		return err
	}
	for _, username := range folder.Users {
		user, err := p.userExistsInternal(username)
		if err == nil {
			var folders []vfs.VirtualFolder
			for idx := range user.VirtualFolders {
				userFolder := &user.VirtualFolders[idx]
				if folder.Name != userFolder.Name {
					folders = append(folders, *userFolder)
				}
			}
			user.VirtualFolders = folders
			p.dbHandle.users[user.Username] = user
		}
	}
	for _, groupname := range folder.Groups {
		group, err := p.groupExistsInternal(groupname)
		if err == nil {
			var folders []vfs.VirtualFolder
			for idx := range group.VirtualFolders {
				groupFolder := &group.VirtualFolders[idx]
				if folder.Name != groupFolder.Name {
					folders = append(folders, *groupFolder)
				}
			}
			group.VirtualFolders = folders
			p.dbHandle.groups[group.Name] = group
		}
	}
	delete(p.dbHandle.vfolders, folder.Name)
	p.dbHandle.vfoldersNames = []string{}
	for name := range p.dbHandle.vfolders {
		p.dbHandle.vfoldersNames = append(p.dbHandle.vfoldersNames, name)
	}
	sort.Strings(p.dbHandle.vfoldersNames)
	return nil
}

func (p *MemoryProvider) apiKeyExistsInternal(keyID string) (APIKey, error) {
	if val, ok := p.dbHandle.apiKeys[keyID]; ok {
		return val.getACopy(), nil
	}
	return APIKey{}, util.NewRecordNotFoundError(fmt.Sprintf("API key %#v does not exist", keyID))
}

func (p *MemoryProvider) apiKeyExists(keyID string) (APIKey, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return APIKey{}, errMemoryProviderClosed
	}
	return p.apiKeyExistsInternal(keyID)
}

func (p *MemoryProvider) addAPIKey(apiKey *APIKey) error {
	err := apiKey.validate()
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err = p.apiKeyExistsInternal(apiKey.KeyID)
	if err == nil {
		return fmt.Errorf("API key %#v already exists", apiKey.KeyID)
	}
	if apiKey.User != "" {
		if _, err := p.userExistsInternal(apiKey.User); err != nil {
			return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", apiKey.User))
		}
	}
	if apiKey.Admin != "" {
		if _, err := p.adminExistsInternal(apiKey.Admin); err != nil {
			return util.NewValidationError(fmt.Sprintf("related admin %#v does not exists", apiKey.User))
		}
	}
	apiKey.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	apiKey.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	apiKey.LastUseAt = 0
	p.dbHandle.apiKeys[apiKey.KeyID] = apiKey.getACopy()
	p.dbHandle.apiKeysIDs = append(p.dbHandle.apiKeysIDs, apiKey.KeyID)
	sort.Strings(p.dbHandle.apiKeysIDs)
	return nil
}

func (p *MemoryProvider) updateAPIKey(apiKey *APIKey) error {
	err := apiKey.validate()
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	k, err := p.apiKeyExistsInternal(apiKey.KeyID)
	if err != nil {
		return err
	}
	if apiKey.User != "" {
		if _, err := p.userExistsInternal(apiKey.User); err != nil {
			return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", apiKey.User))
		}
	}
	if apiKey.Admin != "" {
		if _, err := p.adminExistsInternal(apiKey.Admin); err != nil {
			return util.NewValidationError(fmt.Sprintf("related admin %#v does not exists", apiKey.User))
		}
	}
	apiKey.ID = k.ID
	apiKey.KeyID = k.KeyID
	apiKey.Key = k.Key
	apiKey.CreatedAt = k.CreatedAt
	apiKey.LastUseAt = k.LastUseAt
	apiKey.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.apiKeys[apiKey.KeyID] = apiKey.getACopy()
	return nil
}

func (p *MemoryProvider) deleteAPIKey(apiKey APIKey) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err := p.apiKeyExistsInternal(apiKey.KeyID)
	if err != nil {
		return err
	}

	delete(p.dbHandle.apiKeys, apiKey.KeyID)
	p.updateAPIKeysOrdering()

	return nil
}

func (p *MemoryProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, limit)

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return apiKeys, errMemoryProviderClosed
	}
	if limit <= 0 {
		return apiKeys, nil
	}
	itNum := 0
	if order == OrderDESC {
		for i := len(p.dbHandle.apiKeysIDs) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			keyID := p.dbHandle.apiKeysIDs[i]
			k := p.dbHandle.apiKeys[keyID]
			apiKey := k.getACopy()
			apiKey.HideConfidentialData()
			apiKeys = append(apiKeys, apiKey)
			if len(apiKeys) >= limit {
				break
			}
		}
	} else {
		for _, keyID := range p.dbHandle.apiKeysIDs {
			itNum++
			if itNum <= offset {
				continue
			}
			k := p.dbHandle.apiKeys[keyID]
			apiKey := k.getACopy()
			apiKey.HideConfidentialData()
			apiKeys = append(apiKeys, apiKey)
			if len(apiKeys) >= limit {
				break
			}
		}
	}

	return apiKeys, nil
}

func (p *MemoryProvider) dumpAPIKeys() ([]APIKey, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	apiKeys := make([]APIKey, 0, len(p.dbHandle.apiKeys))
	if p.dbHandle.isClosed {
		return apiKeys, errMemoryProviderClosed
	}
	for _, k := range p.dbHandle.apiKeys {
		apiKeys = append(apiKeys, k)
	}
	return apiKeys, nil
}

func (p *MemoryProvider) deleteAPIKeysWithUser(username string) {
	found := false
	for k, v := range p.dbHandle.apiKeys {
		if v.User == username {
			delete(p.dbHandle.apiKeys, k)
			found = true
		}
	}
	if found {
		p.updateAPIKeysOrdering()
	}
}

func (p *MemoryProvider) deleteAPIKeysWithAdmin(username string) {
	found := false
	for k, v := range p.dbHandle.apiKeys {
		if v.Admin == username {
			delete(p.dbHandle.apiKeys, k)
			found = true
		}
	}
	if found {
		p.updateAPIKeysOrdering()
	}
}

func (p *MemoryProvider) deleteSharesWithUser(username string) {
	found := false
	for k, v := range p.dbHandle.shares {
		if v.Username == username {
			delete(p.dbHandle.shares, k)
			found = true
		}
	}
	if found {
		p.updateSharesOrdering()
	}
}

func (p *MemoryProvider) updateAPIKeysOrdering() {
	// this could be more efficient
	p.dbHandle.apiKeysIDs = make([]string, 0, len(p.dbHandle.apiKeys))
	for keyID := range p.dbHandle.apiKeys {
		p.dbHandle.apiKeysIDs = append(p.dbHandle.apiKeysIDs, keyID)
	}
	sort.Strings(p.dbHandle.apiKeysIDs)
}

func (p *MemoryProvider) updateSharesOrdering() {
	// this could be more efficient
	p.dbHandle.sharesIDs = make([]string, 0, len(p.dbHandle.shares))
	for shareID := range p.dbHandle.shares {
		p.dbHandle.sharesIDs = append(p.dbHandle.sharesIDs, shareID)
	}
	sort.Strings(p.dbHandle.sharesIDs)
}

func (p *MemoryProvider) shareExistsInternal(shareID, username string) (Share, error) {
	if val, ok := p.dbHandle.shares[shareID]; ok {
		if username != "" && val.Username != username {
			return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %#v does not exist", shareID))
		}
		return val.getACopy(), nil
	}
	return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %#v does not exist", shareID))
}

func (p *MemoryProvider) shareExists(shareID, username string) (Share, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return Share{}, errMemoryProviderClosed
	}
	return p.shareExistsInternal(shareID, username)
}

func (p *MemoryProvider) addShare(share *Share) error {
	err := share.validate()
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err = p.shareExistsInternal(share.ShareID, share.Username)
	if err == nil {
		return fmt.Errorf("share %#v already exists", share.ShareID)
	}
	if _, err := p.userExistsInternal(share.Username); err != nil {
		return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", share.Username))
	}
	if !share.IsRestore {
		share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		share.UpdatedAt = share.CreatedAt
		share.LastUseAt = 0
		share.UsedTokens = 0
	}
	if share.CreatedAt == 0 {
		share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	if share.UpdatedAt == 0 {
		share.UpdatedAt = share.CreatedAt
	}
	p.dbHandle.shares[share.ShareID] = share.getACopy()
	p.dbHandle.sharesIDs = append(p.dbHandle.sharesIDs, share.ShareID)
	sort.Strings(p.dbHandle.sharesIDs)
	return nil
}

func (p *MemoryProvider) updateShare(share *Share) error {
	err := share.validate()
	if err != nil {
		return err
	}

	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	s, err := p.shareExistsInternal(share.ShareID, share.Username)
	if err != nil {
		return err
	}
	if _, err := p.userExistsInternal(share.Username); err != nil {
		return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", share.Username))
	}
	share.ID = s.ID
	share.ShareID = s.ShareID
	if !share.IsRestore {
		share.UsedTokens = s.UsedTokens
		share.CreatedAt = s.CreatedAt
		share.LastUseAt = s.LastUseAt
		share.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	if share.CreatedAt == 0 {
		share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	if share.UpdatedAt == 0 {
		share.UpdatedAt = share.CreatedAt
	}
	p.dbHandle.shares[share.ShareID] = share.getACopy()
	return nil
}

func (p *MemoryProvider) deleteShare(share Share) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err := p.shareExistsInternal(share.ShareID, share.Username)
	if err != nil {
		return err
	}

	delete(p.dbHandle.shares, share.ShareID)
	p.updateSharesOrdering()

	return nil
}

func (p *MemoryProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return []Share{}, errMemoryProviderClosed
	}
	if limit <= 0 {
		return []Share{}, nil
	}
	shares := make([]Share, 0, limit)
	itNum := 0
	if order == OrderDESC {
		for i := len(p.dbHandle.sharesIDs) - 1; i >= 0; i-- {
			shareID := p.dbHandle.sharesIDs[i]
			s := p.dbHandle.shares[shareID]
			if s.Username != username {
				continue
			}
			itNum++
			if itNum <= offset {
				continue
			}
			share := s.getACopy()
			share.HideConfidentialData()
			shares = append(shares, share)
			if len(shares) >= limit {
				break
			}
		}
	} else {
		for _, shareID := range p.dbHandle.sharesIDs {
			s := p.dbHandle.shares[shareID]
			if s.Username != username {
				continue
			}
			itNum++
			if itNum <= offset {
				continue
			}
			share := s.getACopy()
			share.HideConfidentialData()
			shares = append(shares, share)
			if len(shares) >= limit {
				break
			}
		}
	}

	return shares, nil
}

func (p *MemoryProvider) dumpShares() ([]Share, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	shares := make([]Share, 0, len(p.dbHandle.shares))
	if p.dbHandle.isClosed {
		return shares, errMemoryProviderClosed
	}
	for _, s := range p.dbHandle.shares {
		shares = append(shares, s)
	}
	return shares, nil
}

func (p *MemoryProvider) updateShareLastUse(shareID string, numTokens int) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	share, err := p.shareExistsInternal(shareID, "")
	if err != nil {
		return err
	}
	share.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
	share.UsedTokens += numTokens
	p.dbHandle.shares[share.ShareID] = share
	return nil
}

func (p *MemoryProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return nil, ErrNotImplemented
}

func (p *MemoryProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *MemoryProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *MemoryProvider) updateDefenderBanTime(ip string, minutes int) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) deleteDefenderHost(ip string) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) addDefenderEvent(ip string, score int) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) setDefenderBanTime(ip string, banTime int64) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) cleanupDefender(from int64) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) addActiveTransfer(transfer ActiveTransfer) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) removeActiveTransfer(transferID int64, connectionID string) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) cleanupActiveTransfers(before time.Time) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return nil, ErrNotImplemented
}

func (p *MemoryProvider) addSharedSession(session Session) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) deleteSharedSession(key string) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) getSharedSession(key string) (Session, error) {
	return Session{}, ErrNotImplemented
}

func (p *MemoryProvider) cleanupSharedSessions(sessionType SessionType, before int64) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	if limit <= 0 {
		return nil, nil
	}
	actions := make([]BaseEventAction, 0, limit)
	itNum := 0
	if order == OrderASC {
		for _, name := range p.dbHandle.actionsNames {
			itNum++
			if itNum <= offset {
				continue
			}
			a := p.dbHandle.actions[name]
			action := a.getACopy()
			action.PrepareForRendering()
			actions = append(actions, action)
			if len(actions) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.actionsNames) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			name := p.dbHandle.actionsNames[i]
			a := p.dbHandle.actions[name]
			action := a.getACopy()
			action.PrepareForRendering()
			actions = append(actions, action)
			if len(actions) >= limit {
				break
			}
		}
	}
	return actions, nil
}

func (p *MemoryProvider) dumpEventActions() ([]BaseEventAction, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	actions := make([]BaseEventAction, 0, len(p.dbHandle.actions))
	for _, name := range p.dbHandle.actionsNames {
		a := p.dbHandle.actions[name]
		action := a.getACopy()
		actions = append(actions, action)
	}
	return actions, nil
}

func (p *MemoryProvider) eventActionExists(name string) (BaseEventAction, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return BaseEventAction{}, errMemoryProviderClosed
	}
	return p.actionExistsInternal(name)
}

func (p *MemoryProvider) addEventAction(action *BaseEventAction) error {
	err := action.validate()
	if err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err = p.actionExistsInternal(action.Name)
	if err == nil {
		return fmt.Errorf("event action %q already exists", action.Name)
	}
	action.ID = p.getNextActionID()
	action.Rules = nil
	p.dbHandle.actions[action.Name] = action.getACopy()
	p.dbHandle.actionsNames = append(p.dbHandle.actionsNames, action.Name)
	sort.Strings(p.dbHandle.actionsNames)
	return nil
}

func (p *MemoryProvider) updateEventAction(action *BaseEventAction) error {
	err := action.validate()
	if err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	oldAction, err := p.actionExistsInternal(action.Name)
	if err != nil {
		return fmt.Errorf("event action %s does not exist", action.Name)
	}
	action.ID = oldAction.ID
	action.Name = oldAction.Name
	action.Rules = nil
	if len(oldAction.Rules) > 0 {
		var relatedRules []string
		for _, ruleName := range oldAction.Rules {
			rule, err := p.ruleExistsInternal(ruleName)
			if err == nil {
				relatedRules = append(relatedRules, ruleName)
				rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
				p.dbHandle.rules[ruleName] = rule
				setLastRuleUpdate()
			}
		}
		action.Rules = relatedRules
	}
	p.dbHandle.actions[action.Name] = action.getACopy()
	return nil
}

func (p *MemoryProvider) deleteEventAction(action BaseEventAction) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	oldAction, err := p.actionExistsInternal(action.Name)
	if err != nil {
		return fmt.Errorf("event action %s does not exist", action.Name)
	}
	if len(oldAction.Rules) > 0 {
		return util.NewValidationError(fmt.Sprintf("action %s is referenced, it cannot be removed", oldAction.Name))
	}
	delete(p.dbHandle.actions, action.Name)
	// this could be more efficient
	p.dbHandle.actionsNames = make([]string, 0, len(p.dbHandle.actions))
	for name := range p.dbHandle.actions {
		p.dbHandle.actionsNames = append(p.dbHandle.actionsNames, name)
	}
	sort.Strings(p.dbHandle.actionsNames)
	return nil
}

func (p *MemoryProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	if limit <= 0 {
		return nil, nil
	}
	itNum := 0
	rules := make([]EventRule, 0, limit)
	if order == OrderASC {
		for _, name := range p.dbHandle.rulesNames {
			itNum++
			if itNum <= offset {
				continue
			}
			r := p.dbHandle.rules[name]
			rule := r.getACopy()
			p.addActionsToRule(&rule)
			rule.PrepareForRendering()
			rules = append(rules, rule)
			if len(rules) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.rulesNames) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			name := p.dbHandle.rulesNames[i]
			r := p.dbHandle.rules[name]
			rule := r.getACopy()
			p.addActionsToRule(&rule)
			rule.PrepareForRendering()
			rules = append(rules, rule)
			if len(rules) >= limit {
				break
			}
		}
	}
	return rules, nil
}

func (p *MemoryProvider) dumpEventRules() ([]EventRule, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	rules := make([]EventRule, 0, len(p.dbHandle.rules))
	for _, name := range p.dbHandle.rulesNames {
		r := p.dbHandle.rules[name]
		rule := r.getACopy()
		p.addActionsToRule(&rule)
		rules = append(rules, rule)
	}
	return rules, nil
}

func (p *MemoryProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	if getLastRuleUpdate() < after {
		return nil, nil
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	rules := make([]EventRule, 0, 10)
	for _, name := range p.dbHandle.rulesNames {
		r := p.dbHandle.rules[name]
		if r.UpdatedAt < after {
			continue
		}
		rule := r.getACopy()
		p.addActionsToRule(&rule)
		rules = append(rules, rule)
	}
	return rules, nil
}

func (p *MemoryProvider) eventRuleExists(name string) (EventRule, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return EventRule{}, errMemoryProviderClosed
	}
	rule, err := p.ruleExistsInternal(name)
	if err != nil {
		return rule, err
	}
	p.addActionsToRule(&rule)
	return rule, nil
}

func (p *MemoryProvider) addEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err := p.ruleExistsInternal(rule.Name)
	if err == nil {
		return fmt.Errorf("event rule %q already exists", rule.Name)
	}
	rule.ID = p.getNextRuleID()
	rule.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	rule.UpdatedAt = rule.CreatedAt
	var mappedActions []string
	for idx := range rule.Actions {
		if err := p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name); err != nil {
			// try to remove action mapping
			for _, a := range mappedActions {
				p.removeRuleFromActionMapping(rule.Name, a)
			}
			return err
		}
		mappedActions = append(mappedActions, rule.Actions[idx].Name)
	}
	sort.Slice(rule.Actions, func(i, j int) bool {
		return rule.Actions[i].Order < rule.Actions[j].Order
	})
	p.dbHandle.rules[rule.Name] = rule.getACopy()
	p.dbHandle.rulesNames = append(p.dbHandle.rulesNames, rule.Name)
	sort.Strings(p.dbHandle.rulesNames)
	setLastRuleUpdate()
	return nil
}

func (p *MemoryProvider) updateEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	oldRule, err := p.ruleExistsInternal(rule.Name)
	if err != nil {
		return err
	}
	for idx := range oldRule.Actions {
		p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name)
	}
	for idx := range rule.Actions {
		if err = p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name); err != nil {
			// try to add old mapping
			for _, oldAction := range oldRule.Actions {
				if errRollback := p.addRuleToActionMapping(oldRule.Name, oldAction.Name); errRollback != nil {
					providerLog(logger.LevelError, "unable to rollback old action mapping %q for rule %q, error: %v",
						oldAction.Name, oldRule.Name, errRollback)
				}
			}
			return err
		}
	}
	rule.ID = oldRule.ID
	rule.CreatedAt = oldRule.CreatedAt
	rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	sort.Slice(rule.Actions, func(i, j int) bool {
		return rule.Actions[i].Order < rule.Actions[j].Order
	})
	p.dbHandle.rules[rule.Name] = rule.getACopy()
	setLastRuleUpdate()
	return nil
}

func (p *MemoryProvider) deleteEventRule(rule EventRule, softDelete bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	oldRule, err := p.ruleExistsInternal(rule.Name)
	if err != nil {
		return err
	}
	if len(oldRule.Actions) > 0 {
		for idx := range oldRule.Actions {
			p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name)
		}
	}
	delete(p.dbHandle.rules, rule.Name)
	p.dbHandle.rulesNames = make([]string, 0, len(p.dbHandle.rules))
	for name := range p.dbHandle.rules {
		p.dbHandle.rulesNames = append(p.dbHandle.rulesNames, name)
	}
	sort.Strings(p.dbHandle.rulesNames)
	setLastRuleUpdate()
	return nil
}

func (*MemoryProvider) getTaskByName(name string) (Task, error) {
	return Task{}, ErrNotImplemented
}

func (*MemoryProvider) addTask(name string) error {
	return ErrNotImplemented
}

func (*MemoryProvider) updateTask(name string, version int64) error {
	return ErrNotImplemented
}

func (*MemoryProvider) updateTaskTimestamp(name string) error {
	return ErrNotImplemented
}

func (*MemoryProvider) addNode() error {
	return ErrNotImplemented
}

func (*MemoryProvider) getNodeByName(name string) (Node, error) {
	return Node{}, ErrNotImplemented
}

func (*MemoryProvider) getNodes() ([]Node, error) {
	return nil, ErrNotImplemented
}

func (*MemoryProvider) updateNodeTimestamp() error {
	return ErrNotImplemented
}

func (*MemoryProvider) cleanupNodes() error {
	return ErrNotImplemented
}

func (p *MemoryProvider) setFirstDownloadTimestamp(username string) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return err
	}
	if user.FirstDownload > 0 {
		return util.NewGenericError(fmt.Sprintf("first download already set to %v",
			util.GetTimeFromMsecSinceEpoch(user.FirstDownload)))
	}
	user.FirstDownload = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p *MemoryProvider) setFirstUploadTimestamp(username string) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return err
	}
	if user.FirstUpload > 0 {
		return util.NewGenericError(fmt.Sprintf("first upload already set to %v",
			util.GetTimeFromMsecSinceEpoch(user.FirstUpload)))
	}
	user.FirstUpload = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p *MemoryProvider) getNextID() int64 {
	nextID := int64(1)
	for _, v := range p.dbHandle.users {
		if v.ID >= nextID {
			nextID = v.ID + 1
		}
	}
	return nextID
}

func (p *MemoryProvider) getNextFolderID() int64 {
	nextID := int64(1)
	for _, v := range p.dbHandle.vfolders {
		if v.ID >= nextID {
			nextID = v.ID + 1
		}
	}
	return nextID
}

func (p *MemoryProvider) getNextAdminID() int64 {
	nextID := int64(1)
	for _, a := range p.dbHandle.admins {
		if a.ID >= nextID {
			nextID = a.ID + 1
		}
	}
	return nextID
}

func (p *MemoryProvider) getNextGroupID() int64 {
	nextID := int64(1)
	for _, g := range p.dbHandle.groups {
		if g.ID >= nextID {
			nextID = g.ID + 1
		}
	}
	return nextID
}

func (p *MemoryProvider) getNextActionID() int64 {
	nextID := int64(1)
	for _, a := range p.dbHandle.actions {
		if a.ID >= nextID {
			nextID = a.ID + 1
		}
	}
	return nextID
}

func (p *MemoryProvider) getNextRuleID() int64 {
	nextID := int64(1)
	for _, r := range p.dbHandle.rules {
		if r.ID >= nextID {
			nextID = r.ID + 1
		}
	}
	return nextID
}

func (p *MemoryProvider) clear() {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	p.dbHandle.usernames = []string{}
	p.dbHandle.users = make(map[string]User)
	p.dbHandle.vfoldersNames = []string{}
	p.dbHandle.vfolders = make(map[string]vfs.BaseVirtualFolder)
	p.dbHandle.admins = make(map[string]Admin)
	p.dbHandle.adminsUsernames = []string{}
	p.dbHandle.apiKeys = make(map[string]APIKey)
	p.dbHandle.apiKeysIDs = []string{}
	p.dbHandle.shares = make(map[string]Share)
	p.dbHandle.sharesIDs = []string{}
}

func (p *MemoryProvider) reloadConfig() error {
	if p.dbHandle.configFile == "" {
		providerLog(logger.LevelDebug, "no dump configuration file defined")
		return nil
	}
	providerLog(logger.LevelDebug, "loading dump from file: %#v", p.dbHandle.configFile)
	fi, err := os.Stat(p.dbHandle.configFile)
	if err != nil {
		providerLog(logger.LevelError, "error loading dump: %v", err)
		return err
	}
	if fi.Size() == 0 {
		err = errors.New("dump configuration file is invalid, its size must be > 0")
		providerLog(logger.LevelError, "error loading dump: %v", err)
		return err
	}
	if fi.Size() > 10485760 {
		err = errors.New("dump configuration file is invalid, its size must be <= 10485760 bytes")
		providerLog(logger.LevelError, "error loading dump: %v", err)
		return err
	}
	content, err := os.ReadFile(p.dbHandle.configFile)
	if err != nil {
		providerLog(logger.LevelError, "error loading dump: %v", err)
		return err
	}
	dump, err := ParseDumpData(content)
	if err != nil {
		providerLog(logger.LevelError, "error loading dump: %v", err)
		return err
	}
	p.clear()

	if err := p.restoreFolders(dump); err != nil {
		return err
	}

	if err := p.restoreGroups(dump); err != nil {
		return err
	}

	if err := p.restoreUsers(dump); err != nil {
		return err
	}

	if err := p.restoreAdmins(dump); err != nil {
		return err
	}

	if err := p.restoreAPIKeys(dump); err != nil {
		return err
	}

	if err := p.restoreShares(dump); err != nil {
		return err
	}

	if err := p.restoreEventActions(dump); err != nil {
		return err
	}

	if err := p.restoreEventRules(dump); err != nil {
		return err
	}

	providerLog(logger.LevelDebug, "config loaded from file: %#v", p.dbHandle.configFile)
	return nil
}

func (p *MemoryProvider) restoreEventActions(dump BackupData) error {
	for _, action := range dump.EventActions {
		a, err := p.eventActionExists(action.Name)
		action := action // pin
		if err == nil {
			action.ID = a.ID
			err = UpdateEventAction(&action, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating event action %q: %v", action.Name, err)
				return err
			}
		} else {
			err = AddEventAction(&action, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding event action %q: %v", action.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreEventRules(dump BackupData) error {
	for _, rule := range dump.EventRules {
		r, err := p.eventRuleExists(rule.Name)
		rule := rule // pin
		if err == nil {
			rule.ID = r.ID
			err = UpdateEventRule(&rule, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating event rule %q: %v", rule.Name, err)
				return err
			}
		} else {
			err = AddEventRule(&rule, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding event rule %q: %v", rule.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreShares(dump BackupData) error {
	for _, share := range dump.Shares {
		s, err := p.shareExists(share.ShareID, "")
		share := share // pin
		share.IsRestore = true
		if err == nil {
			share.ID = s.ID
			err = UpdateShare(&share, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating share %#v: %v", share.ShareID, err)
				return err
			}
		} else {
			err = AddShare(&share, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding share %#v: %v", share.ShareID, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreAPIKeys(dump BackupData) error {
	for _, apiKey := range dump.APIKeys {
		if apiKey.Key == "" {
			return fmt.Errorf("cannot restore an empty API key: %+v", apiKey)
		}
		k, err := p.apiKeyExists(apiKey.KeyID)
		apiKey := apiKey // pin
		if err == nil {
			apiKey.ID = k.ID
			err = UpdateAPIKey(&apiKey, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating API key %#v: %v", apiKey.KeyID, err)
				return err
			}
		} else {
			err = AddAPIKey(&apiKey, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding API key %#v: %v", apiKey.KeyID, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreAdmins(dump BackupData) error {
	for _, admin := range dump.Admins {
		admin := admin // pin
		admin.Username = config.convertName(admin.Username)
		a, err := p.adminExists(admin.Username)
		if err == nil {
			admin.ID = a.ID
			err = UpdateAdmin(&admin, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating admin %#v: %v", admin.Username, err)
				return err
			}
		} else {
			err = AddAdmin(&admin, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding admin %#v: %v", admin.Username, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreGroups(dump BackupData) error {
	for _, group := range dump.Groups {
		group := group // pin
		group.Name = config.convertName(group.Name)
		g, err := p.groupExists(group.Name)
		if err == nil {
			group.ID = g.ID
			err = UpdateGroup(&group, g.Users, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating group %#v: %v", group.Name, err)
				return err
			}
		} else {
			group.Users = nil
			err = AddGroup(&group, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding group %#v: %v", group.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreFolders(dump BackupData) error {
	for _, folder := range dump.Folders {
		folder := folder // pin
		folder.Name = config.convertName(folder.Name)
		f, err := p.getFolderByName(folder.Name)
		if err == nil {
			folder.ID = f.ID
			err = UpdateFolder(&folder, f.Users, f.Groups, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating folder %#v: %v", folder.Name, err)
				return err
			}
		} else {
			folder.Users = nil
			err = AddFolder(&folder, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding folder %#v: %v", folder.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreUsers(dump BackupData) error {
	for _, user := range dump.Users {
		user := user // pin
		user.Username = config.convertName(user.Username)
		u, err := p.userExists(user.Username)
		if err == nil {
			user.ID = u.ID
			err = UpdateUser(&user, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating user %#v: %v", user.Username, err)
				return err
			}
		} else {
			err = AddUser(&user, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error adding user %#v: %v", user.Username, err)
				return err
			}
		}
	}
	return nil
}

// initializeDatabase does nothing, no initilization is needed for memory provider
func (p *MemoryProvider) initializeDatabase() error {
	return ErrNoInitRequired
}

func (p *MemoryProvider) migrateDatabase() error {
	return ErrNoInitRequired
}

func (p *MemoryProvider) revertDatabase(targetVersion int) error {
	return errors.New("memory provider does not store data, revert not possible")
}

func (p *MemoryProvider) resetDatabase() error {
	return errors.New("memory provider does not store data, reset not possible")
}
