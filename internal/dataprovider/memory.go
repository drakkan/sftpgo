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

package dataprovider

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
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
	// map for roles, name is the key
	roles map[string]Role
	// slice with ordered roles
	roleNames []string
	// map for IP List entry
	ipListEntries map[string]IPListEntry
	// slice with ordered IP list entries
	ipListEntriesKeys []string
	// configurations
	configs Configs
}

// MemoryProvider defines the auth provider for a memory store
type MemoryProvider struct {
	dbHandle *memoryProviderHandle
}

func initializeMemoryProvider(basePath string) error {
	configFile := ""
	if util.IsFileInputValid(config.Name) {
		configFile = config.Name
		if !filepath.IsAbs(configFile) {
			configFile = filepath.Join(basePath, configFile)
		}
	}
	provider = &MemoryProvider{
		dbHandle: &memoryProviderHandle{
			isClosed:          false,
			usernames:         []string{},
			users:             make(map[string]User),
			groupnames:        []string{},
			groups:            make(map[string]Group),
			vfolders:          make(map[string]vfs.BaseVirtualFolder),
			vfoldersNames:     []string{},
			admins:            make(map[string]Admin),
			adminsUsernames:   []string{},
			apiKeys:           make(map[string]APIKey),
			apiKeysIDs:        []string{},
			shares:            make(map[string]Share),
			sharesIDs:         []string{},
			actions:           make(map[string]BaseEventAction),
			actionsNames:      []string{},
			rules:             make(map[string]EventRule),
			rulesNames:        []string{},
			roles:             map[string]Role{},
			roleNames:         []string{},
			ipListEntries:     map[string]IPListEntry{},
			ipListEntriesKeys: []string{},
			configs:           Configs{},
			configFile:        configFile,
		},
	}
	return provider.reloadConfig()
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
	user, err := p.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}
	return checkUserAndTLSCertificate(&user, protocol, tlsCert)
}

func (p *MemoryProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	user, err := p.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}
	return checkUserAndPass(&user, password, ip, protocol)
}

func (p *MemoryProvider) validateUserAndPubKey(username string, pubKey []byte, isSSHCert bool) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}
	user, err := p.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey, isSSHCert)
}

func (p *MemoryProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	admin, err := p.adminExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating admin %q: %v", username, err)
		return admin, err
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

func (p *MemoryProvider) getAdminSignature(username string) (string, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return "", errMemoryProviderClosed
	}
	admin, err := p.adminExistsInternal(username)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(admin.UpdatedAt, 10), nil
}

func (p *MemoryProvider) getUserSignature(username string) (string, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return "", errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(user.UpdatedAt, 10), nil
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
		providerLog(logger.LevelError, "unable to update transfer quota for user %q error: %v", username, err)
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
	providerLog(logger.LevelDebug, "transfer quota updated for user %q, ul increment: %v dl increment: %v is reset? %v",
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
		providerLog(logger.LevelError, "unable to update quota for user %q error: %v", username, err)
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
	providerLog(logger.LevelDebug, "quota updated for user %q, files increment: %v size increment: %v is reset? %v",
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
		providerLog(logger.LevelError, "unable to get quota for user %q error: %v", username, err)
		return 0, 0, 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, user.UsedUploadDataTransfer, user.UsedDownloadDataTransfer, err
}

func (p *MemoryProvider) addUser(user *User) error {
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
		return util.NewI18nError(
			fmt.Errorf("%w: username %v already exists", ErrDuplicatedKey, user.Username),
			util.I18nErrorDuplicatedUsername,
		)
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
	if err := p.addUserToRole(user.Username, user.Role); err != nil {
		return err
	}
	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})
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
	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})
	var mappedFolders []string
	for idx := range user.VirtualFolders {
		if err = p.addUserToFolderMapping(user.Username, user.VirtualFolders[idx].Name); err != nil {
			// try to remove folder mapping
			for _, f := range mappedFolders {
				p.removeRelationFromFolderMapping(f, user.Username, "")
			}
			return err
		}
		mappedFolders = append(mappedFolders, user.VirtualFolders[idx].Name)
	}
	p.dbHandle.users[user.Username] = user.getACopy()
	p.dbHandle.usernames = append(p.dbHandle.usernames, user.Username)
	sort.Strings(p.dbHandle.usernames)
	return nil
}

func (p *MemoryProvider) updateUser(user *User) error { //nolint:gocyclo
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
	p.removeUserFromRole(u.Username, u.Role)
	if err := p.addUserToRole(user.Username, user.Role); err != nil {
		// try ro add old role
		if errRollback := p.addUserToRole(u.Username, u.Role); errRollback != nil {
			providerLog(logger.LevelError, "unable to rollback old role %q for user %q, error: %v",
				u.Role, u.Username, errRollback)
		}
		return err
	}
	for idx := range u.Groups {
		p.removeUserFromGroupMapping(u.Username, u.Groups[idx].Name)
	}
	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})
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
	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})
	for idx := range user.VirtualFolders {
		if err = p.addUserToFolderMapping(user.Username, user.VirtualFolders[idx].Name); err != nil {
			// try to add old mapping
			for _, f := range u.VirtualFolders {
				if errRollback := p.addUserToFolderMapping(user.Username, f.Name); errRollback != nil {
					providerLog(logger.LevelError, "unable to rollback old folder mapping %q for user %q, error: %v",
						f.Name, user.Username, errRollback)
				}
			}
			return err
		}
	}
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

func (p *MemoryProvider) deleteUser(user User, _ bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	u, err := p.userExistsInternal(user.Username)
	if err != nil {
		return err
	}
	p.removeUserFromRole(u.Username, u.Role)
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
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
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

func (p *MemoryProvider) getUsers(limit int, offset int, order, role string) ([]User, error) {
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
			if !user.hasRole(role) {
				continue
			}
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
			if !user.hasRole(role) {
				continue
			}
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

func (p *MemoryProvider) userExists(username, role string) (User, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return user, err
	}
	if !user.hasRole(role) {
		return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
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

func (p *MemoryProvider) roleExistsInternal(name string) (Role, error) {
	if val, ok := p.dbHandle.roles[name]; ok {
		return val.getACopy(), nil
	}
	return Role{}, util.NewRecordNotFoundError(fmt.Sprintf("role %q does not exist", name))
}

func (p *MemoryProvider) ipListEntryExistsInternal(entry *IPListEntry) (IPListEntry, error) {
	if val, ok := p.dbHandle.ipListEntries[entry.getKey()]; ok {
		return val.getACopy(), nil
	}
	return IPListEntry{}, util.NewRecordNotFoundError(fmt.Sprintf("IP list entry %q does not exist", entry.getName()))
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
		return util.NewI18nError(
			fmt.Errorf("%w: admin %q already exists", ErrDuplicatedKey, admin.Username),
			util.I18nErrorDuplicatedUsername,
		)
	}
	admin.ID = p.getNextAdminID()
	admin.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	admin.LastLogin = 0
	if err := p.addAdminToRole(admin.Username, admin.Role); err != nil {
		return err
	}
	var mappedAdmins []string
	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})
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
	p.removeAdminFromRole(a.Username, a.Role)
	if err := p.addAdminToRole(admin.Username, admin.Role); err != nil {
		// try ro add old role
		if errRollback := p.addAdminToRole(a.Username, a.Role); errRollback != nil {
			providerLog(logger.LevelError, "unable to rollback old role %q for admin %q, error: %v",
				a.Role, a.Username, errRollback)
		}
		return err
	}
	for idx := range a.Groups {
		p.removeAdminFromGroupMapping(a.Username, a.Groups[idx].Name)
	}
	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})
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
	p.removeAdminFromRole(a.Username, a.Role)
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
	return Admin{}, util.NewRecordNotFoundError(fmt.Sprintf("admin %q does not exist", username))
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
		providerLog(logger.LevelError, "unable to update quota for folder %q error: %v", name, err)
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

func (p *MemoryProvider) getGroups(limit, offset int, order string, _ bool) ([]Group, error) {
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
		return util.NewI18nError(
			fmt.Errorf("%w: group %q already exists", ErrDuplicatedKey, group.Name),
			util.I18nErrorDuplicatedUsername,
		)
	}
	group.ID = p.getNextGroupID()
	group.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	group.Users = nil
	group.Admins = nil
	sort.Slice(group.VirtualFolders, func(i, j int) bool {
		return group.VirtualFolders[i].Name < group.VirtualFolders[j].Name
	})
	var mappedFolders []string
	for idx := range group.VirtualFolders {
		if err = p.addGroupToFolderMapping(group.Name, group.VirtualFolders[idx].Name); err != nil {
			// try to remove folder mapping
			for _, f := range mappedFolders {
				p.removeRelationFromFolderMapping(f, "", group.Name)
			}
			return err
		}
		mappedFolders = append(mappedFolders, group.VirtualFolders[idx].Name)
	}
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
	sort.Slice(group.VirtualFolders, func(i, j int) bool {
		return group.VirtualFolders[i].Name < group.VirtualFolders[j].Name
	})
	for idx := range group.VirtualFolders {
		if err = p.addGroupToFolderMapping(group.Name, group.VirtualFolders[idx].Name); err != nil {
			// try to add old mapping
			for _, f := range g.VirtualFolders {
				if errRollback := p.addGroupToFolderMapping(group.Name, f.Name); errRollback != nil {
					providerLog(logger.LevelError, "unable to rollback old folder mapping %q for group %q, error: %v",
						f.Name, group.Name, errRollback)
				}
			}
			return err
		}
	}
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
		return util.NewValidationError(fmt.Sprintf("the group %q is referenced, it cannot be removed", group.Name))
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
		providerLog(logger.LevelError, "unable to get quota for folder %q error: %v", name, err)
		return 0, 0, err
	}
	return folder.UsedQuotaFiles, folder.UsedQuotaSize, err
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
	if !slices.Contains(a.Rules, ruleName) {
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
	if slices.Contains(a.Rules, ruleName) {
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
	if !slices.Contains(g.Admins, username) {
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
	if !slices.Contains(g.Users, username) {
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

func (p *MemoryProvider) addAdminToRole(username, role string) error {
	if role == "" {
		return nil
	}
	r, err := p.roleExistsInternal(role)
	if err != nil {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, role)
	}
	if !slices.Contains(r.Admins, username) {
		r.Admins = append(r.Admins, username)
		p.dbHandle.roles[role] = r
	}
	return nil
}

func (p *MemoryProvider) removeAdminFromRole(username, role string) {
	if role == "" {
		return
	}
	r, err := p.roleExistsInternal(role)
	if err != nil {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove admin %q", role, username)
		return
	}
	var admins []string
	for _, a := range r.Admins {
		if a != username {
			admins = append(admins, a)
		}
	}
	r.Admins = admins
	p.dbHandle.roles[role] = r
}

func (p *MemoryProvider) addUserToRole(username, role string) error {
	if role == "" {
		return nil
	}
	r, err := p.roleExistsInternal(role)
	if err != nil {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, role)
	}
	if !slices.Contains(r.Users, username) {
		r.Users = append(r.Users, username)
		p.dbHandle.roles[role] = r
	}
	return nil
}

func (p *MemoryProvider) removeUserFromRole(username, role string) {
	if role == "" {
		return
	}
	r, err := p.roleExistsInternal(role)
	if err != nil {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove user %q", role, username)
		return
	}
	var users []string
	for _, u := range r.Users {
		if u != username {
			users = append(users, u)
		}
	}
	r.Users = users
	p.dbHandle.roles[role] = r
}

func (p *MemoryProvider) addUserToFolderMapping(username, foldername string) error {
	f, err := p.folderExistsInternal(foldername)
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("unable to get folder %q: %v", foldername, err))
	}
	if !slices.Contains(f.Users, username) {
		f.Users = append(f.Users, username)
		p.dbHandle.vfolders[foldername] = f
	}
	return nil
}

func (p *MemoryProvider) addGroupToFolderMapping(name, foldername string) error {
	f, err := p.folderExistsInternal(foldername)
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("unable to get folder %q: %v", foldername, err))
	}
	if !slices.Contains(f.Groups, name) {
		f.Groups = append(f.Groups, name)
		p.dbHandle.vfolders[foldername] = f
	}
	return nil
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
	if err != nil {
		return
	}
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

func (p *MemoryProvider) folderExistsInternal(name string) (vfs.BaseVirtualFolder, error) {
	if val, ok := p.dbHandle.vfolders[name]; ok {
		return val, nil
	}
	return vfs.BaseVirtualFolder{}, util.NewRecordNotFoundError(fmt.Sprintf("folder %q does not exist", name))
}

func (p *MemoryProvider) getFolders(limit, offset int, order string, _ bool) ([]vfs.BaseVirtualFolder, error) {
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
		return util.NewI18nError(
			fmt.Errorf("%w: folder %q already exists", ErrDuplicatedKey, folder.Name),
			util.I18nErrorDuplicatedUsername,
		)
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
	return APIKey{}, util.NewRecordNotFoundError(fmt.Sprintf("API key %q does not exist", keyID))
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
		return fmt.Errorf("API key %q already exists", apiKey.KeyID)
	}
	if apiKey.User != "" {
		if _, err := p.userExistsInternal(apiKey.User); err != nil {
			return fmt.Errorf("%w: related user %q does not exists", ErrForeignKeyViolated, apiKey.User)
		}
	}
	if apiKey.Admin != "" {
		if _, err := p.adminExistsInternal(apiKey.Admin); err != nil {
			return fmt.Errorf("%w: related admin %q does not exists", ErrForeignKeyViolated, apiKey.Admin)
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
			return fmt.Errorf("%w: related user %q does not exists", ErrForeignKeyViolated, apiKey.User)
		}
	}
	if apiKey.Admin != "" {
		if _, err := p.adminExistsInternal(apiKey.Admin); err != nil {
			return fmt.Errorf("%w: related admin %q does not exists", ErrForeignKeyViolated, apiKey.Admin)
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
			return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %q does not exist", shareID))
		}
		return val.getACopy(), nil
	}
	return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %q does not exist", shareID))
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
		return fmt.Errorf("share %q already exists", share.ShareID)
	}
	if _, err := p.userExistsInternal(share.Username); err != nil {
		return util.NewValidationError(fmt.Sprintf("related user %q does not exists", share.Username))
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
		return util.NewValidationError(fmt.Sprintf("related user %q does not exists", share.Username))
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

func (p *MemoryProvider) getDefenderHosts(_ int64, _ int) ([]DefenderEntry, error) {
	return nil, ErrNotImplemented
}

func (p *MemoryProvider) getDefenderHostByIP(_ string, _ int64) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *MemoryProvider) isDefenderHostBanned(_ string) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *MemoryProvider) updateDefenderBanTime(_ string, _ int) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) deleteDefenderHost(_ string) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) addDefenderEvent(_ string, _ int) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) setDefenderBanTime(_ string, _ int64) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) cleanupDefender(_ int64) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) addActiveTransfer(_ ActiveTransfer) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) updateActiveTransferSizes(_, _, _ int64, _ string) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) removeActiveTransfer(_ int64, _ string) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) cleanupActiveTransfers(_ time.Time) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) getActiveTransfers(_ time.Time) ([]ActiveTransfer, error) {
	return nil, ErrNotImplemented
}

func (p *MemoryProvider) addSharedSession(_ Session) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) deleteSharedSession(_ string, _ SessionType) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) getSharedSession(_ string, _ SessionType) (Session, error) {
	return Session{}, ErrNotImplemented
}

func (p *MemoryProvider) cleanupSharedSessions(_ SessionType, _ int64) error {
	return ErrNotImplemented
}

func (p *MemoryProvider) getEventActions(limit, offset int, order string, _ bool) ([]BaseEventAction, error) {
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
		return util.NewI18nError(
			fmt.Errorf("%w: event action %q already exists", ErrDuplicatedKey, action.Name),
			util.I18nErrorDuplicatedName,
		)
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
		return util.NewI18nError(
			fmt.Errorf("%w: event rule %q already exists", ErrDuplicatedKey, rule.Name),
			util.I18nErrorDuplicatedName,
		)
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

func (p *MemoryProvider) deleteEventRule(rule EventRule, _ bool) error {
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

func (*MemoryProvider) getTaskByName(_ string) (Task, error) {
	return Task{}, ErrNotImplemented
}

func (*MemoryProvider) addTask(_ string) error {
	return ErrNotImplemented
}

func (*MemoryProvider) updateTask(_ string, _ int64) error {
	return ErrNotImplemented
}

func (*MemoryProvider) updateTaskTimestamp(_ string) error {
	return ErrNotImplemented
}

func (*MemoryProvider) addNode() error {
	return ErrNotImplemented
}

func (*MemoryProvider) getNodeByName(_ string) (Node, error) {
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

func (p *MemoryProvider) roleExists(name string) (Role, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return Role{}, errMemoryProviderClosed
	}
	role, err := p.roleExistsInternal(name)
	if err != nil {
		return role, err
	}
	return role, nil
}

func (p *MemoryProvider) addRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err := p.roleExistsInternal(role.Name)
	if err == nil {
		return util.NewI18nError(
			fmt.Errorf("%w: role %q already exists", ErrDuplicatedKey, role.Name),
			util.I18nErrorDuplicatedName,
		)
	}
	role.ID = p.getNextRoleID()
	role.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.Users = nil
	role.Admins = nil
	p.dbHandle.roles[role.Name] = role.getACopy()
	p.dbHandle.roleNames = append(p.dbHandle.roleNames, role.Name)
	sort.Strings(p.dbHandle.roleNames)
	return nil
}

func (p *MemoryProvider) updateRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	oldRole, err := p.roleExistsInternal(role.Name)
	if err != nil {
		return err
	}
	role.ID = oldRole.ID
	role.CreatedAt = oldRole.CreatedAt
	role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.Users = oldRole.Users
	role.Admins = oldRole.Admins
	p.dbHandle.roles[role.Name] = role.getACopy()
	return nil
}

func (p *MemoryProvider) deleteRole(role Role) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	oldRole, err := p.roleExistsInternal(role.Name)
	if err != nil {
		return err
	}
	if len(oldRole.Admins) > 0 {
		return util.NewValidationError(fmt.Sprintf("the role %q is referenced, it cannot be removed", oldRole.Name))
	}
	for _, username := range oldRole.Users {
		user, err := p.userExistsInternal(username)
		if err != nil {
			continue
		}
		if user.Role == role.Name {
			user.Role = ""
			p.dbHandle.users[username] = user
		} else {
			providerLog(logger.LevelError, "user %q does not have the expected role %q, actual %q", username, role.Name, user.Role)
		}
	}
	delete(p.dbHandle.roles, role.Name)
	p.dbHandle.roleNames = make([]string, 0, len(p.dbHandle.roles))
	for name := range p.dbHandle.roles {
		p.dbHandle.roleNames = append(p.dbHandle.roleNames, name)
	}
	sort.Strings(p.dbHandle.roleNames)
	return nil
}

func (p *MemoryProvider) getRoles(limit int, offset int, order string, _ bool) ([]Role, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	if limit <= 0 {
		return nil, nil
	}
	roles := make([]Role, 0, 10)
	itNum := 0
	if order == OrderASC {
		for _, name := range p.dbHandle.roleNames {
			itNum++
			if itNum <= offset {
				continue
			}
			r := p.dbHandle.roles[name]
			role := r.getACopy()
			roles = append(roles, role)
			if len(roles) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.roleNames) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			name := p.dbHandle.roleNames[i]
			r := p.dbHandle.roles[name]
			role := r.getACopy()
			roles = append(roles, role)
			if len(roles) >= limit {
				break
			}
		}
	}
	return roles, nil
}

func (p *MemoryProvider) dumpRoles() ([]Role, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}

	roles := make([]Role, 0, len(p.dbHandle.roles))
	for _, name := range p.dbHandle.roleNames {
		r := p.dbHandle.roles[name]
		roles = append(roles, r.getACopy())
	}
	return roles, nil
}

func (p *MemoryProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return IPListEntry{}, errMemoryProviderClosed
	}
	entry, err := p.ipListEntryExistsInternal(&IPListEntry{IPOrNet: ipOrNet, Type: listType})
	if err != nil {
		return entry, err
	}
	entry.PrepareForRendering()
	return entry, nil
}

func (p *MemoryProvider) addIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err := p.ipListEntryExistsInternal(entry)
	if err == nil {
		return util.NewI18nError(
			fmt.Errorf("%w: entry %q already exists", ErrDuplicatedKey, entry.IPOrNet),
			util.I18nErrorDuplicatedIPNet,
		)
	}
	entry.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.ipListEntries[entry.getKey()] = entry.getACopy()
	p.dbHandle.ipListEntriesKeys = append(p.dbHandle.ipListEntriesKeys, entry.getKey())
	sort.Strings(p.dbHandle.ipListEntriesKeys)
	return nil
}

func (p *MemoryProvider) updateIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	oldEntry, err := p.ipListEntryExistsInternal(entry)
	if err != nil {
		return err
	}
	entry.CreatedAt = oldEntry.CreatedAt
	entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.ipListEntries[entry.getKey()] = entry.getACopy()
	return nil
}

func (p *MemoryProvider) deleteIPListEntry(entry IPListEntry, _ bool) error {
	if err := entry.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err := p.ipListEntryExistsInternal(&entry)
	if err != nil {
		return err
	}
	delete(p.dbHandle.ipListEntries, entry.getKey())
	p.dbHandle.ipListEntriesKeys = make([]string, 0, len(p.dbHandle.ipListEntries))
	for k := range p.dbHandle.ipListEntries {
		p.dbHandle.ipListEntriesKeys = append(p.dbHandle.ipListEntriesKeys, k)
	}
	sort.Strings(p.dbHandle.ipListEntriesKeys)
	return nil
}

func (p *MemoryProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	entries := make([]IPListEntry, 0, 15)
	if order == OrderASC {
		for _, k := range p.dbHandle.ipListEntriesKeys {
			e := p.dbHandle.ipListEntries[k]
			if e.Type == listType && e.satisfySearchConstraints(filter, from, order) {
				entry := e.getACopy()
				entry.PrepareForRendering()
				entries = append(entries, entry)
				if limit > 0 && len(entries) >= limit {
					break
				}
			}
		}
	} else {
		for i := len(p.dbHandle.ipListEntriesKeys) - 1; i >= 0; i-- {
			e := p.dbHandle.ipListEntries[p.dbHandle.ipListEntriesKeys[i]]
			if e.Type == listType && e.satisfySearchConstraints(filter, from, order) {
				entry := e.getACopy()
				entry.PrepareForRendering()
				entries = append(entries, entry)
				if limit > 0 && len(entries) >= limit {
					break
				}
			}
		}
	}

	return entries, nil
}

func (p *MemoryProvider) getRecentlyUpdatedIPListEntries(_ int64) ([]IPListEntry, error) {
	return nil, ErrNotImplemented
}

func (p *MemoryProvider) dumpIPListEntries() ([]IPListEntry, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	if count := len(p.dbHandle.ipListEntriesKeys); count > ipListMemoryLimit {
		providerLog(logger.LevelInfo, "IP lists excluded from dump, too many entries: %d", count)
		return nil, nil
	}
	entries := make([]IPListEntry, 0, len(p.dbHandle.ipListEntries))
	for _, k := range p.dbHandle.ipListEntriesKeys {
		e := p.dbHandle.ipListEntries[k]
		entry := e.getACopy()
		entry.PrepareForRendering()
		entries = append(entries, entry)
	}
	return entries, nil
}

func (p *MemoryProvider) countIPListEntries(listType IPListType) (int64, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return 0, errMemoryProviderClosed
	}
	if listType == 0 {
		return int64(len(p.dbHandle.ipListEntriesKeys)), nil
	}
	var count int64
	for _, k := range p.dbHandle.ipListEntriesKeys {
		e := p.dbHandle.ipListEntries[k]
		if e.Type == listType {
			count++
		}
	}
	return count, nil
}

func (p *MemoryProvider) getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()

	if p.dbHandle.isClosed {
		return nil, errMemoryProviderClosed
	}
	entries := make([]IPListEntry, 0, 3)
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return entries, fmt.Errorf("invalid ip address %s", ip)
	}
	var netType int
	var ipBytes []byte
	if ipAddr.Is4() || ipAddr.Is4In6() {
		netType = ipTypeV4
		as4 := ipAddr.As4()
		ipBytes = as4[:]
	} else {
		netType = ipTypeV6
		as16 := ipAddr.As16()
		ipBytes = as16[:]
	}
	for _, k := range p.dbHandle.ipListEntriesKeys {
		e := p.dbHandle.ipListEntries[k]
		if e.Type == listType && e.IPType == netType && bytes.Compare(ipBytes, e.First) >= 0 && bytes.Compare(ipBytes, e.Last) <= 0 {
			entry := e.getACopy()
			entry.PrepareForRendering()
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (p *MemoryProvider) getConfigs() (Configs, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return Configs{}, errMemoryProviderClosed
	}
	return p.dbHandle.configs.getACopy(), nil
}

func (p *MemoryProvider) setConfigs(configs *Configs) error {
	if err := configs.validate(); err != nil {
		return err
	}
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	p.dbHandle.configs = configs.getACopy()
	return nil
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
		return util.NewGenericError(fmt.Sprintf("first download already set to %s",
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
		return util.NewGenericError(fmt.Sprintf("first upload already set to %s",
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

func (p *MemoryProvider) getNextRoleID() int64 {
	nextID := int64(1)
	for _, r := range p.dbHandle.roles {
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
	p.dbHandle.groupnames = []string{}
	p.dbHandle.groups = map[string]Group{}
	p.dbHandle.vfoldersNames = []string{}
	p.dbHandle.vfolders = make(map[string]vfs.BaseVirtualFolder)
	p.dbHandle.admins = make(map[string]Admin)
	p.dbHandle.adminsUsernames = []string{}
	p.dbHandle.apiKeys = make(map[string]APIKey)
	p.dbHandle.apiKeysIDs = []string{}
	p.dbHandle.shares = make(map[string]Share)
	p.dbHandle.sharesIDs = []string{}
	p.dbHandle.actions = map[string]BaseEventAction{}
	p.dbHandle.actionsNames = []string{}
	p.dbHandle.rules = map[string]EventRule{}
	p.dbHandle.rulesNames = []string{}
	p.dbHandle.roles = map[string]Role{}
	p.dbHandle.roleNames = []string{}
	p.dbHandle.ipListEntries = map[string]IPListEntry{}
	p.dbHandle.ipListEntriesKeys = []string{}
	p.dbHandle.configs = Configs{}
}

func (p *MemoryProvider) reloadConfig() error {
	if p.dbHandle.configFile == "" {
		providerLog(logger.LevelDebug, "no dump configuration file defined")
		return nil
	}
	providerLog(logger.LevelDebug, "loading dump from file: %q", p.dbHandle.configFile)
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
	if fi.Size() > 20971520 {
		err = errors.New("dump configuration file is invalid, its size must be <= 20971520 bytes")
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
	return p.restoreDump(&dump)
}

func (p *MemoryProvider) restoreDump(dump *BackupData) error {
	p.clear()

	if err := p.restoreConfigs(dump); err != nil {
		return err
	}

	if err := p.restoreIPListEntries(dump); err != nil {
		return err
	}

	if err := p.restoreRoles(dump); err != nil {
		return err
	}

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

	providerLog(logger.LevelDebug, "config loaded from file: %q", p.dbHandle.configFile)
	return nil
}

func (p *MemoryProvider) restoreEventActions(dump *BackupData) error {
	for idx := range dump.EventActions {
		action := dump.EventActions[idx]
		a, err := p.eventActionExists(action.Name)
		if err == nil {
			action.ID = a.ID
			err = UpdateEventAction(&action, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating event action %q: %v", action.Name, err)
				return err
			}
		} else {
			err = AddEventAction(&action, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding event action %q: %v", action.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreEventRules(dump *BackupData) error {
	for idx := range dump.EventRules {
		rule := dump.EventRules[idx]
		r, err := p.eventRuleExists(rule.Name)
		if dump.Version < 15 {
			rule.Status = 1
		}
		if err == nil {
			rule.ID = r.ID
			err = UpdateEventRule(&rule, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating event rule %q: %v", rule.Name, err)
				return err
			}
		} else {
			err = AddEventRule(&rule, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding event rule %q: %v", rule.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreShares(dump *BackupData) error {
	for idx := range dump.Shares {
		share := dump.Shares[idx]
		s, err := p.shareExists(share.ShareID, "")
		share.IsRestore = true
		if err == nil {
			share.ID = s.ID
			err = UpdateShare(&share, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating share %q: %v", share.ShareID, err)
				return err
			}
		} else {
			err = AddShare(&share, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding share %q: %v", share.ShareID, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreAPIKeys(dump *BackupData) error {
	for idx := range dump.APIKeys {
		apiKey := dump.APIKeys[idx]
		if apiKey.Key == "" {
			return fmt.Errorf("cannot restore an empty API key: %+v", apiKey)
		}
		k, err := p.apiKeyExists(apiKey.KeyID)
		if err == nil {
			apiKey.ID = k.ID
			err = UpdateAPIKey(&apiKey, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating API key %q: %v", apiKey.KeyID, err)
				return err
			}
		} else {
			err = AddAPIKey(&apiKey, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding API key %q: %v", apiKey.KeyID, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreAdmins(dump *BackupData) error {
	for idx := range dump.Admins {
		admin := dump.Admins[idx]
		admin.Username = config.convertName(admin.Username)
		a, err := p.adminExists(admin.Username)
		if err == nil {
			admin.ID = a.ID
			err = UpdateAdmin(&admin, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating admin %q: %v", admin.Username, err)
				return err
			}
		} else {
			err = AddAdmin(&admin, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding admin %q: %v", admin.Username, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreConfigs(dump *BackupData) error {
	if dump.Configs != nil && dump.Configs.UpdatedAt > 0 {
		return UpdateConfigs(dump.Configs, ActionExecutorSystem, "", "")
	}
	return nil
}

func (p *MemoryProvider) restoreIPListEntries(dump *BackupData) error {
	for idx := range dump.IPLists {
		entry := dump.IPLists[idx]
		_, err := p.ipListEntryExists(entry.IPOrNet, entry.Type)
		if err == nil {
			err = UpdateIPListEntry(&entry, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating IP list entry %q: %v", entry.getName(), err)
				return err
			}
		} else {
			err = AddIPListEntry(&entry, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding IP list entry %q: %v", entry.getName(), err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreRoles(dump *BackupData) error {
	for idx := range dump.Roles {
		role := dump.Roles[idx]
		role.Name = config.convertName(role.Name)
		r, err := p.roleExists(role.Name)
		if err == nil {
			role.ID = r.ID
			err = UpdateRole(&role, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating role %q: %v", role.Name, err)
				return err
			}
		} else {
			role.Admins = nil
			role.Users = nil
			err = AddRole(&role, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding role %q: %v", role.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreGroups(dump *BackupData) error {
	for idx := range dump.Groups {
		group := dump.Groups[idx]
		group.Name = config.convertName(group.Name)
		g, err := p.groupExists(group.Name)
		if err == nil {
			group.ID = g.ID
			err = UpdateGroup(&group, g.Users, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating group %q: %v", group.Name, err)
				return err
			}
		} else {
			group.Users = nil
			err = AddGroup(&group, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding group %q: %v", group.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreFolders(dump *BackupData) error {
	for idx := range dump.Folders {
		folder := dump.Folders[idx]
		folder.Name = config.convertName(folder.Name)
		f, err := p.getFolderByName(folder.Name)
		if err == nil {
			folder.ID = f.ID
			err = UpdateFolder(&folder, f.Users, f.Groups, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating folder %q: %v", folder.Name, err)
				return err
			}
		} else {
			folder.Users = nil
			err = AddFolder(&folder, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding folder %q: %v", folder.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreUsers(dump *BackupData) error {
	for idx := range dump.Users {
		user := dump.Users[idx]
		user.Username = config.convertName(user.Username)
		u, err := p.userExists(user.Username, "")
		if err == nil {
			user.ID = u.ID
			err = UpdateUser(&user, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error updating user %q: %v", user.Username, err)
				return err
			}
		} else {
			err = AddUser(&user, ActionExecutorSystem, "", "")
			if err != nil {
				providerLog(logger.LevelError, "error adding user %q: %v", user.Username, err)
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

func (p *MemoryProvider) revertDatabase(_ int) error {
	return errors.New("memory provider does not store data, revert not possible")
}

func (p *MemoryProvider) resetDatabase() error {
	return errors.New("memory provider does not store data, reset not possible")
}
