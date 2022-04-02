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

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
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
			vfolders:        make(map[string]vfs.BaseVirtualFolder),
			vfoldersNames:   []string{},
			admins:          make(map[string]Admin),
			adminsUsernames: []string{},
			apiKeys:         make(map[string]APIKey),
			apiKeysIDs:      []string{},
			shares:          make(map[string]Share),
			sharesIDs:       []string{},
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
	var user User
	if password == "" {
		return user, errors.New("credentials cannot be null or empty")
	}
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
	user.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	user.VirtualFolders = p.joinVirtualFoldersFields(user)
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
	for _, oldFolder := range u.VirtualFolders {
		p.removeUserFromFolderMapping(oldFolder.Name, u.Username)
	}
	user.VirtualFolders = p.joinVirtualFoldersFields(user)
	user.LastQuotaUpdate = u.LastQuotaUpdate
	user.UsedQuotaSize = u.UsedQuotaSize
	user.UsedQuotaFiles = u.UsedQuotaFiles
	user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
	user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
	user.LastLogin = u.LastLogin
	user.CreatedAt = u.CreatedAt
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	user.ID = u.ID
	// pre-login and external auth hook will use the passed *user so save a copy
	p.dbHandle.users[user.Username] = user.getACopy()
	return nil
}

func (p *MemoryProvider) deleteUser(user *User) error {
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
		p.removeUserFromFolderMapping(oldFolder.Name, u.Username)
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
		err = addCredentialsToUser(&user)
		if err != nil {
			return users, err
		}
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

// memory provider cannot be shared, so we always return no recently updated users
func (p *MemoryProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return nil, nil
}

func (p *MemoryProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	users := make([]User, 0, 30)
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return users, errMemoryProviderClosed
	}
	for _, username := range p.dbHandle.usernames {
		if val, ok := toFetch[username]; ok {
			u := p.dbHandle.users[username]
			user := u.getACopy()
			if val {
				p.addVirtualFoldersToUser(&user)
			}
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
	return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
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
	admin.ID = a.ID
	admin.CreatedAt = a.CreatedAt
	admin.LastLogin = a.LastLogin
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.admins[admin.Username] = admin.getACopy()
	return nil
}

func (p *MemoryProvider) deleteAdmin(admin *Admin) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err := p.adminExistsInternal(admin.Username)
	if err != nil {
		return err
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

func (p *MemoryProvider) joinVirtualFoldersFields(user *User) []vfs.VirtualFolder {
	var folders []vfs.VirtualFolder
	for idx := range user.VirtualFolders {
		folder := &user.VirtualFolders[idx]
		f, err := p.addOrUpdateFolderInternal(&folder.BaseVirtualFolder, user.Username, 0, 0, 0)
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

func (p *MemoryProvider) removeUserFromFolderMapping(folderName, username string) {
	folder, err := p.folderExistsInternal(folderName)
	if err == nil {
		var usernames []string
		for _, user := range folder.Users {
			if user != username {
				usernames = append(usernames, user)
			}
		}
		folder.Users = usernames
		p.dbHandle.vfolders[folder.Name] = folder
	}
}

func (p *MemoryProvider) updateFoldersMappingInternal(folder vfs.BaseVirtualFolder) {
	p.dbHandle.vfolders[folder.Name] = folder
	if !util.IsStringInSlice(folder.Name, p.dbHandle.vfoldersNames) {
		p.dbHandle.vfoldersNames = append(p.dbHandle.vfoldersNames, folder.Name)
		sort.Strings(p.dbHandle.vfoldersNames)
	}
}

func (p *MemoryProvider) addOrUpdateFolderInternal(baseFolder *vfs.BaseVirtualFolder, username string, usedQuotaSize int64,
	usedQuotaFiles int, lastQuotaUpdate int64) (vfs.BaseVirtualFolder, error,
) {
	folder, err := p.folderExistsInternal(baseFolder.Name)
	if err == nil {
		// exists
		folder.MappedPath = baseFolder.MappedPath
		folder.Description = baseFolder.Description
		folder.FsConfig = baseFolder.FsConfig.GetACopy()
		if !util.IsStringInSlice(username, folder.Users) {
			folder.Users = append(folder.Users, username)
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
		folder.Users = []string{username}
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

func (p *MemoryProvider) getFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error) {
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

func (p *MemoryProvider) deleteFolder(folder *vfs.BaseVirtualFolder) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err := p.folderExistsInternal(folder.Name)
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

func (p *MemoryProvider) deleteAPIKey(apiKey *APIKey) error {
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

func (p *MemoryProvider) deleteShare(share *Share) error {
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

	if err := p.restoreFolders(&dump); err != nil {
		return err
	}

	if err := p.restoreUsers(&dump); err != nil {
		return err
	}

	if err := p.restoreAdmins(&dump); err != nil {
		return err
	}

	if err := p.restoreAPIKeys(&dump); err != nil {
		return err
	}

	if err := p.restoreShares(&dump); err != nil {
		return err
	}

	providerLog(logger.LevelDebug, "config loaded from file: %#v", p.dbHandle.configFile)
	return nil
}

func (p *MemoryProvider) restoreShares(dump *BackupData) error {
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

func (p *MemoryProvider) restoreAPIKeys(dump *BackupData) error {
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

func (p *MemoryProvider) restoreAdmins(dump *BackupData) error {
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

func (p *MemoryProvider) restoreFolders(dump *BackupData) error {
	for _, folder := range dump.Folders {
		folder := folder // pin
		folder.Name = config.convertName(folder.Name)
		f, err := p.getFolderByName(folder.Name)
		if err == nil {
			folder.ID = f.ID
			err = UpdateFolder(&folder, f.Users, ActionExecutorSystem, "")
			if err != nil {
				providerLog(logger.LevelError, "error updating folder %#v: %v", folder.Name, err)
				return err
			}
		} else {
			folder.Users = nil
			err = AddFolder(&folder)
			if err != nil {
				providerLog(logger.LevelError, "error adding folder %#v: %v", folder.Name, err)
				return err
			}
		}
	}
	return nil
}

func (p *MemoryProvider) restoreUsers(dump *BackupData) error {
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
