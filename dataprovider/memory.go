package dataprovider

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
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
	// mapping between ID and username
	usersIdx map[int64]string
	// map for users, username is the key
	users map[string]User
	// map for virtual folders, MappedPath is the key
	vfolders map[string]vfs.BaseVirtualFolder
	// slice with ordered folders mapped path
	vfoldersPaths []string
}

// MemoryProvider auth provider for a memory store
type MemoryProvider struct {
	dbHandle *memoryProviderHandle
}

func initializeMemoryProvider(basePath string) {
	logSender = fmt.Sprintf("dataprovider_%v", MemoryDataProviderName)
	configFile := ""
	if utils.IsFileInputValid(config.Name) {
		configFile = config.Name
		if !filepath.IsAbs(configFile) {
			configFile = filepath.Join(basePath, configFile)
		}
	}
	provider = MemoryProvider{
		dbHandle: &memoryProviderHandle{
			isClosed:      false,
			usernames:     []string{},
			usersIdx:      make(map[int64]string),
			users:         make(map[string]User),
			vfolders:      make(map[string]vfs.BaseVirtualFolder),
			vfoldersPaths: []string{},
			configFile:    configFile,
		},
	}
	if err := provider.reloadConfig(); err != nil {
		logger.Error(logSender, "", "unable to load initial data: %v", err)
		logger.ErrorToConsole("unable to load initial data: %v", err)
	}
}

func (p MemoryProvider) checkAvailability() error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	return nil
}

func (p MemoryProvider) close() error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	p.dbHandle.isClosed = true
	return nil
}

func (p MemoryProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	var user User
	if len(password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v, error: %v", username, err)
		return user, err
	}
	return checkUserAndPass(user, password, ip, protocol)
}

func (p MemoryProvider) validateUserAndPubKey(username string, pubKey []byte) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v, error: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(user, pubKey)
}

func (p MemoryProvider) getUserByID(ID int64) (User, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errMemoryProviderClosed
	}
	if val, ok := p.dbHandle.usersIdx[ID]; ok {
		return p.userExistsInternal(val)
	}
	return User{}, &RecordNotFoundError{err: fmt.Sprintf("user with ID %v does not exist", ID)}
}

func (p MemoryProvider) updateLastLogin(username string) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		return err
	}
	user.LastLogin = utils.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p MemoryProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to update quota for user %#v error: %v", username, err)
		return err
	}
	if reset {
		user.UsedQuotaSize = sizeAdd
		user.UsedQuotaFiles = filesAdd
	} else {
		user.UsedQuotaSize += sizeAdd
		user.UsedQuotaFiles += filesAdd
	}
	user.LastQuotaUpdate = utils.GetTimeAsMsSinceEpoch(time.Now())
	providerLog(logger.LevelDebug, "quota updated for user %#v, files increment: %v size increment: %v is reset? %v",
		username, filesAdd, sizeAdd, reset)
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p MemoryProvider) getUsedQuota(username string) (int, int64, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return 0, 0, errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to get quota for user %#v error: %v", username, err)
		return 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, err
}

func (p MemoryProvider) addUser(user User) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	err := validateUser(&user)
	if err != nil {
		return err
	}
	_, err = p.userExistsInternal(user.Username)
	if err == nil {
		return fmt.Errorf("username %#v already exists", user.Username)
	}
	user.ID = p.getNextID()
	user.LastQuotaUpdate = 0
	user.UsedQuotaSize = 0
	user.UsedQuotaFiles = 0
	user.LastLogin = 0
	user.VirtualFolders = p.joinVirtualFoldersFields(user)
	p.dbHandle.users[user.Username] = user
	p.dbHandle.usersIdx[user.ID] = user.Username
	p.dbHandle.usernames = append(p.dbHandle.usernames, user.Username)
	sort.Strings(p.dbHandle.usernames)
	return nil
}

func (p MemoryProvider) updateUser(user User) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	err := validateUser(&user)
	if err != nil {
		return err
	}
	u, err := p.userExistsInternal(user.Username)
	if err != nil {
		return err
	}
	for _, oldFolder := range u.VirtualFolders {
		p.removeUserFromFolderMapping(oldFolder.MappedPath, u.Username)
	}
	user.VirtualFolders = p.joinVirtualFoldersFields(user)
	user.LastQuotaUpdate = u.LastQuotaUpdate
	user.UsedQuotaSize = u.UsedQuotaSize
	user.UsedQuotaFiles = u.UsedQuotaFiles
	user.LastLogin = u.LastLogin
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p MemoryProvider) deleteUser(user User) error {
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
		p.removeUserFromFolderMapping(oldFolder.MappedPath, u.Username)
	}
	delete(p.dbHandle.users, user.Username)
	delete(p.dbHandle.usersIdx, user.ID)
	// this could be more efficient
	p.dbHandle.usernames = []string{}
	for username := range p.dbHandle.users {
		p.dbHandle.usernames = append(p.dbHandle.usernames, username)
	}
	sort.Strings(p.dbHandle.usernames)
	return nil
}

func (p MemoryProvider) dumpUsers() ([]User, error) {
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
		err = addCredentialsToUser(&user)
		if err != nil {
			return users, err
		}
		users = append(users, user)
	}
	return users, err
}

func (p MemoryProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	folders := make([]vfs.BaseVirtualFolder, 0, len(p.dbHandle.vfoldersPaths))
	if p.dbHandle.isClosed {
		return folders, errMemoryProviderClosed
	}
	for _, f := range p.dbHandle.vfolders {
		folders = append(folders, f)
	}
	return folders, nil
}

func (p MemoryProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
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
	if len(username) > 0 {
		if offset == 0 {
			user, err := p.userExistsInternal(username)
			if err == nil {
				user.HideConfidentialData()
				users = append(users, user)
			}
		}
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
			user.HideConfidentialData()
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
			user.HideConfidentialData()
			users = append(users, user)
			if len(users) >= limit {
				break
			}
		}
	}
	return users, err
}

func (p MemoryProvider) userExists(username string) (User, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errMemoryProviderClosed
	}
	return p.userExistsInternal(username)
}

func (p MemoryProvider) userExistsInternal(username string) (User, error) {
	if val, ok := p.dbHandle.users[username]; ok {
		return val.getACopy(), nil
	}
	return User{}, &RecordNotFoundError{err: fmt.Sprintf("username %#v does not exist", username)}
}

func (p MemoryProvider) updateFolderQuota(mappedPath string, filesAdd int, sizeAdd int64, reset bool) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	folder, err := p.folderExistsInternal(mappedPath)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to update quota for folder %#v error: %v", mappedPath, err)
		return err
	}
	if reset {
		folder.UsedQuotaSize = sizeAdd
		folder.UsedQuotaFiles = filesAdd
	} else {
		folder.UsedQuotaSize += sizeAdd
		folder.UsedQuotaFiles += filesAdd
	}
	folder.LastQuotaUpdate = utils.GetTimeAsMsSinceEpoch(time.Now())
	p.dbHandle.vfolders[mappedPath] = folder
	return nil
}

func (p MemoryProvider) getUsedFolderQuota(mappedPath string) (int, int64, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return 0, 0, errMemoryProviderClosed
	}
	folder, err := p.folderExistsInternal(mappedPath)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to get quota for folder %#v error: %v", mappedPath, err)
		return 0, 0, err
	}
	return folder.UsedQuotaFiles, folder.UsedQuotaSize, err
}

func (p MemoryProvider) joinVirtualFoldersFields(user User) []vfs.VirtualFolder {
	var folders []vfs.VirtualFolder
	for _, folder := range user.VirtualFolders {
		f, err := p.addOrGetFolderInternal(folder.MappedPath, user.Username, folder.UsedQuotaSize, folder.UsedQuotaFiles,
			folder.LastQuotaUpdate)
		if err == nil {
			folder.UsedQuotaFiles = f.UsedQuotaFiles
			folder.UsedQuotaSize = f.UsedQuotaSize
			folder.LastQuotaUpdate = f.LastQuotaUpdate
			folder.ID = f.ID
			folders = append(folders, folder)
		}
	}
	return folders
}

func (p MemoryProvider) removeUserFromFolderMapping(mappedPath, username string) {
	folder, err := p.folderExistsInternal(mappedPath)
	if err == nil {
		var usernames []string
		for _, user := range folder.Users {
			if user != username {
				usernames = append(usernames, user)
			}
		}
		folder.Users = usernames
		p.dbHandle.vfolders[folder.MappedPath] = folder
	}
}

func (p MemoryProvider) updateFoldersMappingInternal(folder vfs.BaseVirtualFolder) {
	p.dbHandle.vfolders[folder.MappedPath] = folder
	if !utils.IsStringInSlice(folder.MappedPath, p.dbHandle.vfoldersPaths) {
		p.dbHandle.vfoldersPaths = append(p.dbHandle.vfoldersPaths, folder.MappedPath)
		sort.Strings(p.dbHandle.vfoldersPaths)
	}
}

func (p MemoryProvider) addOrGetFolderInternal(mappedPath, username string, usedQuotaSize int64, usedQuotaFiles int, lastQuotaUpdate int64) (vfs.BaseVirtualFolder, error) {
	folder, err := p.folderExistsInternal(mappedPath)
	if _, ok := err.(*RecordNotFoundError); ok {
		folder := vfs.BaseVirtualFolder{
			ID:              p.getNextFolderID(),
			MappedPath:      mappedPath,
			UsedQuotaSize:   usedQuotaSize,
			UsedQuotaFiles:  usedQuotaFiles,
			LastQuotaUpdate: lastQuotaUpdate,
			Users:           []string{username},
		}
		p.updateFoldersMappingInternal(folder)
		return folder, nil
	}
	if err == nil && !utils.IsStringInSlice(username, folder.Users) {
		folder.Users = append(folder.Users, username)
		p.updateFoldersMappingInternal(folder)
	}
	return folder, err
}

func (p MemoryProvider) folderExistsInternal(mappedPath string) (vfs.BaseVirtualFolder, error) {
	if val, ok := p.dbHandle.vfolders[mappedPath]; ok {
		return val, nil
	}
	return vfs.BaseVirtualFolder{}, &RecordNotFoundError{err: fmt.Sprintf("folder %#v does not exist", mappedPath)}
}

func (p MemoryProvider) getFolders(limit, offset int, order, folderPath string) ([]vfs.BaseVirtualFolder, error) {
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
	if len(folderPath) > 0 {
		if offset == 0 {
			var folder vfs.BaseVirtualFolder
			folder, err = p.folderExistsInternal(folderPath)
			if err == nil {
				folders = append(folders, folder)
			}
		}
		return folders, err
	}
	itNum := 0
	if order == OrderASC {
		for _, mappedPath := range p.dbHandle.vfoldersPaths {
			itNum++
			if itNum <= offset {
				continue
			}
			folder := p.dbHandle.vfolders[mappedPath]
			folders = append(folders, folder)
			if len(folders) >= limit {
				break
			}
		}
	} else {
		for i := len(p.dbHandle.vfoldersPaths) - 1; i >= 0; i-- {
			itNum++
			if itNum <= offset {
				continue
			}
			mappedPath := p.dbHandle.vfoldersPaths[i]
			folder := p.dbHandle.vfolders[mappedPath]
			folders = append(folders, folder)
			if len(folders) >= limit {
				break
			}
		}
	}
	return folders, err
}

func (p MemoryProvider) getFolderByPath(mappedPath string) (vfs.BaseVirtualFolder, error) {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return vfs.BaseVirtualFolder{}, errMemoryProviderClosed
	}
	return p.folderExistsInternal(mappedPath)
}

func (p MemoryProvider) addFolder(folder vfs.BaseVirtualFolder) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	err := validateFolder(&folder)
	if err != nil {
		return err
	}
	_, err = p.folderExistsInternal(folder.MappedPath)
	if err == nil {
		return fmt.Errorf("folder %#v already exists", folder.MappedPath)
	}
	folder.ID = p.getNextFolderID()
	p.dbHandle.vfolders[folder.MappedPath] = folder
	p.dbHandle.vfoldersPaths = append(p.dbHandle.vfoldersPaths, folder.MappedPath)
	sort.Strings(p.dbHandle.vfoldersPaths)
	return nil
}

func (p MemoryProvider) deleteFolder(folder vfs.BaseVirtualFolder) error {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}

	_, err := p.folderExistsInternal(folder.MappedPath)
	if err != nil {
		return err
	}
	for _, username := range folder.Users {
		user, err := p.userExistsInternal(username)
		if err == nil {
			var folders []vfs.VirtualFolder
			for _, userFolder := range user.VirtualFolders {
				if folder.MappedPath != userFolder.MappedPath {
					folders = append(folders, userFolder)
				}
			}
			user.VirtualFolders = folders
			p.dbHandle.users[user.Username] = user
		}
	}
	delete(p.dbHandle.vfolders, folder.MappedPath)
	p.dbHandle.vfoldersPaths = []string{}
	for mappedPath := range p.dbHandle.vfolders {
		p.dbHandle.vfoldersPaths = append(p.dbHandle.vfoldersPaths, mappedPath)
	}
	sort.Strings(p.dbHandle.vfoldersPaths)
	return nil
}

func (p MemoryProvider) getNextID() int64 {
	nextID := int64(1)
	for id := range p.dbHandle.usersIdx {
		if id >= nextID {
			nextID = id + 1
		}
	}
	return nextID
}

func (p MemoryProvider) getNextFolderID() int64 {
	nextID := int64(1)
	for _, v := range p.dbHandle.vfolders {
		if v.ID >= nextID {
			nextID = v.ID + 1
		}
	}
	return nextID
}

func (p MemoryProvider) clear() {
	p.dbHandle.Lock()
	defer p.dbHandle.Unlock()
	p.dbHandle.usernames = []string{}
	p.dbHandle.usersIdx = make(map[int64]string)
	p.dbHandle.users = make(map[string]User)
	p.dbHandle.vfoldersPaths = []string{}
	p.dbHandle.vfolders = make(map[string]vfs.BaseVirtualFolder)
}

func (p MemoryProvider) reloadConfig() error {
	if p.dbHandle.configFile == "" {
		providerLog(logger.LevelDebug, "no users configuration file defined")
		return nil
	}
	providerLog(logger.LevelDebug, "loading users from file: %#v", p.dbHandle.configFile)
	fi, err := os.Stat(p.dbHandle.configFile)
	if err != nil {
		providerLog(logger.LevelWarn, "error loading users: %v", err)
		return err
	}
	if fi.Size() == 0 {
		err = errors.New("users configuration file is invalid, its size must be > 0")
		providerLog(logger.LevelWarn, "error loading users: %v", err)
		return err
	}
	if fi.Size() > 10485760 {
		err = errors.New("users configuration file is invalid, its size must be <= 10485760 bytes")
		providerLog(logger.LevelWarn, "error loading users: %v", err)
		return err
	}
	content, err := ioutil.ReadFile(p.dbHandle.configFile)
	if err != nil {
		providerLog(logger.LevelWarn, "error loading users: %v", err)
		return err
	}
	dump, err := ParseDumpData(content)
	if err != nil {
		providerLog(logger.LevelWarn, "error loading users: %v", err)
		return err
	}
	p.clear()
	for _, folder := range dump.Folders {
		_, err := p.getFolderByPath(folder.MappedPath)
		if err == nil {
			logger.Debug(logSender, "", "folder %#v already exists, restore not needed", folder.MappedPath)
			continue
		}
		folder.Users = nil
		err = p.addFolder(folder)
		if err != nil {
			providerLog(logger.LevelWarn, "error adding folder %#v: %v", folder.MappedPath, err)
			return err
		}
	}
	for _, user := range dump.Users {
		u, err := p.userExists(user.Username)
		if err == nil {
			user.ID = u.ID
			err = p.updateUser(user)
			if err != nil {
				providerLog(logger.LevelWarn, "error updating user %#v: %v", user.Username, err)
				return err
			}
		} else {
			err = p.addUser(user)
			if err != nil {
				providerLog(logger.LevelWarn, "error adding user %#v: %v", user.Username, err)
				return err
			}
		}
	}
	providerLog(logger.LevelDebug, "user and folders loaded from file: %#v", p.dbHandle.configFile)
	return nil
}

// initializeDatabase does nothing, no initilization is needed for memory provider
func (p MemoryProvider) initializeDatabase() error {
	return ErrNoInitRequired
}

func (p MemoryProvider) migrateDatabase() error {
	return ErrNoInitRequired
}

func (p MemoryProvider) revertDatabase(targetVersion int) error {
	return errors.New("memory provider does not store data, revert not possible")
}
