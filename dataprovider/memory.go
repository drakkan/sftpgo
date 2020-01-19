package dataprovider

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

var (
	errMemoryProviderClosed = errors.New("memory provider is closed")
)

type memoryProviderHandle struct {
	isClosed bool
	// slice with ordered usernames
	usernames []string
	// mapping between ID and username
	usersIdx map[int64]string
	// map for users, username is the key
	users map[string]User
	lock  *sync.Mutex
}

// MemoryProvider auth provider for a memory store
type MemoryProvider struct {
	dbHandle *memoryProviderHandle
}

func initializeMemoryProvider() error {
	provider = MemoryProvider{
		dbHandle: &memoryProviderHandle{
			isClosed:  false,
			usernames: []string{},
			usersIdx:  make(map[int64]string),
			users:     make(map[string]User),
			lock:      new(sync.Mutex),
		},
	}
	return nil
}

func (p MemoryProvider) checkAvailability() error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	return nil
}

func (p MemoryProvider) close() error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	p.dbHandle.isClosed = true
	return nil
}

func (p MemoryProvider) validateUserAndPass(username string, password string) (User, error) {
	var user User
	if len(password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, err
	}
	return checkUserAndPass(user, password)
}

func (p MemoryProvider) validateUserAndPubKey(username string, pubKey string) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(user, pubKey)
}

func (p MemoryProvider) getUserByID(ID int64) (User, error) {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errMemoryProviderClosed
	}
	if val, ok := p.dbHandle.usersIdx[ID]; ok {
		return p.userExistsInternal(val)
	}
	return User{}, &RecordNotFoundError{err: fmt.Sprintf("user with ID %v does not exist", ID)}
}

func (p MemoryProvider) updateLastLogin(username string) error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
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
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to update quota for user %v error: %v", username, err)
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
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p MemoryProvider) getUsedQuota(username string) (int, int64, error) {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return 0, 0, errMemoryProviderClosed
	}
	user, err := p.userExistsInternal(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to get quota for user %v error: %v", username, err)
		return 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, err
}

func (p MemoryProvider) addUser(user User) error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	err := validateUser(&user)
	if err != nil {
		return err
	}
	_, err = p.userExistsInternal(user.Username)
	if err == nil {
		return fmt.Errorf("username %v already exists", user.Username)
	}
	user.ID = p.getNextID()
	p.dbHandle.users[user.Username] = user
	p.dbHandle.usersIdx[user.ID] = user.Username
	p.dbHandle.usernames = append(p.dbHandle.usernames, user.Username)
	sort.Strings(p.dbHandle.usernames)
	return nil
}

func (p MemoryProvider) updateUser(user User) error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	err := validateUser(&user)
	if err != nil {
		return err
	}
	_, err = p.userExistsInternal(user.Username)
	if err != nil {
		return err
	}
	p.dbHandle.users[user.Username] = user
	return nil
}

func (p MemoryProvider) deleteUser(user User) error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errMemoryProviderClosed
	}
	_, err := p.userExistsInternal(user.Username)
	if err != nil {
		return err
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
	users := []User{}
	var err error
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return users, errMemoryProviderClosed
	}
	for _, username := range p.dbHandle.usernames {
		user := p.dbHandle.users[username]
		users = append(users, user)
	}
	return users, err
}

func (p MemoryProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	users := []User{}
	var err error
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
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
				users = append(users, HideUserSensitiveData(&user))
			}
		}
		return users, err
	}
	itNum := 0
	if order == "ASC" {
		for _, username := range p.dbHandle.usernames {
			itNum++
			if itNum <= offset {
				continue
			}
			user := p.dbHandle.users[username]
			users = append(users, HideUserSensitiveData(&user))
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
			user := p.dbHandle.users[username]
			users = append(users, HideUserSensitiveData(&user))
			if len(users) >= limit {
				break
			}
		}
	}
	return users, err
}

func (p MemoryProvider) userExists(username string) (User, error) {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errMemoryProviderClosed
	}
	return p.userExistsInternal(username)
}

func (p MemoryProvider) userExistsInternal(username string) (User, error) {
	if val, ok := p.dbHandle.users[username]; ok {
		return val.getACopy(), nil
	}
	return User{}, &RecordNotFoundError{err: fmt.Sprintf("username %v does not exist", username)}
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
