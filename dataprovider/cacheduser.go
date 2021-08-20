package dataprovider

import (
	"sync"
	"time"

	"golang.org/x/net/webdav"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	webDAVUsersCache *usersCache
)

func init() {
	webDAVUsersCache = &usersCache{
		users: map[string]CachedUser{},
	}
}

// InitializeWebDAVUserCache initializes the cache for webdav users
func InitializeWebDAVUserCache(maxSize int) {
	webDAVUsersCache = &usersCache{
		users:   map[string]CachedUser{},
		maxSize: maxSize,
	}
}

// CachedUser adds fields useful for caching to a SFTPGo user
type CachedUser struct {
	User       User
	Expiration time.Time
	Password   string
	LockSystem webdav.LockSystem
}

// IsExpired returns true if the cached user is expired
func (c *CachedUser) IsExpired() bool {
	if c.Expiration.IsZero() {
		return false
	}
	return c.Expiration.Before(time.Now())
}

type usersCache struct {
	sync.RWMutex
	users   map[string]CachedUser
	maxSize int
}

func (cache *usersCache) updateLastLogin(username string) {
	cache.Lock()
	defer cache.Unlock()

	if cachedUser, ok := cache.users[username]; ok {
		cachedUser.User.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
		cache.users[username] = cachedUser
	}
}

// swapWebDAVUser updates an existing cached user with the specified one
// preserving the lock fs if possible
func (cache *usersCache) swap(user *User) {
	cache.Lock()
	defer cache.Unlock()

	if cachedUser, ok := cache.users[user.Username]; ok {
		if cachedUser.User.Password != user.Password {
			providerLog(logger.LevelDebug, "current password different from the cached one for user %#v, removing from cache",
				user.Username)
			// the password changed, the cached user is no longer valid
			delete(cache.users, user.Username)
			return
		}
		if cachedUser.User.isFsEqual(user) {
			// the updated user has the same fs as the cached one, we can preserve the lock filesystem
			providerLog(logger.LevelDebug, "current password and fs unchanged for for user %#v, swap cached one",
				user.Username)
			cachedUser.User = *user
			cache.users[user.Username] = cachedUser
		} else {
			// filesystem changed, the cached user is no longer valid
			providerLog(logger.LevelDebug, "current fs different from the cached one for user %#v, removing from cache",
				user.Username)
			delete(cache.users, user.Username)
		}
	}
}

func (cache *usersCache) add(cachedUser *CachedUser) {
	cache.Lock()
	defer cache.Unlock()

	if cache.maxSize > 0 && len(cache.users) >= cache.maxSize {
		var userToRemove string
		var expirationTime time.Time

		for k, v := range cache.users {
			if userToRemove == "" {
				userToRemove = k
				expirationTime = v.Expiration
				continue
			}
			expireTime := v.Expiration
			if !expireTime.IsZero() && expireTime.Before(expirationTime) {
				userToRemove = k
				expirationTime = expireTime
			}
		}

		delete(cache.users, userToRemove)
	}

	if cachedUser.User.Username != "" {
		cache.users[cachedUser.User.Username] = *cachedUser
	}
}

func (cache *usersCache) remove(username string) {
	cache.Lock()
	defer cache.Unlock()

	delete(cache.users, username)
}

func (cache *usersCache) get(username string) (*CachedUser, bool) {
	cache.RLock()
	defer cache.RUnlock()

	cachedUser, ok := cache.users[username]
	return &cachedUser, ok
}

// CacheWebDAVUser add a user to the WebDAV cache
func CacheWebDAVUser(cachedUser *CachedUser) {
	webDAVUsersCache.add(cachedUser)
}

// GetCachedWebDAVUser returns a previously cached WebDAV user
func GetCachedWebDAVUser(username string) (*CachedUser, bool) {
	return webDAVUsersCache.get(username)
}

// RemoveCachedWebDAVUser removes a cached WebDAV user
func RemoveCachedWebDAVUser(username string) {
	webDAVUsersCache.remove(username)
}
