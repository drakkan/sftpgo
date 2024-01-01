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
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	cachedUserPasswords  credentialsCache
	cachedAdminPasswords credentialsCache
	cachedAPIKeys        credentialsCache
)

func init() {
	cachedUserPasswords = credentialsCache{
		name:      "users",
		sizeLimit: 500,
		cache:     make(map[string]credentialObject),
	}
	cachedAdminPasswords = credentialsCache{
		name:      "admins",
		sizeLimit: 100,
		cache:     make(map[string]credentialObject),
	}
	cachedAPIKeys = credentialsCache{
		name:      "API keys",
		sizeLimit: 500,
		cache:     make(map[string]credentialObject),
	}
}

// CheckCachedUserPassword is an utility method used only in test cases
func CheckCachedUserPassword(username, password, hash string) (bool, bool) {
	return cachedUserPasswords.Check(username, password, hash)
}

type credentialObject struct {
	key      string
	hash     string
	password string
	usedAt   *atomic.Int64
}

type credentialsCache struct {
	name      string
	sizeLimit int
	sync.RWMutex
	cache map[string]credentialObject
}

func (c *credentialsCache) Add(username, password, hash string) {
	if !config.PasswordCaching || username == "" || password == "" || hash == "" {
		return
	}

	c.Lock()
	defer c.Unlock()

	obj := credentialObject{
		key:      username,
		hash:     hash,
		password: password,
		usedAt:   &atomic.Int64{},
	}
	obj.usedAt.Store(util.GetTimeAsMsSinceEpoch(time.Now()))

	c.cache[username] = obj
}

func (c *credentialsCache) Remove(username string) {
	if !config.PasswordCaching {
		return
	}

	c.Lock()
	defer c.Unlock()

	delete(c.cache, username)
}

// Check returns if the username is found and if the password match
func (c *credentialsCache) Check(username, password, hash string) (bool, bool) {
	if username == "" || password == "" || hash == "" {
		return false, false
	}

	c.RLock()
	defer c.RUnlock()

	creds, ok := c.cache[username]
	if !ok {
		return false, false
	}
	if creds.hash != hash {
		creds.usedAt.Store(0)
		return false, false
	}
	match := creds.password == password
	if match {
		creds.usedAt.Store(util.GetTimeAsMsSinceEpoch(time.Now()))
	}
	return true, match
}

func (c *credentialsCache) count() int {
	c.RLock()
	defer c.RUnlock()

	return len(c.cache)
}

func (c *credentialsCache) cleanup() {
	if !config.PasswordCaching {
		return
	}
	if c.count() <= c.sizeLimit {
		return
	}

	c.Lock()
	defer c.Unlock()

	for k, v := range c.cache {
		if v.usedAt.Load() < util.GetTimeAsMsSinceEpoch(time.Now().Add(-60*time.Minute)) {
			delete(c.cache, k)
		}
	}
	providerLog(logger.LevelDebug, "size for credentials %q after cleanup: %d", c.name, len(c.cache))

	if len(c.cache) < c.sizeLimit*5 {
		return
	}
	numToRemove := len(c.cache) - c.sizeLimit
	providerLog(logger.LevelDebug, "additional item to remove from credentials %q: %d", c.name, numToRemove)
	credentials := make([]credentialObject, 0, len(c.cache))
	for _, v := range c.cache {
		credentials = append(credentials, v)
	}
	sort.Slice(credentials, func(i, j int) bool {
		return credentials[i].usedAt.Load() < credentials[j].usedAt.Load()
	})

	for idx := range credentials {
		if idx >= numToRemove {
			break
		}
		delete(c.cache, credentials[idx].key)
	}
	providerLog(logger.LevelDebug, "size for credentials %q after additional cleanup: %d", c.name, len(c.cache))
}
