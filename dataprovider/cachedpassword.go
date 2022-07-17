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
	"sync"
)

var cachedPasswords passwordsCache

func init() {
	cachedPasswords = passwordsCache{
		cache: make(map[string]string),
	}
}

type passwordsCache struct {
	sync.RWMutex
	cache map[string]string
}

func (c *passwordsCache) Add(username, password string) {
	if !config.PasswordCaching || username == "" || password == "" {
		return
	}

	c.Lock()
	defer c.Unlock()

	c.cache[username] = password
}

func (c *passwordsCache) Remove(username string) {
	if !config.PasswordCaching {
		return
	}

	c.Lock()
	defer c.Unlock()

	delete(c.cache, username)
}

// Check returns if the user is found and if the password match
func (c *passwordsCache) Check(username, password string) (bool, bool) {
	if username == "" || password == "" {
		return false, false
	}

	c.RLock()
	defer c.RUnlock()

	pwd, ok := c.cache[username]
	if !ok {
		return false, false
	}

	return true, pwd == password
}

// CheckCachedPassword is an utility method used only in test cases
func CheckCachedPassword(username, password string) (bool, bool) {
	return cachedPasswords.Check(username, password)
}
