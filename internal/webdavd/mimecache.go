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

package webdavd

import "sync"

type mimeCache struct {
	maxSize int
	sync.RWMutex
	mimeTypes map[string]string
}

var (
	mimeTypeCache         mimeCache
	customMimeTypeMapping map[string]string
)

func (c *mimeCache) addMimeToCache(key, value string) {
	c.Lock()
	defer c.Unlock()

	if key == "" || value == "" {
		return
	}

	if len(c.mimeTypes) >= c.maxSize {
		return
	}
	c.mimeTypes[key] = value
}

func (c *mimeCache) getMimeFromCache(key string) string {
	c.RLock()
	defer c.RUnlock()

	if val, ok := c.mimeTypes[key]; ok {
		return val
	}
	return ""
}
