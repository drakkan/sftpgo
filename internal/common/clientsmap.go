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

package common

import (
	"sync"
	"sync/atomic"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

// clienstMap is a struct containing the map of the connected clients
type clientsMap struct {
	totalConnections atomic.Int32
	mu               sync.RWMutex
	clients          map[string]int
}

func (c *clientsMap) add(source string) {
	c.totalConnections.Add(1)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.clients[source]++
}

func (c *clientsMap) remove(source string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if val, ok := c.clients[source]; ok {
		c.totalConnections.Add(-1)
		c.clients[source]--
		if val > 1 {
			return
		}
		delete(c.clients, source)
	} else {
		logger.Warn(logSender, "", "cannot remove client %v it is not mapped", source)
	}
}

func (c *clientsMap) getTotal() int32 {
	return c.totalConnections.Load()
}

func (c *clientsMap) getTotalFrom(source string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.clients[source]
}
