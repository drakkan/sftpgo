package common

import (
	"sync"
	"sync/atomic"

	"github.com/drakkan/sftpgo/v2/logger"
)

// clienstMap is a struct containing the map of the connected clients
type clientsMap struct {
	totalConnections int32
	mu               sync.RWMutex
	clients          map[string]int
}

func (c *clientsMap) add(source string) {
	atomic.AddInt32(&c.totalConnections, 1)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.clients[source]++
}

func (c *clientsMap) remove(source string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if val, ok := c.clients[source]; ok {
		atomic.AddInt32(&c.totalConnections, -1)
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
	return atomic.LoadInt32(&c.totalConnections)
}

func (c *clientsMap) getTotalFrom(source string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.clients[source]
}
