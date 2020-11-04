package webdavd

import "sync"

type mimeCache struct {
	maxSize int
	sync.RWMutex
	mimeTypes map[string]string
}

var mimeTypeCache mimeCache

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
