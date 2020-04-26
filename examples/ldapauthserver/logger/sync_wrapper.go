package logger

import (
	"os"
	"sync"
)

type logSyncWrapper struct {
	lock   *sync.Mutex
	output *os.File
}

func (l logSyncWrapper) Write(b []byte) (n int, err error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	return l.output.Write(b)
}
