package logger

import (
	"os"
	"sync"
)

type logSyncWrapper struct {
	output *os.File
	lock   *sync.Mutex
}

func (l logSyncWrapper) Write(b []byte) (n int, err error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	return l.output.Write(b)
}
