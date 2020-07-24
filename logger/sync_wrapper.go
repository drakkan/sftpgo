package logger

import (
	"os"
	"sync"
)

type logSyncWrapper struct {
	sync.Mutex
	output *os.File
}

func (l *logSyncWrapper) Write(b []byte) (n int, err error) {
	l.Lock()
	defer l.Unlock()
	return l.output.Write(b)
}
