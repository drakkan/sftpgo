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
