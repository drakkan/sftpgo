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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientsMap(t *testing.T) {
	m := clientsMap{
		clients: make(map[string]int),
	}
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"
	m.add(ip1)
	assert.Equal(t, int32(1), m.getTotal())
	assert.Equal(t, 1, m.getTotalFrom(ip1))
	assert.Equal(t, 0, m.getTotalFrom(ip2))

	m.add(ip1)
	m.add(ip2)
	assert.Equal(t, int32(3), m.getTotal())
	assert.Equal(t, 2, m.getTotalFrom(ip1))
	assert.Equal(t, 1, m.getTotalFrom(ip2))

	m.add(ip1)
	m.add(ip1)
	m.add(ip2)
	assert.Equal(t, int32(6), m.getTotal())
	assert.Equal(t, 4, m.getTotalFrom(ip1))
	assert.Equal(t, 2, m.getTotalFrom(ip2))

	m.remove(ip2)
	assert.Equal(t, int32(5), m.getTotal())
	assert.Equal(t, 4, m.getTotalFrom(ip1))
	assert.Equal(t, 1, m.getTotalFrom(ip2))

	m.remove("unknown")
	assert.Equal(t, int32(5), m.getTotal())
	assert.Equal(t, 4, m.getTotalFrom(ip1))
	assert.Equal(t, 1, m.getTotalFrom(ip2))

	m.remove(ip2)
	assert.Equal(t, int32(4), m.getTotal())
	assert.Equal(t, 4, m.getTotalFrom(ip1))
	assert.Equal(t, 0, m.getTotalFrom(ip2))

	m.remove(ip1)
	m.remove(ip1)
	m.remove(ip1)
	assert.Equal(t, int32(1), m.getTotal())
	assert.Equal(t, 1, m.getTotalFrom(ip1))
	assert.Equal(t, 0, m.getTotalFrom(ip2))

	m.remove(ip1)
	assert.Equal(t, int32(0), m.getTotal())
	assert.Equal(t, 0, m.getTotalFrom(ip1))
	assert.Equal(t, 0, m.getTotalFrom(ip2))
}

func TestClientsMapTryAdd(t *testing.T) {
	m := clientsMap{
		clients: make(map[string]int),
	}
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"
	assert.True(t, m.tryAdd(ip1, 2))
	assert.True(t, m.tryAdd(ip1, 2))
	assert.False(t, m.tryAdd(ip1, 2))
	assert.True(t, m.tryAdd(ip2, 2))
	assert.Equal(t, int32(3), m.getTotal())
	assert.Equal(t, 2, m.getTotalFrom(ip1))
	// 0 means no limit
	assert.True(t, m.tryAdd(ip1, 0))
	assert.Equal(t, 3, m.getTotalFrom(ip1))
	m.remove(ip1)
	m.remove(ip1)
	assert.True(t, m.tryAdd(ip1, 2))

	// concurrent additions never exceed the limit
	const limit = 10
	var wg sync.WaitGroup
	var added atomic.Int32
	for range 100 {
		wg.Go(func() {
			if m.tryAdd("concurrent", limit) {
				added.Add(1)
			}
		})
	}
	wg.Wait()
	assert.Equal(t, int32(limit), added.Load())
	assert.Equal(t, limit, m.getTotalFrom("concurrent"))
}
