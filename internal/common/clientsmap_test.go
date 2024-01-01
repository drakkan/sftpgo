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
