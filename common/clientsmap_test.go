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
