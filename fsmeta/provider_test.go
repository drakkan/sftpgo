package fsmeta

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEmptyProvider(t *testing.T) {
	Ctx := context.Background()
	Key := Key{
		Path:      `users/test1/`,
		ETag:      "9b99c17f7943a02a250fc6ca7d10efcd",
		StoreTime: time.Now(),
		Size:      1645,
	}

	assert.Nil(t, EmptyProvider.Put(Ctx, Meta{
		Key:          Key,
		LastModified: time.Now(),
	}))
	assert.Nil(t, EmptyProvider.Preload(Ctx, ``, ``, ``))

	Actual, err := EmptyProvider.Get(Ctx, Key)

	assert.Equal(t, Meta{
		Key:          Key,
		LastModified: Key.StoreTime,
	}, Actual)
	assert.Equal(t, ErrCacheMiss, err)
}
