package fsmeta

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

func TestEmptyCache(t *testing.T) {
	Key := Key{
		Path:      `users/test3/test.csv`,
		ETag:      `etag3`,
		StoreTime: time.Now(),
		Size:      12345,
	}
	Actual, err := emptyCache.Get(context.Background(), Key)
	assert.Equal(t, ErrCacheMiss, err)
	assert.Equal(t, Meta{
		Key:          Key,
		LastModified: Key.StoreTime,
	}, Actual)
}

func TestParseTime(t *testing.T) {
	Expected := time.Date(2020, time.January, 12, 23, 45, 14, 0, time.UTC)

	// Test RFC3339
	Actual, err := parseTime(Expected.Format(time.RFC3339))
	assert.Nil(t, err)
	assert.True(t, Expected.Equal(Actual))

	// Test Unix (Seconds)
	Actual, err = parseTime(strconv.FormatInt(Expected.Unix(), 10))
	assert.Nil(t, err)
	assert.True(t, Expected.Equal(Actual))

	// Test Unix (Nanoseconds)
	Actual, err = parseTime(strconv.FormatInt(Expected.UnixNano(), 10))
	assert.Nil(t, err)
	assert.True(t, Expected.Equal(Actual))

	// Test Invalid Date
	Actual, err = parseTime(`not a date`)
	assert.EqualError(t, err, `parsing time "not a date" as "2006-01-02T15:04:05Z07:00": cannot parse "not a date" as "2006"`)
	assert.Equal(t, time.Time{}, Actual)
}

func TestNewS3Metadata(t *testing.T) {
	EnabledRestore := Enabled
	t.Cleanup(func() {
		Enabled = EnabledRestore
	})

	Enabled = false
	assert.Nil(t, NewS3Metadata(time.Now()))
	assert.Nil(t, NewS3Metadata(time.Time{}))

	Enabled = true
	Now := time.Now()
	Expected := make(map[string]*string)
	Expected[S3MetaKey] = aws.String(Now.Format(time.RFC3339))
	assert.Equal(t, Expected, NewS3Metadata(Now))
}

func TestKeyEqualsETagQuotes(t *testing.T) {
	Key1 := Key{
		Path:      "users/test1/test.csv",
		ETag:      "abcd1234",
		StoreTime: time.Time{},
		Size:      12345,
	}

	Key2 := Key1
	Key2.ETag = `"` + Key1.ETag + `"`

	assert.True(t, Key1.Equals(Key2))
}

func TestKeyEqualsStoreTimeTolerance(t *testing.T) {
	Key1 := Key{
		Path:      "users/test1/test.csv",
		ETag:      "abcd1234",
		StoreTime: time.Now(),
		Size:      12345,
	}

	Key2 := Key1
	Key2.StoreTime = Key1.StoreTime.Add(999 * time.Millisecond)
	assert.True(t, Key1.Equals(Key2))

	Key2.StoreTime = Key1.StoreTime.Add(-999 * time.Millisecond)
	assert.True(t, Key1.Equals(Key2))

	Key2.StoreTime = Key1.StoreTime.Add(1000 * time.Millisecond)
	assert.False(t, Key1.Equals(Key2))

	Key2.StoreTime = Key1.StoreTime.Add(-1000 * time.Millisecond)
	assert.False(t, Key1.Equals(Key2))
}
