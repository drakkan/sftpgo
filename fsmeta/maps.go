package fsmeta

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
)

type emptyGetterS struct{}
type fileMap map[string]Meta
type MetaHelper map[string]*string

var (
	ErrMetaKeyNotFound = errors.New(`meta key not found`)
)

func (K Key) Equals(Cmp Key) bool {
	K.ETag = strings.Trim(K.ETag, `"`)
	Cmp.ETag = strings.Trim(Cmp.ETag, `"`)

	return K.Size == Cmp.Size &&
		K.Path == Cmp.Path &&
		K.ETag == Cmp.ETag &&
		K.StoreTime.Equal(Cmp.StoreTime)
}

func (f emptyGetterS) Get(_ context.Context, Key Key) (Meta, error) {
	return Meta{
		Key:          Key,
		LastModified: Key.StoreTime,
	}, ErrCacheMiss
}

func (f fileMap) Get(_ context.Context, Key Key) (Meta, error) {
	if Record, ok := f[Key.Path]; ok {
		if Record.Key.Equals(Key) {
			return Record, nil
		}
		return Meta{
			Key: Key,
		}, ErrCacheInvalid
	}
	return Meta{
		Key: Key,
	}, ErrCacheMiss
}

func (Helper MetaHelper) GetTime(Key string) (time.Time, error) {
	if Value, ok := Helper[Key]; ok && Value != nil {
		return parseTime(*Value)
	} else if Value, ok := Helper[strings.ToLower(Key)]; ok && Value != nil {
		return parseTime(*Value)
	}

	return time.Time{}, ErrMetaKeyNotFound
}

// parseTime parse a time in either RFC3339 format, an Int(seconds), or an Int(Nanoseconds)
func parseTime(v string) (time.Time, error) {
	if Time, err := time.Parse(time.RFC3339, v); err == nil {
		return Time, nil
	} else if I, errInt := strconv.ParseInt(v, 10, 64); errInt == nil {
		if I > 100000000000 {
			// Assume time.UnixNano()
			return time.Unix(0, I), nil
		}
		return time.Unix(I, 0), nil
	} else {
		return time.Time{}, err
	}
}

func NewS3Metadata(T time.Time) map[string]*string {
	if !Enabled || T.IsZero() {
		return nil
	}
	m := make(map[string]*string)
	m[S3MetaKey] = aws.String(T.Format(time.RFC3339))
	return m
}
