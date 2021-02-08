package fsmeta

import (
	"time"
)

var (
	Enabled        bool
	DefaultFactory S3Factory
)

type S3Factory interface {
	New(S3 S3API, Bucket string) Provider
}

type Key struct {
	Path      string    `json:"path"`
	ETag      string    `json:"etag"`
	StoreTime time.Time `json:"store_time"`
	Size      int64     `json:"size"`
}

type Meta struct {
	Key          Key       `json:"key"`
	LastModified time.Time `json:"mtime"`
}
