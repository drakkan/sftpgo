package fsmeta

import (
	"context"
	"errors"
)

var (
	ErrCacheInvalid          = errors.New(`fsmeta: Get(cached key invalid)`)
	ErrCacheMiss             = errors.New(`fsmeta: Get(cache miss)`)
	emptyCache      Getter   = &emptyGetterS{}
	EmptyProvider   Provider = &emptyProvider{}
)

type emptyProvider struct{}

type Getter interface {
	Get(ctx context.Context, Key Key) (Meta, error)
}

type Putter interface {
	Put(ctx context.Context, Meta Meta) error
}

type Provider interface {
	Getter
	Putter
	Preload(ctx context.Context, Folder string) error
}

func (emptyProvider) Get(_ context.Context, Key Key) (Meta, error) {
	return Meta{
		Key:          Key,
		LastModified: Key.StoreTime,
	}, ErrCacheMiss
}

func (emptyProvider) Put(_ context.Context, _ Meta) error {
	return nil
}

func (emptyProvider) Preload(_ context.Context, _ string) error {
	return nil
}
