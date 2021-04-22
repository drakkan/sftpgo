package fsmeta

import (
	"context"
	"database/sql"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

type fsMetaPostgres struct {
	DB            *sql.DB
	S3            Getter
	loaded        Getter
	Bucket        string
	folderIDCache map[string]uint64
}

type postgresS3Factory struct {
	DB *sql.DB
}

func (p postgresS3Factory) New(S3 S3API, Bucket string) Provider {
	return &fsMetaPostgres{
		DB:            p.DB,
		S3:            NewS3Provider(S3, Bucket),
		loaded:        emptyCache,
		Bucket:        Bucket,
		folderIDCache: make(map[string]uint64),
	}
}

func NewPostgresS3Factory(DB *sql.DB) S3Factory {
	return &postgresS3Factory{
		DB: DB,
	}
}

func (Provider *fsMetaPostgres) Preload(ctx context.Context, Folder, From, To string) error {
	FolderID, err := Provider.getFolderID(ctx, Folder)
	if err != nil && err == sql.ErrNoRows {
		Provider.loaded = emptyCache
		return nil
	} else if err != nil {
		Provider.loaded = emptyCache
		return err
	}

	From = filepath.Base(From)
	To = filepath.Base(To)

	Rows, err := Provider.DB.QueryContext(ctx, `SELECT filename, filesize, uploaded, etag, last_modified `+
		`FROM fsmeta_files WHERE folder_id = $1`, FolderID)
	//Rows, err := Provider.DB.QueryContext(ctx, `SELECT filename, filesize, uploaded, etag, last_modified `+
	//	`FROM fsmeta_files WHERE folder_id = $1 AND filename >= $2 AND filename <= $3`, FolderID, From, To)
	if err != nil {
		return err
	}
	//goland:noinspection GoUnhandledErrorResult
	defer Rows.Close()

	fileMap := make(fileMap)

	for Rows.Next() {
		var Filename string
		var Meta Meta

		if err := Rows.Scan(&Filename, &Meta.Key.Size, &Meta.Key.StoreTime, &Meta.Key.ETag, &Meta.LastModified); err != nil {
			return err
		}
		Meta.Key.Path = path.Clean(Folder + `/` + Filename)
		fileMap[Meta.Key.Path] = Meta
	}
	if err := Rows.Err(); err != nil {
		return err
	}

	Provider.loaded = fileMap
	return nil
}

func (Provider *fsMetaPostgres) Put(ctx context.Context, Meta Meta) error {
	lastIndex := strings.LastIndex(Meta.Key.Path, `/`)
	if lastIndex > 0 {
		Folder := Meta.Key.Path[0 : lastIndex+1]
		Filename := Meta.Key.Path[lastIndex+1:]

		FolderID, err := Provider.getFolderID(ctx, Folder)
		if err == sql.ErrNoRows {
			FolderID, err = Provider.createFolder(ctx, Folder)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		Meta.Key.ETag = strings.Trim(Meta.Key.ETag, `"`)
		if _, err := Provider.DB.ExecContext(ctx, `INSERT INTO fsmeta_files `+
			`(folder_id, filename, uploaded, filesize, etag, last_modified) VALUES ($1, $2, $3, $4, $5, $6) `+
			`ON CONFLICT (folder_id, filename) DO UPDATE `+
			`SET uploaded=$3, filesize=$4, etag=$5, last_modified=$6`,
			FolderID, Filename, Meta.Key.StoreTime, Meta.Key.Size, Meta.Key.ETag, Meta.LastModified); err != nil {
			return err
		}
	}

	return nil
}

func (Provider *fsMetaPostgres) getFolderID(ctx context.Context, v string) (uint64, error) {
	if ID, ok := Provider.folderIDCache[v]; ok {
		return ID, nil
	}
	var FolderKey uint64
	Row := Provider.DB.QueryRowContext(ctx, `SELECT id FROM fsmeta_folders WHERE path=$1`, Provider.formatPath(v))
	err := Row.Scan(&FolderKey)
	if err == nil {
		Provider.folderIDCache[v] = FolderKey
	}
	return FolderKey, err
}

func (Provider *fsMetaPostgres) createFolder(ctx context.Context, v string) (uint64, error) {
	var folderID uint64
	Row := Provider.DB.QueryRowContext(ctx, `INSERT INTO fsmeta_folders (path) VALUES ($1) ON CONFLICT (path) DO NOTHING RETURNING id`, Provider.formatPath(v))
	err := Row.Scan(&folderID)
	if err == sql.ErrNoRows {
		// ON CONFLICT DO NOTHING: Causes empty result set.
		return Provider.getFolderID(ctx, v)
	} else if err == nil {
		Provider.folderIDCache[v] = folderID
	}
	return folderID, err
}

func (Provider *fsMetaPostgres) formatPath(v string) string {
	return fmt.Sprintf(`s3://%s/%s`, Provider.Bucket, v)
}

func (Provider *fsMetaPostgres) Get(ctx context.Context, Key Key) (Meta, error) {
	if M, err := Provider.loaded.Get(ctx, Key); err == nil {
		return M, nil
	} else if err == ErrCacheMiss || err == ErrCacheInvalid {
		// TODO: metrics self healing.
		S3Meta, err := Provider.S3.Get(ctx, Key)
		if err != nil {
			return Meta{
				Key:          Key,
				LastModified: Key.StoreTime,
			}, err
		}
		if err := Provider.Put(ctx, S3Meta); err != nil {
			return S3Meta, err
		}
		return S3Meta, nil
	} else {
		return Meta{
			Key:          Key,
			LastModified: Key.StoreTime,
		}, err
	}
}
