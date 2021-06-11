package dataprovider

import (
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/vfs"
)

type compatAzBlobFsConfigV9 struct {
	Container         string      `json:"container,omitempty"`
	AccountName       string      `json:"account_name,omitempty"`
	AccountKey        *kms.Secret `json:"account_key,omitempty"`
	Endpoint          string      `json:"endpoint,omitempty"`
	SASURL            string      `json:"sas_url,omitempty"`
	KeyPrefix         string      `json:"key_prefix,omitempty"`
	UploadPartSize    int64       `json:"upload_part_size,omitempty"`
	UploadConcurrency int         `json:"upload_concurrency,omitempty"`
	UseEmulator       bool        `json:"use_emulator,omitempty"`
	AccessTier        string      `json:"access_tier,omitempty"`
}

type compatFilesystemV9 struct {
	Provider     vfs.FilesystemProvider `json:"provider"`
	S3Config     vfs.S3FsConfig         `json:"s3config,omitempty"`
	GCSConfig    vfs.GCSFsConfig        `json:"gcsconfig,omitempty"`
	AzBlobConfig compatAzBlobFsConfigV9 `json:"azblobconfig,omitempty"`
	CryptConfig  vfs.CryptFsConfig      `json:"cryptconfig,omitempty"`
	SFTPConfig   vfs.SFTPFsConfig       `json:"sftpconfig,omitempty"`
}

type compatBaseFolderV9 struct {
	ID              int64              `json:"id"`
	Name            string             `json:"name"`
	MappedPath      string             `json:"mapped_path,omitempty"`
	Description     string             `json:"description,omitempty"`
	UsedQuotaSize   int64              `json:"used_quota_size"`
	UsedQuotaFiles  int                `json:"used_quota_files"`
	LastQuotaUpdate int64              `json:"last_quota_update"`
	Users           []string           `json:"users,omitempty"`
	FsConfig        compatFilesystemV9 `json:"filesystem"`
}

type compatFolderV9 struct {
	compatBaseFolderV9
	VirtualPath string `json:"virtual_path"`
	QuotaSize   int64  `json:"quota_size"`
	QuotaFiles  int    `json:"quota_files"`
}

type compatUserV9 struct {
	ID       int64              `json:"id"`
	Username string             `json:"username"`
	FsConfig compatFilesystemV9 `json:"filesystem"`
}

func convertFsConfigFromV9(compatFs compatFilesystemV9, aead string) (vfs.Filesystem, error) {
	fsConfig := vfs.Filesystem{
		Provider:    compatFs.Provider,
		S3Config:    compatFs.S3Config,
		GCSConfig:   compatFs.GCSConfig,
		CryptConfig: compatFs.CryptConfig,
		SFTPConfig:  compatFs.SFTPConfig,
	}
	azSASURL := kms.NewEmptySecret()
	if compatFs.Provider == vfs.AzureBlobFilesystemProvider && compatFs.AzBlobConfig.SASURL != "" {
		azSASURL = kms.NewPlainSecret(compatFs.AzBlobConfig.SASURL)
	}
	if compatFs.AzBlobConfig.AccountKey == nil {
		compatFs.AzBlobConfig.AccountKey = kms.NewEmptySecret()
	}
	fsConfig.AzBlobConfig = vfs.AzBlobFsConfig{
		Container:         compatFs.AzBlobConfig.Container,
		AccountName:       compatFs.AzBlobConfig.AccountName,
		AccountKey:        compatFs.AzBlobConfig.AccountKey,
		Endpoint:          compatFs.AzBlobConfig.Endpoint,
		SASURL:            azSASURL,
		KeyPrefix:         compatFs.AzBlobConfig.KeyPrefix,
		UploadPartSize:    compatFs.AzBlobConfig.UploadPartSize,
		UploadConcurrency: compatFs.AzBlobConfig.UploadConcurrency,
		UseEmulator:       compatFs.AzBlobConfig.UseEmulator,
		AccessTier:        compatFs.AzBlobConfig.AccessTier,
	}
	err := fsConfig.AzBlobConfig.EncryptCredentials(aead)
	return fsConfig, err
}

func convertFsConfigToV9(fs vfs.Filesystem) (compatFilesystemV9, error) {
	azSASURL := ""
	if fs.Provider == vfs.AzureBlobFilesystemProvider {
		if fs.AzBlobConfig.SASURL != nil && fs.AzBlobConfig.SASURL.IsEncrypted() {
			err := fs.AzBlobConfig.SASURL.Decrypt()
			if err != nil {
				return compatFilesystemV9{}, err
			}
			azSASURL = fs.AzBlobConfig.SASURL.GetPayload()
		}
	}
	azFsCompat := compatAzBlobFsConfigV9{
		Container:         fs.AzBlobConfig.Container,
		AccountName:       fs.AzBlobConfig.AccountName,
		AccountKey:        fs.AzBlobConfig.AccountKey,
		Endpoint:          fs.AzBlobConfig.Endpoint,
		SASURL:            azSASURL,
		KeyPrefix:         fs.AzBlobConfig.KeyPrefix,
		UploadPartSize:    fs.AzBlobConfig.UploadPartSize,
		UploadConcurrency: fs.AzBlobConfig.UploadConcurrency,
		UseEmulator:       fs.AzBlobConfig.UseEmulator,
		AccessTier:        fs.AzBlobConfig.AccessTier,
	}
	fsV9 := compatFilesystemV9{
		Provider:     fs.Provider,
		S3Config:     fs.S3Config,
		GCSConfig:    fs.GCSConfig,
		AzBlobConfig: azFsCompat,
		CryptConfig:  fs.CryptConfig,
		SFTPConfig:   fs.SFTPConfig,
	}
	return fsV9, nil
}
