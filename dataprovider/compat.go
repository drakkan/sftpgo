package dataprovider

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

type compatUserV2 struct {
	ID                int64    `json:"id"`
	Username          string   `json:"username"`
	Password          string   `json:"password,omitempty"`
	PublicKeys        []string `json:"public_keys,omitempty"`
	HomeDir           string   `json:"home_dir"`
	UID               int      `json:"uid"`
	GID               int      `json:"gid"`
	MaxSessions       int      `json:"max_sessions"`
	QuotaSize         int64    `json:"quota_size"`
	QuotaFiles        int      `json:"quota_files"`
	Permissions       []string `json:"permissions"`
	UsedQuotaSize     int64    `json:"used_quota_size"`
	UsedQuotaFiles    int      `json:"used_quota_files"`
	LastQuotaUpdate   int64    `json:"last_quota_update"`
	UploadBandwidth   int64    `json:"upload_bandwidth"`
	DownloadBandwidth int64    `json:"download_bandwidth"`
	ExpirationDate    int64    `json:"expiration_date"`
	LastLogin         int64    `json:"last_login"`
	Status            int      `json:"status"`
}

type compatS3FsConfigV4 struct {
	Bucket            string `json:"bucket,omitempty"`
	KeyPrefix         string `json:"key_prefix,omitempty"`
	Region            string `json:"region,omitempty"`
	AccessKey         string `json:"access_key,omitempty"`
	AccessSecret      string `json:"access_secret,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	StorageClass      string `json:"storage_class,omitempty"`
	UploadPartSize    int64  `json:"upload_part_size,omitempty"`
	UploadConcurrency int    `json:"upload_concurrency,omitempty"`
}

type compatGCSFsConfigV4 struct {
	Bucket               string `json:"bucket,omitempty"`
	KeyPrefix            string `json:"key_prefix,omitempty"`
	CredentialFile       string `json:"-"`
	Credentials          []byte `json:"credentials,omitempty"`
	AutomaticCredentials int    `json:"automatic_credentials,omitempty"`
	StorageClass         string `json:"storage_class,omitempty"`
}

type compatAzBlobFsConfigV4 struct {
	Container         string `json:"container,omitempty"`
	AccountName       string `json:"account_name,omitempty"`
	AccountKey        string `json:"account_key,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	SASURL            string `json:"sas_url,omitempty"`
	KeyPrefix         string `json:"key_prefix,omitempty"`
	UploadPartSize    int64  `json:"upload_part_size,omitempty"`
	UploadConcurrency int    `json:"upload_concurrency,omitempty"`
	UseEmulator       bool   `json:"use_emulator,omitempty"`
	AccessTier        string `json:"access_tier,omitempty"`
}

type compatFilesystemV4 struct {
	Provider     FilesystemProvider     `json:"provider"`
	S3Config     compatS3FsConfigV4     `json:"s3config,omitempty"`
	GCSConfig    compatGCSFsConfigV4    `json:"gcsconfig,omitempty"`
	AzBlobConfig compatAzBlobFsConfigV4 `json:"azblobconfig,omitempty"`
}

type compatUserV4 struct {
	ID                int64               `json:"id"`
	Status            int                 `json:"status"`
	Username          string              `json:"username"`
	ExpirationDate    int64               `json:"expiration_date"`
	Password          string              `json:"password,omitempty"`
	PublicKeys        []string            `json:"public_keys,omitempty"`
	HomeDir           string              `json:"home_dir"`
	VirtualFolders    []vfs.VirtualFolder `json:"virtual_folders,omitempty"`
	UID               int                 `json:"uid"`
	GID               int                 `json:"gid"`
	MaxSessions       int                 `json:"max_sessions"`
	QuotaSize         int64               `json:"quota_size"`
	QuotaFiles        int                 `json:"quota_files"`
	Permissions       map[string][]string `json:"permissions"`
	UsedQuotaSize     int64               `json:"used_quota_size"`
	UsedQuotaFiles    int                 `json:"used_quota_files"`
	LastQuotaUpdate   int64               `json:"last_quota_update"`
	UploadBandwidth   int64               `json:"upload_bandwidth"`
	DownloadBandwidth int64               `json:"download_bandwidth"`
	LastLogin         int64               `json:"last_login"`
	Filters           UserFilters         `json:"filters"`
	FsConfig          compatFilesystemV4  `json:"filesystem"`
}

type backupDataV4Compat struct {
	Users   []compatUserV4          `json:"users"`
	Folders []vfs.BaseVirtualFolder `json:"folders"`
}

func createUserFromV4(u compatUserV4, fsConfig Filesystem) User {
	user := User{
		ID:                u.ID,
		Status:            u.Status,
		Username:          u.Username,
		ExpirationDate:    u.ExpirationDate,
		Password:          u.Password,
		PublicKeys:        u.PublicKeys,
		HomeDir:           u.HomeDir,
		VirtualFolders:    u.VirtualFolders,
		UID:               u.UID,
		GID:               u.GID,
		MaxSessions:       u.MaxSessions,
		QuotaSize:         u.QuotaSize,
		QuotaFiles:        u.QuotaFiles,
		Permissions:       u.Permissions,
		UsedQuotaSize:     u.UsedQuotaSize,
		UsedQuotaFiles:    u.UsedQuotaFiles,
		LastQuotaUpdate:   u.LastQuotaUpdate,
		UploadBandwidth:   u.UploadBandwidth,
		DownloadBandwidth: u.DownloadBandwidth,
		LastLogin:         u.LastLogin,
		Filters:           u.Filters,
	}
	user.FsConfig = fsConfig
	user.SetEmptySecretsIfNil()
	return user
}

func convertUserToV4(u User, fsConfig compatFilesystemV4) compatUserV4 {
	user := compatUserV4{
		ID:                u.ID,
		Status:            u.Status,
		Username:          u.Username,
		ExpirationDate:    u.ExpirationDate,
		Password:          u.Password,
		PublicKeys:        u.PublicKeys,
		HomeDir:           u.HomeDir,
		VirtualFolders:    u.VirtualFolders,
		UID:               u.UID,
		GID:               u.GID,
		MaxSessions:       u.MaxSessions,
		QuotaSize:         u.QuotaSize,
		QuotaFiles:        u.QuotaFiles,
		Permissions:       u.Permissions,
		UsedQuotaSize:     u.UsedQuotaSize,
		UsedQuotaFiles:    u.UsedQuotaFiles,
		LastQuotaUpdate:   u.LastQuotaUpdate,
		UploadBandwidth:   u.UploadBandwidth,
		DownloadBandwidth: u.DownloadBandwidth,
		LastLogin:         u.LastLogin,
		Filters:           u.Filters,
	}
	user.FsConfig = fsConfig
	return user
}

func getCGSCredentialsFromV4(config compatGCSFsConfigV4) (*kms.Secret, error) {
	secret := kms.NewEmptySecret()
	var err error
	if len(config.Credentials) > 0 {
		secret = kms.NewPlainSecret(string(config.Credentials))
		return secret, nil
	}
	if config.CredentialFile != "" {
		creds, err := ioutil.ReadFile(config.CredentialFile)
		if err != nil {
			return secret, err
		}
		secret = kms.NewPlainSecret(string(creds))
		return secret, nil
	}
	return secret, err
}

func getCGSCredentialsFromV6(config vfs.GCSFsConfig, username string) (string, error) {
	if config.Credentials == nil {
		config.Credentials = kms.NewEmptySecret()
	}
	if config.Credentials.IsEmpty() {
		config.CredentialFile = filepath.Join(credentialsDirPath, fmt.Sprintf("%v_gcs_credentials.json",
			username))
		creds, err := ioutil.ReadFile(config.CredentialFile)
		if err != nil {
			return "", err
		}
		err = json.Unmarshal(creds, &config.Credentials)
		if err != nil {
			return "", err
		}
	}
	if config.Credentials.IsEncrypted() {
		err := config.Credentials.Decrypt()
		if err != nil {
			return "", err
		}
		// in V4 GCS credentials were not encrypted
		return config.Credentials.GetPayload(), nil
	}
	return "", nil
}

func convertFsConfigToV4(fs Filesystem, username string) (compatFilesystemV4, error) {
	fsV4 := compatFilesystemV4{
		Provider:     fs.Provider,
		S3Config:     compatS3FsConfigV4{},
		AzBlobConfig: compatAzBlobFsConfigV4{},
		GCSConfig:    compatGCSFsConfigV4{},
	}
	switch fs.Provider {
	case S3FilesystemProvider:
		fsV4.S3Config = compatS3FsConfigV4{
			Bucket:            fs.S3Config.Bucket,
			KeyPrefix:         fs.S3Config.KeyPrefix,
			Region:            fs.S3Config.Region,
			AccessKey:         fs.S3Config.AccessKey,
			AccessSecret:      "",
			Endpoint:          fs.S3Config.Endpoint,
			StorageClass:      fs.S3Config.StorageClass,
			UploadPartSize:    fs.S3Config.UploadPartSize,
			UploadConcurrency: fs.S3Config.UploadConcurrency,
		}
		if fs.S3Config.AccessSecret.IsEncrypted() {
			err := fs.S3Config.AccessSecret.Decrypt()
			if err != nil {
				return fsV4, err
			}
			secretV4, err := utils.EncryptData(fs.S3Config.AccessSecret.GetPayload())
			if err != nil {
				return fsV4, err
			}
			fsV4.S3Config.AccessSecret = secretV4
		}
	case AzureBlobFilesystemProvider:
		fsV4.AzBlobConfig = compatAzBlobFsConfigV4{
			Container:         fs.AzBlobConfig.Container,
			AccountName:       fs.AzBlobConfig.AccountName,
			AccountKey:        "",
			Endpoint:          fs.AzBlobConfig.Endpoint,
			SASURL:            fs.AzBlobConfig.SASURL,
			KeyPrefix:         fs.AzBlobConfig.KeyPrefix,
			UploadPartSize:    fs.AzBlobConfig.UploadPartSize,
			UploadConcurrency: fs.AzBlobConfig.UploadConcurrency,
			UseEmulator:       fs.AzBlobConfig.UseEmulator,
			AccessTier:        fs.AzBlobConfig.AccessTier,
		}
		if fs.AzBlobConfig.AccountKey.IsEncrypted() {
			err := fs.AzBlobConfig.AccountKey.Decrypt()
			if err != nil {
				return fsV4, err
			}
			secretV4, err := utils.EncryptData(fs.AzBlobConfig.AccountKey.GetPayload())
			if err != nil {
				return fsV4, err
			}
			fsV4.AzBlobConfig.AccountKey = secretV4
		}
	case GCSFilesystemProvider:
		fsV4.GCSConfig = compatGCSFsConfigV4{
			Bucket:               fs.GCSConfig.Bucket,
			KeyPrefix:            fs.GCSConfig.KeyPrefix,
			CredentialFile:       fs.GCSConfig.CredentialFile,
			AutomaticCredentials: fs.GCSConfig.AutomaticCredentials,
			StorageClass:         fs.GCSConfig.StorageClass,
		}
		if fs.GCSConfig.AutomaticCredentials == 0 {
			creds, err := getCGSCredentialsFromV6(fs.GCSConfig, username)
			if err != nil {
				return fsV4, err
			}
			fsV4.GCSConfig.Credentials = []byte(creds)
		}
	case CryptedFilesystemProvider:
		// crypted provider was not supported in v4, the configuration will be lost
		fsV4.Provider = 0
	}
	return fsV4, nil
}

func convertFsConfigFromV4(compatFs compatFilesystemV4, username string) (Filesystem, error) {
	fsConfig := Filesystem{
		Provider:     compatFs.Provider,
		S3Config:     vfs.S3FsConfig{},
		AzBlobConfig: vfs.AzBlobFsConfig{},
		GCSConfig:    vfs.GCSFsConfig{},
	}
	switch compatFs.Provider {
	case S3FilesystemProvider:
		fsConfig.S3Config = vfs.S3FsConfig{
			Bucket:            compatFs.S3Config.Bucket,
			KeyPrefix:         compatFs.S3Config.KeyPrefix,
			Region:            compatFs.S3Config.Region,
			AccessKey:         compatFs.S3Config.AccessKey,
			AccessSecret:      kms.NewEmptySecret(),
			Endpoint:          compatFs.S3Config.Endpoint,
			StorageClass:      compatFs.S3Config.StorageClass,
			UploadPartSize:    compatFs.S3Config.UploadPartSize,
			UploadConcurrency: compatFs.S3Config.UploadConcurrency,
		}
		if compatFs.S3Config.AccessSecret != "" {
			secret, err := kms.GetSecretFromCompatString(compatFs.S3Config.AccessSecret)
			if err != nil {
				providerLog(logger.LevelError, "unable to convert v4 filesystem for user %#v: %v", username, err)
				return fsConfig, err
			}
			fsConfig.S3Config.AccessSecret = secret
		}
	case AzureBlobFilesystemProvider:
		fsConfig.AzBlobConfig = vfs.AzBlobFsConfig{
			Container:         compatFs.AzBlobConfig.Container,
			AccountName:       compatFs.AzBlobConfig.AccountName,
			AccountKey:        kms.NewEmptySecret(),
			Endpoint:          compatFs.AzBlobConfig.Endpoint,
			SASURL:            compatFs.AzBlobConfig.SASURL,
			KeyPrefix:         compatFs.AzBlobConfig.KeyPrefix,
			UploadPartSize:    compatFs.AzBlobConfig.UploadPartSize,
			UploadConcurrency: compatFs.AzBlobConfig.UploadConcurrency,
			UseEmulator:       compatFs.AzBlobConfig.UseEmulator,
			AccessTier:        compatFs.AzBlobConfig.AccessTier,
		}
		if compatFs.AzBlobConfig.AccountKey != "" {
			secret, err := kms.GetSecretFromCompatString(compatFs.AzBlobConfig.AccountKey)
			if err != nil {
				providerLog(logger.LevelError, "unable to convert v4 filesystem for user %#v: %v", username, err)
				return fsConfig, err
			}
			fsConfig.AzBlobConfig.AccountKey = secret
		}
	case GCSFilesystemProvider:
		fsConfig.GCSConfig = vfs.GCSFsConfig{
			Bucket:               compatFs.GCSConfig.Bucket,
			KeyPrefix:            compatFs.GCSConfig.KeyPrefix,
			CredentialFile:       compatFs.GCSConfig.CredentialFile,
			AutomaticCredentials: compatFs.GCSConfig.AutomaticCredentials,
			StorageClass:         compatFs.GCSConfig.StorageClass,
		}
		if compatFs.GCSConfig.AutomaticCredentials == 0 {
			compatFs.GCSConfig.CredentialFile = filepath.Join(credentialsDirPath, fmt.Sprintf("%v_gcs_credentials.json",
				username))
		}
		secret, err := getCGSCredentialsFromV4(compatFs.GCSConfig)
		if err != nil {
			providerLog(logger.LevelError, "unable to convert v4 filesystem for user %#v: %v", username, err)
			return fsConfig, err
		}
		fsConfig.GCSConfig.Credentials = secret
	}
	return fsConfig, nil
}
