//go:build !nobolt
// +build !nobolt

package dataprovider

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	boltDatabaseVersion = 15
)

var (
	usersBucket     = []byte("users")
	foldersBucket   = []byte("folders")
	adminsBucket    = []byte("admins")
	apiKeysBucket   = []byte("api_keys")
	sharesBucket    = []byte("shares")
	dbVersionBucket = []byte("db_version")
	dbVersionKey    = []byte("version")
	boltBuckets     = [][]byte{usersBucket, foldersBucket, adminsBucket, apiKeysBucket,
		sharesBucket, dbVersionBucket}
)

// BoltProvider defines the auth provider for bolt key/value store
type BoltProvider struct {
	dbHandle *bolt.DB
}

func init() {
	version.AddFeature("+bolt")
}

func initializeBoltProvider(basePath string) error {
	var err error

	dbPath := config.Name
	if !util.IsFileInputValid(dbPath) {
		return fmt.Errorf("invalid database path: %#v", dbPath)
	}
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(basePath, dbPath)
	}
	dbHandle, err := bolt.Open(dbPath, 0600, &bolt.Options{
		NoGrowSync:   false,
		FreelistType: bolt.FreelistArrayType,
		Timeout:      5 * time.Second})
	if err == nil {
		providerLog(logger.LevelDebug, "bolt key store handle created")

		for _, bucket := range boltBuckets {
			if err := dbHandle.Update(func(tx *bolt.Tx) error {
				_, e := tx.CreateBucketIfNotExists(bucket)
				return e
			}); err != nil {
				providerLog(logger.LevelError, "error creating bucket %#v: %v", string(bucket), err)
			}
		}

		provider = &BoltProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelError, "error creating bolt key/value store handler: %v", err)
	}
	return err
}

func (p *BoltProvider) checkAvailability() error {
	_, err := getBoltDatabaseVersion(p.dbHandle)
	return err
}

func (p *BoltProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	var user User
	if tlsCert == nil {
		return user, errors.New("TLS certificate cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, err
	}
	return checkUserAndTLSCertificate(&user, protocol, tlsCert)
}

func (p *BoltProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	var user User
	if password == "" {
		return user, errors.New("credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, err
	}
	return checkUserAndPass(&user, password, ip, protocol)
}

func (p *BoltProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	admin, err := p.adminExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating admin %#v: %v", username, err)
		return admin, ErrInvalidCredentials
	}
	err = admin.checkUserAndPass(password, ip)
	return admin, err
}

func (p *BoltProvider) validateUserAndPubKey(username string, pubKey []byte, isSSHCert bool) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey, isSSHCert)
}

func (p *BoltProvider) updateAPIKeyLastUse(keyID string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAPIKeysBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(keyID)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("key %#v does not exist, unable to update last use", keyID))
		}
		var apiKey APIKey
		err = json.Unmarshal(u, &apiKey)
		if err != nil {
			return err
		}
		apiKey.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(apiKey)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(keyID), buf)
		if err != nil {
			providerLog(logger.LevelWarn, "error updating last use for key %#v: %v", keyID, err)
			return err
		}
		providerLog(logger.LevelDebug, "last use updated for key %#v", keyID)
		return nil
	})
}

func (p *BoltProvider) setUpdatedAt(username string) {
	p.dbHandle.Update(func(tx *bolt.Tx) error { //nolint:errcheck
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist, unable to update updated at", username))
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(username), buf)
		if err == nil {
			providerLog(logger.LevelDebug, "updated at set for user %#v", username)
		} else {
			providerLog(logger.LevelWarn, "error setting updated_at for user %#v: %v", username, err)
		}
		return err
	})
}

func (p *BoltProvider) updateLastLogin(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist, unable to update last login", username))
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		user.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(username), buf)
		if err == nil {
			providerLog(logger.LevelDebug, "last login updated for user %#v", username)
		} else {
			providerLog(logger.LevelWarn, "error updating last login for user %#v: %v", username, err)
		}
		return err
	})
}

func (p *BoltProvider) updateAdminLastLogin(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAdminsBucket(tx)
		if err != nil {
			return err
		}
		var a []byte
		if a = bucket.Get([]byte(username)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("admin %#v does not exist, unable to update last login", username))
		}
		var admin Admin
		err = json.Unmarshal(a, &admin)
		if err != nil {
			return err
		}
		admin.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(admin)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(username), buf)
		if err == nil {
			providerLog(logger.LevelDebug, "last login updated for admin %#v", username)
			return err
		}
		providerLog(logger.LevelWarn, "error updating last login for admin %#v: %v", username, err)
		return err
	})
}

func (p *BoltProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist, unable to update transfer quota",
				username))
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		if !reset {
			user.UsedUploadDataTransfer += uploadSize
			user.UsedDownloadDataTransfer += downloadSize
		} else {
			user.UsedUploadDataTransfer = uploadSize
			user.UsedDownloadDataTransfer = downloadSize
		}
		user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(username), buf)
		providerLog(logger.LevelDebug, "transfer quota updated for user %#v, ul increment: %v dl increment: %v is reset? %v",
			username, uploadSize, downloadSize, reset)
		return err
	})
}

func (p *BoltProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist, unable to update quota", username))
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		if reset {
			user.UsedQuotaSize = sizeAdd
			user.UsedQuotaFiles = filesAdd
		} else {
			user.UsedQuotaSize += sizeAdd
			user.UsedQuotaFiles += filesAdd
		}
		user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(username), buf)
		providerLog(logger.LevelDebug, "quota updated for user %#v, files increment: %v size increment: %v is reset? %v",
			username, filesAdd, sizeAdd, reset)
		return err
	})
}

func (p *BoltProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for user %v error: %v", username, err)
		return 0, 0, 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, user.UsedUploadDataTransfer, user.UsedDownloadDataTransfer, err
}

func (p *BoltProvider) adminExists(username string) (Admin, error) {
	var admin Admin

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getAdminsBucket(tx)
		if err != nil {
			return err
		}
		a := bucket.Get([]byte(username))
		if a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
		}
		return json.Unmarshal(a, &admin)
	})

	return admin, err
}

func (p *BoltProvider) addAdmin(admin *Admin) error {
	err := admin.validate()
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAdminsBucket(tx)
		if err != nil {
			return err
		}
		if a := bucket.Get([]byte(admin.Username)); a != nil {
			return fmt.Errorf("admin %v already exists", admin.Username)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		admin.ID = int64(id)
		admin.LastLogin = 0
		admin.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(admin)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(admin.Username), buf)
	})
}

func (p *BoltProvider) updateAdmin(admin *Admin) error {
	err := admin.validate()
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAdminsBucket(tx)
		if err != nil {
			return err
		}
		var a []byte

		if a = bucket.Get([]byte(admin.Username)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
		}
		var oldAdmin Admin
		err = json.Unmarshal(a, &oldAdmin)
		if err != nil {
			return err
		}

		admin.ID = oldAdmin.ID
		admin.CreatedAt = oldAdmin.CreatedAt
		admin.LastLogin = oldAdmin.LastLogin
		admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(admin)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(admin.Username), buf)
	})
}

func (p *BoltProvider) deleteAdmin(admin *Admin) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAdminsBucket(tx)
		if err != nil {
			return err
		}

		if bucket.Get([]byte(admin.Username)) == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
		}

		if err := deleteRelatedAPIKey(tx, admin.Username, APIKeyScopeAdmin); err != nil {
			return err
		}

		return bucket.Delete([]byte(admin.Username))
	})
}

func (p *BoltProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	admins := make([]Admin, 0, limit)

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getAdminsBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var admin Admin
				err = json.Unmarshal(v, &admin)
				if err != nil {
					return err
				}
				admin.HideConfidentialData()
				admins = append(admins, admin)
				if len(admins) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var admin Admin
				err = json.Unmarshal(v, &admin)
				if err != nil {
					return err
				}
				admin.HideConfidentialData()
				admins = append(admins, admin)
				if len(admins) >= limit {
					break
				}
			}
		}
		return err
	})

	return admins, err
}

func (p *BoltProvider) dumpAdmins() ([]Admin, error) {
	admins := make([]Admin, 0, 30)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getAdminsBucket(tx)
		if err != nil {
			return err
		}

		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var admin Admin
			err = json.Unmarshal(v, &admin)
			if err != nil {
				return err
			}
			admins = append(admins, admin)
		}
		return err
	})

	return admins, err
}

func (p *BoltProvider) userExists(username string) (User, error) {
	var user User
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		u := bucket.Get([]byte(username))
		if u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
		}
		folderBucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		user, err = joinUserAndFolders(u, folderBucket)
		return err
	})
	return user, err
}

func (p *BoltProvider) addUser(user *User) error {
	err := ValidateUser(user)
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		folderBucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		if u := bucket.Get([]byte(user.Username)); u != nil {
			return fmt.Errorf("username %v already exists", user.Username)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		user.ID = int64(id)
		user.LastQuotaUpdate = 0
		user.UsedQuotaSize = 0
		user.UsedQuotaFiles = 0
		user.UsedUploadDataTransfer = 0
		user.UsedDownloadDataTransfer = 0
		user.LastLogin = 0
		user.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		for idx := range user.VirtualFolders {
			err = addUserToFolderMapping(&user.VirtualFolders[idx].BaseVirtualFolder, user, folderBucket)
			if err != nil {
				return err
			}
		}
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(user.Username), buf)
	})
}

func (p *BoltProvider) updateUser(user *User) error {
	err := ValidateUser(user)
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		folderBucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(user.Username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", user.Username))
		}
		var oldUser User
		err = json.Unmarshal(u, &oldUser)
		if err != nil {
			return err
		}
		for idx := range oldUser.VirtualFolders {
			err = removeUserFromFolderMapping(&oldUser.VirtualFolders[idx], &oldUser, folderBucket)
			if err != nil {
				return err
			}
		}
		for idx := range user.VirtualFolders {
			err = addUserToFolderMapping(&user.VirtualFolders[idx].BaseVirtualFolder, user, folderBucket)
			if err != nil {
				return err
			}
		}
		user.ID = oldUser.ID
		user.LastQuotaUpdate = oldUser.LastQuotaUpdate
		user.UsedQuotaSize = oldUser.UsedQuotaSize
		user.UsedQuotaFiles = oldUser.UsedQuotaFiles
		user.UsedUploadDataTransfer = oldUser.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = oldUser.UsedDownloadDataTransfer
		user.LastLogin = oldUser.LastLogin
		user.CreatedAt = oldUser.CreatedAt
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(user.Username), buf)
	})
}

func (p *BoltProvider) deleteUser(user *User) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		exists := bucket.Get([]byte(user.Username))
		if exists == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("user %#v does not exist", user.Username))
		}

		if len(user.VirtualFolders) > 0 {
			folderBucket, err := getFoldersBucket(tx)
			if err != nil {
				return err
			}
			for idx := range user.VirtualFolders {
				err = removeUserFromFolderMapping(&user.VirtualFolders[idx], user, folderBucket)
				if err != nil {
					return err
				}
			}
		}

		if err := deleteRelatedAPIKey(tx, user.Username, APIKeyScopeUser); err != nil {
			return err
		}
		if err := deleteRelatedShares(tx, user.Username); err != nil {
			return err
		}
		return bucket.Delete([]byte(user.Username))
	})
}

func (p *BoltProvider) updateUserPassword(username, password string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		user.Password = password
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(username), buf)
	})
}

func (p *BoltProvider) dumpUsers() ([]User, error) {
	users := make([]User, 0, 100)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		folderBucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			user, err := joinUserAndFolders(v, folderBucket)
			if err != nil {
				return err
			}
			err = addCredentialsToUser(&user)
			if err != nil {
				return err
			}
			users = append(users, user)
		}
		return err
	})
	return users, err
}

// bolt provider cannot be shared, so we always return no recently updated users
func (p *BoltProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return nil, nil
}

func (p *BoltProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	users := make([]User, 0, 30)

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var user User
			err := json.Unmarshal(v, &user)
			if err != nil {
				return err
			}
			needFolders, ok := toFetch[user.Username]
			if !ok {
				continue
			}
			if needFolders && len(user.VirtualFolders) > 0 {
				var folders []vfs.VirtualFolder
				for idx := range user.VirtualFolders {
					folder := &user.VirtualFolders[idx]
					baseFolder, err := folderExistsInternal(folder.Name, foldersBucket)
					if err != nil {
						continue
					}
					folder.BaseVirtualFolder = baseFolder
					folders = append(folders, *folder)
				}
				user.VirtualFolders = folders
			}

			user.SetEmptySecretsIfNil()
			user.PrepareForRendering()
			users = append(users, user)
		}
		return nil
	})

	return users, err
}

func (p *BoltProvider) getUsers(limit int, offset int, order string) ([]User, error) {
	users := make([]User, 0, limit)
	var err error
	if limit <= 0 {
		return users, err
	}
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		folderBucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				user, err := joinUserAndFolders(v, folderBucket)
				if err == nil {
					user.PrepareForRendering()
					users = append(users, user)
				}
				if len(users) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				user, err := joinUserAndFolders(v, folderBucket)
				if err == nil {
					user.PrepareForRendering()
					users = append(users, user)
				}
				if len(users) >= limit {
					break
				}
			}
		}
		return err
	})
	return users, err
}

func (p *BoltProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, 50)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var folder vfs.BaseVirtualFolder
			err = json.Unmarshal(v, &folder)
			if err != nil {
				return err
			}
			folders = append(folders, folder)
		}
		return err
	})
	return folders, err
}

func (p *BoltProvider) getFolders(limit, offset int, order string) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	var err error
	if limit <= 0 {
		return folders, err
	}
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var folder vfs.BaseVirtualFolder
				err = json.Unmarshal(v, &folder)
				if err != nil {
					return err
				}
				folder.PrepareForRendering()
				folders = append(folders, folder)
				if len(folders) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var folder vfs.BaseVirtualFolder
				err = json.Unmarshal(v, &folder)
				if err != nil {
					return err
				}
				folder.PrepareForRendering()
				folders = append(folders, folder)
				if len(folders) >= limit {
					break
				}
			}
		}
		return err
	})
	return folders, err
}

func (p *BoltProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		folder, err = folderExistsInternal(name, bucket)
		return err
	})
	return folder, err
}

func (p *BoltProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	err := ValidateFolder(folder)
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		if f := bucket.Get([]byte(folder.Name)); f != nil {
			return fmt.Errorf("folder %v already exists", folder.Name)
		}
		folder.Users = nil
		return addFolderInternal(*folder, bucket)
	})
}

func (p *BoltProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	err := ValidateFolder(folder)
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		var f []byte

		if f = bucket.Get([]byte(folder.Name)); f == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", folder.Name))
		}
		var oldFolder vfs.BaseVirtualFolder
		err = json.Unmarshal(f, &oldFolder)
		if err != nil {
			return err
		}

		folder.ID = oldFolder.ID
		folder.LastQuotaUpdate = oldFolder.LastQuotaUpdate
		folder.UsedQuotaFiles = oldFolder.UsedQuotaFiles
		folder.UsedQuotaSize = oldFolder.UsedQuotaSize
		folder.Users = oldFolder.Users
		buf, err := json.Marshal(folder)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(folder.Name), buf)
	})
}

func (p *BoltProvider) deleteFolder(folder *vfs.BaseVirtualFolder) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		usersBucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var f []byte
		if f = bucket.Get([]byte(folder.Name)); f == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", folder.Name))
		}
		var folder vfs.BaseVirtualFolder
		err = json.Unmarshal(f, &folder)
		if err != nil {
			return err
		}
		for _, username := range folder.Users {
			var u []byte
			if u = usersBucket.Get([]byte(username)); u == nil {
				continue
			}
			var user User
			err = json.Unmarshal(u, &user)
			if err != nil {
				return err
			}
			var folders []vfs.VirtualFolder
			for _, userFolder := range user.VirtualFolders {
				if folder.Name != userFolder.Name {
					folders = append(folders, userFolder)
				}
			}
			user.VirtualFolders = folders
			buf, err := json.Marshal(user)
			if err != nil {
				return err
			}
			err = usersBucket.Put([]byte(user.Username), buf)
			if err != nil {
				return err
			}
		}

		return bucket.Delete([]byte(folder.Name))
	})
}

func (p *BoltProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		var f []byte
		if f = bucket.Get([]byte(name)); f == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("folder %#v does not exist, unable to update quota", name))
		}
		var folder vfs.BaseVirtualFolder
		err = json.Unmarshal(f, &folder)
		if err != nil {
			return err
		}
		if reset {
			folder.UsedQuotaSize = sizeAdd
			folder.UsedQuotaFiles = filesAdd
		} else {
			folder.UsedQuotaSize += sizeAdd
			folder.UsedQuotaFiles += filesAdd
		}
		folder.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(folder)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(folder.Name), buf)
	})
}

func (p *BoltProvider) getUsedFolderQuota(name string) (int, int64, error) {
	folder, err := p.getFolderByName(name)
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for folder %#v error: %v", name, err)
		return 0, 0, err
	}
	return folder.UsedQuotaFiles, folder.UsedQuotaSize, err
}

func (p *BoltProvider) apiKeyExists(keyID string) (APIKey, error) {
	var apiKey APIKey
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getAPIKeysBucket(tx)
		if err != nil {
			return err
		}

		k := bucket.Get([]byte(keyID))
		if k == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", keyID))
		}
		return json.Unmarshal(k, &apiKey)
	})
	return apiKey, err
}

func (p *BoltProvider) addAPIKey(apiKey *APIKey) error {
	err := apiKey.validate()
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAPIKeysBucket(tx)
		if err != nil {
			return err
		}
		if a := bucket.Get([]byte(apiKey.KeyID)); a != nil {
			return fmt.Errorf("API key %v already exists", apiKey.KeyID)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		apiKey.ID = int64(id)
		apiKey.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		apiKey.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		apiKey.LastUseAt = 0
		if apiKey.User != "" {
			if err := p.userExistsInternal(tx, apiKey.User); err != nil {
				return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", apiKey.User))
			}
		}
		if apiKey.Admin != "" {
			if err := p.adminExistsInternal(tx, apiKey.Admin); err != nil {
				return util.NewValidationError(fmt.Sprintf("related admin %#v does not exists", apiKey.User))
			}
		}
		buf, err := json.Marshal(apiKey)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(apiKey.KeyID), buf)
	})
}

func (p *BoltProvider) updateAPIKey(apiKey *APIKey) error {
	err := apiKey.validate()
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAPIKeysBucket(tx)
		if err != nil {
			return err
		}
		var a []byte

		if a = bucket.Get([]byte(apiKey.KeyID)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
		}
		var oldAPIKey APIKey
		err = json.Unmarshal(a, &oldAPIKey)
		if err != nil {
			return err
		}

		apiKey.ID = oldAPIKey.ID
		apiKey.KeyID = oldAPIKey.KeyID
		apiKey.Key = oldAPIKey.Key
		apiKey.CreatedAt = oldAPIKey.CreatedAt
		apiKey.LastUseAt = oldAPIKey.LastUseAt
		apiKey.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		if apiKey.User != "" {
			if err := p.userExistsInternal(tx, apiKey.User); err != nil {
				return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", apiKey.User))
			}
		}
		if apiKey.Admin != "" {
			if err := p.adminExistsInternal(tx, apiKey.Admin); err != nil {
				return util.NewValidationError(fmt.Sprintf("related admin %#v does not exists", apiKey.User))
			}
		}
		buf, err := json.Marshal(apiKey)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(apiKey.KeyID), buf)
	})
}

func (p *BoltProvider) deleteAPIKey(apiKey *APIKey) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getAPIKeysBucket(tx)
		if err != nil {
			return err
		}

		if bucket.Get([]byte(apiKey.KeyID)) == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
		}

		return bucket.Delete([]byte(apiKey.KeyID))
	})
}

func (p *BoltProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, limit)

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getAPIKeysBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var apiKey APIKey
				err = json.Unmarshal(v, &apiKey)
				if err != nil {
					return err
				}
				apiKey.HideConfidentialData()
				apiKeys = append(apiKeys, apiKey)
				if len(apiKeys) >= limit {
					break
				}
			}
			return nil
		}
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			itNum++
			if itNum <= offset {
				continue
			}
			var apiKey APIKey
			err = json.Unmarshal(v, &apiKey)
			if err != nil {
				return err
			}
			apiKey.HideConfidentialData()
			apiKeys = append(apiKeys, apiKey)
			if len(apiKeys) >= limit {
				break
			}
		}
		return nil
	})

	return apiKeys, err
}

func (p *BoltProvider) dumpAPIKeys() ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, 30)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getAPIKeysBucket(tx)
		if err != nil {
			return err
		}

		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var apiKey APIKey
			err = json.Unmarshal(v, &apiKey)
			if err != nil {
				return err
			}
			apiKeys = append(apiKeys, apiKey)
		}
		return err
	})

	return apiKeys, err
}

func (p *BoltProvider) shareExists(shareID, username string) (Share, error) {
	var share Share
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getSharesBucket(tx)
		if err != nil {
			return err
		}

		s := bucket.Get([]byte(shareID))
		if s == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
		}
		if err := json.Unmarshal(s, &share); err != nil {
			return err
		}
		if username != "" && share.Username != username {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
		}
		return nil
	})
	return share, err
}

func (p *BoltProvider) addShare(share *Share) error {
	err := share.validate()
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getSharesBucket(tx)
		if err != nil {
			return err
		}
		if a := bucket.Get([]byte(share.ShareID)); a != nil {
			return fmt.Errorf("share %v already exists", share.ShareID)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		share.ID = int64(id)
		if !share.IsRestore {
			share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
			share.UpdatedAt = share.CreatedAt
			share.LastUseAt = 0
			share.UsedTokens = 0
		}
		if share.CreatedAt == 0 {
			share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		}
		if share.UpdatedAt == 0 {
			share.UpdatedAt = share.CreatedAt
		}
		if err := p.userExistsInternal(tx, share.Username); err != nil {
			return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", share.Username))
		}
		buf, err := json.Marshal(share)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(share.ShareID), buf)
	})
}

func (p *BoltProvider) updateShare(share *Share) error {
	if err := share.validate(); err != nil {
		return err
	}

	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getSharesBucket(tx)
		if err != nil {
			return err
		}
		var s []byte

		if s = bucket.Get([]byte(share.ShareID)); s == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}
		var oldObject Share
		if err = json.Unmarshal(s, &oldObject); err != nil {
			return err
		}
		if oldObject.Username != share.Username {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}

		share.ID = oldObject.ID
		share.ShareID = oldObject.ShareID
		if !share.IsRestore {
			share.UsedTokens = oldObject.UsedTokens
			share.CreatedAt = oldObject.CreatedAt
			share.LastUseAt = oldObject.LastUseAt
			share.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		}
		if share.CreatedAt == 0 {
			share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		}
		if share.UpdatedAt == 0 {
			share.UpdatedAt = share.CreatedAt
		}
		if err := p.userExistsInternal(tx, share.Username); err != nil {
			return util.NewValidationError(fmt.Sprintf("related user %#v does not exists", share.Username))
		}
		buf, err := json.Marshal(share)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(share.ShareID), buf)
	})
}

func (p *BoltProvider) deleteShare(share *Share) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getSharesBucket(tx)
		if err != nil {
			return err
		}

		var s []byte

		if s = bucket.Get([]byte(share.ShareID)); s == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}
		var oldObject Share
		if err = json.Unmarshal(s, &oldObject); err != nil {
			return err
		}
		if oldObject.Username != share.Username {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}

		return bucket.Delete([]byte(share.ShareID))
	})
}

func (p *BoltProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	shares := make([]Share, 0, limit)

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getSharesBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				var share Share
				if err := json.Unmarshal(v, &share); err != nil {
					return err
				}
				if share.Username != username {
					continue
				}
				itNum++
				if itNum <= offset {
					continue
				}
				share.HideConfidentialData()
				shares = append(shares, share)
				if len(shares) >= limit {
					break
				}
			}
			return nil
		}
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			var share Share
			err = json.Unmarshal(v, &share)
			if err != nil {
				return err
			}
			if share.Username != username {
				continue
			}
			itNum++
			if itNum <= offset {
				continue
			}
			share.HideConfidentialData()
			shares = append(shares, share)
			if len(shares) >= limit {
				break
			}
		}
		return nil
	})

	return shares, err
}

func (p *BoltProvider) dumpShares() ([]Share, error) {
	shares := make([]Share, 0, 30)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getSharesBucket(tx)
		if err != nil {
			return err
		}

		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var share Share
			err = json.Unmarshal(v, &share)
			if err != nil {
				return err
			}
			shares = append(shares, share)
		}
		return err
	})

	return shares, err
}

func (p *BoltProvider) updateShareLastUse(shareID string, numTokens int) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getSharesBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(shareID)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("share %#v does not exist, unable to update last use", shareID))
		}
		var share Share
		err = json.Unmarshal(u, &share)
		if err != nil {
			return err
		}
		share.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
		share.UsedTokens += numTokens
		buf, err := json.Marshal(share)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(shareID), buf)
		if err != nil {
			providerLog(logger.LevelWarn, "error updating last use for share %#v: %v", shareID, err)
			return err
		}
		providerLog(logger.LevelDebug, "last use updated for share %#v", shareID)
		return nil
	})
}

func (p *BoltProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return nil, ErrNotImplemented
}

func (p *BoltProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *BoltProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *BoltProvider) updateDefenderBanTime(ip string, minutes int) error {
	return ErrNotImplemented
}

func (p *BoltProvider) deleteDefenderHost(ip string) error {
	return ErrNotImplemented
}

func (p *BoltProvider) addDefenderEvent(ip string, score int) error {
	return ErrNotImplemented
}

func (p *BoltProvider) setDefenderBanTime(ip string, banTime int64) error {
	return ErrNotImplemented
}

func (p *BoltProvider) cleanupDefender(from int64) error {
	return ErrNotImplemented
}

func (p *BoltProvider) addActiveTransfer(transfer ActiveTransfer) error {
	return ErrNotImplemented
}

func (p *BoltProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
	return ErrNotImplemented
}

func (p *BoltProvider) removeActiveTransfer(transferID int64, connectionID string) error {
	return ErrNotImplemented
}

func (p *BoltProvider) cleanupActiveTransfers(before time.Time) error {
	return ErrNotImplemented
}

func (p *BoltProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return nil, ErrNotImplemented
}

func (p *BoltProvider) close() error {
	return p.dbHandle.Close()
}

func (p *BoltProvider) reloadConfig() error {
	return nil
}

// initializeDatabase does nothing, no initilization is needed for bolt provider
func (p *BoltProvider) initializeDatabase() error {
	return ErrNoInitRequired
}

func (p *BoltProvider) migrateDatabase() error {
	dbVersion, err := getBoltDatabaseVersion(p.dbHandle)
	if err != nil {
		return err
	}
	switch version := dbVersion.Version; {
	case version == boltDatabaseVersion:
		providerLog(logger.LevelDebug, "bolt database is up to date, current version: %v", version)
		return ErrNoInitRequired
	case version < 15:
		err = fmt.Errorf("database version %v is too old, please see the upgrading docs", version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 15:
		return updateBoltDatabaseVersion(p.dbHandle, 16)
	default:
		if version > boltDatabaseVersion {
			providerLog(logger.LevelError, "database version %v is newer than the supported one: %v", version,
				boltDatabaseVersion)
			logger.WarnToConsole("database version %v is newer than the supported one: %v", version,
				boltDatabaseVersion)
			return nil
		}
		return fmt.Errorf("database version not handled: %v", version)
	}
}

func (p *BoltProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := getBoltDatabaseVersion(p.dbHandle)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}
	switch dbVersion.Version {
	case 16:
		return updateBoltDatabaseVersion(p.dbHandle, 15)
	default:
		return fmt.Errorf("database version not handled: %v", dbVersion.Version)
	}
}

func (p *BoltProvider) resetDatabase() error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		for _, bucketName := range boltBuckets {
			err := tx.DeleteBucket(bucketName)
			if err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
				return fmt.Errorf("unable to remove bucket %v: %w", bucketName, err)
			}
		}
		return nil
	})
}

func joinUserAndFolders(u []byte, foldersBucket *bolt.Bucket) (User, error) {
	var user User
	err := json.Unmarshal(u, &user)
	if err != nil {
		return user, err
	}
	if len(user.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range user.VirtualFolders {
			folder := &user.VirtualFolders[idx]
			baseFolder, err := folderExistsInternal(folder.Name, foldersBucket)
			if err != nil {
				continue
			}
			folder.BaseVirtualFolder = baseFolder
			folders = append(folders, *folder)
		}
		user.VirtualFolders = folders
	}
	user.SetEmptySecretsIfNil()
	return user, err
}

func folderExistsInternal(name string, bucket *bolt.Bucket) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	f := bucket.Get([]byte(name))
	if f == nil {
		err := util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", name))
		return folder, err
	}
	err := json.Unmarshal(f, &folder)
	return folder, err
}

func addFolderInternal(folder vfs.BaseVirtualFolder, bucket *bolt.Bucket) error {
	id, err := bucket.NextSequence()
	if err != nil {
		return err
	}
	folder.ID = int64(id)
	buf, err := json.Marshal(folder)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(folder.Name), buf)
}

func addUserToFolderMapping(baseFolder *vfs.BaseVirtualFolder, user *User, bucket *bolt.Bucket) error {
	f := bucket.Get([]byte(baseFolder.Name))
	if f == nil {
		// folder does not exists, try to create
		baseFolder.LastQuotaUpdate = 0
		baseFolder.UsedQuotaFiles = 0
		baseFolder.UsedQuotaSize = 0
		baseFolder.Users = []string{user.Username}
		return addFolderInternal(*baseFolder, bucket)
	}
	var oldFolder vfs.BaseVirtualFolder
	err := json.Unmarshal(f, &oldFolder)
	if err != nil {
		return err
	}
	baseFolder.ID = oldFolder.ID
	baseFolder.LastQuotaUpdate = oldFolder.LastQuotaUpdate
	baseFolder.UsedQuotaFiles = oldFolder.UsedQuotaFiles
	baseFolder.UsedQuotaSize = oldFolder.UsedQuotaSize
	baseFolder.Users = oldFolder.Users
	if !util.IsStringInSlice(user.Username, baseFolder.Users) {
		baseFolder.Users = append(baseFolder.Users, user.Username)
	}
	buf, err := json.Marshal(baseFolder)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(baseFolder.Name), buf)
}

func removeUserFromFolderMapping(folder *vfs.VirtualFolder, user *User, bucket *bolt.Bucket) error {
	var f []byte
	if f = bucket.Get([]byte(folder.Name)); f == nil {
		// the folder does not exists so there is no associated user
		return nil
	}
	var baseFolder vfs.BaseVirtualFolder
	err := json.Unmarshal(f, &baseFolder)
	if err != nil {
		return err
	}
	if util.IsStringInSlice(user.Username, baseFolder.Users) {
		var newUserMapping []string
		for _, u := range baseFolder.Users {
			if u != user.Username {
				newUserMapping = append(newUserMapping, u)
			}
		}
		baseFolder.Users = newUserMapping
		buf, err := json.Marshal(baseFolder)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(folder.Name), buf)
	}
	return err
}

func (p *BoltProvider) adminExistsInternal(tx *bolt.Tx, username string) error {
	bucket, err := getAdminsBucket(tx)
	if err != nil {
		return err
	}
	a := bucket.Get([]byte(username))
	if a == nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
	}
	return nil
}

func (p *BoltProvider) userExistsInternal(tx *bolt.Tx, username string) error {
	bucket, err := getUsersBucket(tx)
	if err != nil {
		return err
	}
	u := bucket.Get([]byte(username))
	if u == nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
	}
	return nil
}

func deleteRelatedShares(tx *bolt.Tx, username string) error {
	bucket, err := getSharesBucket(tx)
	if err != nil {
		return err
	}
	var toRemove []string
	cursor := bucket.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		var share Share
		err = json.Unmarshal(v, &share)
		if err != nil {
			return err
		}
		if share.Username == username {
			toRemove = append(toRemove, share.ShareID)
		}
	}

	for _, k := range toRemove {
		if err := bucket.Delete([]byte(k)); err != nil {
			return err
		}
	}

	return nil
}

func deleteRelatedAPIKey(tx *bolt.Tx, username string, scope APIKeyScope) error {
	bucket, err := getAPIKeysBucket(tx)
	if err != nil {
		return err
	}
	var toRemove []string
	cursor := bucket.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		var apiKey APIKey
		err = json.Unmarshal(v, &apiKey)
		if err != nil {
			return err
		}
		if scope == APIKeyScopeUser {
			if apiKey.User == username {
				toRemove = append(toRemove, apiKey.KeyID)
			}
		} else {
			if apiKey.Admin == username {
				toRemove = append(toRemove, apiKey.KeyID)
			}
		}
	}

	for _, k := range toRemove {
		if err := bucket.Delete([]byte(k)); err != nil {
			return err
		}
	}

	return nil
}

func getSharesBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error

	bucket := tx.Bucket(sharesBucket)
	if bucket == nil {
		err = errors.New("unable to find shares bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getAPIKeysBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error

	bucket := tx.Bucket(apiKeysBucket)
	if bucket == nil {
		err = errors.New("unable to find api keys bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getAdminsBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error

	bucket := tx.Bucket(adminsBucket)
	if bucket == nil {
		err = errors.New("unable to find admins bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getUsersBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(usersBucket)
	if bucket == nil {
		err = errors.New("unable to find users bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getFoldersBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(foldersBucket)
	if bucket == nil {
		err = fmt.Errorf("unable to find folders buckets, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getBoltDatabaseVersion(dbHandle *bolt.DB) (schemaVersion, error) {
	var dbVersion schemaVersion
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dbVersionBucket)
		if bucket == nil {
			return fmt.Errorf("unable to find database version bucket")
		}
		v := bucket.Get(dbVersionKey)
		if v == nil {
			dbVersion = schemaVersion{
				Version: 15,
			}
			return nil
		}
		return json.Unmarshal(v, &dbVersion)
	})
	return dbVersion, err
}

func updateBoltDatabaseVersion(dbHandle *bolt.DB, version int) error {
	err := dbHandle.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dbVersionBucket)
		if bucket == nil {
			return fmt.Errorf("unable to find database version bucket")
		}
		newDbVersion := schemaVersion{
			Version: version,
		}
		buf, err := json.Marshal(newDbVersion)
		if err != nil {
			return err
		}
		return bucket.Put(dbVersionKey, buf)
	})
	return err
}
