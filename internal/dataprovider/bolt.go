// Copyright (C) 2019-2022  Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//go:build !nobolt
// +build !nobolt

package dataprovider

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	boltDatabaseVersion = 23
)

var (
	usersBucket     = []byte("users")
	groupsBucket    = []byte("groups")
	foldersBucket   = []byte("folders")
	adminsBucket    = []byte("admins")
	apiKeysBucket   = []byte("api_keys")
	sharesBucket    = []byte("shares")
	actionsBucket   = []byte("events_actions")
	rulesBucket     = []byte("events_rules")
	dbVersionBucket = []byte("db_version")
	dbVersionKey    = []byte("version")
	boltBuckets     = [][]byte{usersBucket, groupsBucket, foldersBucket, adminsBucket, apiKeysBucket,
		sharesBucket, actionsBucket, rulesBucket, dbVersionBucket}
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
		bucket, err := p.getAPIKeysBucket(tx)
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
		bucket, err := p.getUsersBucket(tx)
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
			setLastUserUpdate()
		} else {
			providerLog(logger.LevelWarn, "error setting updated_at for user %#v: %v", username, err)
		}
		return err
	})
}

func (p *BoltProvider) updateLastLogin(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getUsersBucket(tx)
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
		if err != nil {
			providerLog(logger.LevelWarn, "error updating last login for user %#v: %v", username, err)
		} else {
			providerLog(logger.LevelDebug, "last login updated for user %#v", username)
		}
		return err
	})
}

func (p *BoltProvider) updateAdminLastLogin(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getAdminsBucket(tx)
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
		bucket, err := p.getUsersBucket(tx)
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
		bucket, err := p.getUsersBucket(tx)
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
		bucket, err := p.getAdminsBucket(tx)
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
		bucket, err := p.getAdminsBucket(tx)
		if err != nil {
			return err
		}
		groupBucket, err := p.getGroupsBucket(tx)
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
		for idx := range admin.Groups {
			err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name, groupBucket)
			if err != nil {
				return err
			}
		}
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
		bucket, err := p.getAdminsBucket(tx)
		if err != nil {
			return err
		}
		groupBucket, err := p.getGroupsBucket(tx)
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

		for idx := range oldAdmin.Groups {
			err = p.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name, groupBucket)
			if err != nil {
				return err
			}
		}
		for idx := range admin.Groups {
			err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name, groupBucket)
			if err != nil {
				return err
			}
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

func (p *BoltProvider) deleteAdmin(admin Admin) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getAdminsBucket(tx)
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
		if len(oldAdmin.Groups) > 0 {
			groupBucket, err := p.getGroupsBucket(tx)
			if err != nil {
				return err
			}
			for idx := range oldAdmin.Groups {
				err = p.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name, groupBucket)
				if err != nil {
					return err
				}
			}
		}

		if err := p.deleteRelatedAPIKey(tx, admin.Username, APIKeyScopeAdmin); err != nil {
			return err
		}

		return bucket.Delete([]byte(admin.Username))
	})
}

func (p *BoltProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	admins := make([]Admin, 0, limit)

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getAdminsBucket(tx)
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
		bucket, err := p.getAdminsBucket(tx)
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
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		u := bucket.Get([]byte(username))
		if u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		user, err = p.joinUserAndFolders(u, foldersBucket)
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
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		groupBucket, err := p.getGroupsBucket(tx)
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
		user.FirstDownload = 0
		user.FirstUpload = 0
		user.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		for idx := range user.VirtualFolders {
			err = p.addRelationToFolderMapping(&user.VirtualFolders[idx].BaseVirtualFolder, user, nil, foldersBucket)
			if err != nil {
				return err
			}
		}
		for idx := range user.Groups {
			err = p.addUserToGroupMapping(user.Username, user.Groups[idx].Name, groupBucket)
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
		bucket, err := p.getUsersBucket(tx)
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
		if err = p.updateUserRelations(tx, user, oldUser); err != nil {
			return err
		}
		user.ID = oldUser.ID
		user.LastQuotaUpdate = oldUser.LastQuotaUpdate
		user.UsedQuotaSize = oldUser.UsedQuotaSize
		user.UsedQuotaFiles = oldUser.UsedQuotaFiles
		user.UsedUploadDataTransfer = oldUser.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = oldUser.UsedDownloadDataTransfer
		user.LastLogin = oldUser.LastLogin
		user.FirstDownload = oldUser.FirstDownload
		user.FirstUpload = oldUser.FirstUpload
		user.CreatedAt = oldUser.CreatedAt
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}

		err = bucket.Put([]byte(user.Username), buf)
		if err == nil {
			setLastUserUpdate()
		}
		return err
	})
}

func (p *BoltProvider) deleteUser(user User, softDelete bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(user.Username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", user.Username))
		}
		var oldUser User
		err = json.Unmarshal(u, &oldUser)
		if err != nil {
			return err
		}

		if len(oldUser.VirtualFolders) > 0 {
			foldersBucket, err := p.getFoldersBucket(tx)
			if err != nil {
				return err
			}
			for idx := range oldUser.VirtualFolders {
				err = p.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, "", foldersBucket)
				if err != nil {
					return err
				}
			}
		}
		if len(oldUser.Groups) > 0 {
			groupBucket, err := p.getGroupsBucket(tx)
			if err != nil {
				return err
			}
			for idx := range oldUser.Groups {
				err = p.removeUserFromGroupMapping(oldUser.Username, oldUser.Groups[idx].Name, groupBucket)
				if err != nil {
					return err
				}
			}
		}
		if err := p.deleteRelatedAPIKey(tx, user.Username, APIKeyScopeUser); err != nil {
			return err
		}
		if err := p.deleteRelatedShares(tx, user.Username); err != nil {
			return err
		}
		return bucket.Delete([]byte(user.Username))
	})
}

func (p *BoltProvider) updateUserPassword(username, password string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getUsersBucket(tx)
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
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			user, err := p.joinUserAndFolders(v, foldersBucket)
			if err != nil {
				return err
			}
			users = append(users, user)
		}
		return err
	})
	return users, err
}

func (p *BoltProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	if getLastUserUpdate() < after {
		return nil, nil
	}
	users := make([]User, 0, 10)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		groupsBucket, err := p.getGroupsBucket(tx)
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
			if user.UpdatedAt < after {
				continue
			}
			if len(user.VirtualFolders) > 0 {
				var folders []vfs.VirtualFolder
				for idx := range user.VirtualFolders {
					folder := &user.VirtualFolders[idx]
					baseFolder, err := p.folderExistsInternal(folder.Name, foldersBucket)
					if err != nil {
						continue
					}
					folder.BaseVirtualFolder = baseFolder
					folders = append(folders, *folder)
				}
				user.VirtualFolders = folders
			}
			if len(user.Groups) > 0 {
				groupMapping := make(map[string]Group)
				for idx := range user.Groups {
					group, err := p.groupExistsInternal(user.Groups[idx].Name, groupsBucket)
					if err != nil {
						continue
					}
					groupMapping[group.Name] = group
				}
				user.applyGroupSettings(groupMapping)
			}
			user.SetEmptySecretsIfNil()
			users = append(users, user)
		}
		return err
	})
	return users, err
}

func (p *BoltProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	users := make([]User, 0, 10)

	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		groupsBucket, err := p.getGroupsBucket(tx)
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
			if needFolders, ok := toFetch[user.Username]; ok {
				if needFolders && len(user.VirtualFolders) > 0 {
					var folders []vfs.VirtualFolder
					for idx := range user.VirtualFolders {
						folder := &user.VirtualFolders[idx]
						baseFolder, err := p.folderExistsInternal(folder.Name, foldersBucket)
						if err != nil {
							continue
						}
						folder.BaseVirtualFolder = baseFolder
						folders = append(folders, *folder)
					}
					user.VirtualFolders = folders
				}
				if len(user.Groups) > 0 {
					groupMapping := make(map[string]Group)
					for idx := range user.Groups {
						group, err := p.groupExistsInternal(user.Groups[idx].Name, groupsBucket)
						if err != nil {
							continue
						}
						groupMapping[group.Name] = group
					}
					user.applyGroupSettings(groupMapping)
				}

				user.SetEmptySecretsIfNil()
				user.PrepareForRendering()
				users = append(users, user)
			}
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
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
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
				user, err := p.joinUserAndFolders(v, foldersBucket)
				if err != nil {
					return err
				}
				user.PrepareForRendering()
				users = append(users, user)
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
				user, err := p.joinUserAndFolders(v, foldersBucket)
				if err != nil {
					return err
				}
				user.PrepareForRendering()
				users = append(users, user)
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
		bucket, err := p.getFoldersBucket(tx)
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

func (p *BoltProvider) getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	var err error
	if limit <= 0 {
		return folders, err
	}
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getFoldersBucket(tx)
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
		bucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		folder, err = p.folderExistsInternal(name, bucket)
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
		bucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		if f := bucket.Get([]byte(folder.Name)); f != nil {
			return fmt.Errorf("folder %v already exists", folder.Name)
		}
		folder.Users = nil
		folder.Groups = nil
		return p.addFolderInternal(*folder, bucket)
	})
}

func (p *BoltProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	err := ValidateFolder(folder)
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getFoldersBucket(tx)
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
		folder.Groups = oldFolder.Groups
		buf, err := json.Marshal(folder)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(folder.Name), buf)
	})
}

func (p *BoltProvider) deleteFolderMappings(folder vfs.BaseVirtualFolder, usersBucket, groupsBucket *bolt.Bucket) error {
	for _, username := range folder.Users {
		var u []byte
		if u = usersBucket.Get([]byte(username)); u == nil {
			continue
		}
		var user User
		err := json.Unmarshal(u, &user)
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
	for _, groupname := range folder.Groups {
		var u []byte
		if u = groupsBucket.Get([]byte(groupname)); u == nil {
			continue
		}
		var group Group
		err := json.Unmarshal(u, &group)
		if err != nil {
			return err
		}
		var folders []vfs.VirtualFolder
		for _, groupFolder := range group.VirtualFolders {
			if folder.Name != groupFolder.Name {
				folders = append(folders, groupFolder)
			}
		}
		group.VirtualFolders = folders
		buf, err := json.Marshal(group)
		if err != nil {
			return err
		}
		err = groupsBucket.Put([]byte(group.Name), buf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *BoltProvider) deleteFolder(baseFolder vfs.BaseVirtualFolder) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		usersBucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		groupsBucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}

		var f []byte
		if f = bucket.Get([]byte(baseFolder.Name)); f == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", baseFolder.Name))
		}
		var folder vfs.BaseVirtualFolder
		err = json.Unmarshal(f, &folder)
		if err != nil {
			return err
		}
		if err = p.deleteFolderMappings(folder, usersBucket, groupsBucket); err != nil {
			return err
		}

		return bucket.Delete([]byte(folder.Name))
	})
}

func (p *BoltProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getFoldersBucket(tx)
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

func (p *BoltProvider) getGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	groups := make([]Group, 0, limit)
	var err error
	if limit <= 0 {
		return groups, err
	}
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
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
				var group Group
				group, err = p.joinGroupAndFolders(v, foldersBucket)
				if err != nil {
					return err
				}
				group.PrepareForRendering()
				groups = append(groups, group)
				if len(groups) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var group Group
				group, err = p.joinGroupAndFolders(v, foldersBucket)
				if err != nil {
					return err
				}
				group.PrepareForRendering()
				groups = append(groups, group)
				if len(groups) >= limit {
					break
				}
			}
		}
		return err
	})
	return groups, err
}

func (p *BoltProvider) getGroupsWithNames(names []string) ([]Group, error) {
	var groups []Group
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		for _, name := range names {
			g := bucket.Get([]byte(name))
			if g == nil {
				continue
			}
			group, err := p.joinGroupAndFolders(g, foldersBucket)
			if err != nil {
				return err
			}
			groups = append(groups, group)
		}
		return nil
	})
	return groups, err
}

func (p *BoltProvider) getUsersInGroups(names []string) ([]string, error) {
	var usernames []string
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		for _, name := range names {
			g := bucket.Get([]byte(name))
			if g == nil {
				continue
			}
			var group Group
			err := json.Unmarshal(g, &group)
			if err != nil {
				return err
			}
			usernames = append(usernames, group.Users...)
		}
		return nil
	})
	return usernames, err
}

func (p *BoltProvider) groupExists(name string) (Group, error) {
	var group Group
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		g := bucket.Get([]byte(name))
		if g == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("group %#v does not exist", name))
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		group, err = p.joinGroupAndFolders(g, foldersBucket)
		return err
	})
	return group, err
}

func (p *BoltProvider) addGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		if u := bucket.Get([]byte(group.Name)); u != nil {
			return fmt.Errorf("group %v already exists", group.Name)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		group.ID = int64(id)
		group.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		group.Users = nil
		group.Admins = nil
		for idx := range group.VirtualFolders {
			err = p.addRelationToFolderMapping(&group.VirtualFolders[idx].BaseVirtualFolder, nil, group, foldersBucket)
			if err != nil {
				return err
			}
		}
		buf, err := json.Marshal(group)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group.Name), buf)
	})
}

func (p *BoltProvider) updateGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		var g []byte
		if g = bucket.Get([]byte(group.Name)); g == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("group %#v does not exist", group.Name))
		}
		var oldGroup Group
		err = json.Unmarshal(g, &oldGroup)
		if err != nil {
			return err
		}
		for idx := range oldGroup.VirtualFolders {
			err = p.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name, foldersBucket)
			if err != nil {
				return err
			}
		}
		for idx := range group.VirtualFolders {
			err = p.addRelationToFolderMapping(&group.VirtualFolders[idx].BaseVirtualFolder, nil, group, foldersBucket)
			if err != nil {
				return err
			}
		}
		group.ID = oldGroup.ID
		group.CreatedAt = oldGroup.CreatedAt
		group.Users = oldGroup.Users
		group.Admins = oldGroup.Admins
		group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(group)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group.Name), buf)
	})
}

func (p *BoltProvider) deleteGroup(group Group) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		var g []byte
		if g = bucket.Get([]byte(group.Name)); g == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("group %#v does not exist", group.Name))
		}
		var oldGroup Group
		err = json.Unmarshal(g, &oldGroup)
		if err != nil {
			return err
		}
		if len(oldGroup.Users) > 0 {
			return util.NewValidationError(fmt.Sprintf("the group %#v is referenced, it cannot be removed", oldGroup.Name))
		}
		if len(oldGroup.VirtualFolders) > 0 {
			foldersBucket, err := p.getFoldersBucket(tx)
			if err != nil {
				return err
			}
			for idx := range oldGroup.VirtualFolders {
				err = p.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name, foldersBucket)
				if err != nil {
					return err
				}
			}
		}
		if len(oldGroup.Admins) > 0 {
			adminsBucket, err := p.getAdminsBucket(tx)
			if err != nil {
				return err
			}
			for idx := range oldGroup.Admins {
				err = p.removeGroupFromAdminMapping(oldGroup.Name, oldGroup.Admins[idx], adminsBucket)
				if err != nil {
					return err
				}
			}
		}

		return bucket.Delete([]byte(group.Name))
	})
}

func (p *BoltProvider) dumpGroups() ([]Group, error) {
	groups := make([]Group, 0, 50)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getGroupsBucket(tx)
		if err != nil {
			return err
		}
		foldersBucket, err := p.getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			group, err := p.joinGroupAndFolders(v, foldersBucket)
			if err != nil {
				return err
			}
			groups = append(groups, group)
		}
		return err
	})
	return groups, err
}

func (p *BoltProvider) apiKeyExists(keyID string) (APIKey, error) {
	var apiKey APIKey
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getAPIKeysBucket(tx)
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
		bucket, err := p.getAPIKeysBucket(tx)
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
		bucket, err := p.getAPIKeysBucket(tx)
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

func (p *BoltProvider) deleteAPIKey(apiKey APIKey) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getAPIKeysBucket(tx)
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
		bucket, err := p.getAPIKeysBucket(tx)
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
		bucket, err := p.getAPIKeysBucket(tx)
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
		bucket, err := p.getSharesBucket(tx)
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
		bucket, err := p.getSharesBucket(tx)
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
		bucket, err := p.getSharesBucket(tx)
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

func (p *BoltProvider) deleteShare(share Share) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getSharesBucket(tx)
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
		bucket, err := p.getSharesBucket(tx)
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
		bucket, err := p.getSharesBucket(tx)
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
		bucket, err := p.getSharesBucket(tx)
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

func (p *BoltProvider) addSharedSession(session Session) error {
	return ErrNotImplemented
}

func (p *BoltProvider) deleteSharedSession(key string) error {
	return ErrNotImplemented
}

func (p *BoltProvider) getSharedSession(key string) (Session, error) {
	return Session{}, ErrNotImplemented
}

func (p *BoltProvider) cleanupSharedSessions(sessionType SessionType, before int64) error {
	return ErrNotImplemented
}

func (p *BoltProvider) getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	if limit <= 0 {
		return nil, nil
	}
	actions := make([]BaseEventAction, 0, limit)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		itNum := 0
		cursor := bucket.Cursor()
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var action BaseEventAction
				err = json.Unmarshal(v, &action)
				if err != nil {
					return err
				}
				action.PrepareForRendering()
				actions = append(actions, action)
				if len(actions) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var action BaseEventAction
				err = json.Unmarshal(v, &action)
				if err != nil {
					return err
				}
				action.PrepareForRendering()
				actions = append(actions, action)
				if len(actions) >= limit {
					break
				}
			}
		}
		return nil
	})
	return actions, err
}

func (p *BoltProvider) dumpEventActions() ([]BaseEventAction, error) {
	actions := make([]BaseEventAction, 0, 50)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var action BaseEventAction
			err = json.Unmarshal(v, &action)
			if err != nil {
				return err
			}
			actions = append(actions, action)
		}
		return nil
	})
	return actions, err
}

func (p *BoltProvider) eventActionExists(name string) (BaseEventAction, error) {
	var action BaseEventAction
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		k := bucket.Get([]byte(name))
		if k == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("action %q does not exist", name))
		}
		return json.Unmarshal(k, &action)
	})
	return action, err
}

func (p *BoltProvider) addEventAction(action *BaseEventAction) error {
	err := action.validate()
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		if a := bucket.Get([]byte(action.Name)); a != nil {
			return fmt.Errorf("event action %s already exists", action.Name)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		action.ID = int64(id)
		action.Rules = nil
		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(action.Name), buf)
	})
}

func (p *BoltProvider) updateEventAction(action *BaseEventAction) error {
	err := action.validate()
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		var a []byte

		if a = bucket.Get([]byte(action.Name)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event action %s does not exist", action.Name))
		}
		var oldAction BaseEventAction
		err = json.Unmarshal(a, &oldAction)
		if err != nil {
			return err
		}
		action.ID = oldAction.ID
		action.Name = oldAction.Name
		action.Rules = nil
		if len(oldAction.Rules) > 0 {
			rulesBucket, err := p.getRulesBucket(tx)
			if err != nil {
				return err
			}
			var relatedRules []string
			for _, ruleName := range oldAction.Rules {
				r := rulesBucket.Get([]byte(ruleName))
				if r != nil {
					relatedRules = append(relatedRules, ruleName)
					var rule EventRule
					err := json.Unmarshal(r, &rule)
					if err != nil {
						return err
					}
					rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
					buf, err := json.Marshal(rule)
					if err != nil {
						return err
					}
					if err = rulesBucket.Put([]byte(rule.Name), buf); err != nil {
						return err
					}
					setLastRuleUpdate()
				}
			}
			action.Rules = relatedRules
		}
		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(action.Name), buf)
	})
}

func (p *BoltProvider) deleteEventAction(action BaseEventAction) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		var a []byte

		if a = bucket.Get([]byte(action.Name)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("action %s does not exist", action.Name))
		}
		var oldAction BaseEventAction
		err = json.Unmarshal(a, &oldAction)
		if err != nil {
			return err
		}
		if len(oldAction.Rules) > 0 {
			return util.NewValidationError(fmt.Sprintf("action %s is referenced, it cannot be removed", oldAction.Name))
		}
		return bucket.Delete([]byte(action.Name))
	})
}

func (p *BoltProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	if limit <= 0 {
		return nil, nil
	}
	rules := make([]EventRule, 0, limit)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getRulesBucket(tx)
		if err != nil {
			return err
		}
		actionsBucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		itNum := 0
		cursor := bucket.Cursor()
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var rule EventRule
				rule, err = p.joinRuleAndActions(v, actionsBucket)
				if err != nil {
					return err
				}
				rule.PrepareForRendering()
				rules = append(rules, rule)
				if len(rules) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var rule EventRule
				rule, err = p.joinRuleAndActions(v, actionsBucket)
				if err != nil {
					return err
				}
				rule.PrepareForRendering()
				rules = append(rules, rule)
				if len(rules) >= limit {
					break
				}
			}
		}
		return err
	})
	return rules, err
}

func (p *BoltProvider) dumpEventRules() ([]EventRule, error) {
	rules := make([]EventRule, 0, 50)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getRulesBucket(tx)
		if err != nil {
			return err
		}
		actionsBucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			rule, err := p.joinRuleAndActions(v, actionsBucket)
			if err != nil {
				return err
			}
			rules = append(rules, rule)
		}
		return nil
	})
	return rules, err
}

func (p *BoltProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	if getLastRuleUpdate() < after {
		return nil, nil
	}
	rules := make([]EventRule, 0, 10)
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getRulesBucket(tx)
		if err != nil {
			return err
		}
		actionsBucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var rule EventRule
			err := json.Unmarshal(v, &rule)
			if err != nil {
				return err
			}
			if rule.UpdatedAt < after {
				continue
			}
			var actions []EventAction
			for idx := range rule.Actions {
				action := &rule.Actions[idx]
				var baseAction BaseEventAction
				k := actionsBucket.Get([]byte(action.Name))
				if k == nil {
					continue
				}
				err = json.Unmarshal(k, &baseAction)
				if err != nil {
					continue
				}
				baseAction.Options.SetEmptySecretsIfNil()
				action.BaseEventAction = baseAction
				actions = append(actions, *action)
			}
			rule.Actions = actions
			rules = append(rules, rule)
		}
		return nil
	})
	return rules, err
}

func (p *BoltProvider) eventRuleExists(name string) (EventRule, error) {
	var rule EventRule
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := p.getRulesBucket(tx)
		if err != nil {
			return err
		}
		r := bucket.Get([]byte(name))
		if r == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", name))
		}
		actionsBucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		rule, err = p.joinRuleAndActions(r, actionsBucket)
		return err
	})
	return rule, err
}

func (p *BoltProvider) addEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getRulesBucket(tx)
		if err != nil {
			return err
		}
		actionsBucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		if r := bucket.Get([]byte(rule.Name)); r != nil {
			return fmt.Errorf("event rule %q already exists", rule.Name)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		rule.ID = int64(id)
		rule.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		rule.UpdatedAt = rule.CreatedAt
		for idx := range rule.Actions {
			if err = p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name, actionsBucket); err != nil {
				return err
			}
		}
		sort.Slice(rule.Actions, func(i, j int) bool {
			return rule.Actions[i].Order < rule.Actions[j].Order
		})
		buf, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(rule.Name), buf)
		if err == nil {
			setLastRuleUpdate()
		}
		return err
	})
}

func (p *BoltProvider) updateEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getRulesBucket(tx)
		if err != nil {
			return err
		}
		actionsBucket, err := p.getActionsBucket(tx)
		if err != nil {
			return err
		}
		var r []byte
		if r = bucket.Get([]byte(rule.Name)); r == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
		}
		var oldRule EventRule
		if err = json.Unmarshal(r, &oldRule); err != nil {
			return err
		}
		for idx := range oldRule.Actions {
			if err = p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name, actionsBucket); err != nil {
				return err
			}
		}
		for idx := range rule.Actions {
			if err = p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name, actionsBucket); err != nil {
				return err
			}
		}
		rule.ID = oldRule.ID
		rule.CreatedAt = oldRule.CreatedAt
		rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		sort.Slice(rule.Actions, func(i, j int) bool {
			return rule.Actions[i].Order < rule.Actions[j].Order
		})
		err = bucket.Put([]byte(rule.Name), buf)
		if err == nil {
			setLastRuleUpdate()
		}
		return err
	})
}

func (p *BoltProvider) deleteEventRule(rule EventRule, softDelete bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getRulesBucket(tx)
		if err != nil {
			return err
		}
		var r []byte
		if r = bucket.Get([]byte(rule.Name)); r == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
		}
		var oldRule EventRule
		if err = json.Unmarshal(r, &oldRule); err != nil {
			return err
		}
		if len(oldRule.Actions) > 0 {
			actionsBucket, err := p.getActionsBucket(tx)
			if err != nil {
				return err
			}
			for idx := range oldRule.Actions {
				if err = p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name, actionsBucket); err != nil {
					return err
				}
			}
		}
		return bucket.Delete([]byte(rule.Name))
	})
}

func (*BoltProvider) getTaskByName(name string) (Task, error) {
	return Task{}, ErrNotImplemented
}

func (*BoltProvider) addTask(name string) error {
	return ErrNotImplemented
}

func (*BoltProvider) updateTask(name string, version int64) error {
	return ErrNotImplemented
}

func (*BoltProvider) updateTaskTimestamp(name string) error {
	return ErrNotImplemented
}

func (*BoltProvider) addNode() error {
	return ErrNotImplemented
}

func (*BoltProvider) getNodeByName(name string) (Node, error) {
	return Node{}, ErrNotImplemented
}

func (*BoltProvider) getNodes() ([]Node, error) {
	return nil, ErrNotImplemented
}

func (*BoltProvider) updateNodeTimestamp() error {
	return ErrNotImplemented
}

func (*BoltProvider) cleanupNodes() error {
	return ErrNotImplemented
}

func (p *BoltProvider) setFirstDownloadTimestamp(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist, unable to set download timestamp",
				username))
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		if user.FirstDownload > 0 {
			return util.NewGenericError(fmt.Sprintf("first download already set to %v",
				util.GetTimeFromMsecSinceEpoch(user.FirstDownload)))
		}
		user.FirstDownload = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(username), buf)
	})
}

func (p *BoltProvider) setFirstUploadTimestamp(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := p.getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist, unable to set upload timestamp",
				username))
		}
		var user User
		if err = json.Unmarshal(u, &user); err != nil {
			return err
		}
		if user.FirstUpload > 0 {
			return util.NewGenericError(fmt.Sprintf("first upload already set to %v",
				util.GetTimeFromMsecSinceEpoch(user.FirstUpload)))
		}
		user.FirstUpload = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(username), buf)
	})
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
	case version < 19:
		err = fmt.Errorf("database schema version %v is too old, please see the upgrading docs", version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 19, version == 20, version == 21, version == 22:
		logger.InfoToConsole(fmt.Sprintf("updating database schema version: %d -> 23", version))
		providerLog(logger.LevelInfo, "updating database schema version: %d -> 23", version)
		return updateBoltDatabaseVersion(p.dbHandle, 23)
	default:
		if version > boltDatabaseVersion {
			providerLog(logger.LevelError, "database schema version %v is newer than the supported one: %v", version,
				boltDatabaseVersion)
			logger.WarnToConsole("database schema version %v is newer than the supported one: %v", version,
				boltDatabaseVersion)
			return nil
		}
		return fmt.Errorf("database schema version not handled: %v", version)
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
	case 20, 21, 22, 23:
		logger.InfoToConsole("downgrading database schema version: %d -> 19", dbVersion.Version)
		providerLog(logger.LevelInfo, "downgrading database schema version: %d -> 19", dbVersion.Version)
		err := p.dbHandle.Update(func(tx *bolt.Tx) error {
			for _, bucketName := range [][]byte{actionsBucket, rulesBucket} {
				err := tx.DeleteBucket(bucketName)
				if err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		return updateBoltDatabaseVersion(p.dbHandle, 19)
	default:
		return fmt.Errorf("database schema version not handled: %v", dbVersion.Version)
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

func (p *BoltProvider) joinRuleAndActions(r []byte, actionsBucket *bolt.Bucket) (EventRule, error) {
	var rule EventRule
	err := json.Unmarshal(r, &rule)
	if err != nil {
		return rule, err
	}
	var actions []EventAction
	for idx := range rule.Actions {
		action := &rule.Actions[idx]
		var baseAction BaseEventAction
		k := actionsBucket.Get([]byte(action.Name))
		if k == nil {
			continue
		}
		err = json.Unmarshal(k, &baseAction)
		if err != nil {
			continue
		}
		baseAction.Options.SetEmptySecretsIfNil()
		action.BaseEventAction = baseAction
		actions = append(actions, *action)
	}
	rule.Actions = actions
	return rule, nil
}

func (p *BoltProvider) joinGroupAndFolders(g []byte, foldersBucket *bolt.Bucket) (Group, error) {
	var group Group
	err := json.Unmarshal(g, &group)
	if err != nil {
		return group, err
	}
	if len(group.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range group.VirtualFolders {
			folder := &group.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name, foldersBucket)
			if err != nil {
				continue
			}
			folder.BaseVirtualFolder = baseFolder
			folders = append(folders, *folder)
		}
		group.VirtualFolders = folders
	}
	group.SetEmptySecretsIfNil()
	return group, err
}

func (p *BoltProvider) joinUserAndFolders(u []byte, foldersBucket *bolt.Bucket) (User, error) {
	var user User
	err := json.Unmarshal(u, &user)
	if err != nil {
		return user, err
	}
	if len(user.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range user.VirtualFolders {
			folder := &user.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name, foldersBucket)
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

func (p *BoltProvider) groupExistsInternal(name string, bucket *bolt.Bucket) (Group, error) {
	var group Group
	g := bucket.Get([]byte(name))
	if g == nil {
		err := util.NewRecordNotFoundError(fmt.Sprintf("group %#v does not exist", name))
		return group, err
	}
	err := json.Unmarshal(g, &group)
	return group, err
}

func (p *BoltProvider) folderExistsInternal(name string, bucket *bolt.Bucket) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder
	f := bucket.Get([]byte(name))
	if f == nil {
		err := util.NewRecordNotFoundError(fmt.Sprintf("folder %#v does not exist", name))
		return folder, err
	}
	err := json.Unmarshal(f, &folder)
	return folder, err
}

func (p *BoltProvider) addFolderInternal(folder vfs.BaseVirtualFolder, bucket *bolt.Bucket) error {
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

func (p *BoltProvider) addRuleToActionMapping(ruleName, actionName string, bucket *bolt.Bucket) error {
	a := bucket.Get([]byte(actionName))
	if a == nil {
		return util.NewGenericError(fmt.Sprintf("action %q does not exist", actionName))
	}
	var action BaseEventAction
	err := json.Unmarshal(a, &action)
	if err != nil {
		return err
	}
	if !util.Contains(action.Rules, ruleName) {
		action.Rules = append(action.Rules, ruleName)
		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(action.Name), buf)
	}
	return nil
}

func (p *BoltProvider) removeRuleFromActionMapping(ruleName, actionName string, bucket *bolt.Bucket) error {
	a := bucket.Get([]byte(actionName))
	if a == nil {
		providerLog(logger.LevelWarn, "action %q does not exist, cannot remove from mapping", actionName)
		return nil
	}
	var action BaseEventAction
	err := json.Unmarshal(a, &action)
	if err != nil {
		return err
	}
	if util.Contains(action.Rules, ruleName) {
		var rules []string
		for _, r := range action.Rules {
			if r != ruleName {
				rules = append(rules, r)
			}
		}
		action.Rules = util.RemoveDuplicates(rules, false)
		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(action.Name), buf)
	}
	return nil
}

func (p *BoltProvider) addUserToGroupMapping(username, groupname string, bucket *bolt.Bucket) error {
	g := bucket.Get([]byte(groupname))
	if g == nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}
	var group Group
	err := json.Unmarshal(g, &group)
	if err != nil {
		return err
	}
	if !util.Contains(group.Users, username) {
		group.Users = append(group.Users, username)
		buf, err := json.Marshal(group)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group.Name), buf)
	}
	return nil
}

func (p *BoltProvider) removeUserFromGroupMapping(username, groupname string, bucket *bolt.Bucket) error {
	g := bucket.Get([]byte(groupname))
	if g == nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}
	var group Group
	err := json.Unmarshal(g, &group)
	if err != nil {
		return err
	}
	var users []string
	for _, u := range group.Users {
		if u != username {
			users = append(users, u)
		}
	}
	group.Users = util.RemoveDuplicates(users, false)
	buf, err := json.Marshal(group)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(group.Name), buf)
}

func (p *BoltProvider) addAdminToGroupMapping(username, groupname string, bucket *bolt.Bucket) error {
	g := bucket.Get([]byte(groupname))
	if g == nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}
	var group Group
	err := json.Unmarshal(g, &group)
	if err != nil {
		return err
	}
	if !util.Contains(group.Admins, username) {
		group.Admins = append(group.Admins, username)
		buf, err := json.Marshal(group)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group.Name), buf)
	}
	return nil
}

func (p *BoltProvider) removeAdminFromGroupMapping(username, groupname string, bucket *bolt.Bucket) error {
	g := bucket.Get([]byte(groupname))
	if g == nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}
	var group Group
	err := json.Unmarshal(g, &group)
	if err != nil {
		return err
	}
	var admins []string
	for _, a := range group.Admins {
		if a != username {
			admins = append(admins, a)
		}
	}
	group.Admins = util.RemoveDuplicates(admins, false)
	buf, err := json.Marshal(group)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(group.Name), buf)
}

func (p *BoltProvider) removeGroupFromAdminMapping(groupName, adminName string, bucket *bolt.Bucket) error {
	var a []byte
	if a = bucket.Get([]byte(adminName)); a == nil {
		// the admin does not exist so there is no associated group
		return nil
	}
	var admin Admin
	err := json.Unmarshal(a, &admin)
	if err != nil {
		return err
	}
	var newGroups []AdminGroupMapping
	for _, g := range admin.Groups {
		if g.Name != groupName {
			newGroups = append(newGroups, g)
		}
	}
	admin.Groups = newGroups
	buf, err := json.Marshal(admin)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(adminName), buf)
}

func (p *BoltProvider) addRelationToFolderMapping(baseFolder *vfs.BaseVirtualFolder, user *User, group *Group, bucket *bolt.Bucket) error {
	f := bucket.Get([]byte(baseFolder.Name))
	if f == nil {
		// folder does not exists, try to create
		baseFolder.LastQuotaUpdate = 0
		baseFolder.UsedQuotaFiles = 0
		baseFolder.UsedQuotaSize = 0
		if user != nil {
			baseFolder.Users = []string{user.Username}
		}
		if group != nil {
			baseFolder.Groups = []string{group.Name}
		}
		return p.addFolderInternal(*baseFolder, bucket)
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
	baseFolder.Groups = oldFolder.Groups
	if user != nil && !util.Contains(baseFolder.Users, user.Username) {
		baseFolder.Users = append(baseFolder.Users, user.Username)
	}
	if group != nil && !util.Contains(baseFolder.Groups, group.Name) {
		baseFolder.Groups = append(baseFolder.Groups, group.Name)
	}
	buf, err := json.Marshal(baseFolder)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(baseFolder.Name), buf)
}

func (p *BoltProvider) removeRelationFromFolderMapping(folder vfs.VirtualFolder, username, groupname string,
	bucket *bolt.Bucket,
) error {
	var f []byte
	if f = bucket.Get([]byte(folder.Name)); f == nil {
		// the folder does not exist so there is no associated user/group
		return nil
	}
	var baseFolder vfs.BaseVirtualFolder
	err := json.Unmarshal(f, &baseFolder)
	if err != nil {
		return err
	}
	found := false
	if username != "" {
		found = true
		var newUserMapping []string
		for _, u := range baseFolder.Users {
			if u != username {
				newUserMapping = append(newUserMapping, u)
			}
		}
		baseFolder.Users = newUserMapping
	}
	if groupname != "" {
		found = true
		var newGroupMapping []string
		for _, g := range baseFolder.Groups {
			if g != groupname {
				newGroupMapping = append(newGroupMapping, g)
			}
		}
		baseFolder.Groups = newGroupMapping
	}
	if !found {
		return nil
	}
	buf, err := json.Marshal(baseFolder)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(folder.Name), buf)
}

func (p *BoltProvider) updateUserRelations(tx *bolt.Tx, user *User, oldUser User) error {
	foldersBucket, err := p.getFoldersBucket(tx)
	if err != nil {
		return err
	}
	groupBucket, err := p.getGroupsBucket(tx)
	if err != nil {
		return err
	}
	for idx := range oldUser.VirtualFolders {
		err = p.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, "", foldersBucket)
		if err != nil {
			return err
		}
	}
	for idx := range oldUser.Groups {
		err = p.removeUserFromGroupMapping(user.Username, oldUser.Groups[idx].Name, groupBucket)
		if err != nil {
			return err
		}
	}
	for idx := range user.VirtualFolders {
		err = p.addRelationToFolderMapping(&user.VirtualFolders[idx].BaseVirtualFolder, user, nil, foldersBucket)
		if err != nil {
			return err
		}
	}
	for idx := range user.Groups {
		err = p.addUserToGroupMapping(user.Username, user.Groups[idx].Name, groupBucket)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *BoltProvider) adminExistsInternal(tx *bolt.Tx, username string) error {
	bucket, err := p.getAdminsBucket(tx)
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
	bucket, err := p.getUsersBucket(tx)
	if err != nil {
		return err
	}
	u := bucket.Get([]byte(username))
	if u == nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %#v does not exist", username))
	}
	return nil
}

func (p *BoltProvider) deleteRelatedShares(tx *bolt.Tx, username string) error {
	bucket, err := p.getSharesBucket(tx)
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

func (p *BoltProvider) deleteRelatedAPIKey(tx *bolt.Tx, username string, scope APIKeyScope) error {
	bucket, err := p.getAPIKeysBucket(tx)
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

func (p *BoltProvider) getSharesBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error

	bucket := tx.Bucket(sharesBucket)
	if bucket == nil {
		err = errors.New("unable to find shares bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func (p *BoltProvider) getAPIKeysBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error

	bucket := tx.Bucket(apiKeysBucket)
	if bucket == nil {
		err = errors.New("unable to find api keys bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func (p *BoltProvider) getAdminsBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error

	bucket := tx.Bucket(adminsBucket)
	if bucket == nil {
		err = errors.New("unable to find admins bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func (p *BoltProvider) getUsersBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(usersBucket)
	if bucket == nil {
		err = errors.New("unable to find users bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func (p *BoltProvider) getGroupsBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(groupsBucket)
	if bucket == nil {
		err = fmt.Errorf("unable to find groups bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func (p *BoltProvider) getFoldersBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(foldersBucket)
	if bucket == nil {
		err = fmt.Errorf("unable to find folders bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func (p *BoltProvider) getActionsBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(actionsBucket)
	if bucket == nil {
		err = fmt.Errorf("unable to find event actions bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func (p *BoltProvider) getRulesBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(rulesBucket)
	if bucket == nil {
		err = fmt.Errorf("unable to find event rules bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getBoltDatabaseVersion(dbHandle *bolt.DB) (schemaVersion, error) {
	var dbVersion schemaVersion
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dbVersionBucket)
		if bucket == nil {
			return fmt.Errorf("unable to find database schema version bucket")
		}
		v := bucket.Get(dbVersionKey)
		if v == nil {
			dbVersion = schemaVersion{
				Version: 19,
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
			return fmt.Errorf("unable to find database schema version bucket")
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
