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

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	boltDatabaseVersion = 10
)

var (
	usersBucket     = []byte("users")
	foldersBucket   = []byte("folders")
	adminsBucket    = []byte("admins")
	dbVersionBucket = []byte("db_version")
	dbVersionKey    = []byte("version")
)

// BoltProvider auth provider for bolt key/value store
type BoltProvider struct {
	dbHandle *bolt.DB
}

func init() {
	version.AddFeature("+bolt")
}

func initializeBoltProvider(basePath string) error {
	var err error

	dbPath := config.Name
	if !utils.IsFileInputValid(dbPath) {
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
		err = dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(usersBucket)
			return e
		})
		if err != nil {
			providerLog(logger.LevelWarn, "error creating users bucket: %v", err)
			return err
		}
		if err != nil {
			providerLog(logger.LevelWarn, "error creating username idx bucket: %v", err)
			return err
		}
		err = dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(foldersBucket)
			return e
		})
		if err != nil {
			providerLog(logger.LevelWarn, "error creating folders bucket: %v", err)
			return err
		}
		err = dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(adminsBucket)
			return e
		})
		if err != nil {
			providerLog(logger.LevelWarn, "error creating admins bucket: %v", err)
			return err
		}
		err = dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(dbVersionBucket)
			return e
		})
		if err != nil {
			providerLog(logger.LevelWarn, "error creating database version bucket: %v", err)
			return err
		}
		provider = &BoltProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating bolt key/value store handler: %v", err)
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

func (p *BoltProvider) validateUserAndPubKey(username string, pubKey []byte) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %#v: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey)
}

func (p *BoltProvider) updateLastLogin(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("username %#v does not exist, unable to update last login", username)}
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		user.LastLogin = utils.GetTimeAsMsSinceEpoch(time.Now())
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

func (p *BoltProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("username %#v does not exist, unable to update quota", username)}
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
		user.LastQuotaUpdate = utils.GetTimeAsMsSinceEpoch(time.Now())
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

func (p *BoltProvider) getUsedQuota(username string) (int, int64, error) {
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to get quota for user %v error: %v", username, err)
		return 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, err
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
			return &RecordNotFoundError{err: fmt.Sprintf("admin %v does not exist", username)}
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
			return &RecordNotFoundError{err: fmt.Sprintf("admin %v does not exist", admin.Username)}
		}
		var oldAdmin Admin
		err = json.Unmarshal(a, &oldAdmin)
		if err != nil {
			return err
		}

		admin.ID = oldAdmin.ID
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
			return &RecordNotFoundError{err: fmt.Sprintf("admin %v does not exist", admin.Username)}
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
			return &RecordNotFoundError{err: fmt.Sprintf("username %#v does not exist", username)}
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
		user.LastLogin = 0
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
			return &RecordNotFoundError{err: fmt.Sprintf("username %#v does not exist", user.Username)}
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
		user.LastLogin = oldUser.LastLogin
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
		exists := bucket.Get([]byte(user.Username))
		if exists == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("user %#v does not exist", user.Username)}
		}
		return bucket.Delete([]byte(user.Username))
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
			return &RecordNotFoundError{err: fmt.Sprintf("folder %v does not exist", folder.Name)}
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
			return &RecordNotFoundError{err: fmt.Sprintf("folder %v does not exist", folder.Name)}
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
			return &RecordNotFoundError{err: fmt.Sprintf("folder %#v does not exist, unable to update quota", name)}
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
		folder.LastQuotaUpdate = utils.GetTimeAsMsSinceEpoch(time.Now())
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
		providerLog(logger.LevelWarn, "unable to get quota for folder %#v error: %v", name, err)
		return 0, 0, err
	}
	return folder.UsedQuotaFiles, folder.UsedQuotaSize, err
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
	case version < 6:
		err = fmt.Errorf("database version %v is too old, please see the upgrading docs", version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 6:
		return updateBoltDatabaseFrom6To10(p.dbHandle)
	default:
		if version > boltDatabaseVersion {
			providerLog(logger.LevelWarn, "database version %v is newer than the supported one: %v", version,
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
	if targetVersion >= 8 {
		targetVersion = 6
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}
	if dbVersion.Version == 10 {
		return downgradeBoltDatabaseFrom10To6(p.dbHandle)
	}
	return errors.New("the current version cannot be reverted")
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
		err := &RecordNotFoundError{err: fmt.Sprintf("folder %v does not exist", name)}
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
	if !utils.IsStringInSlice(user.Username, baseFolder.Users) {
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
	if utils.IsStringInSlice(user.Username, baseFolder.Users) {
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

func getAdminsBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error

	bucket := tx.Bucket(adminsBucket)
	if bucket == nil {
		err = errors.New("unable to find admin bucket, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getUsersBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(usersBucket)
	if bucket == nil {
		err = errors.New("unable to find required buckets, bolt database structure not correcly defined")
	}
	return bucket, err
}

func getFoldersBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(foldersBucket)
	if bucket == nil {
		err = fmt.Errorf("unable to find required buckets, bolt database structure not correcly defined")
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
				Version: 6,
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

func updateBoltDatabaseFrom6To10(dbHandle *bolt.DB) error {
	logger.InfoToConsole("updating database version: 6 -> 10")
	providerLog(logger.LevelInfo, "updating database version: 6 -> 10")

	if err := boltUpdateV7Folders(dbHandle); err != nil {
		return err
	}
	if err := boltUpdateV7Users(dbHandle); err != nil {
		return err
	}
	return updateBoltDatabaseVersion(dbHandle, 10)
}

func downgradeBoltDatabaseFrom10To6(dbHandle *bolt.DB) error {
	logger.InfoToConsole("downgrading database version: 10 -> 6")
	providerLog(logger.LevelInfo, "downgrading database version: 10 -> 6")

	if err := boltDowngradeV7Folders(dbHandle); err != nil {
		return err
	}
	if err := boltDowngradeV7Users(dbHandle); err != nil {
		return err
	}
	return updateBoltDatabaseVersion(dbHandle, 6)
}

func boltUpdateV7Folders(dbHandle *bolt.DB) error {
	var folders []map[string]interface{}
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var folderMap map[string]interface{}
			err = json.Unmarshal(v, &folderMap)
			if err != nil {
				return err
			}
			fsBytes, err := json.Marshal(folderMap["filesystem"])
			if err != nil {
				continue
			}
			var compatFsConfig compatFilesystemV9
			err = json.Unmarshal(fsBytes, &compatFsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v9 fsconfig for folder %#v, is it already migrated?", folderMap["name"])
				continue
			}
			if compatFsConfig.AzBlobConfig.SASURL != "" {
				folder := vfs.BaseVirtualFolder{
					Name: folderMap["name"].(string),
				}
				fsConfig, err := convertFsConfigFromV9(compatFsConfig, folder.GetEncrytionAdditionalData())
				if err != nil {
					return err
				}
				folderMap["filesystem"] = fsConfig
				folders = append(folders, folderMap)
			}
		}
		return err
	})

	if err != nil {
		return err
	}

	return dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		for _, folder := range folders {
			buf, err := json.Marshal(folder)
			if err != nil {
				return err
			}
			err = bucket.Put([]byte(folder["name"].(string)), buf)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

//nolint:gocyclo
func boltUpdateV7Users(dbHandle *bolt.DB) error {
	var users []map[string]interface{}
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var userMap map[string]interface{}
			err = json.Unmarshal(v, &userMap)
			if err != nil {
				return err
			}
			fsBytes, err := json.Marshal(userMap["filesystem"])
			if err != nil {
				continue
			}
			foldersBytes, err := json.Marshal(userMap["virtual_folders"])
			if err != nil {
				continue
			}
			var compatFsConfig compatFilesystemV9
			err = json.Unmarshal(fsBytes, &compatFsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v9 fsconfig for user %#v, is it already migrated?", userMap["name"])
				continue
			}
			var compatFolders []compatFolderV9
			err = json.Unmarshal(foldersBytes, &compatFolders)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v9 folders for user %#v, is it already migrated?", userMap["name"])
				continue
			}
			toConvert := false
			for idx := range compatFolders {
				f := &compatFolders[idx]
				if f.FsConfig.AzBlobConfig.SASURL != "" {
					f.FsConfig.AzBlobConfig = compatAzBlobFsConfigV9{}
					toConvert = true
				}
			}
			if compatFsConfig.AzBlobConfig.SASURL != "" {
				user := User{
					Username: userMap["username"].(string),
				}
				fsConfig, err := convertFsConfigFromV9(compatFsConfig, user.GetEncrytionAdditionalData())
				if err != nil {
					return err
				}
				userMap["filesystem"] = fsConfig
				toConvert = true
			}
			if toConvert {
				userMap["virtual_folders"] = compatFolders
				users = append(users, userMap)
			}
		}
		return err
	})

	if err != nil {
		return err
	}

	return dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		for _, user := range users {
			buf, err := json.Marshal(user)
			if err != nil {
				return err
			}
			err = bucket.Put([]byte(user["username"].(string)), buf)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

//nolint:dupl
func boltDowngradeV7Folders(dbHandle *bolt.DB) error {
	var folders []map[string]interface{}
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var folderMap map[string]interface{}
			err = json.Unmarshal(v, &folderMap)
			if err != nil {
				return err
			}
			fsBytes, err := json.Marshal(folderMap["filesystem"])
			if err != nil {
				continue
			}
			var fsConfig vfs.Filesystem
			err = json.Unmarshal(fsBytes, &fsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v10 fsconfig for folder %#v, is it already migrated?", folderMap["name"])
				continue
			}
			if fsConfig.AzBlobConfig.SASURL != nil && !fsConfig.AzBlobConfig.SASURL.IsEmpty() {
				fsV9, err := convertFsConfigToV9(fsConfig)
				if err != nil {
					return err
				}
				folderMap["filesystem"] = fsV9
				folders = append(folders, folderMap)
			}
		}
		return err
	})

	if err != nil {
		return err
	}

	return dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getFoldersBucket(tx)
		if err != nil {
			return err
		}
		for _, folder := range folders {
			buf, err := json.Marshal(folder)
			if err != nil {
				return err
			}
			err = bucket.Put([]byte(folder["name"].(string)), buf)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

//nolint:dupl,gocyclo
func boltDowngradeV7Users(dbHandle *bolt.DB) error {
	var users []map[string]interface{}
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var userMap map[string]interface{}
			err = json.Unmarshal(v, &userMap)
			if err != nil {
				return err
			}
			fsBytes, err := json.Marshal(userMap["filesystem"])
			if err != nil {
				continue
			}
			foldersBytes, err := json.Marshal(userMap["virtual_folders"])
			if err != nil {
				continue
			}
			var fsConfig vfs.Filesystem
			err = json.Unmarshal(fsBytes, &fsConfig)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v10 fsconfig for user %#v, is it already migrated?", userMap["username"])
				continue
			}
			var folders []vfs.VirtualFolder
			err = json.Unmarshal(foldersBytes, &folders)
			if err != nil {
				logger.WarnToConsole("failed to unmarshal v9 folders for user %#v, is it already migrated?", userMap["name"])
				continue
			}
			toConvert := false
			for idx := range folders {
				f := &folders[idx]
				f.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{}
				toConvert = true
			}
			if fsConfig.AzBlobConfig.SASURL != nil && !fsConfig.AzBlobConfig.SASURL.IsEmpty() {
				fsV9, err := convertFsConfigToV9(fsConfig)
				if err != nil {
					return err
				}
				userMap["filesystem"] = fsV9
				toConvert = true
			}
			if toConvert {
				userMap["virtual_folders"] = folders
				users = append(users, userMap)
			}
		}
		return err
	})

	if err != nil {
		return err
	}

	return dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := getUsersBucket(tx)
		if err != nil {
			return err
		}
		for _, user := range users {
			buf, err := json.Marshal(user)
			if err != nil {
				return err
			}
			err = bucket.Put([]byte(user["username"].(string)), buf)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
