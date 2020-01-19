package dataprovider

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	bolt "go.etcd.io/bbolt"
)

const (
	databaseVersion = 3
)

var (
	usersBucket      = []byte("users")
	usersIDIdxBucket = []byte("users_id_idx")
	dbVersionBucket  = []byte("db_version")
	dbVersionKey     = []byte("version")
)

// BoltProvider auth provider for bolt key/value store
type BoltProvider struct {
	dbHandle *bolt.DB
}

type boltDatabaseVersion struct {
	Version int
}

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

func initializeBoltProvider(basePath string) error {
	var err error
	logSender = BoltDataProviderName
	dbPath := config.Name
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
		err = dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(usersIDIdxBucket)
			return e
		})
		if err != nil {
			providerLog(logger.LevelWarn, "error creating username idx bucket: %v", err)
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
		provider = BoltProvider{dbHandle: dbHandle}
		err = checkBoltDatabaseVersion(dbHandle)
	} else {
		providerLog(logger.LevelWarn, "error creating bolt key/value store handler: %v", err)
	}
	return err
}

func (p BoltProvider) checkAvailability() error {
	_, err := p.getUsers(1, 0, "ASC", "")
	return err
}

func (p BoltProvider) validateUserAndPass(username string, password string) (User, error) {
	var user User
	if len(password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, err
	}
	return checkUserAndPass(user, password)
}

func (p BoltProvider) validateUserAndPubKey(username string, pubKey string) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(user, pubKey)
}

func (p BoltProvider) getUserByID(ID int64) (User, error) {
	var user User
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, idxBucket, err := getBuckets(tx)
		if err != nil {
			return err
		}
		userIDAsBytes := itob(ID)
		username := idxBucket.Get(userIDAsBytes)
		if username == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("user with ID %v does not exist", ID)}
		}
		u := bucket.Get(username)
		if u == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("username %#v and ID: %v does not exist", string(username), ID)}
		}
		return json.Unmarshal(u, &user)
	})

	return user, err
}

func (p BoltProvider) updateLastLogin(username string) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
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
		return bucket.Put([]byte(username), buf)
	})
}

func (p BoltProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
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
		return bucket.Put([]byte(username), buf)
	})
}

func (p BoltProvider) getUsedQuota(username string) (int, int64, error) {
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to get quota for user %v error: %v", username, err)
		return 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, err
}

func (p BoltProvider) userExists(username string) (User, error) {
	var user User
	err := p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
		if err != nil {
			return err
		}
		u := bucket.Get([]byte(username))
		if u == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("username %v does not exist", username)}
		}
		return json.Unmarshal(u, &user)
	})
	return user, err
}

func (p BoltProvider) addUser(user User) error {
	err := validateUser(&user)
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, idxBucket, err := getBuckets(tx)
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
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		userIDAsBytes := itob(user.ID)
		err = bucket.Put([]byte(user.Username), buf)
		if err != nil {
			return err
		}
		return idxBucket.Put(userIDAsBytes, []byte(user.Username))
	})
}

func (p BoltProvider) updateUser(user User) error {
	err := validateUser(&user)
	if err != nil {
		return err
	}
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
		if err != nil {
			return err
		}
		if u := bucket.Get([]byte(user.Username)); u == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("username %v does not exist", user.Username)}
		}
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(user.Username), buf)
	})
}

func (p BoltProvider) deleteUser(user User) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, idxBucket, err := getBuckets(tx)
		if err != nil {
			return err
		}
		userIDAsBytes := itob(user.ID)
		userName := idxBucket.Get(userIDAsBytes)
		if userName == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("user with id %v does not exist", user.ID)}
		}
		err = bucket.Delete(userName)
		if err != nil {
			return err
		}
		return idxBucket.Delete(userIDAsBytes)
	})
}

func (p BoltProvider) dumpUsers() ([]User, error) {
	users := []User{}
	var err error
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var user User
			err = json.Unmarshal(v, &user)
			if err != nil {
				return err
			}
			users = append(users, user)
		}
		return err
	})
	return users, err
}

func (p BoltProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	users := []User{}
	var err error
	if limit <= 0 {
		return users, err
	}
	if len(username) > 0 {
		if offset == 0 {
			user, err := p.userExists(username)
			if err == nil {
				users = append(users, HideUserSensitiveData(&user))
			}
		}
		return users, err
	}
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == "ASC" {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var user User
				err = json.Unmarshal(v, &user)
				if err == nil {
					users = append(users, HideUserSensitiveData(&user))
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
				var user User
				err = json.Unmarshal(v, &user)
				if err == nil {
					users = append(users, HideUserSensitiveData(&user))
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

func (p BoltProvider) close() error {
	return p.dbHandle.Close()
}

// itob returns an 8-byte big endian representation of v.
func itob(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

func getBuckets(tx *bolt.Tx) (*bolt.Bucket, *bolt.Bucket, error) {
	var err error
	bucket := tx.Bucket(usersBucket)
	idxBucket := tx.Bucket(usersIDIdxBucket)
	if bucket == nil || idxBucket == nil {
		err = fmt.Errorf("unable to find required buckets, bolt database structure not correcly defined")
	}
	return bucket, idxBucket, err
}

func checkBoltDatabaseVersion(dbHandle *bolt.DB) error {
	dbVersion, err := getBoltDatabaseVersion(dbHandle)
	if err != nil {
		return err
	}
	if dbVersion.Version == databaseVersion {
		providerLog(logger.LevelDebug, "bolt database updated, version: %v", dbVersion.Version)
		return nil
	}
	if dbVersion.Version == 1 {
		err = updateDatabaseFrom1To2(dbHandle)
		if err != nil {
			return err
		}
		return updateDatabaseFrom2To3(dbHandle)
	} else if dbVersion.Version == 2 {
		return updateDatabaseFrom2To3(dbHandle)
	}

	return nil
}

func updateDatabaseFrom1To2(dbHandle *bolt.DB) error {
	providerLog(logger.LevelInfo, "updating bolt database version: 1 -> 2")
	usernames, err := getBoltAvailableUsernames(dbHandle)
	if err != nil {
		return err
	}
	for _, u := range usernames {
		user, err := provider.userExists(u)
		if err != nil {
			return err
		}
		user.Status = 1
		err = provider.updateUser(user)
		if err != nil {
			return err
		}
		providerLog(logger.LevelInfo, "user %#v updated, \"status\" setted to 1", user.Username)
	}
	return updateBoltDatabaseVersion(dbHandle, 2)
}

func updateDatabaseFrom2To3(dbHandle *bolt.DB) error {
	providerLog(logger.LevelInfo, "updating bolt database version: 2 -> 3")
	users := []User{}
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var compatUser compatUserV2
			err = json.Unmarshal(v, &compatUser)
			if err == nil {
				user := User{}
				user.ID = compatUser.ID
				user.Username = compatUser.Username
				user.Password = compatUser.Password
				user.PublicKeys = compatUser.PublicKeys
				user.HomeDir = compatUser.HomeDir
				user.UID = compatUser.UID
				user.GID = compatUser.GID
				user.MaxSessions = compatUser.MaxSessions
				user.QuotaSize = compatUser.QuotaSize
				user.QuotaFiles = compatUser.QuotaFiles
				user.Permissions = make(map[string][]string)
				user.Permissions["/"] = compatUser.Permissions
				user.UsedQuotaSize = compatUser.UsedQuotaSize
				user.UsedQuotaFiles = compatUser.UsedQuotaFiles
				user.LastQuotaUpdate = compatUser.LastQuotaUpdate
				user.UploadBandwidth = compatUser.UploadBandwidth
				user.DownloadBandwidth = compatUser.DownloadBandwidth
				user.ExpirationDate = compatUser.ExpirationDate
				user.LastLogin = compatUser.LastLogin
				user.Status = compatUser.Status
				users = append(users, user)
			}
		}
		return err
	})
	if err != nil {
		return err
	}

	for _, user := range users {
		err = provider.updateUser(user)
		if err != nil {
			return err
		}
		providerLog(logger.LevelInfo, "user %#v updated, \"permissions\" setted to %+v", user.Username, user.Permissions)
	}

	return updateBoltDatabaseVersion(dbHandle, 3)
}

func getBoltAvailableUsernames(dbHandle *bolt.DB) ([]string, error) {
	usernames := []string{}
	err := dbHandle.View(func(tx *bolt.Tx) error {
		_, idxBucket, err := getBuckets(tx)
		if err != nil {
			return err
		}
		cursor := idxBucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			usernames = append(usernames, string(v))
		}
		return nil
	})

	return usernames, err
}

func getBoltDatabaseVersion(dbHandle *bolt.DB) (boltDatabaseVersion, error) {
	var dbVersion boltDatabaseVersion
	err := dbHandle.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dbVersionBucket)
		if bucket == nil {
			return fmt.Errorf("unable to find database version bucket")
		}
		v := bucket.Get(dbVersionKey)
		if v == nil {
			dbVersion = boltDatabaseVersion{
				Version: 1,
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
		newDbVersion := boltDatabaseVersion{
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
