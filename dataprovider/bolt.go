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

var (
	usersBucket      = []byte("users")
	usersIDIdxBucket = []byte("users_id_idx")
)

// BoltProvider auth provider for bolt key/value store
type BoltProvider struct {
	dbHandle *bolt.DB
}

func initializeBoltProvider(basePath string) error {
	var err error
	dbPath := config.Name
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(basePath, dbPath)
	}
	dbHandle, err := bolt.Open(dbPath, 0600, &bolt.Options{
		NoGrowSync:   false,
		FreelistType: bolt.FreelistArrayType,
		Timeout:      5 * time.Second})
	if err == nil {
		logger.Debug(logSender, "bolt key store handle created")
		err = dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(usersBucket)
			return e
		})
		if err != nil {
			logger.Warn(logSender, "error creating users bucket: %v", err)
			return err
		}
		err = dbHandle.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists(usersIDIdxBucket)
			return e
		})
		if err != nil {
			logger.Warn(logSender, "error creating username idx bucket: %v", err)
			return err
		}
		provider = BoltProvider{dbHandle: dbHandle}
	} else {
		logger.Warn(logSender, "error creating bolt key/value store handler: %v", err)
	}
	return err
}

func (p BoltProvider) validateUserAndPass(username string, password string) (User, error) {
	var user User
	if len(password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		logger.Warn(logSender, "error authenticating user: %v, error: %v", username, err)
		return user, err
	}
	return checkUserAndPass(user, password)
}

func (p BoltProvider) validateUserAndPubKey(username string, pubKey string) (User, error) {
	var user User
	if len(pubKey) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		logger.Warn(logSender, "error authenticating user: %v, error: %v", username, err)
		return user, err
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
			return &RecordNotFoundError{err: fmt.Sprintf("username %v and ID: %v does not exist", string(username), ID)}
		}
		return json.Unmarshal(u, &user)
	})

	return user, err
}

func (p BoltProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return p.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, _, err := getBuckets(tx)
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return &RecordNotFoundError{err: fmt.Sprintf("username %v does not exist, unable to update quota", username)}
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
		logger.Warn(logSender, "unable to get quota for user '%v' error: %v", username, err)
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
			return &RecordNotFoundError{err: fmt.Sprintf("username %v does not exist", user.Username)}
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
			return fmt.Errorf("username '%v' already exists", user.Username)
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
			return &RecordNotFoundError{err: fmt.Sprintf("username '%v' does not exist", user.Username)}
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

func (p BoltProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	users := []User{}
	var err error
	if len(username) > 0 {
		if offset == 0 {
			user, err := p.userExists(username)
			if err == nil {
				users = append(users, getUserNoCredentials(&user))
			}
		}
		return users, err
	}
	err = p.dbHandle.View(func(tx *bolt.Tx) error {
		if limit <= 0 {
			return nil
		}
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
					users = append(users, getUserNoCredentials(&user))
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
					users = append(users, getUserNoCredentials(&user))
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

func getUserNoCredentials(user *User) User {
	user.Password = ""
	user.PublicKeys = []string{}
	return *user
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
		err = fmt.Errorf("Unable to find required buckets, bolt database structure not correcly defined")
	}
	return bucket, idxBucket, err
}
