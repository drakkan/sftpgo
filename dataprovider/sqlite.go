package dataprovider

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/drakkan/sftpgo/logger"
)

// SQLiteProvider auth provider for SQLite database
type SQLiteProvider struct {
}

func initializeSQLiteProvider(basePath string) error {
	var err error
	var connectionString string
	if len(config.ConnectionString) == 0 {
		dbPath := filepath.Join(basePath, config.Name)
		fi, err := os.Stat(dbPath)
		if err != nil {
			logger.Warn(logSender, "sqlite database file does not exists, please be sure to create and initialize"+
				" a database before starting sftpgo")
			return err
		}
		if fi.Size() == 0 {
			return errors.New("sqlite database file is invalid, please be sure to create and initialize" +
				" a database before starting sftpgo")
		}
		connectionString = fmt.Sprintf("file:%v?cache=shared", dbPath)
	} else {
		connectionString = config.ConnectionString
	}
	dbHandle, err = sql.Open("sqlite3", connectionString)
	if err == nil {
		logger.Debug(logSender, "sqlite database handle created, connection string: \"%v\"", connectionString)
		dbHandle.SetMaxOpenConns(1)
	} else {
		logger.Warn(logSender, "error creating sqlite database handler, connection string: \"%v\", error: %v", connectionString, err)
	}
	return err
}

func (p SQLiteProvider) validateUserAndPass(username string, password string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password)
}

func (p SQLiteProvider) validateUserAndPubKey(username string, publicKey string) (User, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey)
}

func (p SQLiteProvider) getUserByID(ID int64) (User, error) {
	return sqlCommonGetUserByID(ID)
}

func (p SQLiteProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	// we keep only 1 open connection (SetMaxOpenConns(1)) so a transaction is not needed and it could block
	// the database access since it will try to open a new connection
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p)
}

func (p SQLiteProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username)
}

func (p SQLiteProvider) userExists(username string) (User, error) {
	return sqlCommonCheckUserExists(username)
}

func (p SQLiteProvider) addUser(user User) error {
	return sqlCommonAddUser(user)
}

func (p SQLiteProvider) updateUser(user User) error {
	return sqlCommonUpdateUser(user)
}

func (p SQLiteProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user)
}

func (p SQLiteProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, username)
}
