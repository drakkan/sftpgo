package dataprovider

import (
	"database/sql"
	"fmt"
	"runtime"
	"time"

	"github.com/drakkan/sftpgo/logger"
)

// MySQLProvider auth provider for MySQL/MariaDB database
type MySQLProvider struct {
}

func initializeMySQLProvider() error {
	var err error
	var connectionString string
	if len(config.ConnectionString) == 0 {
		connectionString = fmt.Sprintf("%v:%v@tcp([%v]:%v)/%v?charset=utf8&interpolateParams=true&timeout=10s&tls=%v",
			config.Username, config.Password, config.Host, config.Port, config.Name, getSSLMode())
	} else {
		connectionString = config.ConnectionString
	}
	dbHandle, err = sql.Open("mysql", connectionString)
	if err == nil {
		numCPU := runtime.NumCPU()
		logger.Debug(logSender, "mysql database handle created, connection string: '%v', pool size: %v", connectionString, numCPU)
		dbHandle.SetMaxIdleConns(numCPU)
		dbHandle.SetMaxOpenConns(numCPU)
		dbHandle.SetConnMaxLifetime(1800 * time.Second)
	} else {
		logger.Warn(logSender, "error creating mysql database handler, connection string: '%v', error: %v", connectionString, err)
	}
	return err
}

func (p MySQLProvider) validateUserAndPass(username string, password string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password)
}

func (p MySQLProvider) validateUserAndPubKey(username string, publicKey string) (User, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey)
}

func (p MySQLProvider) getUserByID(ID int64) (User, error) {
	return sqlCommonGetUserByID(ID)
}

func (p MySQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	tx, err := dbHandle.Begin()
	if err != nil {
		logger.Warn(logSender, "error starting transaction to update quota for user %v: %v", username, err)
		return err
	}
	err = sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p)
	if err == nil {
		err = tx.Commit()
	} else {
		err = tx.Rollback()
	}
	if err != nil {
		logger.Warn(logSender, "error closing transaction to update quota for user %v: %v", username, err)
	}
	return err
}

func (p MySQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username)
}

func (p MySQLProvider) userExists(username string) (User, error) {
	return sqlCommonCheckUserExists(username)
}

func (p MySQLProvider) addUser(user User) error {
	return sqlCommonAddUser(user)
}

func (p MySQLProvider) updateUser(user User) error {
	return sqlCommonUpdateUser(user)
}

func (p MySQLProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user)
}

func (p MySQLProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, username)
}
