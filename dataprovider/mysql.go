package dataprovider

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/drakkan/sftpgo/logger"
)

// MySQLProvider auth provider for MySQL/MariaDB database
type MySQLProvider struct {
	dbHandle *sql.DB
}

func initializeMySQLProvider() error {
	var err error
	logSender = MySQLDataProviderName
	dbHandle, err := sql.Open("mysql", getMySQLConnectionString(false))
	if err == nil {
		providerLog(logger.LevelDebug, "mysql database handle created, connection string: %#v, pool size: %v",
			getMySQLConnectionString(true), config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		dbHandle.SetConnMaxLifetime(1800 * time.Second)
		provider = MySQLProvider{dbHandle: dbHandle}
	} else {
		providerLog(logger.LevelWarn, "error creating mysql database handler, connection string: %#v, error: %v",
			getMySQLConnectionString(true), err)
	}
	return err
}
func getMySQLConnectionString(redactedPwd bool) string {
	var connectionString string
	if len(config.ConnectionString) == 0 {
		password := config.Password
		if redactedPwd {
			password = "[redacted]"
		}
		connectionString = fmt.Sprintf("%v:%v@tcp([%v]:%v)/%v?charset=utf8&interpolateParams=true&timeout=10s&tls=%v&writeTimeout=10s&readTimeout=10s",
			config.Username, password, config.Host, config.Port, config.Name, getSSLMode())
	} else {
		connectionString = config.ConnectionString
	}
	return connectionString
}

func (p MySQLProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p MySQLProvider) validateUserAndPass(username string, password string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, p.dbHandle)
}

func (p MySQLProvider) validateUserAndPubKey(username string, publicKey string) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p MySQLProvider) getUserByID(ID int64) (User, error) {
	return sqlCommonGetUserByID(ID, p.dbHandle)
}

func (p MySQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p MySQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p MySQLProvider) userExists(username string) (User, error) {
	return sqlCommonCheckUserExists(username, p.dbHandle)
}

func (p MySQLProvider) addUser(user User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p MySQLProvider) updateUser(user User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p MySQLProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p MySQLProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, username, p.dbHandle)
}

func (p MySQLProvider) close() error {
	return p.dbHandle.Close()
}
