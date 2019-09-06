package dataprovider

import (
	"database/sql"
	"fmt"
	"runtime"
)

// PGSQLProvider auth provider for PostgreSQL database
type PGSQLProvider struct {
	dbHandle *sql.DB
}

func initializePGSQLProvider() error {
	var err error
	var connectionString string
	provider = PGSQLProvider{}
	if len(config.ConnectionString) == 0 {
		connectionString = fmt.Sprintf("host='%v' port=%v dbname='%v' user='%v' password='%v' sslmode=%v connect_timeout=10",
			config.Host, config.Port, config.Name, config.Username, config.Password, getSSLMode())
	} else {
		connectionString = config.ConnectionString
	}
	dbHandle, err := sql.Open("postgres", connectionString)
	if err == nil {
		numCPU := runtime.NumCPU()
		provider.log(Debug, "postgres database handle created, connection string: %#v, pool size: %v", connectionString, numCPU)
		dbHandle.SetMaxIdleConns(numCPU)
		dbHandle.SetMaxOpenConns(numCPU)
		provider = PGSQLProvider{dbHandle: dbHandle}
	} else {
		provider.log(Warn, "error creating postgres database handler, connection string: %#v, error: %v", connectionString, err)
	}
	return err
}

func (p PGSQLProvider) validateUserAndPass(username string, password string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, p.dbHandle)
}

func (p PGSQLProvider) validateUserAndPubKey(username string, publicKey string) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, p.dbHandle)
}

func (p PGSQLProvider) getUserByID(ID int64) (User, error) {
	return sqlCommonGetUserByID(ID, p.dbHandle)
}

func (p PGSQLProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	tx, err := p.dbHandle.Begin()
	if err != nil {
		p.log(Warn, "error starting transaction to update quota for user %v: %v", username, err)
		return err
	}
	err = sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
	if err == nil {
		err = tx.Commit()
	} else {
		err = tx.Rollback()
	}
	if err != nil {
		p.log(Warn, "error closing transaction to update quota for user %v: %v", username, err)
	}
	return err
}

func (p PGSQLProvider) getUsedQuota(username string) (int, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p PGSQLProvider) userExists(username string) (User, error) {
	return sqlCommonCheckUserExists(username, p.dbHandle)
}

func (p PGSQLProvider) addUser(user User) error {
	return sqlCommonAddUser(user, p.dbHandle)
}

func (p PGSQLProvider) updateUser(user User) error {
	return sqlCommonUpdateUser(user, p.dbHandle)
}

func (p PGSQLProvider) deleteUser(user User) error {
	return sqlCommonDeleteUser(user, p.dbHandle)
}

func (p PGSQLProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, username, p.dbHandle)
}

func (p PGSQLProvider) log(level string, format string, v ...interface{}) {
	sqlCommonLog(level, p.providerName(), format, v...)
}

func (p PGSQLProvider) providerName() string {
	return PGSQLDataProviderName
}
