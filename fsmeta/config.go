package fsmeta

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	bindata "github.com/golang-migrate/migrate/v4/source/go_bindata"

	// import migrate postgres driver to register the postgres driver
	_ "github.com/golang-migrate/migrate/v4/database/postgres"

	sqlbindata "github.com/drakkan/sftpgo/fsmeta/sql"
	"github.com/drakkan/sftpgo/logger"
)

const (
	S3MetaKey = `Fs-Mtime`
)

var (
	logSender = "fsMeta"
)

// Config provider configuration
type Config struct {
	// Enables FS Meta Data features.
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// Driver name, must be one of the SupportedProviders
	Driver string `json:"driver" mapstructure:"driver"`
	// Database name.
	Database string `json:"database" mapstructure:"database"`
	// Database schema.
	Schema string `json:"schema" mapstructure:"schema"`
	// Database host
	Host string `json:"host" mapstructure:"host"`
	// Database port
	Port int `json:"port" mapstructure:"port"`
	// Database username
	Username string `json:"username" mapstructure:"username"`
	// Database password
	Password string `json:"password" mapstructure:"password"`
	// Used for drivers mysql and postgresql.
	// 0 disable SSL/TLS connections.
	// 1 require ssl.
	// 2 set ssl mode to verify-ca for driver postgresql and skip-verify for driver mysql.
	// 3 set ssl mode to verify-full for driver postgresql and preferred for driver mysql.
	SSLMode int `json:"sslmode" mapstructure:"sslmode"`
	// Sets the maximum number of open connections for mysql and postgresql driver.
	// Default 0 (unlimited)
	PoolSize int `json:"pool_size" mapstructure:"pool_size"`
}

func (config *Config) GetDSN(redactedPwd bool, additionalFields url.Values) string {
	UserInfo := url.UserPassword(config.Username, config.Password)
	if redactedPwd {
		UserInfo = url.User(config.Username)
	}
	u := url.URL{
		Scheme: "postgres",
		User:   UserInfo,
		Host:   fmt.Sprintf(`%s:%d`, config.Host, config.Port),
		Path:   config.Database,
	}
	q := u.Query()
	q.Set("sslmode", getSSLMode(config.SSLMode))
	q.Set("connect_timeout", "10")
	if config.Schema != `` {
		q.Set("search_path", config.Schema)
	}
	for k, v := range additionalFields {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func metaLog(level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, logSender, "", format, v...)
}

func (config *Config) initializePGSQLProvider() error {
	var err error
	logSender = fmt.Sprintf("fsmeta_%v", config.Driver)
	dbHandle, err := sql.Open("postgres", config.GetDSN(false, nil))
	if err == nil {
		metaLog(logger.LevelDebug, "postgres database handle created, connection string: %#v, pool size: %v",
			config.GetDSN(true, nil), config.PoolSize)
		dbHandle.SetMaxOpenConns(config.PoolSize)
		if config.PoolSize > 0 {
			dbHandle.SetMaxIdleConns(config.PoolSize)
		} else {
			dbHandle.SetMaxIdleConns(2)
		}
		dbHandle.SetConnMaxLifetime(240 * time.Second)
		DefaultFactory = NewPostgresS3Factory(dbHandle)
	} else {
		metaLog(logger.LevelWarn, "error creating postgres database handler, connection string: %#v, error: %v",
			config.GetDSN(true, nil), err)
	}
	return err
}

func getSSLMode(SSLMode int) string {
	if SSLMode == 0 {
		return "disable"
	} else if SSLMode == 1 {
		return "require"
	} else if SSLMode == 2 {
		return "verify-ca"
	} else if SSLMode == 3 {
		return "verify-full"
	}
	return ``
}

func Initialize(cnf Config) error {
	if cnf.Enabled {
		if err := cnf.migrateDatabase(); err != nil && err != migrate.ErrNoChange {
			logger.ErrorToConsole("error running fsmeta migrations: %s", err)
			return err
		}

		if err := cnf.initializePGSQLProvider(); err != nil {
			return err
		}
	}
	Enabled = cnf.Enabled
	return nil
}

type migrateLogger struct{}

func (m migrateLogger) Printf(format string, v ...interface{}) {
	logger.InfoToConsole(`FSMeta Migrations: `+strings.TrimSpace(format), v...)
}

func (m migrateLogger) Verbose() bool {
	return true
}

func (config *Config) migrateDatabase() error {
	s := bindata.Resource(sqlbindata.AssetNames(),
		func(name string) ([]byte, error) {
			return sqlbindata.Asset(name)
		})

	d, err := bindata.WithInstance(s)
	if err != nil {
		return err
	}
	values := url.Values{}
	values.Set(`x-migrations-table`, `fsmeta_schema_migrations`)
	dsn := config.GetDSN(false, values)
	m, err := migrate.NewWithSourceInstance(`go-bindata`, d, dsn)
	if err != nil {
		return err
	}
	m.Log = &migrateLogger{}
	return m.Up()
}
