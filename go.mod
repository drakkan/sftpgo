module github.com/drakkan/sftpgo

go 1.14

require (
	cloud.google.com/go v0.67.0 // indirect
	cloud.google.com/go/storage v1.12.0
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/alexedwards/argon2id v0.0.0-20200802152012-2464efd3196b
	github.com/aws/aws-sdk-go v1.35.2
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/fclairamb/ftpserverlib v0.8.1-0.20200917000118-04bdfa67808e
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/jlaffaye/ftp v0.0.0-20200720194710-13949d38913e
	github.com/lib/pq v1.8.0
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mattn/go-sqlite3 v1.14.4
	github.com/miekg/dns v1.1.31 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/otiai10/copy v1.2.0
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/pires/go-proxyproto v0.1.3
	github.com/pkg/sftp v1.12.1-0.20201002132022-fcaa492add82
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.14.0 // indirect
	github.com/prometheus/procfs v0.2.0 // indirect
	github.com/rs/cors v1.7.1-0.20200626170627-8b4a00bd362b
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.20.0
	github.com/spf13/afero v1.4.0
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/studio-b12/gowebdav v0.0.0-20200303150724-9380631c29a1
	go.etcd.io/bbolt v1.3.5
	go.uber.org/automaxprocs v1.3.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/net v0.0.0-20201002202402-0a1ea396d57c
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/tools v0.0.0-20201002184944-ecd9fd270d5d // indirect
	google.golang.org/api v0.32.0
	google.golang.org/genproto v0.0.0-20201002142447-3860012362da // indirect
	gopkg.in/ini.v1 v1.61.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20200730125632-b21eac28818c
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20201004100511-699278c1b1a6
	golang.org/x/net => github.com/drakkan/net v0.0.0-20201004094948-09a397c99801
)
