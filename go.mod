module github.com/drakkan/sftpgo

go 1.15

require (
	cloud.google.com/go v0.80.0 // indirect
	cloud.google.com/go/storage v1.14.0
	github.com/Azure/azure-storage-blob-go v0.13.0
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/StackExchange/wmi v0.0.0-20210224194228-fe8f1750fd46 // indirect
	github.com/alexedwards/argon2id v0.0.0-20210326052512-e2135f7c9c77
	github.com/aws/aws-sdk-go v1.38.7
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/fclairamb/ftpserverlib v0.13.2
	github.com/frankban/quicktest v1.11.3 // indirect
	github.com/go-chi/chi/v5 v5.0.2
	github.com/go-chi/jwtauth/v5 v5.0.0
	github.com/go-chi/render v1.0.1
	github.com/go-ole/go-ole v1.2.5 // indirect
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang/mock v1.5.0
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.2.0 // indirect
	github.com/google/wire v0.5.0 // indirect
	github.com/grandcat/zeroconf v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.8
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/klauspost/cpuid/v2 v2.0.6 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/jwx v1.1.6
	github.com/lib/pq v1.10.0
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.6
	github.com/miekg/dns v1.1.41 // indirect
	github.com/minio/sha256-simd v1.0.0
	github.com/minio/sio v0.2.1
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/otiai10/copy v1.5.0
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/pires/go-proxyproto v0.5.0
	github.com/pkg/sftp v1.13.0
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/common v0.20.0 // indirect
	github.com/rs/cors v1.7.1-0.20200626170627-8b4a00bd362b
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.21.0
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shirou/gopsutil/v3 v3.21.2
	github.com/spf13/afero v1.6.0
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/studio-b12/gowebdav v0.0.0-20210203212356-8244b5a5f51a
	github.com/yl2chen/cidranger v1.0.2
	go.etcd.io/bbolt v1.3.5
	go.uber.org/automaxprocs v1.4.0
	gocloud.dev v0.22.0
	gocloud.dev/secrets/hashivault v0.22.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20210326220855-61e056675ecf
	golang.org/x/oauth2 v0.0.0-20210323180902-22b0adad7558 // indirect
	golang.org/x/sys v0.0.0-20210326220804-49726bf1d181
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	google.golang.org/api v0.43.0
	google.golang.org/genproto v0.0.0-20210325224202-eed09b1b5210 // indirect
	google.golang.org/grpc v1.36.1 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20201114075148-9b9adce499a9
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20210328115714-16565bf4b31d
	golang.org/x/net => github.com/drakkan/net v0.0.0-20210328115440-0aedf3ac0c83
)
