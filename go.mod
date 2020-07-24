module github.com/drakkan/sftpgo

go 1.13

require (
	cloud.google.com/go v0.60.0 // indirect
	cloud.google.com/go/storage v1.10.0
	github.com/alexedwards/argon2id v0.0.0-20200522061839-9369edc04b05
	github.com/aws/aws-sdk-go v1.33.1
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/lib/pq v1.7.0
	github.com/mattn/go-sqlite3 v1.14.0
	github.com/miekg/dns v1.1.29 // indirect
	github.com/mitchellh/mapstructure v1.3.2 // indirect
	github.com/nathanaelle/password/v2 v2.0.1
	github.com/otiai10/copy v1.2.0
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/pires/go-proxyproto v0.1.3
	github.com/pkg/sftp v1.11.1-0.20200716191756-97b9df616e69
	github.com/prometheus/client_golang v1.7.1
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.19.0
	github.com/spf13/afero v1.3.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	go.etcd.io/bbolt v1.3.5
	go.opencensus.io v0.22.4 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20200625001655-4c5254603344 // indirect
	golang.org/x/sys v0.0.0-20200625212154-ddb9806d33ae
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/tools v0.0.0-20200702044944-0cc1aa72b347 // indirect
	google.golang.org/api v0.28.0
	google.golang.org/genproto v0.0.0-20200702021140-07506425bd67 // indirect
	google.golang.org/grpc v1.30.0 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20200705203859-05ad140ecdbd
