module github.com/drakkan/sftpgo

go 1.13

require (
	cloud.google.com/go v0.58.0 // indirect
	cloud.google.com/go/storage v1.10.0
	github.com/alexedwards/argon2id v0.0.0-20200522061839-9369edc04b05
	github.com/aws/aws-sdk-go v1.32.6
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
	github.com/pkg/sftp v1.11.1-0.20200310224833-18dc4db7a456
	github.com/prometheus/client_golang v1.7.0
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.19.0
	github.com/spf13/afero v1.3.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	go.etcd.io/bbolt v1.3.5
	go.opencensus.io v0.22.4 // indirect
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9 // indirect
	golang.org/x/sys v0.0.0-20200620081246-981b61492c35
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/tools v0.0.0-20200619210111-0f592d2728bb // indirect
	google.golang.org/api v0.28.0
	google.golang.org/genproto v0.0.0-20200620020550-bd6e04640131 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/pkg/sftp => github.com/drakkan/sftp v0.0.0-20200319122022-2fc68482d27f
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20200620134748-26f306d56f79
)
