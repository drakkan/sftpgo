module github.com/drakkan/sftpgo

go 1.13

require (
	cloud.google.com/go v0.65.0 // indirect
	cloud.google.com/go/storage v1.11.0
	github.com/alexedwards/argon2id v0.0.0-20200802152012-2464efd3196b
	github.com/aws/aws-sdk-go v1.34.13
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/fclairamb/ftpserverlib v0.8.1-0.20200828235935-8e22c5f260e1
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/jlaffaye/ftp v0.0.0-20200720194710-13949d38913e
	github.com/lib/pq v1.8.0
	github.com/magiconair/properties v1.8.2 // indirect
	github.com/mattn/go-sqlite3 v1.14.2
	github.com/miekg/dns v1.1.31 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/nathanaelle/password/v2 v2.0.1
	github.com/otiai10/copy v1.2.0
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/pires/go-proxyproto v0.1.3
	github.com/pkg/sftp v1.12.0
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.13.0 // indirect
	github.com/rs/cors v1.7.1-0.20200626170627-8b4a00bd362b
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.19.0
	github.com/spf13/afero v1.3.4
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/studio-b12/gowebdav v0.0.0-20200303150724-9380631c29a1
	go.etcd.io/bbolt v1.3.5
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/net v0.0.0-20200822124328-c89045814202
	golang.org/x/sys v0.0.0-20200828194041-157a740278f4
	golang.org/x/tools v0.0.0-20200828161849-5deb26317202 // indirect
	google.golang.org/api v0.30.0
	google.golang.org/genproto v0.0.0-20200829155447-2bf3329a0021 // indirect
	google.golang.org/grpc v1.31.1 // indirect
	gopkg.in/ini.v1 v1.60.2 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20200730125632-b21eac28818c
	github.com/pkg/sftp => github.com/drakkan/sftp v0.0.0-20200830084022-ea67d57ce589
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20200824205004-9f5ce89c1796
	golang.org/x/net => github.com/drakkan/net v0.0.0-20200824204746-8b31adf087bf
)
