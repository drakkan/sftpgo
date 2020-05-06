module github.com/drakkan/sftpgo

go 1.13

require (
	cloud.google.com/go v0.56.0 // indirect
	cloud.google.com/go/storage v1.6.0
	github.com/alexedwards/argon2id v0.0.0-20190612080829-01a59b2b8802
	github.com/aws/aws-sdk-go v1.30.3
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-chi/chi v4.1.1+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/lib/pq v1.3.0
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/miekg/dns v1.1.29 // indirect
	github.com/mitchellh/mapstructure v1.2.2 // indirect
	github.com/nathanaelle/password/v2 v2.0.1
	github.com/pelletier/go-toml v1.7.0 // indirect
	github.com/pires/go-proxyproto v0.0.0-20200402183925-afa328f5c7c0
	github.com/pkg/sftp v1.11.1-0.20200310224833-18dc4db7a456
	github.com/prometheus/client_golang v1.5.1
	github.com/prometheus/procfs v0.0.11 // indirect
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.18.0
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.6.3
	github.com/stretchr/testify v1.5.1
	go.etcd.io/bbolt v1.3.4
	golang.org/x/crypto v0.0.0-20200323165209-0ec3e9974c59
	golang.org/x/sys v0.0.0-20200331124033-c3d80250170d
	golang.org/x/tools v0.0.0-20200403170748-4480df5f1627 // indirect
	google.golang.org/api v0.20.0
	google.golang.org/genproto v0.0.0-20200403120447-c50568487044 // indirect
	gopkg.in/ini.v1 v1.55.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/pkg/sftp => github.com/drakkan/sftp v0.0.0-20200319122022-2fc68482d27f
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20200409210311-95730af1ff98
)
