module github.com/drakkan/sftpgo

go 1.13

require (
	cloud.google.com/go v0.55.0 // indirect
	cloud.google.com/go/storage v1.6.0
	github.com/alexedwards/argon2id v0.0.0-20190612080829-01a59b2b8802
	github.com/aws/aws-sdk-go v1.29.29
	github.com/eikenb/pipeat v0.0.0-20190316224601-fb1f3a9aa29f
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-chi/chi v4.0.3+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/jmespath/go-jmespath v0.3.0 // indirect
	github.com/lib/pq v1.3.0
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/miekg/dns v1.1.29 // indirect
	github.com/mitchellh/mapstructure v1.2.2 // indirect
	github.com/nathanaelle/password/v2 v2.0.1
	github.com/pelletier/go-toml v1.6.0 // indirect
	github.com/pires/go-proxyproto v0.0.0-20200315140437-f0371d3cede2
	github.com/pkg/sftp v1.11.1-0.20200310224833-18dc4db7a456
	github.com/prometheus/client_golang v1.5.1
	github.com/prometheus/procfs v0.0.11 // indirect
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.18.0
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v0.0.6
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.6.2
	go.etcd.io/bbolt v1.3.4
	golang.org/x/crypto v0.0.0-20200320181102-891825fb96df
	golang.org/x/net v0.0.0-20200320220750-118fecf932d8 // indirect
	golang.org/x/sys v0.0.0-20200320181252-af34d8274f85
	golang.org/x/tools v0.0.0-20200321014904-268ba720d32c // indirect
	google.golang.org/api v0.20.0
	google.golang.org/genproto v0.0.0-20200319113533-08878b785e9c // indirect
	gopkg.in/ini.v1 v1.55.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.2.8 // indirect
)

replace (
	github.com/eikenb/pipeat => github.com/drakkan/pipeat v0.0.0-20200315002837-010186aaa07d
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20200321090003-6a46fd93e864
)
