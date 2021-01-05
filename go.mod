module github.com/drakkan/sftpgo

go 1.15

require (
	cloud.google.com/go v0.74.0 // indirect
	cloud.google.com/go/storage v1.12.0
	github.com/Azure/azure-storage-blob-go v0.12.0
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/alexedwards/argon2id v0.0.0-20201228115903-cf543ebc1f7b
	github.com/aws/aws-sdk-go v1.36.20
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/fclairamb/ftpserverlib v0.12.0
	github.com/frankban/quicktest v1.11.2 // indirect
	github.com/go-chi/chi v1.5.1
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.1.4 // indirect
	github.com/grandcat/zeroconf v1.0.0
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/lib/pq v1.9.0
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mattn/go-sqlite3 v1.14.6
	github.com/miekg/dns v1.1.35 // indirect
	github.com/minio/sha256-simd v0.1.1
	github.com/minio/sio v0.2.1
	github.com/otiai10/copy v1.4.2
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/pires/go-proxyproto v0.3.3
	github.com/pkg/sftp v1.12.1-0.20201128220914-b5b6f3393fe9
	github.com/prometheus/client_golang v1.9.0
	github.com/rs/cors v1.7.1-0.20200626170627-8b4a00bd362b
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.20.0
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shirou/gopsutil/v3 v3.20.12
	github.com/spf13/afero v1.5.1
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.1.1
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/studio-b12/gowebdav v0.0.0-20200929080739-bdacfab94796
	github.com/yl2chen/cidranger v1.0.2
	go.etcd.io/bbolt v1.3.5
	go.uber.org/automaxprocs v1.3.0
	gocloud.dev v0.21.0
	gocloud.dev/secrets/hashivault v0.21.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/sys v0.0.0-20210104204734-6f8348627aad
	golang.org/x/time v0.0.0-20201208040808-7e3f01d25324 // indirect
	golang.org/x/tools v0.0.0-20210104081019-d8d6ddbec6ee // indirect
	google.golang.org/api v0.36.0
	google.golang.org/genproto v0.0.0-20201214200347-8c77b98c765d // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20201114075148-9b9adce499a9
	github.com/pkg/sftp => github.com/drakkan/sftp v0.0.0-20201211115031-0b6bbc64f191
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20201217113543-470e61ed2598
	golang.org/x/net => github.com/drakkan/net v0.0.0-20201217113732-2a124bb1694b
)
