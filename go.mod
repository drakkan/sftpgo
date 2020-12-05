module github.com/drakkan/sftpgo

go 1.14

require (
	cloud.google.com/go v0.72.0 // indirect
	cloud.google.com/go/storage v1.12.0
	github.com/Azure/azure-storage-blob-go v0.11.0
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/alexedwards/argon2id v0.0.0-20200802152012-2464efd3196b
	github.com/aws/aws-sdk-go v1.35.30
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/eikenb/pipeat v0.0.0-20200430215831-470df5986b6d
	github.com/fclairamb/ftpserverlib v0.9.1-0.20201105003045-1edd6bf7ae53
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/lib/pq v1.8.0
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mattn/go-sqlite3 v1.14.5
	github.com/miekg/dns v1.1.35 // indirect
	github.com/minio/sha256-simd v0.1.1
	github.com/minio/sio v0.2.1
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/otiai10/copy v1.2.0
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/pires/go-proxyproto v0.3.2
	github.com/pkg/sftp v1.12.1-0.20201118115123-7230c61342c8
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/common v0.15.0 // indirect
	github.com/rs/cors v1.7.1-0.20200626170627-8b4a00bd362b
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.20.0
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/afero v1.4.1
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.1.1
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/studio-b12/gowebdav v0.0.0-20200929080739-bdacfab94796
	go.etcd.io/bbolt v1.3.5
	go.uber.org/automaxprocs v1.3.0
	gocloud.dev v0.20.0
	gocloud.dev/secrets/hashivault v0.20.0
	golang.org/x/crypto v0.0.0-20201117144127-c1f2f97bffc9
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/oauth2 v0.0.0-20201109201403-9fd604954f58 // indirect
	golang.org/x/sys v0.0.0-20201117222635-ba5294a509c7
	golang.org/x/tools v0.0.0-20201118030313-598b068a9102 // indirect
	google.golang.org/api v0.35.0
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20201117123952-62d171c70ae1 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20201114075148-9b9adce499a9
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20201118124913-1ba5185435c1
	golang.org/x/net => github.com/drakkan/net v0.0.0-20201114074615-8a2467084c77
)
