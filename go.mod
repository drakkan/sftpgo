module github.com/drakkan/sftpgo

go 1.16

require (
	cloud.google.com/go/storage v1.16.0
	github.com/Azure/azure-storage-blob-go v0.14.0
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/StackExchange/wmi v1.2.0 // indirect
	github.com/alexedwards/argon2id v0.0.0-20210511081203-7d35d68092b8
	github.com/aws/aws-sdk-go v1.40.1
	github.com/cockroachdb/cockroach-go/v2 v2.1.1
	github.com/eikenb/pipeat v0.0.0-20210603033007-44fc3ffce52b
	github.com/fclairamb/ftpserverlib v0.14.0
	github.com/frankban/quicktest v1.13.0 // indirect
	github.com/go-chi/chi/v5 v5.0.3
	github.com/go-chi/jwtauth/v5 v5.0.1
	github.com/go-chi/render v1.0.1
	github.com/go-ole/go-ole v1.2.5 // indirect
	github.com/go-sql-driver/mysql v1.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/klauspost/compress v1.13.1
	github.com/klauspost/cpuid/v2 v2.0.8 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/jwx v1.2.4
	github.com/lib/pq v1.10.2
	github.com/mattn/go-sqlite3 v1.14.8
	github.com/miekg/dns v1.1.43 // indirect
	github.com/minio/sio v0.3.0
	github.com/otiai10/copy v1.6.0
	github.com/pires/go-proxyproto v0.6.0
	github.com/pkg/sftp v1.13.2
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.29.0 // indirect
	github.com/rs/cors v1.8.0
	github.com/rs/xid v1.3.0
	github.com/rs/zerolog v1.23.0
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shirou/gopsutil/v3 v3.21.6
	github.com/spf13/afero v1.6.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/studio-b12/gowebdav v0.0.0-20210630100626-7ff61aa87be8
	github.com/yl2chen/cidranger v1.0.2
	go.etcd.io/bbolt v1.3.6
	go.uber.org/automaxprocs v1.4.0
	gocloud.dev v0.23.0
	gocloud.dev/secrets/hashivault v0.23.0
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c
	golang.org/x/time v0.0.0-20210611083556-38a9dc6acbc6
	google.golang.org/api v0.50.0
	google.golang.org/genproto v0.0.0-20210716133855-ce7ef5c701ea // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20201114075148-9b9adce499a9
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20210515063737-edf1d3b63536
	golang.org/x/net => github.com/drakkan/net v0.0.0-20210615043241-a7f9e02422df
)
