module github.com/drakkan/sftpgo/v2

go 1.16

require (
	cloud.google.com/go/storage v1.16.0
	github.com/Azure/azure-storage-blob-go v0.14.0
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/alexedwards/argon2id v0.0.0-20210511081203-7d35d68092b8
	github.com/aws/aws-sdk-go v1.40.16
	github.com/cockroachdb/cockroach-go/v2 v2.1.1
	github.com/eikenb/pipeat v0.0.0-20210603033007-44fc3ffce52b
	github.com/fatih/color v1.12.0 // indirect
	github.com/fclairamb/ftpserverlib v0.15.0
	github.com/fclairamb/go-log v0.1.0
	github.com/go-chi/chi/v5 v5.0.3
	github.com/go-chi/jwtauth/v5 v5.0.1
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.6.0
	github.com/golang/mock v1.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grandcat/zeroconf v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-plugin v1.4.2
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/hashicorp/yamux v0.0.0-20210707203944-259a57b3608c // indirect
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/klauspost/compress v1.13.3
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/jwx v1.2.5
	github.com/lib/pq v1.10.2
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/mattn/go-sqlite3 v1.14.8
	github.com/miekg/dns v1.1.43 // indirect
	github.com/minio/sio v0.3.0
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/otiai10/copy v1.6.0
	github.com/pires/go-proxyproto v0.6.0
	github.com/pkg/sftp v1.13.2
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.30.0 // indirect
	github.com/rs/cors v1.8.0
	github.com/rs/xid v1.3.0
	github.com/rs/zerolog v1.23.0
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shirou/gopsutil/v3 v3.21.7
	github.com/spf13/afero v1.6.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/studio-b12/gowebdav v0.0.0-20210630100626-7ff61aa87be8
	github.com/wagslane/go-password-validator v0.3.0
	github.com/yl2chen/cidranger v1.0.2
	go.etcd.io/bbolt v1.3.6
	go.uber.org/automaxprocs v1.4.0
	gocloud.dev v0.23.0
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
	google.golang.org/api v0.52.0
	google.golang.org/genproto v0.0.0-20210805201207-89edb61ffb67 // indirect
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace (
	github.com/eikenb/pipeat => github.com/drakkan/pipeat v0.0.0-20210805162858-70e57fa8a639
	github.com/fclairamb/ftpserverlib => github.com/drakkan/ftpserverlib v0.0.0-20210805132427-425f32d9dc15
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20201114075148-9b9adce499a9
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20210515063737-edf1d3b63536
	golang.org/x/net => github.com/drakkan/net v0.0.0-20210725074420-30b60d4a1e60
)
