module github.com/drakkan/sftpgo/v2

go 1.20

require (
	cloud.google.com/go/storage v1.29.0
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.3.1
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.0.0
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/alexedwards/argon2id v0.0.0-20211130144151-3585854a6387
	github.com/aws/aws-sdk-go-v2 v1.17.5
	github.com/aws/aws-sdk-go-v2/config v1.18.15
	github.com/aws/aws-sdk-go-v2/credentials v1.13.15
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.23
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.55
	github.com/aws/aws-sdk-go-v2/service/marketplacemetering v1.14.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.30.5
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.18.6
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.5
	github.com/bmatcuk/doublestar/v4 v4.6.0
	github.com/cockroachdb/cockroach-go/v2 v2.2.20
	github.com/coreos/go-oidc/v3 v3.5.0
	github.com/drakkan/webdav v0.0.0-20230227175313-32996838bcd8
	github.com/eikenb/pipeat v0.0.0-20210730190139-06b3e6902001
	github.com/fclairamb/ftpserverlib v0.21.0
	github.com/fclairamb/go-log v0.4.1
	github.com/go-acme/lego/v4 v4.10.2
	github.com/go-chi/chi/v5 v5.0.8
	github.com/go-chi/jwtauth/v5 v5.1.0
	github.com/go-chi/render v1.0.2
	github.com/go-sql-driver/mysql v1.7.0
	github.com/golang/mock v1.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-hclog v1.4.0
	github.com/hashicorp/go-plugin v1.4.8
	github.com/hashicorp/go-retryablehttp v0.7.2
	github.com/jackc/pgx/v5 v5.3.1
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/klauspost/compress v1.16.0
	github.com/lestrrat-go/jwx/v2 v2.0.8
	github.com/lithammer/shortuuid/v3 v3.0.7
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/mhale/smtpd v0.8.0
	github.com/minio/sio v0.3.1
	github.com/otiai10/copy v1.9.0
	github.com/pires/go-proxyproto v0.6.2
	github.com/pkg/sftp v1.13.6-0.20230213180117-971c283182b6
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.14.0
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/cors v1.8.3
	github.com/rs/xid v1.4.0
	github.com/rs/zerolog v1.29.0
	github.com/sftpgo/sdk v0.1.3-0.20230302063609-7677616c090b
	github.com/shirou/gopsutil/v3 v3.23.2
	github.com/spf13/afero v1.9.4
	github.com/spf13/cobra v1.6.1
	github.com/spf13/viper v1.15.0
	github.com/stretchr/testify v1.8.2
	github.com/studio-b12/gowebdav v0.0.0-20230203202212-3282f94193f2
	github.com/subosito/gotenv v1.4.2
	github.com/unrolled/secure v1.13.0
	github.com/wagslane/go-password-validator v0.3.0
	github.com/wneessen/go-mail v0.3.8
	github.com/yl2chen/cidranger v1.0.3-0.20210928021809-d1cb2c52f37a
	go.etcd.io/bbolt v1.3.7
	go.uber.org/automaxprocs v1.5.1
	gocloud.dev v0.28.0
	golang.org/x/crypto v0.6.0
	golang.org/x/net v0.7.0
	golang.org/x/oauth2 v0.5.0
	golang.org/x/sys v0.5.0
	golang.org/x/term v0.5.0
	golang.org/x/time v0.3.0
	google.golang.org/api v0.111.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	cloud.google.com/go v0.110.0 // indirect
	cloud.google.com/go/compute v1.18.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.12.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.1.2 // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.4 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/goccy/go-json v0.10.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.7.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.1 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.4 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20230110061619-bbe2e5e100de // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/miekg/dns v1.1.51 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.0.7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20221212215047-62379fc7944b // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.41.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230301171018-9ab4bdc49ad5 // indirect
	google.golang.org/grpc v1.53.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20201114075148-9b9adce499a9
	github.com/robfig/cron/v3 => github.com/drakkan/cron/v3 v3.0.0-20230222140221-217a1e4d96c0
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20230209112458-e15d12511558
)
