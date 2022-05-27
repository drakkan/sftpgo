module github.com/drakkan/sftpgo/v2

go 1.18

require (
	cloud.google.com/go/storage v1.22.1
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v0.4.1
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/alexedwards/argon2id v0.0.0-20211130144151-3585854a6387
	github.com/aws/aws-sdk-go-v2 v1.16.4
	github.com/aws/aws-sdk-go-v2/config v1.15.9
	github.com/aws/aws-sdk-go-v2/credentials v1.12.4
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.5
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.14
	github.com/aws/aws-sdk-go-v2/service/marketplacemetering v1.13.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.26.10
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.15.9
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.6
	github.com/cockroachdb/cockroach-go/v2 v2.2.11
	github.com/coreos/go-oidc/v3 v3.2.0
	github.com/eikenb/pipeat v0.0.0-20210730190139-06b3e6902001
	github.com/fclairamb/ftpserverlib v0.18.1-0.20220515214847-f96d31ec626e
	github.com/fclairamb/go-log v0.3.0
	github.com/go-acme/lego/v4 v4.6.0
	github.com/go-chi/chi/v5 v5.0.8-0.20220512131524-9e71a0d4b3d6
	github.com/go-chi/jwtauth/v5 v5.0.2
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.6.0
	github.com/golang/mock v1.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.3.0
	github.com/grandcat/zeroconf v1.0.0
	github.com/hashicorp/go-hclog v1.2.0
	github.com/hashicorp/go-plugin v1.4.4
	github.com/hashicorp/go-retryablehttp v0.7.1
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/klauspost/compress v1.15.5
	github.com/lestrrat-go/jwx v1.2.25
	github.com/lib/pq v1.10.6
	github.com/lithammer/shortuuid/v3 v3.0.7
	github.com/mattn/go-sqlite3 v1.14.13
	github.com/mhale/smtpd v0.8.0
	github.com/minio/sio v0.3.0
	github.com/otiai10/copy v1.7.0
	github.com/pires/go-proxyproto v0.6.2
	github.com/pkg/sftp v1.13.5-0.20220303113417-dcfc1d5e4162
	github.com/pquerna/otp v1.3.0
	github.com/prometheus/client_golang v1.12.2
	github.com/robfig/cron/v3 v3.0.1
	github.com/rs/cors v1.8.2
	github.com/rs/xid v1.4.0
	github.com/rs/zerolog v1.26.2-0.20220505171737-a4ec5e4cdd4b
	github.com/sftpgo/sdk v0.1.1-0.20220425123921-2f843a49e012
	github.com/shirou/gopsutil/v3 v3.22.4
	github.com/spf13/afero v1.8.2
	github.com/spf13/cobra v1.4.0
	github.com/spf13/viper v1.12.0
	github.com/stretchr/testify v1.7.1
	github.com/studio-b12/gowebdav v0.0.0-20220128162035-c7b1ff8a5e62
	github.com/unrolled/secure v1.10.0
	github.com/wagslane/go-password-validator v0.3.0
	github.com/xhit/go-simple-mail/v2 v2.11.0
	github.com/yl2chen/cidranger v1.0.3-0.20210928021809-d1cb2c52f37a
	go.etcd.io/bbolt v1.3.6
	go.uber.org/automaxprocs v1.5.1
	gocloud.dev v0.25.0
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
	golang.org/x/net v0.0.0-20220526153639-5463443f8c37
	golang.org/x/oauth2 v0.0.0-20220524215830-622c5d57e401
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a
	golang.org/x/time v0.0.0-20220411224347-583f2d630306
	google.golang.org/api v0.81.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

require (
	cloud.google.com/go v0.102.0 // indirect
	cloud.google.com/go/compute v1.6.1 // indirect
	cloud.google.com/go/iam v0.3.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.7 // indirect
	github.com/aws/smithy-go v1.11.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/coreos/go-systemd/v22 v22.3.3-0.20220203105225-a9a7ef127534 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-test/deep v1.0.8 // indirect
	github.com/goccy/go-json v0.9.7 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/googleapis/gax-go/v2 v2.4.0 // indirect
	github.com/googleapis/go-type-adapters v1.0.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20211028200310-0bc27b27de87 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.1 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20220517141722-cf486979b281 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/miekg/dns v1.1.49 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20220216144756-c35f1ee13d7c // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.34.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.3.0 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.5.0 // indirect
	github.com/toorop/go-dkim v0.0.0-20201103131630-e1cd1a0a5208 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.10 // indirect
	golang.org/x/xerrors v0.0.0-20220517211312-f3a8303e98df // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220526192754-51939a95c655 // indirect
	google.golang.org/grpc v1.46.2 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/ini.v1 v1.66.4 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0 // indirect
)

replace (
	github.com/jlaffaye/ftp => github.com/drakkan/ftp v0.0.0-20201114075148-9b9adce499a9
	golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20220527053356-5e1caf8ed0e1
	golang.org/x/net => github.com/drakkan/net v0.0.0-20220527053128-4a99afeacbd0
)
