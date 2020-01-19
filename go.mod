module github.com/drakkan/sftpgo

go 1.13

require (
	github.com/alexedwards/argon2id v0.0.0-20190612080829-01a59b2b8802
	github.com/aws/aws-sdk-go v1.28.3
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/eikenb/pipeat v0.0.0-20190316224601-fb1f3a9aa29f
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/grandcat/zeroconf v0.0.0-20190424104450-85eadb44205c
	github.com/lib/pq v1.3.0
	github.com/mattn/go-sqlite3 v2.0.2+incompatible
	github.com/miekg/dns v1.1.27 // indirect
	github.com/nathanaelle/password v1.0.0
	github.com/pkg/sftp v1.11.0
	github.com/prometheus/client_golang v1.3.0
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.17.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.6.1
	go.etcd.io/bbolt v1.3.3
	golang.org/x/crypto v0.0.0-20200109152110-61a87790db17
	golang.org/x/sys v0.0.0-20191220142924-d4481acd189f
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace github.com/eikenb/pipeat v0.0.0-20190316224601-fb1f3a9aa29f => github.com/drakkan/pipeat v0.0.0-20200114135659-fac71c64d75d
