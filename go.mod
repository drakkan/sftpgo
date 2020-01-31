module github.com/drakkan/sftpgo

go 1.13

require (
	cloud.google.com/go v0.52.0 // indirect
	cloud.google.com/go/storage v1.5.0
	github.com/alexedwards/argon2id v0.0.0-20190612080829-01a59b2b8802
	github.com/aws/aws-sdk-go v1.28.3
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/eikenb/pipeat v0.0.0-20190316224601-fb1f3a9aa29f
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-chi/render v1.0.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
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
	golang.org/x/exp v0.0.0-20200119233911-0405dc783f0a // indirect
	golang.org/x/sys v0.0.0-20200122134326-e047566fdf82
	golang.org/x/tools v0.0.0-20200124200720-1b668f209185 // indirect
	google.golang.org/api v0.15.0
	google.golang.org/genproto v0.0.0-20200122232147-0452cf42e150 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace github.com/eikenb/pipeat v0.0.0-20190316224601-fb1f3a9aa29f => github.com/drakkan/pipeat v0.0.0-20200123131427-11c048cfc0ec
