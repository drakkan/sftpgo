# Build SFTPGo from source

Install the package to your [\$GOPATH](https://github.com/golang/go/wiki/GOPATH "GOPATH") with the [go tool](https://golang.org/cmd/go/ "go command") from shell:

```bash
go get -u github.com/drakkan/sftpgo
```

Make sure [Git](https://git-scm.com/downloads) is installed on your machine and in your system's `PATH`.

The following build tags are available:

- `nogcs`, disable Google Cloud Storage backend, default enabled
- `nos3`, disable S3 Compabible Object Storage backends, , default enabled
- `nobolt`, disable Bolt data provider, , default enabled
- `nomysql`, disable MySQL data provider, default enabled
- `nopgsql`, disable PostgreSQL data provider, default enabled
- `nosqlite`, disable SQLite data provider, default enabled
- `noportable`, disable portable mode, default enabled

If no build tag is specified the build will include the default features.

The optional [SQLite driver](https://github.com/mattn/go-sqlite3 "go-sqlite3") is a `CGO` package and so it requires a `C` compiler at build time.
On Linux and macOS, a compiler is easy to install or already installed. On Windows, you need to download [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/) and build SFTPGo from its command prompt.

The compiler is a build time only dependency. It is not required at runtime.

Version info, such as git commit and build date, can be embedded setting the following string variables at build time:

- `github.com/drakkan/sftpgo/utils.commit`
- `github.com/drakkan/sftpgo/utils.date`

For example, you can build using the following command:

```bash
go build -i -tags nogcs,nos3,nosqlite -ldflags "-s -w -X github.com/drakkan/sftpgo/utils.commit=`git describe --always --dirty` -X github.com/drakkan/sftpgo/utils.date=`date -u +%FT%TZ`" -o sftpgo
```

You should get a version that includes git commit, build date and available features like this one:

```bash
$ ./sftpgo -v
SFTPGo 0.9.6-dev-15298b0-dirty-2020-05-22T21:25:51Z -gcs -s3 +bolt +mysql +pgsql -sqlite +portable
```