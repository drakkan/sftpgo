# Build SFTPGo from source

Download the sources and use `go build`.

The following build tags are available:

- `nogcs`, disable Google Cloud Storage backend, default enabled
- `nos3`, disable S3 Compabible Object Storage backends, default enabled
- `noazblob`, disable Azure Blob Storage backend, default enabled
- `nobolt`, disable Bolt data provider, default enabled
- `nomysql`, disable MySQL data provider, default enabled
- `nopgsql`, disable PostgreSQL data provider, default enabled
- `nosqlite`, disable SQLite data provider, default enabled
- `noportable`, disable portable mode, default enabled
- `nometrics`, disable Prometheus metrics, default enabled
- `bundle`, embed static files and templates. Before building with this tag enabled you have to copy `openapi`, `static` and `templates` dirs to `internal/bundle` directory. Default disabled

If no build tag is specified the build will include the default features.

The optional [SQLite driver](https://github.com/mattn/go-sqlite3 "go-sqlite3") is a `CGO` package and so it requires a `C` compiler at build time.
On Linux and macOS, a compiler is easy to install or already installed. On Windows, you need to download [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/) and build SFTPGo from its command prompt.

The compiler is a build time only dependency. It is not required at runtime.

Version info, such as git commit and build date, can be embedded setting the following string variables at build time:

- `github.com/drakkan/sftpgo/v2/internal/version.commit`
- `github.com/drakkan/sftpgo/v2/internal/version.date`

For example, you can build using the following command:

```bash
go build -tags nogcs,nos3,nosqlite -ldflags "-s -w -X github.com/drakkan/sftpgo/v2/internal/version.commit=`git describe --always --abbrev=8 --dirty` -X github.com/drakkan/sftpgo/v2/internal/version.date=`date -u +%FT%TZ`" -o sftpgo
```

You should get a version that includes git commit, build date and available features like this one:

```bash
$ ./sftpgo -v
SFTPGo 2.3.1-dev-c8158e1-2022-07-24T17:25:45Z +metrics +azblob +gcs +s3 +bolt +mysql +pgsql +sqlite +portable
```
