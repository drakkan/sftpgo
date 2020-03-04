# Build SFTPGo from source

Install the package to your [\$GOPATH](https://github.com/golang/go/wiki/GOPATH "GOPATH") with the [go tool](https://golang.org/cmd/go/ "go command") from shell:

```bash
go get -u github.com/drakkan/sftpgo
```

Make sure [Git](https://git-scm.com/downloads) is installed on your machine and in your system's `PATH`.

SFTPGo depends on [go-sqlite3](https://github.com/mattn/go-sqlite3) which is a CGO package and so it requires a `C` compiler at build time.
On Linux and macOS, a compiler is easy to install or already installed. On Windows, you need to download [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/) and build SFTPGo from its command prompt.

The compiler is a build time only dependency. It is not required at runtime.

If you don't need SQLite, you can also get/build SFTPGo setting the environment variable `GCO_ENABLED` to 0. This way, SQLite support will be disabled and PostgreSQL, MySQL, bbolt and memory data providers will keep working. In this way, you don't need a `C` compiler for building.

Version info, such as git commit and build date, can be embedded setting the following string variables at build time:

- `github.com/drakkan/sftpgo/utils.commit`
- `github.com/drakkan/sftpgo/utils.date`

For example, you can build using the following command:

```bash
go build -i -ldflags "-s -w -X github.com/drakkan/sftpgo/utils.commit=`git describe --always --dirty` -X github.com/drakkan/sftpgo/utils.date=`date -u +%FT%TZ`" -o sftpgo
```

You should get a version that includes git commit and build date like this one:

```bash
$ sftpgo -v
SFTPGo version: 0.9.0-dev-90607d4-dirty-2019-08-08T19:28:36Z
```