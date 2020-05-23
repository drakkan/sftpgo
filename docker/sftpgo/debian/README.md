## Dockerfile based on Debian stable

Please read the comments inside the `Dockerfile` to learn how to customize things for your setup.

You can build the container image using `docker build`, for example:

```bash
docker build -t="drakkan/sftpgo" .
```

This will build master of github.com/drakkan/sftpgo.

To build the latest tag you can add `--build-arg TAG=LATEST` and to build a specific tag/commit you can use for example `TAG=0.9.6`, like this:

```bash
docker build -t="drakkan/sftpgo" --build-arg TAG=0.9.6 .
```

To disable some features you can add `--build-arg FEATURES=<features to disable>`. For example you can disable SQLite support like this:

```bash
docker build -t="drakkan/sftpgo" --build-arg FEATURES=nosqlite .
```

Please take a look at the [build from source](./../../../docs/build-from-source.md) documentation for the complete list of the features that can be disabled.

Now create the required folders on the host system, for example:

```bash
sudo mkdir -p /srv/sftpgo/data /srv/sftpgo/config /srv/sftpgo/backups
```

and give write access to them to the UID/GID defined inside the `Dockerfile`. You can choose to create a new user, on the host system, with a matching UID/GID pair, or simply do something like this:

```bash
sudo chown -R <UID>:<GID> /srv/sftpgo/data /srv/sftpgo/config /srv/sftpgo/backups
```

Download the default configuration file and edit it as you need:

```bash
sudo curl https://raw.githubusercontent.com/drakkan/sftpgo/master/sftpgo.json -o /srv/sftpgo/config/sftpgo.json
```

Initialize the configured provider. For PostgreSQL and MySQL providers you need to create the configured database and the `initprovider` command will create the required tables:

```bash
docker run --name sftpgo --mount type=bind,source=/srv/sftpgo/config,target=/app/config drakkan/sftpgo initprovider -c /app/config
```

and finally you can run the image using something like this:

```bash
docker rm sftpgo && docker run --name sftpgo -p 8080:8080 -p 2022:2022 --mount type=bind,source=/srv/sftpgo/data,target=/app/data --mount type=bind,source=/srv/sftpgo/config,target=/app/config --mount type=bind,source=/srv/sftpgo/backups,target=/app/backups drakkan/sftpgo
```
