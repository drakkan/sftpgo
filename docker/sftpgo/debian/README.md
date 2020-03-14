## Dockerfile based on Debian stable

Please read the comments inside the `Dockerfile` to learn how to customize things for your setup.

You can build the container image using `docker build`, for example:

```bash
docker build -t="drakkan/sftpgo" .
```

now create the required folders on the host system, for example:

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