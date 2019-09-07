## Dockerfile based on Debian stable

Please read the comments inside the `Dockerfile` to learn how to customize things for your setup.

You can build the container image using `docker build`, for example:

```bash
docker build -t="drakkan/sftpgo" .
```

and you can run the Dockerfile using something like this:

```bash
docker run --name sftpgo -p 8080:8080 -p 2022:2022 --mount type=bind,source=/srv/sftpgo/data,target=/app/data --mount type=bind,source=/srv/sftpgo/config,target=/app/config drakkan/sftpgo
```

where  `/srv/sftpgo/data` and `/srv/sftpgo/config` are two folders on the host system with write access for UID/GID defined inside the `Dockerfile`. You can choose to create a new user, on the host system, with a matching UID/GID pair or simply do something like:


```bash
chown -R <UID>:<GID> /srv/sftpgo/data /srv/sftpgo/config
```