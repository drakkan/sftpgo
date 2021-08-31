# Dockerfile based on Distroless static-debian10
> ["Distroless"](https://github.com/GoogleContainerTools/distroless) images contain only your application and its runtime dependencies. They do not contain package managers, shells or any other programs you would expect to find in a standard Linux distribution.

:warning: The recommended way to run SFTPGo on Docker is to use the official [images](https://hub.docker.com/r/drakkan/sftpgo). The documentation here is now obsolete.

Please read the comments inside the `Dockerfile` to learn how to customize things for your setup.

You can build the container image using `docker build`, for example:

## Example 

```bash
sudo mkdir -p /srv/sftpgo/data /srv/sftpgo/config /srv/sftpgo/backups
```

and give write access to them to the UID/GID defined inside the `Dockerfile`. You can choose to create a new user, on the host system, with a matching UID/GID pair, or simply do something like this:

**NOTE: You can run as nonroot user using distroless image with UID:GID `65532:65532`**

```bash
sudo chown -R <UID>:<GID> /srv/sftpgo/data /srv/sftpgo/config /srv/sftpgo/backups
```

**Build the image**
```bash
git clone https://github.com/drakkan/sftpgo.git && \
  cd sftpgo && \
  sudo docker build -t sftpgo  - < Dockerfile.distroless
```

**Run image as root**
```bash
sudo docker rm sftpgo && sudo docker run --name sftpgo \
  -e SFTPGO_LOG_FILE_PATH= \
  -e SFTPGO_CONFIG_DIR=/srv/sftpgo/config \
  -e SFTPGO_HTTPD__TEMPLATES_PATH=/usr/share/sftpgo/templates \
  -e SFTPGO_HTTPD__STATIC_FILES_PATH=/usr/share/sftpgo/static \
  -e SFTPGO_HTTPD__BACKUPS_PATH=/srv/sftpgo/backups \
  -p 8080:8080 \
  -p 2022:2022 \
  -v /srv/sftpgo/conf/:/srv/sftpgo/config \
  -v /srv/sftpgo/data:/data \
  -v /srv/sftpgo/backups:/srv/sftpgo/backups \
  sftpgo
```

**Run image as nonroot user**
```bash
sudo docker rm sftpgo && sudo docker run --name sftpgo \
  -e SFTPGO_LOG_FILE_PATH= \
  -e SFTPGO_CONFIG_DIR=/srv/sftpgo/config \
  -e SFTPGO_HTTPD__TEMPLATES_PATH=/usr/share/sftpgo/templates \
  -e SFTPGO_HTTPD__STATIC_FILES_PATH=/usr/share/sftpgo/static \
  -e SFTPGO_HTTPD__BACKUPS_PATH=/srv/sftpgo/backups \
  -p 8080:8080 \
  -p 2022:2022 \
  -e PUID=65532 \
  -e GUID=65532 \
  -v /srv/sftpgo/conf/:/srv/sftpgo/config \
  -v /srv/sftpgo/data:/data \
  -v /srv/sftpgo/backups:/srv/sftpgo/backups \
  sftpgo
```
