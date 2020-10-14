# SFTPGo with Docker and Alpine

:warning: The recommended way to run SFTPGo on Docker is to use the official [images](https://hub.docker.com/r/drakkan/sftpgo). The documentation here is now obsolete.

This DockerFile is made to build image to host multiple instances of SFTPGo started with different users.

## Example

> 1003 is a custom uid:gid for this instance of SFTPGo

```bash
# Prereq on docker host
sudo groupadd -g 1003 sftpgrp && \
  sudo useradd -u 1003 -g 1003 sftpuser -d /home/sftpuser/ && \
  sudo -u sftpuser mkdir /home/sftpuser/{conf,data} && \
  curl https://raw.githubusercontent.com/drakkan/sftpgo/master/sftpgo.json -o /home/sftpuser/conf/sftpgo.json

# Edit sftpgo.json as you need

# Get and build SFTPGo image.
# Add --build-arg TAG=LATEST to build the latest tag or e.g. TAG=v1.0.0 for a specific tag/commit.
# Add --build-arg FEATURES=<build features comma separated> to specify the features to build.
git clone https://github.com/drakkan/sftpgo.git && \
  cd sftpgo && \
  sudo docker build -t sftpgo docker/sftpgo/alpine/

# Initialize the configured provider. For PostgreSQL and MySQL providers you need to create the configured database and the "initprovider" command will create the required tables.
sudo docker run --name sftpgo \
  -e PUID=1003 \
  -e GUID=1003 \
  -v /home/sftpuser/conf/:/srv/sftpgo/config \
  sftpgo initprovider -c /srv/sftpgo/config

# Start the image
sudo docker rm sftpgo && sudo docker run --name sftpgo \
  -e SFTPGO_LOG_FILE_PATH= \
  -e SFTPGO_CONFIG_DIR=/srv/sftpgo/config \
  -e SFTPGO_HTTPD__TEMPLATES_PATH=/srv/sftpgo/web/templates \
  -e SFTPGO_HTTPD__STATIC_FILES_PATH=/srv/sftpgo/web/static \
  -e SFTPGO_HTTPD__BACKUPS_PATH=/srv/sftpgo/backups \
  -p 8080:8080 \
  -p 2022:2022 \
  -e PUID=1003 \
  -e GUID=1003 \
  -v /home/sftpuser/conf/:/srv/sftpgo/config \
  -v /home/sftpuser/data:/data \
  -v /home/sftpuser/backups:/srv/sftpgo/backups \
  sftpgo
```

If you want to enable FTP/S you also need the publish the FTP port and the FTP passive port range, defined in your `Dockerfile`, by adding, for example, the following options to the `docker run` command `-p 2121:2121 -p 50000-50100:50000-50100`. The same goes for WebDAV, you need to publish the configured port.

The script `entrypoint.sh` makes sure to correct the permissions of directories and start the process with the right user.

Several images can be run with different parameters.

## Custom systemd script

An example of systemd script is present [here](sftpgo.service), with `Environment` parameter to set `PUID` and `GUID`

`WorkingDirectory` parameter must be exist with one file in this directory like `sftpgo-${PUID}.env` corresponding to the variable file for SFTPGo instance.
