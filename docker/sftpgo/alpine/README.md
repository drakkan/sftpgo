# SFTPGo with Docker and Alpine

This DockerFile is made to build image to host multiple instances of SFTPGo started with different users.

### Example
> 1003 is a custom uid:gid for this instance of SFTPGo
```bash
# Prereq on docker host
sudo groupadd -g 1003 sftpgrp && \
  sudo useradd -u 1003 -g 1003 sftpuser -d /home/sftpuser/ && \
  sudo -u sftpuser mkdir /home/sftpuser/{conf,data} && \
  curl https://raw.githubusercontent.com/drakkan/sftpgo/master/sql/sqlite/20190828.sql | sqlite3 /home/sftpuser/conf/sftpgo.db && \
  curl https://raw.githubusercontent.com/drakkan/sftpgo/master/sftpgo.json -o /home/sftpuser/conf/sftpgo.json

# Get and build SFTPGo image
git clone https://github.com/drakkan/sftpgo.git && \
  cd sftpgo && \
  sudo docker build -t sftpgo docker/sftpgo/alpine/

# Starting image
sudo docker run --name sftpgo \
  -e SFTPGO_LOG_FILE_PATH= \
  -e SFTPGO_CONFIG_DIR=/srv/sftpgo/config \
  -e SFTPGO_HTTPD__TEMPLATES_PATH=/srv/sftpgo/web/templates \
  -e SFTPGO_HTTPD__STATIC_FILES_PATH=/srv/sftpgo/web/static \
  -p 8080:8080 \
  -p 2022:2022 \
  -e PUID=1003 \
  -e GUID=1003 \
  -v /home/sftpuser/conf/:/srv/sftpgo/config \
  -v /home/sftpuser/data:/data \
  sftpgo
```
The script `entrypoint.sh` makes sure to correct the permissions of directories and start the process with the right user

Several images can be run with different parameters.

### Custom systemd script
An example of systemd script is present [here](sftpgo.service), with `Environment` parameter to set `PUID` and `GUID`

`WorkingDirectory` parameter must be exist with one file in this directory like `sftpgo-${PUID}.env` corresponding to the variable file for SFTPGo instance.