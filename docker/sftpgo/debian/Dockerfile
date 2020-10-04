# we use a multi stage build to have a separate build and run env
FROM golang:latest as buildenv
LABEL maintainer="nicola.murino@gmail.com"
RUN go get -v -d github.com/drakkan/sftpgo
WORKDIR /go/src/github.com/drakkan/sftpgo
ARG TAG
ARG FEATURES
# Use --build-arg TAG=LATEST for latest tag. Use e.g. --build-arg TAG=v1.0.0 for a specific tag/commit. Otherwise HEAD (master) is built.
RUN git checkout $(if [ "${TAG}" = LATEST ]; then echo `git rev-list --tags --max-count=1`; elif [ -n "${TAG}" ]; then echo "${TAG}"; else echo HEAD; fi)
RUN go build $(if [ -n "${FEATURES}" ]; then echo "-tags ${FEATURES}"; fi) -ldflags "-s -w -X github.com/drakkan/sftpgo/version.commit=`git describe --always --dirty` -X github.com/drakkan/sftpgo/version.date=`date -u +%FT%TZ`" -v -o sftpgo

# now define the run environment
FROM debian:latest

# ca-certificates is needed for Cloud Storage Support and for HTTPS/FTPS.
RUN apt-get update && apt-get install -y ca-certificates && apt-get clean

# git and rsync are optional, uncomment the next line to add support for them if needed.
#RUN apt-get update && apt-get install -y git rsync && apt-get clean

ARG BASE_DIR=/app
ARG DATA_REL_DIR=data
ARG CONFIG_REL_DIR=config
ARG BACKUP_REL_DIR=backups
ARG USERNAME=sftpgo
ARG GROUPNAME=sftpgo
ARG UID=515
ARG GID=515
ARG WEB_REL_PATH=web

# HOME_DIR for sftpgo itself
ENV HOME_DIR=${BASE_DIR}/${USERNAME}
# DATA_DIR, this is a volume that you can use hold user's home dirs
ENV DATA_DIR=${BASE_DIR}/${DATA_REL_DIR}
# CONFIG_DIR, this is a volume to persist the daemon private keys, configuration file ecc..
ENV CONFIG_DIR=${BASE_DIR}/${CONFIG_REL_DIR}
# BACKUPS_DIR, this is a volume to store backups done using "dumpdata" REST API
ENV BACKUPS_DIR=${BASE_DIR}/${BACKUP_REL_DIR}
ENV WEB_DIR=${BASE_DIR}/${WEB_REL_PATH}

RUN mkdir -p ${DATA_DIR} ${CONFIG_DIR} ${WEB_DIR} ${BACKUPS_DIR}
RUN groupadd --system -g ${GID} ${GROUPNAME}
RUN useradd --system --create-home --no-log-init --home-dir ${HOME_DIR} --comment "SFTPGo user" --shell /usr/sbin/nologin --gid ${GID} --uid ${UID} ${USERNAME}

WORKDIR ${HOME_DIR}
RUN mkdir -p bin .config/sftpgo
ENV PATH ${HOME_DIR}/bin:$PATH
COPY --from=buildenv /go/src/github.com/drakkan/sftpgo/sftpgo bin/sftpgo
# default config file to use if no config file is found inside the CONFIG_DIR volume.
# You can override each configuration options via env vars too
COPY --from=buildenv /go/src/github.com/drakkan/sftpgo/sftpgo.json .config/sftpgo/
COPY --from=buildenv /go/src/github.com/drakkan/sftpgo/templates ${WEB_DIR}/templates
COPY --from=buildenv /go/src/github.com/drakkan/sftpgo/static ${WEB_DIR}/static
RUN chown -R ${UID}:${GID} ${DATA_DIR} ${BACKUPS_DIR}

# run as non root user
USER ${USERNAME}

EXPOSE 2022 8080

# the defined volumes must have write access for the UID and GID defined above
VOLUME [ "$DATA_DIR", "$CONFIG_DIR", "$BACKUPS_DIR" ]

# override some default configuration options using env vars
ENV SFTPGO_CONFIG_DIR=${CONFIG_DIR}
# setting SFTPGO_LOG_FILE_PATH to an empty string will log to stdout
ENV SFTPGO_LOG_FILE_PATH=""
ENV SFTPGO_HTTPD__BIND_ADDRESS=""
ENV SFTPGO_HTTPD__TEMPLATES_PATH=${WEB_DIR}/templates
ENV SFTPGO_HTTPD__STATIC_FILES_PATH=${WEB_DIR}/static
ENV SFTPGO_DATA_PROVIDER__USERS_BASE_DIR=${DATA_DIR}
ENV SFTPGO_HTTPD__BACKUPS_PATH=${BACKUPS_DIR}

# uncomment the following settings to enable FTP support
#ENV SFTPGO_FTPD__BIND_PORT=2121
#ENV SFTPGO_FTPD__FORCE_PASSIVE_IP=<your FTP visibile IP here>
#EXPOSE 2121
# we need to expose the passive ports range too
#EXPOSE 50000-50100

# it is a good idea to provide certificates to enable FTPS too
#ENV SFTPGO_FTPD__CERTIFICATE_FILE=${CONFIG_DIR}/mycert.crt
#ENV SFTPGO_FTPD__CERTIFICATE_KEY_FILE=${CONFIG_DIR}/mycert.key

# uncomment the following setting to enable WebDAV support
#ENV SFTPGO_WEBDAVD__BIND_PORT=8090

# it is a good idea to provide certificates to enable WebDAV over HTTPS
#ENV SFTPGO_WEBDAVD__CERTIFICATE_FILE=${CONFIG_DIR}/mycert.crt
#ENV SFTPGO_WEBDAVD__CERTIFICATE_KEY_FILE=${CONFIG_DIR}/mycert.key

ENTRYPOINT ["sftpgo"]
CMD ["serve"]
