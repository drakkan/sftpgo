FROM golang:alpine as builder

RUN apk add --no-cache git gcc g++ ca-certificates \
  && go get -v -d github.com/drakkan/sftpgo
WORKDIR /go/src/github.com/drakkan/sftpgo
ARG TAG
ARG FEATURES
# Use --build-arg TAG=LATEST for latest tag. Use e.g. --build-arg TAG=v1.0.0 for a specific tag/commit. Otherwise HEAD (master) is built.
RUN git checkout $(if [ "${TAG}" = LATEST ]; then echo `git rev-list --tags --max-count=1`; elif [ -n "${TAG}" ]; then echo "${TAG}"; else echo HEAD; fi)
RUN go build $(if [ -n "${FEATURES}" ]; then echo "-tags ${FEATURES}"; fi) -ldflags "-s -w -X github.com/drakkan/sftpgo/version.commit=`git describe --always --dirty` -X github.com/drakkan/sftpgo/version.date=`date -u +%FT%TZ`" -v -o /go/bin/sftpgo

FROM alpine:latest

RUN apk add --no-cache ca-certificates su-exec \
  && mkdir -p /data /etc/sftpgo /srv/sftpgo/config /srv/sftpgo/web /srv/sftpgo/backups

# git and rsync are optional, uncomment the next line to add support for them if needed.
#RUN apk add --no-cache git rsync

COPY --from=builder /go/bin/sftpgo /bin/
COPY --from=builder /go/src/github.com/drakkan/sftpgo/sftpgo.json /etc/sftpgo/sftpgo.json
COPY --from=builder /go/src/github.com/drakkan/sftpgo/templates /srv/sftpgo/web/templates
COPY --from=builder /go/src/github.com/drakkan/sftpgo/static /srv/sftpgo/web/static
COPY docker-entrypoint.sh /bin/entrypoint.sh
RUN chmod +x /bin/entrypoint.sh

VOLUME [ "/data", "/srv/sftpgo/config", "/srv/sftpgo/backups" ]
EXPOSE 2022 8080

# uncomment the following settings to enable FTP support
#ENV SFTPGO_FTPD__BIND_PORT=2121
#ENV SFTPGO_FTPD__FORCE_PASSIVE_IP=<your FTP visibile IP here>
#EXPOSE 2121

# we need to expose the passive ports range too
#EXPOSE 50000-50100

# it is a good idea to provide certificates to enable FTPS too
#ENV SFTPGO_FTPD__CERTIFICATE_FILE=/srv/sftpgo/config/mycert.crt
#ENV SFTPGO_FTPD__CERTIFICATE_KEY_FILE=/srv/sftpgo/config/mycert.key

# uncomment the following setting to enable WebDAV support
#ENV SFTPGO_WEBDAVD__BIND_PORT=8090

# it is a good idea to provide certificates to enable WebDAV over HTTPS
#ENV SFTPGO_WEBDAVD__CERTIFICATE_FILE=${CONFIG_DIR}/mycert.crt
#ENV SFTPGO_WEBDAVD__CERTIFICATE_KEY_FILE=${CONFIG_DIR}/mycert.key

ENTRYPOINT ["/bin/entrypoint.sh"]
CMD ["serve"]
