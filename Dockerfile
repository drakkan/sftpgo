FROM golang:1.15-alpine AS builder

ENV GOFLAGS="-mod=readonly"

RUN apk add --update --no-cache bash ca-certificates curl git gcc g++

RUN mkdir -p /workspace
WORKDIR /workspace

ARG GOPROXY

COPY go.mod go.sum ./
RUN go mod download

ARG COMMIT_SHA

COPY . .

RUN set -xe && \
    export COMMIT_SHA=${COMMIT_SHA:-$(git describe --always --dirty)} && \
    go build -ldflags "-s -w -X github.com/drakkan/sftpgo/version.commit=${COMMIT_SHA} -X github.com/drakkan/sftpgo/version.date=`date -u +%FT%TZ`" -v -o sftpgo


FROM alpine:3.12

RUN apk add --update --no-cache ca-certificates tzdata bash

SHELL ["/bin/bash", "-c"]

# set up nsswitch.conf for Go's "netgo" implementation
# https://github.com/gliderlabs/docker-alpine/issues/367#issuecomment-424546457
RUN test ! -e /etc/nsswitch.conf && echo 'hosts: files dns' > /etc/nsswitch.conf

RUN mkdir -p /etc/sftpgo /var/lib/sftpgo /usr/share/sftpgo

RUN addgroup -g 1000 -S sftpgo
RUN adduser -u 1000 -h /var/lib/sftpgo -s /sbin/nologin -G sftpgo -S -D -H sftpgo

# Install some optional packages used by sftpgo features
RUN apk add --update --no-cache rsync git mailcap

# Override some configuration details
ENV SFTPGO_CONFIG_DIR=/etc/sftpgo
ENV SFTPGO_LOG_FILE_PATH=""
ENV SFTPGO_HTTPD__TEMPLATES_PATH=/usr/share/sftpgo/templates
ENV SFTPGO_HTTPD__STATIC_FILES_PATH=/usr/share/sftpgo/static

# Sane defaults, but users should still be able to override this from env vars
ENV SFTPGO_DATA_PROVIDER__USERS_BASE_DIR=/var/lib/sftpgo/users
ENV SFTPGO_DATA_PROVIDER__CREDENTIALS_PATH=/var/lib/sftpgo/credentials
ENV SFTPGO_HTTPD__BACKUPS_PATH=/var/lib/sftpgo/backups
ENV SFTPGO_SFTPD__HOST_KEYS=/var/lib/sftpgo/host_keys/id_rsa,/var/lib/sftpgo/host_keys/id_ecdsa

COPY --from=builder /workspace/sftpgo.json /etc/sftpgo/sftpgo.json
COPY --from=builder /workspace/templates /usr/share/sftpgo/templates
COPY --from=builder /workspace/static /usr/share/sftpgo/static
COPY --from=builder /workspace/sftpgo /usr/local/bin/

RUN sed -i "s|sftpgo.db|/var/lib/sftpgo/sftpgo.db|" /etc/sftpgo/sftpgo.json

RUN chown -R sftpgo:sftpgo /etc/sftpgo /var/lib/sftpgo
RUN chmod 750 /etc/sftpgo /var/lib/sftpgo
RUN chmod 640 /etc/sftpgo/sftpgo.json

USER sftpgo

VOLUME /var/lib/sftpgo

CMD sftpgo serve
