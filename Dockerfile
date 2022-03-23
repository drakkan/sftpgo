FROM golang:1.18-bullseye as builder

ENV GOFLAGS="-mod=readonly"

RUN mkdir -p /workspace
WORKDIR /workspace

ARG GOPROXY

COPY go.mod go.sum ./
RUN go mod download

ARG COMMIT_SHA

# This ARG allows to disable some optional features and it might be useful if you build the image yourself.
# For example you can disable S3 and GCS support like this:
# --build-arg FEATURES=nos3,nogcs
ARG FEATURES

COPY . .

RUN set -xe && \
    export COMMIT_SHA=${COMMIT_SHA:-$(git describe --always --dirty)} && \
    go build $(if [ -n "${FEATURES}" ]; then echo "-tags ${FEATURES}"; fi) -trimpath -ldflags "-s -w -X github.com/drakkan/sftpgo/v2/version.commit=${COMMIT_SHA} -X github.com/drakkan/sftpgo/v2/version.date=`date -u +%FT%TZ`" -v -o sftpgo

FROM debian:bullseye-slim

# Set to "true" to install jq and the optional git and rsync dependencies
ARG INSTALL_OPTIONAL_PACKAGES=false

RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates media-types && rm -rf /var/lib/apt/lists/*

RUN if [ "${INSTALL_OPTIONAL_PACKAGES}" = "true" ]; then apt-get update && apt-get install --no-install-recommends -y jq git rsync && rm -rf /var/lib/apt/lists/*; fi

RUN mkdir -p /etc/sftpgo /var/lib/sftpgo /usr/share/sftpgo /srv/sftpgo/data /srv/sftpgo/backups

RUN groupadd --system -g 1000 sftpgo && \
    useradd --system --gid sftpgo --no-create-home \
    --home-dir /var/lib/sftpgo --shell /usr/sbin/nologin \
    --comment "SFTPGo user" --uid 1000 sftpgo

COPY --from=builder /workspace/sftpgo.json /etc/sftpgo/sftpgo.json
COPY --from=builder /workspace/templates /usr/share/sftpgo/templates
COPY --from=builder /workspace/static /usr/share/sftpgo/static
COPY --from=builder /workspace/openapi /usr/share/sftpgo/openapi
COPY --from=builder /workspace/sftpgo /usr/local/bin/

# Log to the stdout so the logs will be available using docker logs
ENV SFTPGO_LOG_FILE_PATH=""
# templates and static paths are inside the container
ENV SFTPGO_HTTPD__TEMPLATES_PATH=/usr/share/sftpgo/templates
ENV SFTPGO_SMTP__TEMPLATES_PATH=/usr/share/sftpgo/templates
ENV SFTPGO_HTTPD__STATIC_FILES_PATH=/usr/share/sftpgo/static
ENV SFTPGO_HTTPD__OPENAPI_PATH=/usr/share/sftpgo/openapi

# Modify the default configuration file
RUN sed -i 's|"users_base_dir": "",|"users_base_dir": "/srv/sftpgo/data",|' /etc/sftpgo/sftpgo.json && \
    sed -i 's|"backups"|"/srv/sftpgo/backups"|' /etc/sftpgo/sftpgo.json

RUN chown -R sftpgo:sftpgo /etc/sftpgo /srv/sftpgo && chown sftpgo:sftpgo /var/lib/sftpgo && chmod 700 /srv/sftpgo/backups

WORKDIR /var/lib/sftpgo
USER 1000:1000

CMD ["sftpgo", "serve"]
