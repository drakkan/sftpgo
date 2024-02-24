FROM golang:1.22-bookworm as builder

ENV GOFLAGS="-mod=readonly"

RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*

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
    export COMMIT_SHA=${COMMIT_SHA:-$(git describe --always --abbrev=8 --dirty)} && \
    go build $(if [ -n "${FEATURES}" ]; then echo "-tags ${FEATURES}"; fi) -trimpath -ldflags "-s -w -X github.com/drakkan/sftpgo/v2/internal/version.commit=${COMMIT_SHA} -X github.com/drakkan/sftpgo/v2/internal/version.date=`date -u +%FT%TZ`" -v -o sftpgo

# Set to "true" to download the "official" plugins in /usr/local/bin
ARG DOWNLOAD_PLUGINS=false

RUN if [ "${DOWNLOAD_PLUGINS}" = "true" ]; then apt-get update && apt-get install --no-install-recommends -y curl && ./docker/scripts/download-plugins.sh; fi

FROM debian:bookworm-slim

# Set to "true" to install jq and the optional git and rsync dependencies
ARG INSTALL_OPTIONAL_PACKAGES=false

RUN apt-get update && apt-get -y upgrade && apt-get install --no-install-recommends -y ca-certificates media-types && rm -rf /var/lib/apt/lists/*

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
COPY --from=builder /workspace/sftpgo /usr/local/bin/sftpgo-plugin-* /usr/local/bin/

# Log to the stdout so the logs will be available using docker logs
ENV SFTPGO_LOG_FILE_PATH=""

# Modify the default configuration file
RUN sed -i 's|"users_base_dir": "",|"users_base_dir": "/srv/sftpgo/data",|' /etc/sftpgo/sftpgo.json && \
    sed -i 's|"backups"|"/srv/sftpgo/backups"|' /etc/sftpgo/sftpgo.json

RUN chown -R sftpgo:sftpgo /etc/sftpgo /srv/sftpgo && chown sftpgo:sftpgo /var/lib/sftpgo && chmod 700 /srv/sftpgo/backups

WORKDIR /var/lib/sftpgo
USER 1000:1000

CMD ["sftpgo", "serve"]
