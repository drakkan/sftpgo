FROM golang:1.27-trixie AS builder

ENV GOFLAGS="-mod=readonly"

RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace
WORKDIR /workspace

ARG GOPROXY

COPY go.mod go.sum ./
RUN go mod download && go mod verify

ARG COMMIT_SHA

# This ARG allows to disable some optional features and it might be useful if you build the image yourself.
# For example you can disable S3 and GCS support like this:
# --build-arg FEATURES=nos3,nogcs
ARG FEATURES

COPY . .

RUN set -xe && \
    export COMMIT_SHA=${COMMIT_SHA:-$(git describe --always --abbrev=8 --dirty)} && \
    go build $(if [ -n "${FEATURES}" ]; then echo "-tags ${FEATURES}"; fi) -trimpath -ldflags "-s -w -X github.com/xrogers/gonas/v2/internal/version.commit=${COMMIT_SHA} -X github.com/xrogers/gonas/v2/internal/version.date=`date -u +%FT%TZ`" -v -o gonas

# Set to "true" to download the "official" plugins in /usr/local/bin
ARG DOWNLOAD_PLUGINS=false

RUN if [ "${DOWNLOAD_PLUGINS}" = "true" ]; then apt-get update && apt-get install --no-install-recommends -y curl && ./docker/scripts/download-plugins.sh; fi

FROM debian:trixie-slim

# Set to "true" to install jq
ARG INSTALL_OPTIONAL_PACKAGES=false

# Fork: install ffmpeg so the WebClient can generate video thumbnails
# (see FORK_FEATURES.md). Set to "false" to skip it and save image size; image
# thumbnails still work and videos fall back to a generic icon.
ARG INSTALL_FFMPEG=true

RUN apt-get update && apt-get -y upgrade && apt-get install --no-install-recommends -y ca-certificates media-types && rm -rf /var/lib/apt/lists/*

RUN if [ "${INSTALL_OPTIONAL_PACKAGES}" = "true" ]; then apt-get update && apt-get install --no-install-recommends -y jq && rm -rf /var/lib/apt/lists/*; fi

RUN if [ "${INSTALL_FFMPEG}" = "true" ]; then apt-get update && apt-get install --no-install-recommends -y ffmpeg && rm -rf /var/lib/apt/lists/*; fi

RUN mkdir -p /etc/gonas /var/lib/gonas /usr/share/gonas /srv/gonas/data /srv/gonas/backups

RUN groupadd --system -g 1000 gonas && \
    useradd --system --gid gonas --no-create-home \
    --home-dir /var/lib/gonas --shell /usr/sbin/nologin \
    --comment "GoNAS user" --uid 1000 gonas

COPY --from=builder /workspace/gonas.json /etc/gonas/gonas.json
COPY --from=builder /workspace/templates /usr/share/gonas/templates
COPY --from=builder /workspace/static /usr/share/gonas/static
COPY --from=builder /workspace/openapi /usr/share/gonas/openapi
COPY --from=builder /workspace/gonas /usr/local/bin/sftpgo-plugin-* /usr/local/bin/

# Log to the stdout so the logs will be available using docker logs
ENV GONAS_LOG_FILE_PATH=""

# Modify the default configuration file
RUN sed -i 's|"users_base_dir": "",|"users_base_dir": "/srv/gonas/data",|' /etc/gonas/gonas.json && \
    sed -i 's|"backups"|"/srv/gonas/backups"|' /etc/gonas/gonas.json

RUN chown -R gonas:gonas /etc/gonas /srv/gonas && chown gonas:gonas /var/lib/gonas && chmod 700 /srv/gonas/backups

WORKDIR /var/lib/gonas
USER 1000:1000

CMD ["gonas", "serve"]
