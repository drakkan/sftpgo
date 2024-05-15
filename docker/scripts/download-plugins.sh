#!/usr/bin/env bash
set -e

ARCH=`uname -m`

case ${ARCH} in
    "x86_64")
        SUFFIX=amd64
        ;;
    "aarch64")
        SUFFIX=arm64
        ;;
    *)
        SUFFIX=ppc64le
        ;;
esac

echo "download plugins for arch ${SUFFIX}"

curl -L "https://github.com/sftpgo/sftpgo-plugin-geoipfilter/releases/download/v1.0.7/sftpgo-plugin-geoipfilter-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-geoipfilter"
chmod 755 "/usr/local/bin/sftpgo-plugin-geoipfilter"

curl -L "https://github.com/sftpgo/sftpgo-plugin-kms/releases/download/v1.0.10/sftpgo-plugin-kms-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-kms"
chmod 755 "/usr/local/bin/sftpgo-plugin-kms"

curl -L "https://github.com/sftpgo/sftpgo-plugin-pubsub/releases/download/v1.0.11/sftpgo-plugin-pubsub-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-pubsub"
chmod 755 "/usr/local/bin/sftpgo-plugin-pubsub"

curl -L "https://github.com/sftpgo/sftpgo-plugin-eventstore/releases/download/v1.0.15/sftpgo-plugin-eventstore-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-eventstore"
chmod 755 "/usr/local/bin/sftpgo-plugin-eventstore"

curl -L "https://github.com/sftpgo/sftpgo-plugin-eventsearch/releases/download/v1.0.15/sftpgo-plugin-eventsearch-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-eventsearch"
chmod 755 "/usr/local/bin/sftpgo-plugin-eventsearch"

curl -L "https://github.com/sftpgo/sftpgo-plugin-metadata/releases/download/v1.0.12/sftpgo-plugin-metadata-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-metadata"
chmod 755 "/usr/local/bin/sftpgo-plugin-metadata"

curl -L "https://github.com/sftpgo/sftpgo-plugin-auth/releases/download/v1.0.5/sftpgo-plugin-auth-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-auth"
chmod 755 "/usr/local/bin/sftpgo-plugin-auth"
