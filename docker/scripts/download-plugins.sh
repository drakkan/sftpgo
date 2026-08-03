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

for PLUGIN in geoipfilter kms pubsub eventstore eventsearch auth
do
    echo "download plugin from https://github.com/sftpgo/sftpgo-plugin-${PLUGIN}/releases/latest/download/sftpgo-plugin-${PLUGIN}-linux-${SUFFIX}"
    curl -L "https://github.com/sftpgo/sftpgo-plugin-${PLUGIN}/releases/latest/download/sftpgo-plugin-${PLUGIN}-linux-${SUFFIX}" --output "/usr/local/bin/sftpgo-plugin-${PLUGIN}"
    chmod 755 "/usr/local/bin/sftpgo-plugin-${PLUGIN}"
done
