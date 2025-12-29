#!/usr/bin/env bash
set -euo pipefail

ARCH=$(uname -m)

case ${ARCH} in
    x86_64)
        SUFFIX=amd64
        ;;
    aarch64)
        SUFFIX=arm64
        ;;
    *)
        SUFFIX=ppc64le
        ;;
esac

echo "Downloading plugins for arch ${SUFFIX}"

PLUGINS=(geoipfilter kms pubsub eventstore eventsearch auth)

for PLUGIN in "${PLUGINS[@]}"; do
    URL="https://github.com/sftpgo/sftpgo-plugin-${PLUGIN}/releases/latest/download/sftpgo-plugin-${PLUGIN}-linux-${SUFFIX}"
    DEST="/usr/local/bin/sftpgo-plugin-${PLUGIN}"

    echo "Downloading ${PLUGIN}..."
    if curl --fail --silent --show-error -L "${URL}" --output "${DEST}"; then
        chmod 755 "${DEST}"
    else
        echo "Error: Failed to download ${PLUGIN}" >&2
        exit 1
    fi
done

echo "All plugins downloaded successfully"
