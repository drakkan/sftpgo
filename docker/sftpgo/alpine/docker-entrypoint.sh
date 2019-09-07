#!/bin/sh

set -eu

chown -R "${PUID}:${GUID}" /data /etc/sftpgo \
	&& exec su-exec "${PUID}:${GUID}" \
  /bin/sftpgo serve "$@"
