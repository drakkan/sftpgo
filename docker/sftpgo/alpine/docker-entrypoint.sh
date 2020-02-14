#!/bin/sh

set -eu

chown -R "${PUID}:${GUID}" /data /etc/sftpgo /srv/sftpgo/config /srv/sftpgo/backups \
	&& exec su-exec "${PUID}:${GUID}" \
  /bin/sftpgo "$@"
