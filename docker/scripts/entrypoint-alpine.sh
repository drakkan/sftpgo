#!/usr/bin/env bash

SFTPGO_PUID=${SFTPGO_PUID:-1000}
SFTPGO_PGID=${SFTPGO_PGID:-1000}

if [ "$1" = 'sftpgo' ]; then
    if [ "$(id -u)" = '0' ]; then
        for DIR in "/etc/sftpgo" "/var/lib/sftpgo" "/srv/sftpgo"
        do
            DIR_UID=$(stat -c %u ${DIR})
            DIR_GID=$(stat -c %g ${DIR})
            if [ ${DIR_UID} != ${SFTPGO_PUID} ] || [ ${DIR_GID} != ${SFTPGO_PGID} ]; then
                echo `date +%Y-%m-%dT%H:%M:%S` - "entrypoint, change owner for ${DIR} uid: ${SFTPGO_PUID} gid: ${SFTPGO_PGID}"
                if [ ${DIR} = "/etc/sftpgo" ]; then
                    chown -R ${SFTPGO_PUID}:${SFTPGO_PGID} ${DIR}
                else
                    chown ${SFTPGO_PUID}:${SFTPGO_PGID} ${DIR}
                fi
            fi
        done
        echo `date +%Y-%m-%dT%H:%M:%S` - "entrypoint, run as uid: ${SFTPGO_PUID} gid: ${SFTPGO_PGID}"
        exec su-exec ${SFTPGO_PUID}:${SFTPGO_PGID} "$@"
    fi

    exec "$@"
fi

exec "$@"