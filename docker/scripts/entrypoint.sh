#!/usr/bin/env bash

SFTPGO_PUID=${SFTPGO_PUID:-1000}
SFTPGO_PGID=${SFTPGO_PGID:-1000}

if [ "$1" = 'sftpgo' ]; then
    if [ "$(id -u)" = '0' ]; then
        getent passwd ${SFTPGO_PUID} > /dev/null
	    HAS_PUID=$?
	    getent group ${SFTPGO_PGID} > /dev/null
	    HAS_PGID=$?
        if [ ${HAS_PUID} -ne 0 ] || [ ${HAS_PGID} -ne 0 ]; then
            echo `date +%Y-%m-%dT%H:%M:%S.%3N` - "entrypoint, prepare to run as uid: ${SFTPGO_PUID} gid: ${SFTPGO_PGID}"
            if [ ${HAS_PGID} -ne 0 ];  then
                echo `date +%Y-%m-%dT%H:%M:%S.%3N` - "entrypoint, set GID to: ${SFTPGO_PGID}"
                groupmod -g ${SFTPGO_PGID} sftpgo
            fi
            if [ ${HAS_PUID} -ne 0 ]; then
                echo `date +%Y-%m-%dT%H:%M:%S.%3N` - "entrypoint, set UID to: ${SFTPGO_PUID}"
                usermod -u ${SFTPGO_PUID} sftpgo
            fi
            chown -R ${SFTPGO_PUID}:${SFTPGO_PGID} /etc/sftpgo
            chown ${SFTPGO_PUID}:${SFTPGO_PGID} /var/lib/sftpgo /srv/sftpgo
        fi
        echo `date +%Y-%m-%dT%H:%M:%S.%3N` - "entrypoint, run as uid: ${SFTPGO_PUID} gid: ${SFTPGO_PGID}"
        exec gosu ${SFTPGO_PUID}:${SFTPGO_PGID} "$@"
    fi

    exec "$@"
fi

exec "$@"