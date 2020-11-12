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
            echo '{"level":"info","time":"'`date +%Y-%m-%dT%H:%M:%S.%3N`'","sender":"entrypoint","message":"prepare to run as UID: '${SFTPGO_PUID}' GID: '${SFTPGO_PGID}'"}'
            if [ ${HAS_PGID} -ne 0 ];  then
                echo '{"level":"info","time":"'`date +%Y-%m-%dT%H:%M:%S.%3N`'","sender":"entrypoint","message":"set GID to: '${SFTPGO_PGID}'"}'
                groupmod -g ${SFTPGO_PGID} sftpgo
            fi
            if [ ${HAS_PUID} -ne 0 ]; then
                echo '{"level":"info","time":"'`date +%Y-%m-%dT%H:%M:%S.%3N`'","sender":"entrypoint","message":"set UID to: '${SFTPGO_PUID}'"}'
                usermod -u ${SFTPGO_PUID} sftpgo
            fi
            chown -R ${SFTPGO_PUID}:${SFTPGO_PGID} /etc/sftpgo
            chown ${SFTPGO_PUID}:${SFTPGO_PGID} /var/lib/sftpgo /srv/sftpgo
        fi
        echo '{"level":"info","time":"'`date +%Y-%m-%dT%H:%M:%S.%3N`'","sender":"entrypoint","message":"run as UID: '${SFTPGO_PUID}' GID: '${SFTPGO_PGID}'"}'
        exec gosu ${SFTPGO_PUID}:${SFTPGO_PGID} "$@"
    fi

    exec "$@"
fi

exec "$@"