#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  # replacing SFTPGo renames its user, keeping the id of the files it owns
  if [ -z "$2" ] && /usr/share/gonas/migrate-from-sftpgo --needed; then
    /usr/share/gonas/migrate-from-sftpgo
    MIGRATED=1
  fi

  # Add user and group
  if ! getent group gonas >/dev/null; then
    groupadd --system gonas
  fi
  if ! getent passwd gonas >/dev/null; then
    useradd --system \
      --gid gonas \
      --no-create-home \
      --home-dir /var/lib/gonas \
      --shell /usr/sbin/nologin \
      --comment "GoNAS user" \
      gonas
  fi

  if [ -z "$2" ]; then
    # if configure has no args this is the first installation
    # for upgrades the second arg is the previously installed version
    #
    # initialize data provider, the migration already did it for the copied database
    [ -n "${MIGRATED:-}" ] || gonas initprovider -c /etc/gonas
    # ensure files and folders have the appropriate permissions
    chown -R gonas:gonas /etc/gonas /var/lib/gonas /srv/gonas
    chmod 750 /etc/gonas /etc/gonas/env.d /var/lib/gonas /srv/gonas
    chmod 640 /etc/gonas/gonas.json
  fi

  # set the cap_net_bind_service capability so the service and the CLI
  # commands, such as certificate requests, can bind to privileged ports
  setcap cap_net_bind_service=+ep /usr/bin/gonas || true

fi

if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
	# This will only remove masks created by d-s-h on package removal.
	deb-systemd-helper unmask 'gonas.service' >/dev/null || true

	# was-enabled defaults to true, so new installations run enable.
	if deb-systemd-helper --quiet was-enabled 'gonas.service'; then
		# Enables the unit on first installation, creates new
		# symlinks on upgrades if the unit file has changed.
		deb-systemd-helper enable 'gonas.service' >/dev/null || true
	else
		# Update the statefile to add new symlinks (if any), which need to be
		# cleaned up on purge. Also remove old symlinks.
		deb-systemd-helper update-state 'gonas.service' >/dev/null || true
	fi
fi

if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
	if [ -d /run/systemd/system ]; then
		systemctl --system daemon-reload >/dev/null || true
		if [ -n "$2" ]; then
			_dh_action=restart
		else
			_dh_action=start
		fi
		deb-systemd-invoke $_dh_action 'gonas.service' >/dev/null || true
	fi
fi