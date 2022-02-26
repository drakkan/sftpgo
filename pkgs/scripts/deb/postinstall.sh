#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  # Add user and group
  if ! getent group sftpgo >/dev/null; then
    groupadd --system sftpgo
  fi
  if ! getent passwd sftpgo >/dev/null; then
    useradd --system \
      --gid sftpgo \
      --no-create-home \
      --home-dir /var/lib/sftpgo \
      --shell /usr/sbin/nologin \
      --comment "SFTPGo user" \
      sftpgo
  fi

  if [ -z "$2" ]; then
    # if configure has no args this is the first installation
    # for upgrades the second arg is the previously installed version
    #
    # initialize data provider
    sftpgo initprovider -c /etc/sftpgo
    # ensure files and folders have the appropriate permissions
    chown -R sftpgo:sftpgo /etc/sftpgo /var/lib/sftpgo /srv/sftpgo
    chmod 750 /etc/sftpgo /var/lib/sftpgo /srv/sftpgo
    chmod 640 /etc/sftpgo/sftpgo.json
  fi

  # we added /srv/sftpgo after 1.1.0, we should check if we are upgrading
  # from this version but a non-recursive chmod/chown shouldn't hurt
  if [ -d /srv/sftpgo ]; then
    chown sftpgo:sftpgo /srv/sftpgo
    chmod 750 /srv/sftpgo
  fi

  # set the cap_net_bind_service capability so the service can bind to privileged ports
  setcap cap_net_bind_service=+ep /usr/bin/sftpgo || true

fi

if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
	# This will only remove masks created by d-s-h on package removal.
	deb-systemd-helper unmask 'sftpgo.service' >/dev/null || true

	# was-enabled defaults to true, so new installations run enable.
	if deb-systemd-helper --quiet was-enabled 'sftpgo.service'; then
		# Enables the unit on first installation, creates new
		# symlinks on upgrades if the unit file has changed.
		deb-systemd-helper enable 'sftpgo.service' >/dev/null || true
	else
		# Update the statefile to add new symlinks (if any), which need to be
		# cleaned up on purge. Also remove old symlinks.
		deb-systemd-helper update-state 'sftpgo.service' >/dev/null || true
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
		deb-systemd-invoke $_dh_action 'sftpgo.service' >/dev/null || true
	fi
fi