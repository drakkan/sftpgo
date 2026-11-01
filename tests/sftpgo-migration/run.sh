#!/bin/sh
# Installs a real SFTPGo package in a booted Debian container, fills it, then replaces it with the
# GoNAS package and checks the result from the outside. Run as root, on a machine with systemd.
# Usage: run.sh gonas.deb sftpgo.deb
# Needs systemd-container and debootstrap. Keeps the base system in $WORK to save time on the next run.
set -u
[ $# -eq 2 ] || { echo "usage: $0 gonas.deb sftpgo.deb" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
GONAS_DEB=$(realpath "$1")
SFTPGO_DEB=$(realpath "$2")
WORK=${WORK:-/var/tmp/gonas-migration}
BASE=$WORK/base
ROOT=$WORK/root
MACHINE=gonas-migration
FAILED=0

inside() {
  systemd-run -M "$MACHINE" --wait --pipe -q "$@"
}

stop() {
  machinectl poweroff "$MACHINE" 2>/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    machinectl list --no-legend | grep -q "$MACHINE" || return 0
    sleep 1
  done
}

boot() {
  systemd-nspawn -q -D "$ROOT" -b --machine="$MACHINE" --console=read-only >"$WORK/nspawn.log" 2>&1 &
  for _ in $(seq 1 60); do
    inside /bin/true >/dev/null 2>&1 && break
    sleep 0.5
  done
  inside /bin/sh -c 'systemctl is-system-running --wait >/dev/null 2>&1; true'
}

fresh() {
  stop
  rm -rf "$ROOT"
  cp -a "$WORK/seeded" "$ROOT"
  cp "$HERE/verify.py" "$HERE/lib.py" "$ROOT/root/"
  boot
}

install_gonas() {
  inside /bin/sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends /root/gonas.deb' 2>&1 |
    grep -E 'GoNAS migration|^E: '
  sleep 2
}

verify() {
  echo "=== $1"
  inside python3 /root/verify.py || FAILED=$((FAILED + 1))
}

mkdir -p "$WORK"
if [ ! -d "$BASE" ]; then
  /usr/sbin/debootstrap --variant=minbase \
    --include=systemd,systemd-sysv,dbus,curl,ca-certificates,python3,openssh-client,libcap2-bin \
    trixie "$BASE" http://deb.debian.org/debian >"$WORK/debootstrap.log" 2>&1 || exit 1
fi
stop
rm -rf "$ROOT" "$WORK/seeded"
cp -a "$BASE" "$ROOT"
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
cp "$HERE/seed.sh" "$HERE/seed.py" "$HERE/lib.py" "$ROOT/root/"
cp "$SFTPGO_DEB" "$ROOT/root/sftpgo.deb"
cp "$GONAS_DEB" "$ROOT/root/gonas.deb"
boot
inside /bin/sh /root/seed.sh | grep -E '^seeded' || exit 1
stop
cp -a "$ROOT" "$WORK/seeded"

fresh
install_gonas
verify "replacing SFTPGo"

echo "=== reinstalling does not migrate again"
inside /bin/sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall --no-install-recommends /root/gonas.deb' 2>&1 |
  grep -c 'GoNAS migration' | grep -qx 0 || FAILED=$((FAILED + 1))
sleep 2
verify "after reinstalling"

echo "=== going back, as MIGRATING.md says"
inside /bin/sh -c 'DEBIAN_FRONTEND=noninteractive; export DEBIAN_FRONTEND
  apt-get remove -y gonas >/dev/null 2>&1
  groupmod -n sftpgo gonas
  usermod -l sftpgo -d /var/lib/sftpgo -c "SFTPGo user" gonas
  apt-get install -y --no-install-recommends /root/sftpgo.deb >/dev/null 2>&1
  sleep 2
  systemctl is-active sftpgo
  printf "get new.txt /root/back.txt\nbye\n" | sftp -q -b - -i /root/client_key -P 2222 \
    -o UserKnownHostsFile=/root/kh -o StrictHostKeyChecking=yes alice@127.0.0.1' >/dev/null || FAILED=$((FAILED + 1))

fresh
echo "=== a failed migration must not start GoNAS"
inside /bin/sh -c 'cp /etc/sftpgo/sftpgo.json /root/good.json; sed -i "1s/^{/{ broken/" /etc/sftpgo/sftpgo.json'
install_gonas
inside /bin/sh -c '[ "$(systemctl is-active gonas)" != active ]' || FAILED=$((FAILED + 1))
inside /bin/sh -c 'cp /root/good.json /etc/sftpgo/sftpgo.json; dpkg --configure -a' 2>&1 | grep -E 'migration: done'
sleep 2
verify "after fixing the cause"

stop
if [ "$FAILED" -eq 0 ]; then echo "ALL PASSED"; else echo "$FAILED FAILED"; fi
exit "$FAILED"
