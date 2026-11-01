#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq --no-install-recommends /root/sftpgo.deb >/root/apt.log 2>&1
cat >/etc/sftpgo/sftpgo.env <<X
SFTPGO_HTTPD__BINDINGS__0__PORT=8090
SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1
SFTPGO_DEFAULT_ADMIN_USERNAME=admin
SFTPGO_DEFAULT_ADMIN_PASSWORD=Seed-Admin-Pass-1
X
cat >/etc/sftpgo/env.d/custom.env <<X
SFTPGO_SFTPD__BINDINGS__0__PORT=2222
SFTPGO_KMS__SECRETS__MASTER_KEY=a-master-key-only-in-env-d-012345
X
chown -R sftpgo:sftpgo /etc/sftpgo/env.d
mkdir -p /etc/systemd/system/sftpgo.service.d
printf '[Service]\nEnvironment=SFTPGO_COMMON__IDLE_TIMEOUT=7\n' >/etc/systemd/system/sftpgo.service.d/override.conf
mkdir -p /mnt/ext/bob /srv/sftpgo/data/alice; chown -R sftpgo:sftpgo /mnt/ext /srv/sftpgo/data
systemctl daemon-reload; systemctl restart sftpgo
for _ in $(seq 1 40); do curl -sf -o /dev/null http://127.0.0.1:8090/healthz && break; sleep 0.25; done
ssh-keygen -q -t ed25519 -N '' -f /root/client_key
python3 /root/seed.py
echo hello-from-sftpgo >/root/f.txt; rm -f /root/kh
for u in alice bob; do printf 'put /root/f.txt\nbye\n' | sftp -q -b - -i /root/client_key -P 2222 -o UserKnownHostsFile=/root/kh -o StrictHostKeyChecking=accept-new $u@127.0.0.1 >/dev/null; done
id -u sftpgo >/root/old_uid
ls -la /etc/sftpgo /var/lib/sftpgo | cut -c1-70; find /srv/sftpgo /mnt/ext -type f -printf '%u %p\n'
