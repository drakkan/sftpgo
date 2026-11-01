#!/bin/bash

NFPM_VERSION=2.48.0
NFPM_ARCH=${NFPM_ARCH:-amd64}
if [ -z ${GONAS_VERSION} ]
then
  LATEST_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
  NUM_COMMITS_FROM_TAG=$(git rev-list ${LATEST_TAG}.. --count)
  VERSION=$(echo "${LATEST_TAG}" | awk -F. -v OFS=. '{$NF++;print}')-dev.${NUM_COMMITS_FROM_TAG}
else
  VERSION=${GONAS_VERSION}
fi

mkdir dist
echo -n ${VERSION} > dist/version
cd dist
BASE_DIR="../.."

if [ -f "${BASE_DIR}/output/bash_completion/gonas" ]
then
  cp ${BASE_DIR}/output/bash_completion/gonas gonas-completion.bash
else
  $BASE_DIR/gonas gen completion bash > gonas-completion.bash
fi

if [ -d "${BASE_DIR}/output/man/man1" ]
then
  cp -r ${BASE_DIR}/output/man/man1 .
else
  $BASE_DIR/gonas gen man -d man1
fi

if [ ! -f ${BASE_DIR}/gonas ]
then
  cp ${BASE_DIR}/output/gonas ${BASE_DIR}/gonas
  chmod 755 ${BASE_DIR}/gonas
fi

cp ${BASE_DIR}/gonas.json .
sed -i "s|gonas.db|/var/lib/gonas/gonas.db|" gonas.json
sed -i "s|\"users_base_dir\": \"\",|\"users_base_dir\": \"/srv/gonas/data\",|" gonas.json
sed -i "s|\"backups\"|\"/srv/gonas/backups\"|" gonas.json
sed -i "s|\"certs\"|\"/var/lib/gonas/certs\"|" gonas.json

cat >nfpm.yaml <<EOF
name: "gonas"
arch: "${NFPM_ARCH}"
platform: "linux"
version: ${VERSION}
release: 1
section: "net"
priority: "optional"
maintainer: "xrogers <xrogers@gmail.com>"
description: |
  Full-featured and highly configurable SFTP server
  GoNAS has optional HTTP, FTP/S and WebDAV support.
  It can serve local filesystem, S3 (Compatible) Object Storage,
  Google Cloud Storage, Azure Blob Storage, SFTP.
  This is a modified build, not an official GoNAS release.
vendor: "xrogers"
homepage: "https://github.com/xrogers/gonas"
license: "AGPL-3.0"
provides:
  - gonas
# deb: with the conflict below, installing this removes sftpgo. rpm: becomes Obsoletes.
# Never list sftpgo under provides: this is not SFTPGo.
replaces:
  - sftpgo
contents:
  - src: "${BASE_DIR}/gonas${BIN_SUFFIX}"
    dst: "/usr/bin/gonas"

  - src: "./gonas-completion.bash"
    dst: "/usr/share/bash-completion/completions/gonas"

  - src: "./man1/*"
    dst: "/usr/share/man/man1/"

  - src: "${BASE_DIR}/init/gonas.service"
    dst: "/lib/systemd/system/gonas.service"

  - src: "${BASE_DIR}/templates/*"
    dst: "/usr/share/gonas/templates"

  - src: "${BASE_DIR}/static/*"
    dst: "/usr/share/gonas/static"

  - src: "${BASE_DIR}/openapi/*"
    dst: "/usr/share/gonas/openapi"

  - src: "${BASE_DIR}/pkgs/scripts/migrate-from-sftpgo"
    dst: "/usr/share/gonas/migrate-from-sftpgo"
    file_info:
      mode: 0755

  - src: "${BASE_DIR}/MIGRATING.md"
    dst: "/usr/share/doc/gonas/MIGRATING.md"

  - src: "${BASE_DIR}/LICENSE"
    dst: "/usr/share/licenses/gonas/LICENSE"

  - src: "${BASE_DIR}/NOTICE"
    dst: "/usr/share/licenses/gonas/NOTICE"

  - src: "./gonas.json"
    dst: "/etc/gonas/gonas.json"
    type: "config|noreplace"

  - dst: "/srv/gonas"
    type: dir

  - dst: "/var/lib/gonas"
    type: dir

  - dst: "/etc/gonas/env.d"
    type: dir

overrides:
  deb:
    conflicts:
      - sftpgo
    recommends:
      - bash-completion
      - mime-support
      - ffmpeg
    scripts:
      postinstall: ../scripts/deb/postinstall.sh
      preremove: ../scripts/deb/preremove.sh
      postremove: ../scripts/deb/postremove.sh
  rpm:
    recommends:
      - bash-completion
      - mailcap
    scripts:
      postinstall: ../scripts/rpm/postinstall
      preremove: ../scripts/rpm/preremove
      postremove: ../scripts/rpm/postremove

rpm:
  compression: xz

deb:
  compression: xz

EOF

curl --retry 5 --retry-delay 2 --connect-timeout 10 -L -O \
  https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz
tar xvf nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz nfpm
chmod 755 nfpm
mkdir rpm
./nfpm -f nfpm.yaml pkg -p rpm -t rpm
mkdir deb
./nfpm -f nfpm.yaml pkg -p deb -t deb
