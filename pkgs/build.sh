#!/bin/bash

NFPM_VERSION=2.15.1
NFPM_ARCH=${NFPM_ARCH:-amd64}
if [ -z ${SFTPGO_VERSION} ]
then
  LATEST_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
  NUM_COMMITS_FROM_TAG=$(git rev-list ${LATEST_TAG}.. --count)
  VERSION=$(echo "${LATEST_TAG}" | awk -F. -v OFS=. '{$NF++;print}')-dev.${NUM_COMMITS_FROM_TAG}
else
  VERSION=${SFTPGO_VERSION}
fi

mkdir dist
echo -n ${VERSION} > dist/version
cd dist
BASE_DIR="../.."

if [ -f "${BASE_DIR}/output/bash_completion/sftpgo" ]
then
  cp ${BASE_DIR}/output/bash_completion/sftpgo sftpgo-completion.bash
else
  $BASE_DIR/sftpgo gen completion bash > sftpgo-completion.bash
fi

if [ -d "${BASE_DIR}/output/man/man1" ]
then
  cp -r ${BASE_DIR}/output/man/man1 .
else
  $BASE_DIR/sftpgo gen man -d man1
fi

if [ ! -f ${BASE_DIR}/sftpgo ]
then
  cp ${BASE_DIR}/output/sftpgo ${BASE_DIR}/sftpgo
  chmod 755 ${BASE_DIR}/sftpgo
fi

cp ${BASE_DIR}/sftpgo.json .
sed -i "s|sftpgo.db|/var/lib/sftpgo/sftpgo.db|" sftpgo.json
sed -i "s|\"users_base_dir\": \"\",|\"users_base_dir\": \"/srv/sftpgo/data\",|" sftpgo.json
sed -i "s|\"templates\"|\"/usr/share/sftpgo/templates\"|" sftpgo.json
sed -i "s|\"static\"|\"/usr/share/sftpgo/static\"|" sftpgo.json
sed -i "s|\"backups\"|\"/srv/sftpgo/backups\"|" sftpgo.json
sed -i "s|\"openapi\"|\"/usr/share/sftpgo/openapi\"|" sftpgo.json
sed -i "s|\"credentials\"|\"/var/lib/sftpgo/credentials\"|" sftpgo.json

cat >nfpm.yaml <<EOF
name: "sftpgo"
arch: "${NFPM_ARCH}"
platform: "linux"
version: ${VERSION}
release: 1
section: "net"
priority: "optional"
maintainer: "Nicola Murino <nicola.murino@gmail.com>"
description: |
  Fully featured and highly configurable SFTP server
  SFTPGo has optional HTTP, FTP/S and WebDAV support.
  It can serve local filesystem, S3 (Compatible) Object Storage,
  Google Cloud Storage, Azure Blob Storage, SFTP.
vendor: "SFTPGo"
homepage: "https://github.com/drakkan/sftpgo"
license: "AGPL-3.0"
provides:
  - sftpgo
contents:
  - src: "${BASE_DIR}/sftpgo${BIN_SUFFIX}"
    dst: "/usr/bin/sftpgo"

  - src: "./sftpgo-completion.bash"
    dst: "/usr/share/bash-completion/completions/sftpgo"

  - src: "./man1/*"
    dst: "/usr/share/man/man1/"

  - src: "${BASE_DIR}/init/sftpgo.service"
    dst: "/lib/systemd/system/sftpgo.service"

  - src: "${BASE_DIR}/templates/*"
    dst: "/usr/share/sftpgo/templates/"

  - src: "${BASE_DIR}/static/*"
    dst: "/usr/share/sftpgo/static/"

  - src: "${BASE_DIR}/openapi/*"
    dst: "/usr/share/sftpgo/openapi/"

  - src: "./sftpgo.json"
    dst: "/etc/sftpgo/sftpgo.json"
    type: "config|noreplace"

  - dst: "/srv/sftpgo"
    type: dir

  - dst: "/var/lib/sftpgo"
    type: dir

overrides:
  deb:
    recommends:
      - bash-completion
      - mime-support
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
