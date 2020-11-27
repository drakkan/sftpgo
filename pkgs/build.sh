#!/bin/bash

NFPM_VERSION=1.10.2
NFPM_ARCH=${NFPM_ARCH:-amd64}
if [ -z ${SFTPGO_VERSION} ]
then
  LATEST_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
  NUM_COMMITS_FROM_TAG=$(git rev-list ${LATEST_TAG}.. --count)
  #COMMIT_HASH=$(git rev-parse --short HEAD)
  VERSION=$(echo "${LATEST_TAG}" | awk -F. -v OFS=. '{$NF++;print}')-dev.${NUM_COMMITS_FROM_TAG}
else
  VERSION=${SFTPGO_VERSION}
fi

mkdir dist
echo -n ${VERSION} > dist/version
cd dist
BASE_DIR="../.."

cp ${BASE_DIR}/sftpgo.json .
cp ${BASE_DIR}/examples/rest-api-cli/sftpgo_api_cli .
sed -i "s|sftpgo.db|/var/lib/sftpgo/sftpgo.db|" sftpgo.json
sed -i "s|\"users_base_dir\": \"\",|\"users_base_dir\": \"/srv/sftpgo/data\",|" sftpgo.json
sed -i "s|\"templates\"|\"/usr/share/sftpgo/templates\"|" sftpgo.json
sed -i "s|\"static\"|\"/usr/share/sftpgo/static\"|" sftpgo.json
sed -i "s|\"backups\"|\"/srv/sftpgo/backups\"|" sftpgo.json
sed -i "s|\"credentials\"|\"/var/lib/sftpgo/credentials\"|" sftpgo.json

$BASE_DIR/sftpgo gen completion bash > sftpgo-completion.bash
$BASE_DIR/sftpgo gen man -d man1

cat >nfpm.yaml <<EOF
name: "sftpgo"
arch: "${NFPM_ARCH}"
platform: "linux"
version: ${VERSION}
release: 1
section: "net"
priority: "optional"
maintainer: "Nicola Murino <nicola.murino@gmail.com>"
provides:
  - sftpgo
description: |
  Fully featured and highly configurable SFTP server
  SFTPGo has optional FTP/S and WebDAV support.
  It can serve local filesystem, S3 (Compatible) Object Storage,
  Google Cloud Storage and Azure Blob Storage.
vendor: "SFTPGo"
homepage: "https://github.com/drakkan/sftpgo"
license: "GPL-3.0"
files:
  ${BASE_DIR}/sftpgo${BIN_SUFFIX}: "/usr/bin/sftpgo"
  ./sftpgo-completion.bash: "/usr/share/bash-completion/completions/sftpgo"
  ./man1/*: "/usr/share/man/man1/"
  ${BASE_DIR}/init/sftpgo.service: "/lib/systemd/system/sftpgo.service"
  ./sftpgo_api_cli: "/usr/bin/sftpgo_api_cli"
  ${BASE_DIR}/templates/*: "/usr/share/sftpgo/templates/"
  ${BASE_DIR}/static/**/*: "/usr/share/sftpgo/static/"

config_files:
  ./sftpgo.json: "/etc/sftpgo/sftpgo.json"

empty_folders:
  - /var/lib/sftpgo
  - /srv/sftpgo

overrides:
  deb:
    recommends:
      - bash-completion
      - mime-support
    suggests:
      - python3-requests
      - python3-pygments
    scripts:
      postinstall: ../scripts/deb/postinstall.sh
      preremove: ../scripts/deb/preremove.sh
      postremove: ../scripts/deb/postremove.sh
  rpm:
    recommends:
      - bash-completion
      - mailcap
      # centos 8 has python3-requests, centos 6/7 python-requests
    scripts:
      postinstall: ../scripts/rpm/postinstall
      preremove: ../scripts/rpm/preremove
      postremove: ../scripts/rpm/postremove

rpm:
  compression: lzma

  config_noreplace_files:
    ./sftpgo.json: "/etc/sftpgo/sftpgo.json"

EOF

curl --retry 5 --retry-delay 2 --connect-timeout 10 -L -O \
  https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz
tar xvf nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz nfpm
chmod 755 nfpm
mkdir rpm
./nfpm -f nfpm.yaml pkg -p rpm -t rpm
sed -i "s|env python|env python3|" sftpgo_api_cli
mkdir deb
./nfpm -f nfpm.yaml pkg -p deb -t deb
