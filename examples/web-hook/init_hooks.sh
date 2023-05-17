#!/bin/bash

# exit when any command fails
set -Eeuo pipefail

ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
SFTPGO_URL=http://127.0.0.1:8080

# This user will be created
CRETAE_USER_NAME=demo
CREATE_USER_PASSWORD=demo
USER_HOME_DIR=$(pwd)

# This web-hook action will be created and triggerd sync by "pre-upload","pre-download","pre-delete","pre-lsdir" events
EVENT_ACTION_NAME=demo_webhook
EVENT_ACTION_ENDPOINT=http://localhost:8081/do
EVENT_ACTION_TIMEOUT=20
EVENT_RULE_NAME=demo_rule


function notify {
  echo "Something went wrong!"
}

# echo an error message before exiting
trap notify ERR

# Generating jwt token
token=$(curl $SFTPGO_URL/api/v2/token -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

# Adding user
curl --silent --fail-with-body -X POST -H "Authorization: bearer $token" -d "{\"username\": \"$CRETAE_USER_NAME\", \"password\": \"$CREATE_USER_PASSWORD\", \"home_dir\": \"$USER_HOME_DIR\", \"permissions\": {\"/\": [\"*\"]}, \"status\": 1}" $SFTPGO_URL/api/v2/users

# Adding event action
curl --silent --fail-with-body -X POST -H "Authorization: bearer $token" -d '{
  "id": 1,
  "name": "'$EVENT_ACTION_NAME'",
  "description": "string",
  "type": 1,
  "options": {
    "http_config": {
      "endpoint": "'$EVENT_ACTION_ENDPOINT'",
      "timeout": '$EVENT_ACTION_TIMEOUT',
      "skip_tls_verify": true,
			"body": "{\"CRETAE_USER_NAME\": \"{{Name}}\", \"event\": \"{{Event}}\", \"status\": {{Status}}, \"status_string\": \"{{StatusString}}\", \"error_string\": \"{{ErrorString}}\", \"virtual_path\": \"{{VirtualPath}}\", \"virtual_dir_path\": \"{{VirtualDirPath}}\", \"virtual_target_path\": \"{{VirtualTargetPath}}\", \"fs_path\": \"{{FsPath}}\", \"fs_target_path\": \"{{FsTargetPath}}\", \"file_size\": {{FileSize}}, \"elapsed\": {{Elapsed}}, \"protocol\": \"{{Protocol}}\", \"ip\": \"{{IP}}\", \"role\": \"{{Role}}\", \"timestamp\": {{Timestamp}}, \"object_name\": \"{{ObjectName}}\", \"object_type\": \"{{ObjectType}}\", \"object_data\": \"{{ObjectData}}\"}",
      "method": "POST"}}}' $SFTPGO_URL/api/v2/eventactions

# Adding event rule
curl --silent --fail-with-body -X POST -H "Authorization: bearer $token" -d "{
  \"name\": \"$EVENT_RULE_NAME\",
  \"status\": 1,
  \"trigger\": 1,
  \"conditions\": {
    \"fs_events\": [
     \"pre-upload\",\"pre-download\",\"pre-delete\",\"pre-lsdir\"
    ],
    \"options\": {}
  },
  \"actions\": [
    {
      \"name\": \"$EVENT_ACTION_NAME\",
      \"order\": 1,
      \"relation_options\": {
        \"is_failure_action\": false,
        \"stop_on_failure\": false,
        \"execute_sync\": true
      }
    }
  ]
}" $SFTPGO_URL/api/v2/eventrules

cat << EOF

- Run "v run ."
- Browse to $SFTPGO_URL/web/client/files
- Login using the username "$CRETAE_USER_NAME" and the password "$CREATE_USER_PASSWORD"
- Uploading, downloading and listing dir contnet would trigger the web-hook. any registred fs operation won't executed before the handler return first.

EOF

