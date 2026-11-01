#!/usr/bin/env bash
# Browser tests for the WebClient. Usage: tests/webclient-e2e/run.sh [client|strict|prefs]
#   client  every page and flow, with a copy of the Android app's page hooks
#   strict  the same under a strict nonce Content-Security-Policy
#   prefs   language and theme choices
# Needs Go, Node and a Chromium: run "npx playwright install chromium" here once.
set -u
MODE=${1:-client}
HERE=$(cd "$(dirname "$0")" && pwd)
F=$(cd "$HERE/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
R=$WORK/run
SHOTS=$WORK/shots
rm -rf "$R"; mkdir -p "$R" "$SHOTS"
[ -d "$HERE/node_modules" ] || (cd "$HERE" && npm install --silent)
(cd "$F" && GOTOOLCHAIN=auto go build -o "$WORK/server" .) || exit 1
cp "$F/gonas.json" "$R/gonas.json"
LANGS=en,pl,de
[ "$MODE" = prefs ] && LANGS=en,pl,de,zh-CN
export GONAS_HTTPD__BINDINGS__0__PORT=18183 GONAS_HTTPD__BINDINGS__0__ADDRESS=127.0.0.1 \
  GONAS_HTTPD__BINDINGS__0__LANGUAGES=$LANGS GONAS_SFTPD__BINDINGS__0__PORT=0 GONAS_FTPD__BINDINGS__0__PORT=0 \
  GONAS_WEBDAVD__BINDINGS__0__PORT=0 GONAS_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1 \
  GONAS_DEFAULT_ADMIN_USERNAME=admin GONAS_DEFAULT_ADMIN_PASSWORD=e2e-Password-1 \
  GONAS_HTTPD__TEMPLATES_PATH=$F/templates GONAS_HTTPD__STATIC_FILES_PATH=$F/static \
  GONAS_HTTPD__OPENAPI_PATH=$F/openapi GONAS_SMTP__TEMPLATES_PATH=$F/templates GONAS_DATA_PROVIDER__NAME=$R/e2e.db
if [ "$MODE" = strict ]; then
  export GONAS_HTTPD__BINDINGS__0__SECURITY__ENABLED=1
  export GONAS_HTTPD__BINDINGS__0__SECURITY__CONTENT_SECURITY_POLICY="default-src 'none'; script-src \$NONCE; style-src 'self' \$NONCE; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'self'; base-uri 'none'; form-action 'self'"
fi
B=http://127.0.0.1:18183
(cd "$R" && exec "$WORK/server" serve --config-dir "$R" --log-file-path "$R/server.log" >/dev/null 2>&1) &
SPID=$!
trap 'kill $SPID 2>/dev/null' EXIT
for _ in $(seq 1 60); do curl -sf -o /dev/null --max-time 1 $B/healthz && break; sleep 0.25; done
T=$(curl -s --max-time 5 -u admin:e2e-Password-1 $B/api/v2/token | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
H=$R/alice
mkdir -p "$H/photos" "$H/docs" "$H/readonly"
echo 'note body' > "$H/note.txt"; echo x > "$H/copy-me.txt"; echo x > "$H/drag-me.txt"; echo deep > "$H/docs/deep.txt"
python3 -I - "$H" <<'PY'
import sys,zlib,struct
h=sys.argv[1]
w=64; raw=b''.join(b'\0'+b''.join(bytes([x*4%256,y*4%256,120]) for x in range(w)) for y in range(w))
c=lambda t,d:struct.pack('>I',len(d))+t+d+struct.pack('>I',zlib.crc32(t+d))
png=b'\x89PNG\r\n\x1a\n'+c(b'IHDR',struct.pack('>IIBBBBB',w,w,8,2,0,0,0))+c(b'IDAT',zlib.compress(raw))+c(b'IEND',b'')
for n in ('pic','two','three'): open(f'{h}/photos/{n}.png','wb').write(png)
open(h+'/paper.pdf','wb').write(b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 200]>>endobj\ntrailer<</Root 1 0 R>>')
PY
curl -s -o /dev/null -w "user %{http_code}\n" --max-time 5 -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"password\":\"e2e-User-Pass-1\",\"status\":1,\"home_dir\":\"$H\",\"permissions\":{\"/\":[\"*\"],\"/readonly\":[\"list\",\"download\"]}}" $B/api/v2/users
cd "$HERE" || exit 1
if [ "$MODE" = prefs ]; then timeout 150 node prefs.js $B "$SHOTS"; else timeout 240 node client.js $B "$SHOTS" "$H" "$T"; fi
RC=$?
echo "screenshots: $SHOTS"
exit $RC
