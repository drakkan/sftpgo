# New web UIs (fork)

Both web UIs were rewritten for this fork. The WebClient lives in `templates/webclient` and
`static/webclient`, the WebAdmin in `templates/webadmin` and `static/webadmin`, on top of the
WebClient's layout and helpers. The proprietary theme is gone from the tree: no KeenThemes
markup, CSS, icons or bundles, and no jQuery or Bootstrap. `TestWebUIsStayFreeOfTheTheme` fails
if that changes, and `tests/webclient-e2e/run.sh admin` drives the WebAdmin in a browser.

- Scripts are plain files with no build step, so that each one can carry the nonce of a
  strict Content-Security-Policy.
- Atkinson Hyperlegible Next (`static/webclient/fonts`, OFL) keeps `l`, `I`, `1`, `O`
  and `0` apart in file names. The icons are from Lucide (`ICONS-LICENSE.txt`, ISC).
- New strings are in the `client` section of the locale files.

The Android wrapper depends on this behaviour, so keep it: `sign_in_form` and
`sign_in_submit` on the sign-in pages, one `XMLHttpRequest` per upload with the `File` as
its body, and zip downloads as a post form with `target="_blank"`.

## Language dropdown

Every page has one, listing the languages in the binding's `languages` setting. It
applies without a reload. A language picked there is remembered in the browser. Until
then the page follows the browser's language list in order, and falls back to the first
configured language.

## Passkeys

Users and admins can add passkeys on the 2FA page, and sign in with one from the login page instead
of a password. They are stored in the account's filters, so they need no schema change and are part
of backups. The settings are in `httpd.passkeys`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Show passkeys in both UIs |
| `skip_two_factor` | `true` | Whether a passkey satisfies two-factor authentication |
| `android_package_name` | `com.rogers.gonas` | Package of the Android app |
| `android_cert_fingerprints` | empty | SHA-256 fingerprints of its signing certificates |
| `rp_id` | empty | Domain passkeys belong to. Empty means the host name of each request |
| `origins` | empty | Allowed origins. Empty means the origin of each request |

`skip_two_factor` decides what a passkey counts as:

- **`true`:** signing in with a passkey is complete, with no code even if the account has TOTP. It
  can be used instead of the code after a password, and it meets "2FA required" for HTTP. Other
  protocols still need TOTP. An account whose only second factor is a passkey cannot sign in with a
  password alone, and gets recovery codes.
- **`false`:** it only replaces the password. An account with TOTP still enters a code, and "2FA
  required" still means TOTP.

An account with no requirement and no TOTP keeps its password login after adding a passkey.

- Browsers only offer passkeys on `https://` or `localhost`, and never on an IP address. The button
  stays hidden elsewhere.
- With `rp_id` empty, a passkey works only on the host name it was added on. Set `rp_id` to the parent
  domain and list every origin in `origins` to use several. Changing `rp_id` later makes existing
  passkeys stop working. Behind a proxy that does not send `X-Forwarded-Proto`, set `origins`.
- Adding a passkey needs a sign in from the last 10 minutes, as a passkey can get past 2FA.
- "Disable 2FA" in the WebAdmin and `resetpwd` also remove passkeys, as both are the way back in.
- A user who cannot use a password over HTTP (`denied_login_methods`) cannot use a passkey either.
- The REST API can use passkeys too, see [REST API for native apps](#rest-api-for-native-apps). A token
  request with a password from an account that must use 2FA still needs TOTP, and one from an account
  whose second factor is a passkey is refused, as on the login page.
- For the Android app, set `android_cert_fingerprints`. That publishes
  `/.well-known/assetlinks.json`, which Android needs before it lets an app use a domain's passkeys,
  and accepts the app's origin. Two forms of that origin are derived from each fingerprint, as sources
  disagree on the name. If a device reports something else, add the exact value to `origins`.

Challenges are signed instead of stored, so that visitors cannot fill the server with them, and
`invalidatedJWTTokens` makes each one single use. They last 5 minutes and are bound to the client's
address. `tests/webclient-e2e/run.sh passkey` tests all of this through Chromium's virtual
authenticator, with `SKIP_2FA=0` for the other mode.

## REST API for native apps

The Android app talks to the REST API instead of wrapping the WebClient. These routes are in
`openapi/openapi.yaml`, and `api_user_native_test.go` tests them with a key held the way the app
holds its own.

| Route | Use |
| --- | --- |
| `GET /api/v2/user/token/passkey` | WebAuthn options and a token holding their challenge |
| `POST /api/v2/user/token/passkey` | An API token for `{token, credential}`, as `/api/v2/user/token` returns |
| `GET /api/v2/user/token/refresh` | A new token for a valid one, up to 12 hours after the sign in |
| `GET /api/v2/user/passkeys` | The user's passkeys |
| `POST /api/v2/user/passkeys/begin`, `/finish` | Add a passkey, as the 2FA page does |
| `DELETE /api/v2/user/passkeys/{id}` | Remove one |
| `GET /api/v2/user/search?q=&path=` | The WebClient's recursive search, as folder entries plus `path` |
| `GET /api/v2/user/thumbnail?path=` | The WebClient's thumbnails |

- Challenges of the API and of the login page have different audiences, so neither works for the other.
- API tokens now record when the credentials were checked, like web sessions. A refresh keeps that
  time, so a token can add a passkey only in the first 10 minutes after the sign in, and a session
  ends 12 hours after it, as in the WebClient. A changed password or a disabled account ends it sooner.
- A passkey token counts the passkey as the second factor, if `skip_two_factor` is on. Otherwise an
  account with TOTP also sends its code, in `X-GONAS-OTP`.
- The passkey routes refuse API keys, like the TOTP ones.

## API keys

`/web/client/api-keys` lets users create, list and revoke their own keys. It reuses the
REST handlers behind routes that need a form token, and sessions opened with a key
cannot reach it. Users need `allow_api_key_auth` turned on in their profile.

# WebClient enhancements (fork)

This fork adds three **additive, backward-compatible** features to the end-user
WebClient file browser. Nothing in the SFTP/FTP/WebDAV protocols, authentication,
crypto, or the virtual-filesystem sandbox is changed; every feature lives in the
web/HTTP layer and reuses the existing per-user permission checks. Existing
endpoints keep their behavior — only new routes and new optional query params /
config keys were added.

## 1. Drag-and-drop move

Drag a file or folder row onto another folder to move it there, or onto the
breadcrumb to move it up one level. It reuses the existing
`/web/client/file-actions/move` endpoint and its task-status polling — there is
**no** new backend code. It is only enabled for users with rename permission and
is automatically disabled while viewing search results (whose items span
folders).

## 2. Recursive search (wildcard + partial)

The toolbar search box now searches the current directory **and everything
beneath it**.

- New endpoint: `GET /web/client/search?path=<start dir>&q=<query>`
- Wildcard/glob matching when `q` contains `*` or `?` (via `path.Match`),
  otherwise case-insensitive substring ("partial") matching.
- Results use the exact same JSON row shape as `/web/client/dirs`, with an extra
  `path` field naming each hit's parent folder. A "Location" column is revealed
  in the UI so results are navigable.
- The walk goes through the user's permissions per directory and is bounded by
  safety caps (5000 directories / 2000 results) so recursive listing on cloud
  backends (S3/GCS/Azure) can't run away; when a cap is hit the walk stops early
  and logs it, returning partial results.

## 3. Photo/video thumbnails + grid view

Image and (when ffmpeg is available) video files show small cached thumbnails in
the listing, and a toolbar toggle switches to a gallery/grid view. Clicking a
photo in the grid opens the viewer.

- New endpoint: `GET /web/client/thumbnail?path=<file>` returns a ~200px JPEG.
- Files are always opened **through the user's connection**, so the storage
  backend and sandbox are respected. Any failure returns `404` and the UI falls
  back to a generic icon — the main listing never depends on this endpoint.
- Supported image sources: `jpg`, `jpeg`, `png`, `gif`, `webp`, `bmp`.
- Video sources (`mp4`, `mov`, `mkv`, `webm`, `avi`, `m4v`) require **ffmpeg**.
  If ffmpeg is not found, video thumbnails are disabled and videos fall back to
  a generic icon; images still work.
- Thumbnails are cached on disk keyed by user + path + mod time + size, and
  served with `ETag`/`If-None-Match` (304) support.

### ffmpeg (optional, for video thumbnails)

Install ffmpeg and make sure it is on `PATH` (or set `ffmpeg_path`). For example:

```sh
# Debian/Ubuntu
apt-get install -y ffmpeg
# macOS
brew install ffmpeg
```

### Configuration (`sftpgo.json` → `httpd.thumbnails`)

All keys are optional; thumbnails are enabled by default.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Globally enable/disable thumbnail generation. |
| `cache_dir` | `""` | Cache directory (absolute or relative to the config dir). Empty → `thumbnails` inside the config dir. |
| `cache_max_size` | `512` | Max total cache size in MB; oldest thumbnails are evicted past this. `0` = unlimited. |
| `max_source_size` | `100` | Max source file size in MB to thumbnail; larger files fall back to an icon. |
| `ffmpeg_path` | `""` | Path to the ffmpeg binary. Empty → look it up in `PATH`. |

Every key can also be set via environment variable, e.g.
`SFTPGO_HTTPD__THUMBNAILS__ENABLED=false`.
