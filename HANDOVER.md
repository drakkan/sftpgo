# Handover

State of the fork, for carrying on from another machine.

## Where things are

- `local/integration` is the build to run: every feature branch merged.
- The newest package is on `Y:\`: `sftpgo_2.7.99~local.2fb9a683-1_amd64.deb`. It predates this note,
  which adds only tests and documentation.
- `FORK_FEATURES.md` describes the WebClient rewrite. The Android wrapper depends on what it lists.

## Decisions

- **Name:** the fork becomes **GoNAS**. Checked 2026-11-01: free on npm, PyPI, crates.io and Debian,
  and no company or trademark found by web search. USPTO and EUIPO were not searched directly. Two
  tiny GitHub projects use the name (`ssutikno/gonas`, `jimmydagumjr/GoNAS`), and `gonas.io` looked
  free. Check the registers before any public release.
- **WebAdmin:** removal was started and then cancelled before anything changed. It stays for now.

## Not done

**Licence.** Per <https://sftpgo.com/compliance.html>, a modified version must not use the theme-based
UI and must be fully rebranded, including the software and binaries. WebAdmin (`templates/webadmin`,
`templates/common`, `static/assets`) still uses the theme, so these branches do not meet that. The
WebClient does: `TestWebClientStaysFreeOfTheTheme` guards it. Options: replace WebAdmin, remove it,
ask support@sftpgo.com for a grant, or adapt the UI from 2.5.6 or earlier.

**Rebrand.** Not started. What was found so far:

- Rename the module path, binary, package, service, user, `/etc`, `/var/lib` and `/srv` paths, config
  file, `SFTPGO_` environment prefix, `X-SFTPGO-` headers, metric names, the logo, and the UI text.
- Leave `LICENSE`, `NOTICE`, the copyright headers and the `github.com/sftpgo/sdk` dependency alone.
- Stored values to keep or migrate, not rename blindly: `sftpgo_last_modified` (object metadata on
  S3 and friends in `internal/vfs/vfs.go`) and `sftpgo.migration` (MySQL lock, safe once no old
  version runs). Test the rename against a database made by the old build, including an encrypted
  secret.
- An installed system needs a migration: the service user, the config paths and the home directories
  stored in the database all contain the old name.
- If WebAdmin is ever removed, a fresh install has no setup page: the first admin has to come from
  `create_default_admin` and its environment variables.
- The footer's source link points to `xrogers/sftpgo`, so update it if the repository is renamed.

## Android wrapper

The app is a separate repository: `git@github.com:xrogers/sftpgo-android.git`. It builds with the debug key of the machine it was
built on, and Android refuses updates signed with another key, so take `~/.android/debug.keystore`
along, or reinstall the app, which removes its saved sign-in.

## Building and testing

```sh
GOTOOLCHAIN=auto go test ./internal/httpd/... ./internal/config/... -count=1
tests/webclient-e2e/run.sh client   # also: strict, prefs
```

The Go tests need the plugins in `tests/eventsearcher` and `tests/ipfilter` built first. The test
database is `sftpgo.db*` in the repo root: delete it after an aborted run, with `backups/` and
`thumbnails/`.

To build the deb from a clean worktree, with the commit's short hash as `<hash>`:

```sh
GOTOOLCHAIN=auto CGO_ENABLED=1 go build -trimpath -tags netgo,osusergo \
  -ldflags "-s -w -linkmode external -extldflags -static" -o sftpgo .
cd pkgs && SFTPGO_VERSION="2.7.99~local.<hash>" bash build.sh   # output in dist/deb/
```

Never run privileged systemd containers on the WSL machine without masking `systemd-binfmt`: they
wipe `WSLInterop`, shared with Docker Desktop, and Windows programs stop working from WSL.
