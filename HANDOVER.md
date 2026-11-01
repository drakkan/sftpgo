# Handover

State of the fork, for carrying on from another machine.

## Where things are

- `gonas` is the build to run: `local/integration`, renamed, with the new WebAdmin.
- The newest package on `Y:\`, `sftpgo_2.7.99~local.2fb9a683-1_amd64.deb`, predates the rename.
- `FORK_FEATURES.md` describes the rewritten UIs. The Android wrapper depends on what it lists.

## Decisions

- **Name:** the fork becomes **GoNAS**. Checked 2026-11-01: free on npm, PyPI, crates.io and Debian,
  and no company or trademark found by web search. USPTO and EUIPO were not searched directly. Two
  tiny GitHub projects use the name (`ssutikno/gonas`, `jimmydagumjr/GoNAS`), and `gonas.io` looked
  free. Check the registers before any public release.
- **WebAdmin:** replaced. Every page was rewritten without the theme, and `templates/common` and
  `static/assets` are gone. It keeps the URLs, form fields and permissions of the old pages.

## Not done

**Licence and rebrand.** <https://sftpgo.com/compliance.html> asks a modified version not to use the
theme-based UI and to be fully rebranded, including the software and binaries. The name, binary, paths,
environment prefix, headers, logo and icons have changed, and no theme code is left.
`TestWebUIsStayFreeOfTheTheme` guards the theme part. This is not legal advice: have it checked before
any public release, and search the USPTO and EUIPO registers for the name.

- `LICENSE`, `NOTICE`, the copyright headers and the `github.com/sftpgo/sdk` dependency stay.
- Stored values kept on purpose: `sftpgo_last_modified` in object metadata is still read (`internal/vfs/vfs.go`).
- Installing the package over SFTPGo migrates it: see `MIGRATING.md`. User files stay in `/srv/sftpgo` on
  purpose, so those paths and `users_base_dir` keep the old name on migrated systems. To test it, build
  the package, then run `sudo tests/sftpgo-migration/run.sh gonas.deb sftpgo.deb` on a machine with systemd.
- The footer's source link points to `xrogers/sftpgo`, so update it if the repository is renamed.

## Android wrapper

The app is a separate repository: `git@github.com:xrogers/sftpgo-android.git`. It builds with the debug key of the machine it was
built on, and Android refuses updates signed with another key, so take `~/.android/debug.keystore`
along, or reinstall the app, which removes its saved sign-in.

## Building and testing

```sh
GOTOOLCHAIN=auto go test ./internal/httpd/... ./internal/config/... -count=1
tests/webclient-e2e/run.sh client   # also: strict, prefs, admin
```

The Go tests need the plugins in `tests/eventsearcher` and `tests/ipfilter` built first. The test
database is `gonas.db*` in the repo root: delete it after an aborted run, with `backups/` and
`thumbnails/`. All of these are ignored by git.

To build the deb from a clean worktree, with the commit's short hash as `<hash>`:

```sh
GOTOOLCHAIN=auto CGO_ENABLED=1 go build -trimpath -tags netgo,osusergo \
  -ldflags "-s -w -linkmode external -extldflags -static" -o sftpgo .
cd pkgs && SFTPGO_VERSION="2.7.99~local.<hash>" bash build.sh   # output in dist/deb/
```

Never run privileged systemd containers on the WSL machine without masking `systemd-binfmt`: they
wipe `WSLInterop`, shared with Docker Desktop, and Windows programs stop working from WSL.
