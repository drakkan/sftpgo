# Migrating from SFTPGo

Installing the GoNAS package takes over an installed SFTPGo:

```sh
apt install ./gonas_*.deb     # or: dnf install ./gonas-*.rpm
```

Use `apt`, not `dpkg -i`: dpkg refuses to remove `sftpgo` by itself, and stops without changing anything.

Stop here and read the rest first if clients depend on what is listed under
[What you need to change](#what-you-need-to-change). Back up as for any upgrade.

## What happens

The package removes `sftpgo`, then `/usr/share/gonas/migrate-from-sftpgo`:

| What | How |
| --- | --- |
| Service | `sftpgo.service` is stopped and disabled, `gonas.service` starts |
| Service user | `sftpgo` is renamed to `gonas` and keeps its id, so all files keep their owner, also outside `/srv` |
| Configuration | `/etc/sftpgo` is copied to `/etc/gonas`, with the SSH host keys, so clients see the same server |
| Settings | `SFTPGO_` becomes `GONAS_` in `sftpgo.env`, `env.d/*` and overrides in `sftpgo.service.d`, and paths in `/etc` and `/var/lib` are updated |
| Database | `/var/lib/sftpgo` is copied to `/var/lib/gonas`, without the thumbnails cache, and its schema is upgraded |
| User files | Not touched: they stay in `/srv/sftpgo`, and the home directories in the database stay valid |

Accounts, passwords, two-factor settings, API keys and encrypted secrets keep working. Web
sessions end, unless the signing passphrase or key came along, so users may have to sign in again.

If it fails, the package stays unconfigured and GoNAS does not start. Fix the cause shown, then run
`dpkg --configure -a`.

## What you need to change

These names changed with the rename, and only you can update what uses them:

- **Hooks and event actions:** scripts get `GONAS_ACTION_*` and `GONAS_CONNECTION_*` instead of
  `SFTPGO_ACTION_*` and `SFTPGO_CONNECTION_*`.
- **API clients:** `X-SFTPGO-API-KEY`, `X-SFTPGO-OTP` and other `X-SFTPGO-*` headers are now `X-GONAS-*`.
- **Metrics:** the `sftpgo_*` Prometheus metrics are now `gonas_*`.
- **MFA:** authenticator apps keep working. New enrolments show the issuer set in the configuration.
- **Containers and manual installs:** there is no package to run this for you. Rename the same
  paths and variables by hand, or run the script if your layout matches the packages.

With PostgreSQL or MySQL the database is shared, not copied, so the schema upgrade applies to it directly.

## Going back

As long as `sftpgo` was not purged, and with a SQLite database, its files are still in place:

```sh
apt remove gonas
groupmod -n sftpgo gonas
usermod -l sftpgo -d /var/lib/sftpgo -c "SFTPGo user" gonas
apt install ./sftpgo_*.deb
```

Changes made in GoNAS after the migration, such as new accounts, are lost, as they are in its own copy of
the database. Files uploaded meanwhile stay, as they are in `/srv/sftpgo`.

## Cleaning up

When you are sure, remove `/etc/sftpgo` and `/var/lib/sftpgo`. They hold your host keys and secrets, so
do not leave them forever. Do not remove `/srv/sftpgo`: that is where the user files are.
