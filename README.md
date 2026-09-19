# gosamba

A small, dependency-light SMB file server written in pure Go.

`gosamba` speaks the SMB2/SMB3 protocol directly, so it ships as a single static
binary. It is designed to be easy to run on Linux for sharing a few directories
with macOS, Windows, and iOS clients over the network.

It also builds and runs natively on macOS (`darwin/amd64`, `darwin/arm64`).
Windows is not supported as a host platform. On macOS, binding `:445`
requires that the built-in SMB service (File Sharing / `smbd`) isn't already
holding the port — disable macOS File Sharing or run `gosamba` on an
alternate port with `-l`.

On macOS the change-notify watcher needs one file descriptor per watched
directory (and per file it watches for in-place edits), so the number of
watches is capped process-wide — roughly an eighth of `RLIMIT_NOFILE`,
clamped to 32–512. Past that cap, creates, deletes and renames are still
reported; only in-place modifications of the extra files are missed, and a
client recovers by re-enumerating the directory. Raise `ulimit -n` if you
watch very large trees and want the cap to scale with it.

## Features

- **SMB2/SMB3 dialects** — negotiates 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1.
- **Authentication** — NTLMv2 over SPNEGO; passwords stored as NT hashes.
- **Encryption & signing** — SMB3 encryption and message signing, required by
  default (configurable to preferred/off).
- **Durable handles** — opens survive a dropped TCP connection and can be
  reclaimed after reconnect.
- **Byte-range locking and change-notify** for correct multi-client access.
  (Leases are negotiated but granted as `LEASE_NONE`: the server implements no
  lease-break, so it never promises a client a cache it cannot revoke.)
- **Apple client support** — AAPL create-context extensions and a synthesized
  `AFP_AfpInfo` stream so macOS Finder and the iOS Files app work smoothly.
- **Extended attributes & alternate data streams.**
- **Safe path handling** — symlink-escape and path-traversal protection keep
  access inside the share root.
- **Per-share access control** — read-only and guest shares, with per-user
  share allow-lists.
- **Per-user privilege drop** *(optional)* — serve each connection in a
  re-exec'd worker that drops to the authenticated user's uid/gid (requires
  root).
- **Zero-config discovery** — advertises the service over mDNS/Bonjour so Apple
  clients find it automatically.
- **Flexible config** — command-line flags, a TOML file, or both.

## Build

Requires Go 1.26 or newer.

```sh
make build        # produces ./gosamba
# or
go build -o gosamba ./cmd/gosamba
```

### Container

The container runs as numeric UID/GID `65532:65532`, listens on the
unprivileged container port `1445`, and disables mDNS by default. Build it and
publish the standard SMB port on the host with:

```sh
docker build -t gosamba:local .
docker run --rm \
  --publish 445:1445 \
  --mount type=bind,source=/srv/files,target=/shares/public \
  gosamba:local \
  --listen :1445 \
  --mdns=false \
  --share /shares/public=public \
  --user alice:s3cret
```

Arguments after the image name replace the image defaults, so include
`--listen :1445` and `--mdns=false` when supplying command-line shares or
users. Pass `--mdns=true` instead if container networking is configured to
support mDNS.

Bind-mounted shares must be readable by UID/GID `65532:65532`, and writable by
that identity for read-write shares. To use the host user's permissions
instead, set Docker's runtime user before the image name, for example
`--user "$(id -u):$(id -g)"`. This Docker option is separate from gosamba's
`--user alice:s3cret` application option, which defines an SMB login and comes
after the image name. On rootless Docker installations that cannot publish
privileged host ports, use `--publish 1445:1445` or configure the host to allow
binding port 445.

## Quick start

Share a single directory for one user — no system account required:

```sh
sudo mkdir -p /srv/files
sudo ./gosamba \
  --share /srv/files=public \
  --user alice:s3cret
```

This listens on `:445` (the privileged SMB port, hence `sudo`), serves
`/srv/files` as the share `public`, and authenticates the SMB user `alice` with
password `s3cret`. Because no `system_user` was given, file operations run as the
user that launched the server (here `root`). To drop to a specific account or
uid instead, add a third field — see [user mapping](#user-mapping).

Connect from another machine:

```sh
smbclient //your-host/public -U alice
```

> **Note:** passing a password on the command line with `-u` exposes it to other
> processes via `/proc/<pid>/cmdline`. For anything beyond a quick test, use a
> config file with a pre-computed `nt_hash` instead (see below).

## Configuration

### Command-line flags

| Flag | Description |
| --- | --- |
| `-s`, `--share <path>[=<name>]` | Share a directory (repeatable). Name defaults to the basename. |
| `-u`, `--user <smb_user>:<password>[:<system_user>]` | Define a user (repeatable). See [user mapping](#user-mapping). |
| `-c`, `--config <file>` | Load a TOML config file. |
| `-l`, `--listen <addr>` | Listen address (default `:445`). |
| `--netbios` | **Not implemented** — rejected at startup. Nothing binds `:139`; SMB2/3 uses `:445` only. |
| `--mdns` | Advertise via mDNS/Bonjour (default on). |
| `--no-encryption` | Allow non-encrypted SMB3 sessions. |
| `--no-signing` | Allow unsigned messages. |
| `--durable-timeout <dur>` | Durable-handle timeout, e.g. `60s`. |
| `--state-dir <path>` | Reserved — parsed and stored, but nothing reads it yet. |
| `--per-user-privdrop` | Drop to each authenticated user's uid/gid (requires root). |
| `--log-level <level>` | `debug` \| `info` \| `warn` \| `error`. |
| `--log-format <fmt>` | `text` \| `json`. |
| `-V`, `--version` | Print version and exit. |

### User mapping

The optional `system_user` field decides which OS identity a connection runs as,
and whether `gosamba` privilege-drops:

| `-u` form | Runs as | Privilege drop | Reads `/etc/passwd`? |
| --- | --- | --- | --- |
| `smb:pass` | the current process user | no | no |
| `smb:pass:1000` | uid 1000, gid 1000 | yes, if uid differs from current | no |
| `smb:pass:1000/1001` | uid 1000, gid 1001 | yes, if uid differs from current | no |
| `smb:pass:alice` | system user `alice` | yes, if it differs from current | yes |

Privilege drop only happens when the target uid differs from the current one and
the server runs as root (per-connection, via a re-exec'd worker). Use a **numeric**
`system_user` (or omit it) on minimal images such as the `scratch` container,
which has no `/etc/passwd` — a **named** `system_user` requires it.

### TOML config file

For production use, prefer a config file with NT-hashed passwords. The file must
not be group/world-writable (mode `≤ 0640`).

```toml
[server]
listen     = ":445"
encryption = "required"   # required | preferred | off
signing    = "required"   # required | preferred
mdns       = true

[log]
level  = "info"           # debug | info | warn | error
format = "text"           # text | json

[[share]]
name      = "public"
path      = "/srv/files"
read_only = false
guest_ok  = false

[[user]]
name         = "alice"
nt_hash      = "d4c619cb16d4632b275658316a7e657e"  # 32 hex chars (16-byte NT hash)
system_user  = "alice"    # optional: name, uid (e.g. "1000"), or uid/gid ("1000/1001")
allow_shares = ["public"]
```

Generate an `nt_hash` from a password with the built-in `hash` subcommand:

```sh
gosamba hash                          # prompts for the password
printf '%s' 's3cret' | gosamba hash   # or read it from stdin
```

Run with:

```sh
sudo ./gosamba -c /etc/gosamba.toml
```

Flags and the config file can be combined — explicit flags override file values.

## Architecture

The codebase is split into focused internal packages:

| Package | Responsibility |
| --- | --- |
| `cmd/gosamba` | Entry point, flag/config wiring, server lifecycle. |
| `internal/config` | CLI + TOML parsing, merge, and validation. |
| `internal/transport` | SMB direct-TCP framing. |
| `internal/smb2` / `internal/smb3` | Protocol message codecs and negotiate logic. |
| `internal/parent` | Connection/session handling, dispatch, and per-connection worker model. |
| `internal/ntlm` | NTLMv2 authentication. |
| `internal/userdb` | In-memory user store. |
| `internal/vfs` | Safe filesystem access (path resolution, traversal guards). |
| `internal/discovery` | mDNS/Bonjour advertisement. |
| `internal/inotify` | Filesystem change notifications. |
| `internal/logging` | Structured logging. |

The only external dependencies are the `golang.org/x` extensions
(`crypto`, `sys`, `net`, `text`).

## Development

```sh
make test         # go test ./...
make test-race    # race detector
make test-e2e     # smbclient-driven end-to-end tests (needs `make e2e-deps`)
make vet          # go vet
make fmt          # go fmt
```

Some end-to-end tests drive a real `smbclient` against the server. They sit
behind the `smbclient_e2e` build tag, so a plain `make test` skips them —
use `make test-e2e` (CI runs it on Linux). Install `smbclient` with:

```sh
make e2e-deps     # apt-get install smbclient
```

## Security notes

- Encryption and signing are **required by default**; only relax them
  (`--no-encryption` / `--no-signing`) on trusted networks.
- Prefer config-file `nt_hash` entries over plaintext `-u` passwords.
- Binding `:445` requires elevated privileges; consider `--per-user-privdrop`
  (as root) so each connection runs with the authenticated user's permissions.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
