# Caelestia Bitwarden Widget

A Bitwarden vault for the [Caelestia Shell](https://github.com/caelestia-dots/shell) dashboard.
It adds local search, temporary clipboard access for usernames, passwords and TOTP codes,
and links to saved sites. Passkeys stay in the official Bitwarden browser extension.

## Requirements

- Caelestia Shell
- Quickshell
- Wayland with Hyprland
- Bitwarden CLI
- Rust/Cargo, `jq`, `libsecret`, and `wl-clipboard`
- `foot` or `kitty`

This project does not guarantee compatibility with any specific Caelestia or Quickshell
version. The installer replaces Caelestia configuration files, so install it at your own
risk. A backup is created for uninstalling, but you should keep your own backup too.

## Install

```bash
git clone https://github.com/newbraham/caelestia-bitwarden-widget.git
cd caelestia-bitwarden-widget
./install.sh --install-deps
```

If the dependencies are already installed:

```bash
./install.sh
```

The installer copies the system Caelestia config into your user config, backs up the
files it replaces, installs the widget, and restarts Caelestia with one running instance.

## Use

Right-click the distribution icon in the bar to open the Vault tab. Click **Connect**
and complete the Bitwarden sign-in and unlock prompts in the terminal.

On a fresh login, the widget captures the session returned by `bw login --raw` and keeps
it only in the broker process memory by default. Do not copy or export `BW_SESSION`
yourself. If the CLI is already signed in but locked, Bitwarden will ask for the master
password once to unlock it.

The dashboard lets you configure an inactivity timeout in minutes. Set it to `0` to
disable automatic locking. Session persistence across broker or system restarts is
optional and disabled by default; enabling it stores the session in GNOME Keyring and is
less secure against other processes running as your user.

Copied values stay in the clipboard for up to 30 seconds. They are sent through
`wl-copy --sensitive` so compatible clipboard managers can avoid saving them.

## Storage

- The master password never reaches QML or persistent widget storage.
- The complete vault and individual passwords are never cached on disk.
- The Bitwarden CLI session stays in broker memory unless persistence is explicitly enabled.
- Session keys are passed through the process environment, not command-line arguments.
- Searchable item metadata stays in broker and QML memory.
- Usernames, passwords, and TOTP seeds are preloaded into locked broker memory for the
  current inactivity-timeout period. With timeout `0`, the complete decrypted login cache
  remains in memory until lock or restart.
- The broker disables core dumps and exposes only a mode `0600` Unix socket.
- Incomplete socket requests and blocked responses are discarded after two seconds.
- Locking, timeout, sync, session replacement, or broker restart clears the field cache.
- Locking the Vault also clears its session, in-memory metadata, and clipboard contents.
- Failed removals of a persistent Keyring session are reported and retried while the broker
  is running and again after restart; an explicitly locked session is never restored.
- Passwords, usernames, and TOTP codes are copied with the sensitive hint, then removed
  from the clipboard after at most 30 seconds.

These controls reduce persistence and accidental disclosure. They cannot protect a secret
from malicious software already running as the same desktop user. While the Vault is
unlocked, such software can request a copy through the user-owned broker socket and then
read the clipboard; preventing that requires an authentication or user-presence check for
each sensitive action.

## Check or uninstall

```bash
./install.sh --check
./install.sh --uninstall
```

Uninstalling restores the original Caelestia files and removes the widget's backups,
runtime state, clipboard contents, Keyring entries, settings, and local Bitwarden CLI login.
It does not delete the remote vault or sign out of the Bitwarden desktop app.

Backups are kept in `~/.local/state/caelestia-bitwarden-widget/backups` while the
widget is installed.

## Development

Files under `src/` are installed over the user copy of Caelestia. The installer builds
the Rust broker in `broker/main.rs` locally and installs the resulting binary. Compatibility
with upstream releases is not tracked or enforced by this project.

Use debug mode while developing or diagnosing an installation:

```bash
./install.sh --debug
```

Debug mode adds the following diagnostics:

- It compiles the broker without Cargo's `--release` profile, preserving debug symbols
  and Rust debug assertions.
- It formats installer output with timestamps, levels, and components, and appends the
  complete installation output (including Cargo) to
  `~/.local/state/caelestia-bitwarden-widget/debug.log`.
- The installed broker appends lifecycle and request-result events to the same log. It
  never logs session values, vault fields, copied values, or vault item IDs.
- Cargo runs verbosely under GNU `time` when available. The log includes elapsed time,
  peak build RSS, page faults, exit status, host/cgroup memory limits and OOM counters,
  swap, filesystem space, `ulimit` values, and Rust/tool versions.
- Runtime requests have correlation IDs and durations. Health snapshots report broker
  RSS and peak RSS, locked memory, threads, open file descriptors, metadata size, and
  cached-field count. Subprocess events include only program/operation names, exit
  code or signal, duration, and byte counts—not their output.
- Panics include their source location and a full Rust backtrace. QML parse/process
  failures are also sent to the Caelestia/Quickshell console with sizes rather than
  response contents.

Show the last 100 broker/installer events and keep following new ones:

```bash
tail -n 100 -F ~/.local/state/caelestia-bitwarden-widget/debug.log
```

To show only broker runtime events, filter the same stream:

```bash
tail -n 100 -F ~/.local/state/caelestia-bitwarden-widget/debug.log \
  | rg --line-buffered '\[broker\]'
```

QML-side events such as malformed responses are in the Quickshell log instead:

```bash
qs log --newest --tail 100 --follow \
  | rg --line-buffered 'caelestia-vault|Vault.qml'
```

Ask the running broker for a point-in-time, secret-free memory snapshot:

```bash
~/.config/quickshell/caelestia/scripts/caelestia-vault diagnostics | jq
```

Or collect a broader installation/build/runtime report without rebuilding the broker:

```bash
./install.sh --diagnose
```

If Cargo or `rustc` is killed, exits with code 137, or reports an allocation failure,
use the low-memory build. It serializes compilation, disables incremental compilation,
and, for release builds, disables LTO and raises the number of codegen units:

```bash
./install.sh --debug --low-memory
```

You can limit parallelism independently with `--build-jobs N`. For example:

```bash
./install.sh --debug --build-jobs 2
```

Runtime logging is compiled in only for debug builds. The mode `0600` log rotates
continuously at 5 MiB and retains three older files, limiting the set to approximately
20 MiB. `./install.sh --check` reports the installed profile, and the broker's `status`
response includes `"debug": true` while the debug build is running. Run the regular
installer again to return to a release build; release brokers do not write runtime debug
events.

## License

[MIT](LICENSE)
