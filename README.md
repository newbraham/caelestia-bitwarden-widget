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
- The broker disables core dumps and exposes only a mode `0600` Unix socket.
- Locking the Vault clears its session, in-memory metadata, and clipboard contents.
- Passwords, usernames, and TOTP codes are copied with sensitive and single-paste hints,
  then removed from the clipboard after at most 30 seconds.

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

## License

[MIT](LICENSE)
