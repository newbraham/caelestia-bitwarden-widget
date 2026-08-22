# Caelestia Bitwarden Widget

A Bitwarden vault for the [Caelestia Shell](https://github.com/caelestia-dots/shell) dashboard.
It adds local search, temporary clipboard access for usernames, passwords and TOTP codes,
and links to saved sites. Passkeys stay in the official Bitwarden browser extension.

## Requirements

- Caelestia Shell
- Quickshell
- Wayland with Hyprland
- Bitwarden CLI
- `jq`, `libsecret`, `wl-clipboard`, and `openssl`
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

On a fresh login, the widget captures the session returned by `bw login --raw` and
stores it in GNOME Keyring. Do not copy or export `BW_SESSION` yourself. If the CLI is
already signed in but locked, Bitwarden will ask for the master password once to unlock it.

Copied values stay in the clipboard for up to 30 seconds. They are sent through
`wl-copy --sensitive` so compatible clipboard managers can avoid saving them.

## Storage

- The master password never reaches QML or the widget cache.
- The Bitwarden CLI session is stored in GNOME Keyring.
- Session keys are passed through the process environment, not command-line arguments.
- Item metadata is written with mode `0600` under `XDG_RUNTIME_DIR`.
- The local vault cache uses AES-256 encryption. Its key is stored separately in GNOME Keyring.
- Locking the Vault clears its session, metadata, encrypted cache, and clipboard contents.

## Check or uninstall

```bash
./install.sh --check
./install.sh --uninstall
```

Uninstalling restores the original Caelestia files and removes the widget's backups,
runtime cache, clipboard contents, Keyring entries, and local Bitwarden CLI login.
It does not delete the remote vault or sign out of the Bitwarden desktop app.

Backups are kept in `~/.local/state/caelestia-bitwarden-widget/backups` while the
widget is installed.

## Development

Files under `src/` are installed over the user copy of Caelestia. Compatibility with
upstream releases is not tracked or enforced by this project.

## License

[MIT](LICENSE)
