#!/usr/bin/env bash

set -euo pipefail

readonly PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE_DIR="$PROJECT_DIR/src"
readonly BROKER_MANIFEST="$PROJECT_DIR/Cargo.toml"

widget_config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
widget_state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
target_dir="${CAELESTIA_CONFIG_DIR:-$widget_config_home/quickshell/caelestia}"
system_dir="${CAELESTIA_SYSTEM_DIR:-/etc/xdg/quickshell/caelestia}"
state_dir="${CAELESTIA_STATE_DIR:-$widget_state_home/caelestia-bitwarden-widget}"
settings_dir="${CAELESTIA_SETTINGS_DIR:-$widget_config_home/caelestia-vault}"

action="install"
restart_shell=1
install_deps=0
skip_deps=0
force=0
adopt_created=0
build_dir=""
helper_source=""

readonly -a MODIFIED_FILES=(
    "modules/Shortcuts.qml"
    "modules/bar/components/OsIcon.qml"
    "modules/dashboard/Content.qml"
    "modules/drawers/ContentWindow.qml"
)
readonly -a ADDED_FILES=(
    "modules/dashboard/Vault.qml"
    "scripts/caelestia-vault"
)
readonly -a OWNED_FILES=("${MODIFIED_FILES[@]}" "${ADDED_FILES[@]}")

log() {
    printf '[caelestia-vault] %s\n' "$*"
}

die() {
    printf '[caelestia-vault] error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./install.sh [option]

  --install             Install or update the widget (default)
  --uninstall           Restore the pre-install backup
  --check               Check dependencies, files, and running instances
  --install-deps        Install dependencies on Arch Linux with pacman
  --no-restart          Do not restart Caelestia
  --skip-deps           Skip dependency checks
  --force               Allow overwriting unrecognized local changes
  --adopt-created-config
                        Mark the existing config as created by this widget
  -h, --help            Show this help
EOF
}

while (($#)); do
    case "$1" in
        --install) action="install" ;;
        --uninstall) action="uninstall" ;;
        --check) action="check" ;;
        --install-deps) install_deps=1 ;;
        --no-restart) restart_shell=0 ;;
        --skip-deps) skip_deps=1 ;;
        --force) force=1 ;;
        --adopt-created-config) adopt_created=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

sha256() {
    sha256sum "$1" | cut -d' ' -f1
}

cleanup_build() {
    [[ -n "$build_dir" && -d "$build_dir" ]] || return 0
    case "$(basename "$build_dir")" in
        caelestia-vault-build.*) find "$build_dir" -depth -delete ;;
        *) die "refusing to remove unexpected build directory: $build_dir" ;;
    esac
}

trap cleanup_build EXIT

build_helper() {
    [[ -f "$BROKER_MANIFEST" ]] || die "broker manifest is missing: $BROKER_MANIFEST"
    command -v cargo >/dev/null 2>&1 || die "missing dependency: cargo"
    build_dir="$(mktemp -d "${TMPDIR:-/tmp}/caelestia-vault-build.XXXXXX")"
    helper_source="$build_dir/target/release/caelestia-vault"
    log "building the local vault broker"
    CARGO_TARGET_DIR="$build_dir/target" cargo build --locked --release \
        --manifest-path "$BROKER_MANIFEST"
    chmod 700 "$helper_source"
}

source_path() {
    local rel="$1"
    if [[ "$rel" == "scripts/caelestia-vault" ]]; then
        [[ -x "$helper_source" ]] || die "vault broker was not built"
        printf '%s' "$helper_source"
    else
        printf '%s/%s' "$SOURCE_DIR" "$rel"
    fi
}

registered_hash() {
    local rel="$1" manifest="$state_dir/installed.sha256"
    [[ -r "$manifest" ]] || return 1
    awk -v wanted="$rel" '
        $2 == wanted { print $1; found = 1; exit }
        END { if (!found) exit 1 }
    ' "$manifest"
}

write_installed_manifest() {
    local rel manifest_tmp="$state_dir/installed.sha256.$$"
    umask 077
    : >"$manifest_tmp"
    for rel in "${OWNED_FILES[@]}"; do
        printf '%s  %s\n' "$(sha256 "$target_dir/$rel")" "$rel" >>"$manifest_tmp"
    done
    chmod 600 "$manifest_tmp"
    mv -f -- "$manifest_tmp" "$state_dir/installed.sha256"
}

missing_dependencies() {
    local command_name
    for command_name in bw cargo jq secret-tool wl-copy qs caelestia; do
        command -v "$command_name" >/dev/null 2>&1 || printf '%s\n' "$command_name"
    done
    if ! command -v foot >/dev/null 2>&1 && ! command -v kitty >/dev/null 2>&1; then
        printf '%s\n' "foot-or-kitty"
    fi
}

check_dependencies() {
    if [[ "$skip_deps" -eq 1 ]]; then
        return 0
    fi
    local missing
    missing="$(missing_dependencies)"
    [[ -z "$missing" ]] || die "missing dependencies: $(tr '\n' ' ' <<<"$missing")"
}

install_dependencies() {
    if [[ "$install_deps" -ne 1 ]]; then
        return 0
    fi
    command -v pacman >/dev/null 2>&1 || die "--install-deps currently supports Arch Linux only"
    log "installing dependencies"
    sudo pacman -S --needed bitwarden bitwarden-cli rust jq libsecret wl-clipboard foot
}

validate_target() {
    local rel dest current custom registered
    for rel in "${MODIFIED_FILES[@]}"; do
        dest="$target_dir/$rel"
        [[ -f "$dest" ]] || die "base file is missing: $dest"
        registered="$(registered_hash "$rel" || true)"
        if [[ -n "$registered" ]]; then
            current="$(sha256 "$dest")"
            custom="$(sha256 "$(source_path "$rel")")"
            if [[ "$current" != "$custom" && "$current" != "$registered" && "$force" -ne 1 ]]; then
                die "$rel contains changes made after installation; review them before using --force"
            fi
        fi
    done

    for rel in "${ADDED_FILES[@]}"; do
        dest="$target_dir/$rel"
        registered="$(registered_hash "$rel" || true)"
        [[ ! -e "$dest" || "$(sha256 "$dest")" == "$(sha256 "$(source_path "$rel")")" \
            || "$(sha256 "$dest")" == "$registered" || "$force" -eq 1 ]] \
            || die "$rel already exists with different content"
    done
}

is_installed() {
    local rel
    for rel in "${OWNED_FILES[@]}"; do
        [[ -f "$target_dir/$rel" ]] || return 1
        [[ "$(sha256 "$target_dir/$rel")" == "$(sha256 "$(source_path "$rel")")" ]] || return 1
    done
}

create_backup() {
    local created_config="$1" rel src backup_dir
    backup_dir="$state_dir/backups/$(date +%Y%m%d-%H%M%S)-$$"
    mkdir -p "$backup_dir"
    chmod 700 "$state_dir" "$state_dir/backups" "$backup_dir"

    for rel in "${OWNED_FILES[@]}"; do
        src="$target_dir/$rel"
        mkdir -p "$backup_dir/$(dirname "$rel")"
        if [[ -e "$src" ]]; then
            cp -a "$src" "$backup_dir/$rel"
        else
            : >"$backup_dir/$rel.missing"
        fi
    done

    printf 'CREATED_CONFIG=%q\nTARGET_DIR=%q\nSYSTEM_DIR=%q\n' \
        "$created_config" "$target_dir" "$system_dir" >"$backup_dir/meta"
    printf '%s\n' "$backup_dir" >"$state_dir/current"
    chmod 600 "$state_dir/current" "$backup_dir/meta"
    printf '%s' "$backup_dir"
}

install_files() {
    local rel mode source
    for rel in "${OWNED_FILES[@]}"; do
        mode=0644
        [[ "$rel" == "scripts/caelestia-vault" ]] && mode=0700
        source="$(source_path "$rel")"
        install -Dm"$mode" "$source" "$target_dir/$rel"
    done
}

stop_running_helper() {
    local helper="$target_dir/scripts/caelestia-vault"
    [[ -x "$helper" ]] || return 0
    "$helper" shutdown >/dev/null 2>&1 \
        || "$helper" lock >/dev/null 2>&1 \
        || true
}

start_helper() {
    local helper="$target_dir/scripts/caelestia-vault"
    [[ -x "$helper" ]] || die "installed vault broker is missing"
    "$helper" status >/dev/null || die "could not start the vault broker"
}

caelestia_pids() {
    qs list --all 2>/dev/null | awk '
        /^Instance / { pid = "" }
        /Process ID:/ { pid = $3 }
        /Config path:/ {
            if ($3 ~ /\/quickshell\/caelestia\/shell.qml$/ && pid != "") print pid
        }'
}

restart_caelestia() {
    if [[ "$restart_shell" -ne 1 ]]; then
        return 0
    fi
    local pid
    while read -r pid; do
        [[ -n "$pid" ]] && qs kill --pid "$pid" >/dev/null 2>&1 || true
    done < <(caelestia_pids)
    sleep 0.5
    caelestia shell -d
}

purge_vault_data() {
    local runtime_base runtime_dir
    runtime_base="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    runtime_dir="$runtime_base/caelestia-vault"

    stop_running_helper

    # Remove only secrets owned by this integration.
    if command -v secret-tool >/dev/null 2>&1; then
        secret-tool clear application caelestia-vault >/dev/null 2>&1 || true
        secret-tool clear application caelestia-vault-cache >/dev/null 2>&1 || true
        secret-tool clear application caelestia-vault-session-v2 >/dev/null 2>&1 || true
    fi

    # The widget owns the CLI login, so uninstalling logs it out.
    if command -v bw >/dev/null 2>&1; then
        bw logout >/dev/null 2>&1 || bw lock >/dev/null 2>&1 || true
    fi

    if command -v wl-copy >/dev/null 2>&1; then
        wl-copy --clear >/dev/null 2>&1 || true
    fi

    [[ "$(basename "$runtime_dir")" == "caelestia-vault" ]] \
        || die "unexpected runtime directory: $runtime_dir"
    rm -rf -- "$runtime_dir"
    case "$settings_dir" in
        "$widget_config_home"/caelestia-vault) rm -rf -- "$settings_dir" ;;
        *) die "refusing to remove unexpected settings directory: $settings_dir" ;;
    esac
    log "removed the session, cache, clipboard, and local Bitwarden CLI login"
}

install_widget() {
    local created_config=0 backup_dir
    install_dependencies
    check_dependencies
    build_helper
    [[ -d "$system_dir" ]] || die "base config was not found: $system_dir"

    if [[ ! -d "$target_dir" ]]; then
        mkdir -p "$(dirname "$target_dir")"
        cp -a "$system_dir" "$target_dir"
        created_config=1
    elif [[ "$adopt_created" -eq 1 ]]; then
        created_config=1
    fi

    validate_target
    if [[ -r "$state_dir/current" ]]; then
        if is_installed; then
            log "widget is already installed"
        else
            stop_running_helper
            install_files
            log "updated widget in $target_dir; kept the original backup"
        fi
        write_installed_manifest
        start_helper
        restart_caelestia
        return
    fi

    mkdir -p "$state_dir/backups"
    backup_dir="$(create_backup "$created_config")"
    stop_running_helper
    install_files
    write_installed_manifest
    start_helper
    log "installed in $target_dir"
    log "backup: $backup_dir"
    restart_caelestia
}

uninstall_widget() {
    local backup_dir rel
    [[ -r "$state_dir/current" ]] || die "no registered installation was found"
    backup_dir="$(<"$state_dir/current")"
    [[ -d "$backup_dir" && -r "$backup_dir/meta" ]] || die "invalid backup: $backup_dir"
    # shellcheck disable=SC1090
    source "$backup_dir/meta"
    [[ "$TARGET_DIR" == "$target_dir" ]] || die "backup belongs to a different target: $TARGET_DIR"

    purge_vault_data

    for rel in "${OWNED_FILES[@]}"; do
        if [[ -e "$backup_dir/$rel.missing" ]]; then
            rm -f -- "$target_dir/$rel"
            rmdir -- "$(dirname "$target_dir/$rel")" 2>/dev/null || true
        elif [[ -f "$backup_dir/$rel" ]]; then
            mkdir -p "$(dirname "$target_dir/$rel")"
            cp -a -- "$backup_dir/$rel" "$target_dir/$rel"
        fi
    done

    if [[ "$CREATED_CONFIG" == "1" ]] && diff -qr "$SYSTEM_DIR" "$target_dir" >/dev/null 2>&1; then
        case "$target_dir" in
            "$widget_config_home"/quickshell/caelestia) rm -rf -- "$target_dir" ;;
            *) die "refusing to remove unexpected target: $target_dir" ;;
        esac
    fi

    case "$state_dir" in
        /|"$HOME"|"$widget_state_home") die "unsafe state directory: $state_dir" ;;
        *) rm -rf -- "$state_dir" ;;
    esac
    log "removed widget and restored the backup"
    restart_caelestia
}

check_installation() {
    local count=0 status="not-installed" pid
    check_dependencies
    build_helper
    [[ -d "$target_dir" ]] || die "user config is missing"
    is_installed && status="installed"
    while read -r pid; do
        [[ -n "$pid" ]] && ((count += 1))
    done < <(caelestia_pids)
    printf 'widget=%s\ninstances=%d\ntarget=%s\n' "$status" "$count" "$target_dir"
    [[ "$status" == "installed" && "$count" -le 1 ]]
}

case "$action" in
    install) install_widget ;;
    uninstall) uninstall_widget ;;
    check) check_installation ;;
esac
