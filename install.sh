#!/usr/bin/env bash

set -euo pipefail

readonly PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE_DIR="$PROJECT_DIR/src"
readonly BROKER_MANIFEST="$PROJECT_DIR/Cargo.toml"
readonly BUILD_PROFILE_FILE="build-profile"
readonly DEBUG_LOG_FILE="debug.log"
readonly DEBUG_LOG_MAX_BYTES=$((5 * 1024 * 1024))

widget_config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
widget_state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
target_dir="${CAELESTIA_CONFIG_DIR:-$widget_config_home/quickshell/caelestia}"
system_dir="${CAELESTIA_SYSTEM_DIR:-/etc/xdg/quickshell/caelestia}"
state_dir="${CAELESTIA_STATE_DIR:-$widget_state_home/caelestia-bitwarden-widget}"
settings_dir="${CAELESTIA_SETTINGS_DIR:-$widget_config_home/caelestia-vault}"

action="install"
debug_mode=0
restart_shell=1
install_deps=0
skip_deps=0
force=0
adopt_created=0
low_memory=0
build_jobs=""
build_profile="release"
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

log_line() {
    local level="$1"
    shift
    printf '%s [%-5s] [installer] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$level" "$*"
}

log() {
    log_line "INFO" "$*"
}

debug() {
    [[ "$build_profile" == "debug" ]] || return 0
    log_line "DEBUG" "$*"
}

die() {
    log_line "ERROR" "$*" >&2
    exit 1
}

enable_debug_logging() {
    local debug_log_file="$state_dir/$DEBUG_LOG_FILE"
    command -v tee >/dev/null 2>&1 || die "missing dependency: tee"
    umask 077
    mkdir -p "$state_dir"
    [[ -d "$state_dir" && ! -L "$state_dir" ]] || die "unsafe debug state directory: $state_dir"
    chmod 700 "$state_dir"
    [[ ! -L "$debug_log_file" ]] || die "refusing to follow debug log symlink: $debug_log_file"
    if [[ -f "$debug_log_file" ]] && (( $(stat -c %s "$debug_log_file") >= DEBUG_LOG_MAX_BYTES )); then
        [[ -f "$debug_log_file.2" ]] && mv -f -- "$debug_log_file.2" "$debug_log_file.3"
        [[ -f "$debug_log_file.1" ]] && mv -f -- "$debug_log_file.1" "$debug_log_file.2"
        mv -f -- "$debug_log_file" "$debug_log_file.1"
    fi
    touch "$debug_log_file"
    chmod 600 "$debug_log_file"
    exec > >(tee -a "$debug_log_file") 2>&1
    log "debug mode enabled"
    debug "profile=debug log=$debug_log_file"
}

debug_error_trap() {
    local status="$?" line="${BASH_LINENO[0]:-unknown}" function="${FUNCNAME[1]:-main}"
    trap - ERR
    log_line "ERROR" "event=installer_failed exit_code=$status line=$line function=$function"
    log_memory_snapshot "failure"
    exit "$status"
}

usage() {
    cat <<'EOF'
Usage: ./install.sh [action] [options]

  --install             Install or update the widget (default)
  --debug               Install with verbose logs and a debug broker build
  --low-memory          Build serially and disable release LTO
  --build-jobs N        Limit Cargo to N parallel jobs
  --uninstall           Restore the pre-install backup
  --check               Check dependencies, files, and running instances
  --diagnose            Print build, memory, cgroup, and broker diagnostics
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
        --debug) debug_mode=1 ;;
        --low-memory) low_memory=1 ;;
        --build-jobs)
            (($# >= 2)) || die "--build-jobs requires a positive integer"
            [[ "$2" =~ ^[1-9][0-9]*$ ]] || die "invalid --build-jobs value: $2"
            build_jobs="$2"
            shift
            ;;
        --install-deps) install_deps=1 ;;
        --diagnose) action="diagnose" ;;
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

log_file_matches() {
    local label="$1" file="$2" pattern="$3" line
    [[ -r "$file" ]] || return 0
    while IFS= read -r line; do
        log_line "DIAG" "$label $line"
    done < <(awk -v pattern="$pattern" '$0 ~ pattern' "$file")
}

log_memory_snapshot() {
    local reason="$1" value cgroup_path="" cgroup_dir=""
    log_line "DIAG" "event=memory_snapshot reason=$reason"
    log_file_matches "host" /proc/meminfo '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree|CommitLimit|Committed_AS):'
    if [[ -r /proc/self/cgroup ]]; then
        cgroup_path="$(awk -F: '$1 == "0" { print $3; exit }' /proc/self/cgroup)"
        cgroup_dir="/sys/fs/cgroup${cgroup_path}"
        log_line "DIAG" "cgroup_path=${cgroup_path:-unavailable}"
    fi
    for value in memory.current memory.peak memory.max memory.swap.current memory.swap.max memory.events; do
        if [[ -n "$cgroup_dir" && -r "$cgroup_dir/$value" ]]; then
            while IFS= read -r line; do
                log_line "DIAG" "cgroup_$value=$line"
            done < "$cgroup_dir/$value"
        fi
    done
}

log_command_version() {
    local name="$1"
    shift
    local output="" path=""
    path="$(command -v "$name" 2>/dev/null || true)"
    if [[ -z "$path" ]]; then
        log_line "DIAG" "tool=$name status=missing"
        return 0
    fi
    output="$("$@" 2>&1 | head -n 1 || true)"
    log_line "DIAG" "tool=$name path=$path version=${output:-unknown}"
}

log_system_diagnostics() {
    local reason="$1" line
    log_line "DIAG" "event=system_diagnostics reason=$reason timestamp=$(date --iso-8601=seconds)"
    log_line "DIAG" "kernel=$(uname -srmo) architecture=$(uname -m) cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf unknown)"
    log_line "DIAG" "shell=$BASH_VERSION umask=$(umask) tmpdir=${TMPDIR:-/tmp} target=$target_dir"
    log_command_version cargo cargo --version
    log_command_version rustc rustc --version --verbose
    log_command_version bw bw --version
    log_command_version jq jq --version
    log_command_version qs qs --version
    log_command_version caelestia caelestia --version
    while IFS= read -r line; do log_line "DIAG" "ulimit $line"; done < <(ulimit -a)
    log_memory_snapshot "$reason"
    if command -v df >/dev/null 2>&1; then
        while IFS= read -r line; do log_line "DIAG" "filesystem $line"; done \
            < <(df -h -P "${TMPDIR:-/tmp}" "$PROJECT_DIR" 2>&1 | awk '!seen[$0]++')
    fi
}

log_build_failure_hints() {
    local status="$1"
    log_line "ERROR" "event=build_failed exit_code=$status profile=$build_profile jobs=${build_jobs:-cargo-default} low_memory=$low_memory"
    if [[ "$status" -eq 137 || "$status" -eq 9 ]]; then
        log_line "ERROR" "build likely received SIGKILL; check cgroup memory.events oom/oom_kill and retry with --low-memory"
    else
        log_line "ERROR" "if rustc was killed or reports allocation failure, retry with --low-memory or --build-jobs 1"
    fi
    log_memory_snapshot "build-failure"
}

build_helper() {
    local cargo_status line time_file
    local -a cargo_args=(build --locked)
    local -a build_command=()
    local -a build_environment=("CARGO_TERM_COLOR=never")
    [[ -f "$BROKER_MANIFEST" ]] || die "broker manifest is missing: $BROKER_MANIFEST"
    command -v cargo >/dev/null 2>&1 || die "missing dependency: cargo"
    build_dir="$(mktemp -d "${TMPDIR:-/tmp}/caelestia-vault-build.XXXXXX")"
    build_environment+=("CARGO_TARGET_DIR=$build_dir/target")
    if [[ "$build_profile" == "release" ]]; then
        cargo_args+=(--release)
    fi
    [[ "$build_profile" == "debug" ]] && cargo_args+=(--verbose)
    [[ -n "$build_jobs" ]] && cargo_args+=(--jobs "$build_jobs")
    if [[ "$low_memory" -eq 1 ]]; then
        [[ -n "$build_jobs" ]] || cargo_args+=(--jobs 1)
        build_environment+=("CARGO_INCREMENTAL=0")
        if [[ "$build_profile" == "release" ]]; then
            build_environment+=("CARGO_PROFILE_RELEASE_LTO=off" "CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16")
        fi
    fi
    helper_source="$build_dir/target/$build_profile/caelestia-vault"
    log "building the local vault broker ($build_profile) jobs=${build_jobs:-cargo-default} low_memory=$low_memory"
    debug "event=build_started cargo_target=$build_dir/target cargo_profile=$build_profile jobs=${build_jobs:-cargo-default} low_memory=$low_memory"
    [[ "$build_profile" == "debug" ]] && log_system_diagnostics "before-build"
    time_file="$build_dir/build-time.txt"
    if [[ -x /usr/bin/time ]]; then
        build_command=(/usr/bin/time --verbose --output="$time_file" cargo)
    else
        build_command=(cargo)
        debug "GNU time unavailable; peak build RSS will not be measured"
    fi
    set +e
    env "${build_environment[@]}" "${build_command[@]}" \
        "${cargo_args[@]}" --manifest-path "$BROKER_MANIFEST" 2>&1 \
        | while IFS= read -r line; do log_line "CARGO" "$line"; done
    cargo_status="${PIPESTATUS[0]}"
    set -e
    if [[ -r "$time_file" ]]; then
        while IFS= read -r line; do log_line "BUILD" "$line"; done < "$time_file"
    fi
    [[ "$build_profile" == "debug" ]] && log_memory_snapshot "after-build"
    if [[ "$cargo_status" -ne 0 ]]; then
        log_build_failure_hints "$cargo_status"
        die "broker build failed"
    fi
    chmod 700 "$helper_source"
    debug "event=build_completed binary_bytes=$(stat -c %s "$helper_source")"
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

    printf '%s\n' "$build_profile" >"$state_dir/$BUILD_PROFILE_FILE"
    chmod 600 "$state_dir/$BUILD_PROFILE_FILE"
    debug "installation manifest updated profile=$build_profile"
}

load_installed_build_profile() {
    local profile_file="$state_dir/$BUILD_PROFILE_FILE" installed_profile="release"
    if [[ -r "$profile_file" ]]; then
        installed_profile="$(<"$profile_file")"
    fi
    case "$installed_profile" in
        debug|release) build_profile="$installed_profile" ;;
        *) die "invalid installed build profile: $installed_profile" ;;
    esac
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
        debug "dependency check skipped"
        return 0
    fi
    local missing
    missing="$(missing_dependencies)"
    [[ -z "$missing" ]] || die "missing dependencies: $(tr '\n' ' ' <<<"$missing")"
    debug "dependency check passed"
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
    debug "validating target=$target_dir"
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
            debug "validated modified file=$rel"
        fi
    done

    for rel in "${ADDED_FILES[@]}"; do
        dest="$target_dir/$rel"
        registered="$(registered_hash "$rel" || true)"
        [[ ! -e "$dest" || "$(sha256 "$dest")" == "$(sha256 "$(source_path "$rel")")" \
            || "$(sha256 "$dest")" == "$registered" || "$force" -eq 1 ]] \
            || die "$rel already exists with different content"
        debug "validated added file=$rel"
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
        debug "installed file=$rel mode=$mode"
    done
}

stop_running_helper() {
    local helper="$target_dir/scripts/caelestia-vault"
    [[ -x "$helper" ]] || return 0
    if "$helper" shutdown >/dev/null 2>&1; then
        debug "stopped previous broker"
    elif "$helper" lock >/dev/null 2>&1; then
        debug "previous broker locked; no shutdown response"
    else
        debug "previous broker was not running"
    fi
}

start_helper() {
    local helper="$target_dir/scripts/caelestia-vault"
    [[ -x "$helper" ]] || die "installed vault broker is missing"
    "$helper" status >/dev/null || die "could not start the vault broker"
    debug "broker started successfully"
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
        debug "Caelestia restart skipped"
        return 0
    fi
    local pid
    while read -r pid; do
        if [[ -n "$pid" ]]; then
            debug "stopping Caelestia pid=$pid"
            qs kill --pid "$pid" >/dev/null 2>&1 || true
        fi
    done < <(caelestia_pids)
    sleep 0.5
    caelestia shell -d
    debug "Caelestia restart requested"
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
    log "starting widget installation profile=$build_profile"
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
        log "widget installation completed profile=$build_profile"
        return
    fi

    mkdir -p "$state_dir/backups"
    backup_dir="$(create_backup "$created_config")"
    debug "backup created path=$backup_dir"
    stop_running_helper
    install_files
    write_installed_manifest
    start_helper
    log "installed in $target_dir"
    log "backup: $backup_dir"
    restart_caelestia
    log "widget installation completed profile=$build_profile"
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
    load_installed_build_profile
    build_helper
    [[ -d "$target_dir" ]] || die "user config is missing"
    is_installed && status="installed"
    while read -r pid; do
        [[ -n "$pid" ]] && ((count += 1))
    done < <(caelestia_pids)
    printf 'widget=%s\nprofile=%s\ninstances=%d\ntarget=%s\n' \
        "$status" "$build_profile" "$count" "$target_dir"
    [[ "$status" == "installed" && "$count" -le 1 ]]
}

diagnose_installation() {
    local helper="$target_dir/scripts/caelestia-vault" profile="unknown" count=0 pid rel registered current integrity
    log "collecting safe diagnostics (secret values and vault item IDs are excluded)"
    log_system_diagnostics "manual-diagnosis"
    if [[ -r "$state_dir/$BUILD_PROFILE_FILE" ]]; then
        profile="$(<"$state_dir/$BUILD_PROFILE_FILE")"
    fi
    while read -r pid; do
        [[ -n "$pid" ]] && ((count += 1))
    done < <(caelestia_pids)
    log_line "DIAG" "widget_profile=$profile caelestia_instances=$count target_exists=$([[ -d "$target_dir" ]] && printf true || printf false)"
    for rel in "${OWNED_FILES[@]}"; do
        if [[ ! -f "$target_dir/$rel" ]]; then
            log_line "DIAG" "owned_file=$rel status=missing"
            continue
        fi
        registered="$(registered_hash "$rel" || true)"
        current="$(sha256 "$target_dir/$rel")"
        integrity="unregistered"
        [[ -n "$registered" && "$current" == "$registered" ]] && integrity="manifest-match"
        [[ -n "$registered" && "$current" != "$registered" ]] && integrity="manifest-mismatch"
        log_line "DIAG" "owned_file=$rel status=present integrity=$integrity mode=$(stat -c %a "$target_dir/$rel") bytes=$(stat -c %s "$target_dir/$rel")"
    done
    if [[ -e "$state_dir/$DEBUG_LOG_FILE" ]]; then
        log_line "DIAG" "debug_log=$state_dir/$DEBUG_LOG_FILE bytes=$(stat -c %s "$state_dir/$DEBUG_LOG_FILE") mode=$(stat -c %a "$state_dir/$DEBUG_LOG_FILE")"
    else
        log_line "DIAG" "debug_log=missing"
    fi
    if [[ -x "$helper" ]]; then
        log_line "DIAG" "broker_binary=$helper bytes=$(stat -c %s "$helper")"
        if ! "$helper" diagnostics; then
            log_line "ERROR" "broker diagnostics request failed"
        fi
    else
        log_line "DIAG" "broker_binary=missing"
    fi
    log "diagnostics completed"
}

if [[ "$debug_mode" -eq 1 ]]; then
    [[ "$action" == "install" ]] || die "--debug can only be used when installing"
    build_profile="debug"
    enable_debug_logging
    trap debug_error_trap ERR
fi

case "$action" in
    install) install_widget ;;
    uninstall) uninstall_widget ;;
    check) check_installation ;;
    diagnose) diagnose_installation ;;
esac

if [[ "$debug_mode" -eq 1 ]]; then
    log "follow runtime logs with: tail -n 100 -F $state_dir/$DEBUG_LOG_FILE"
fi
