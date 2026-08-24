use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString, c_int, c_void};
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::NonNull;
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const APP_ID: &str = "caelestia-vault";
const SESSION_KEY_ID: &str = "caelestia-vault-session-v2";
const LEGACY_SESSION_ID: &str = "caelestia-vault";
const LEGACY_CACHE_KEY_ID: &str = "caelestia-vault-cache";
const DEFAULT_TIMEOUT_MINUTES: u32 = 15;
const MAX_TIMEOUT_MINUTES: u32 = 525_600;
const CLIPBOARD_LIFETIME: Duration = Duration::from_secs(30);
const MAX_PACKET_PARTS: u32 = 16;
const MAX_PACKET_PART_SIZE: u32 = 1024 * 1024;
const HEALTH_LOG_INTERVAL: Duration = Duration::from_secs(60);
const DEBUG_LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
const DEBUG_LOG_BACKUPS: usize = 3;

const PR_SET_DUMPABLE: c_int = 4;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const RLIMIT_CORE: c_int = 4;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_PRIVATE: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;
const O_NOFOLLOW: c_int = 0x20000;
const SC_PAGESIZE: c_int = 30;

#[repr(C)]
struct RLimit {
    current: u64,
    maximum: u64,
}

unsafe extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
    fn setrlimit(resource: c_int, limit: *const RLimit) -> c_int;
    fn mlock(address: *const c_void, length: usize) -> c_int;
    fn munlock(address: *const c_void, length: usize) -> c_int;
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        file_descriptor: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> c_int;
    fn sysconf(name: c_int) -> i64;
    fn flock(fd: c_int, operation: c_int) -> c_int;
}

struct LockedSecret {
    address: NonNull<u8>,
    length: usize,
    allocation_length: usize,
}

type FieldCache = HashMap<Vec<u8>, LockedSecret>;

impl LockedSecret {
    fn new(mut bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "empty secret"));
        }
        let page_size = match unsafe { sysconf(SC_PAGESIZE) } {
            size if size > 0 => size as usize,
            _ => 4096,
        };
        let allocation_length = match bytes
            .len()
            .checked_add(page_size - 1)
            .map(|length| length / page_size * page_size)
        {
            Some(length) => length,
            None => {
                zero_bytes(&mut bytes);
                return Err(io::Error::other("secret allocation is too large"));
            }
        };
        let raw_address = unsafe {
            mmap(
                std::ptr::null_mut(),
                allocation_length,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw_address as isize == -1 {
            let error = io::Error::last_os_error();
            process_log(
                "ERROR",
                &format!(
                    "event=secure_allocation_failed stage=mmap allocation_kib={} error=\"{}\"",
                    allocation_length / 1024,
                    json_escape(&error.to_string())
                ),
            );
            zero_bytes(&mut bytes);
            return Err(error);
        }
        let Some(address) = NonNull::new(raw_address.cast::<u8>()) else {
            zero_bytes(&mut bytes);
            return Err(io::Error::other(
                "secret allocation returned a null address",
            ));
        };
        if unsafe { mlock(address.as_ptr().cast(), allocation_length) } != 0 {
            let error = io::Error::last_os_error();
            let metrics = process_metrics();
            process_log(
                "ERROR",
                &format!(
                    "event=secure_allocation_failed stage=mlock allocation_kib={} locked_kib={} rss_kib={} error=\"{}\" hint=check_ulimit_l",
                    allocation_length / 1024,
                    metrics.locked_kib,
                    metrics.rss_kib,
                    json_escape(&error.to_string())
                ),
            );
            unsafe {
                munmap(address.as_ptr().cast(), allocation_length);
            }
            zero_bytes(&mut bytes);
            return Err(error);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), address.as_ptr(), bytes.len());
        }
        let length = bytes.len();
        zero_bytes(&mut bytes);
        Ok(Self {
            address,
            length,
            allocation_length,
        })
    }

    fn copy(&self) -> io::Result<Self> {
        Self::new(self.as_bytes().to_vec())
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.length) }
    }

    fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(self.as_bytes())
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        unsafe {
            let bytes = std::slice::from_raw_parts_mut(self.address.as_ptr(), self.length);
            zero_bytes(bytes);
            munlock(self.address.as_ptr().cast(), self.allocation_length);
            munmap(self.address.as_ptr().cast(), self.allocation_length);
        }
    }
}

#[derive(Clone, Copy)]
struct Settings {
    timeout_minutes: u32,
    persist: bool,
    last_activity_unix: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            timeout_minutes: DEFAULT_TIMEOUT_MINUTES,
            persist: false,
            last_activity_unix: 0,
        }
    }
}

struct AppPaths {
    runtime_dir: PathBuf,
    socket: PathBuf,
    lock: PathBuf,
    settings_dir: PathBuf,
    settings: PathBuf,
    state_dir: PathBuf,
    debug_log: PathBuf,
}

struct Broker {
    session: Option<LockedSecret>,
    metadata: Vec<u8>,
    field_cache: FieldCache,
    settings: Settings,
    paths: AppPaths,
    started_at: Instant,
    last_health_log: Instant,
    next_request_id: u64,
}

#[derive(Default)]
struct ProcessMetrics {
    rss_kib: u64,
    peak_rss_kib: u64,
    locked_kib: u64,
    threads: u64,
    open_fds: usize,
}

fn main() {
    install_panic_hook();
    let mut args = env::args_os().skip(1);
    let first = args.next().unwrap_or_else(|| OsString::from("status"));
    let command = first.to_string_lossy();

    if command == "serve" {
        if let Err(error) = serve() {
            if cfg!(debug_assertions) {
                process_log(
                    "ERROR",
                    &format!(
                        "event=server_failed error=\"{}\"",
                        json_escape(&error.to_string())
                    ),
                );
            } else {
                eprintln!("{error}");
            }
            std::process::exit(1);
        }
        return;
    }
    if command == "unlock" {
        match open_terminal() {
            Ok(()) => println!("{{\"ok\":true}}"),
            Err(error) => {
                println!("{}", error_json(&error.to_string()));
                std::process::exit(1);
            }
        }
        return;
    }
    if command == "unlock-interactive" {
        harden_process();
        if let Err(error) = unlock_interactive() {
            eprintln!("\n{error}\n");
            thread::sleep(Duration::from_secs(2));
            std::process::exit(1);
        }
        return;
    }

    let mut parts = vec![first.into_vec()];
    parts.extend(args.map(OsStringExt::into_vec));
    match send_request(&parts) {
        Ok(response) => {
            let _ = io::stdout().write_all(&response);
            let _ = io::stdout().write_all(b"\n");
        }
        Err(error) => {
            println!("{}", error_json(&error.to_string()));
            std::process::exit(1);
        }
    }
}

fn install_panic_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let location = info
                .location()
                .map(|location| {
                    format!(
                        "{}:{}:{}",
                        location.file(),
                        location.line(),
                        location.column()
                    )
                })
                .unwrap_or_else(|| "unknown".into());
            let backtrace = std::backtrace::Backtrace::force_capture();
            process_log(
                "ERROR",
                &format!(
                    "event=panic location=\"{}\" backtrace=\"{}\"",
                    json_escape(&location),
                    json_escape(&backtrace.to_string())
                ),
            );
        }));
    });
}

fn resolve_paths() -> io::Result<AppPaths> {
    let runtime_base = env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe_getuid())));
    let config_base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "config home is unavailable"))?;
    let state_dir = env::var_os("CAELESTIA_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
                })
                .map(|state| state.join("caelestia-bitwarden-widget"))
        })
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "state home is unavailable"))?;
    let runtime_dir = runtime_base.join(APP_ID);
    let settings_dir = config_base.join(APP_ID);
    Ok(AppPaths {
        socket: runtime_dir.join("broker.sock"),
        lock: runtime_dir.join("broker.lock"),
        settings: settings_dir.join("settings.conf"),
        debug_log: state_dir.join("debug.log"),
        runtime_dir,
        settings_dir,
        state_dir,
    })
}

unsafe extern "C" {
    fn getuid() -> u32;
}

fn unsafe_getuid() -> u32 {
    unsafe { getuid() }
}

fn harden_process() {
    let no_core = RLimit {
        current: 0,
        maximum: 0,
    };
    unsafe {
        setrlimit(RLIMIT_CORE, &no_core);
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
}

fn secure_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("unsafe directory: {}", path.display()),
        ));
    }
    if metadata.st_uid() != unsafe_getuid() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "directory is not owned by the current user",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn open_debug_log(paths: &AppPaths) -> io::Result<fs::File> {
    secure_directory(&paths.state_dir)?;
    if let Ok(metadata) = fs::symlink_metadata(&paths.debug_log)
        && metadata.file_type().is_symlink()
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "refusing to follow debug log symlink",
        ));
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&paths.debug_log)?;
    fs::set_permissions(&paths.debug_log, fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn rotated_debug_log(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn rotate_debug_log(paths: &AppPaths) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(&paths.debug_log) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "refusing to rotate debug log symlink",
        ));
    }
    if metadata.len() < DEBUG_LOG_MAX_BYTES {
        return Ok(());
    }
    for index in (1..=DEBUG_LOG_BACKUPS).rev() {
        let source = if index == 1 {
            paths.debug_log.clone()
        } else {
            rotated_debug_log(&paths.debug_log, index - 1)
        };
        let destination = rotated_debug_log(&paths.debug_log, index);
        match fs::rename(&source, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn runtime_log(paths: &AppPaths, level: &str, event: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let safe_event = event.replace(['\n', '\r'], " ");
    let write = || -> io::Result<()> {
        secure_directory(&paths.state_dir)?;
        let lock_path = paths.state_dir.join("debug-log.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(lock_path)?;
        if unsafe { flock(lock_file.as_raw_fd(), LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        rotate_debug_log(paths)?;
        let mut file = open_debug_log(paths)?;
        writeln!(
            file,
            "{} [{level:<5}] [broker] pid={} {safe_event}",
            iso8601_utc(now_unix()),
            std::process::id()
        )
    };
    let _ = write();
}

fn process_log(level: &str, event: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    if let Ok(paths) = resolve_paths() {
        runtime_log(&paths, level, event);
    }
}

fn process_metrics() -> ProcessMetrics {
    let mut metrics = ProcessMetrics::default();
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("VmRSS:") => {
                    metrics.rss_kib = fields
                        .next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0)
                }
                Some("VmHWM:") => {
                    metrics.peak_rss_kib = fields
                        .next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0)
                }
                Some("VmLck:") => {
                    metrics.locked_kib = fields
                        .next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0)
                }
                Some("Threads:") => {
                    metrics.threads = fields
                        .next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0)
                }
                _ => {}
            }
        }
    }
    metrics.open_fds = fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0);
    metrics
}

fn exit_status(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit_code={code}"),
        (_, Some(signal)) => format!("signal={signal}"),
        _ => "exit_status=unknown".into(),
    }
}

fn safe_bw_operation(args: &[&OsStr]) -> &'static str {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("list") => "list-items",
        Some("get") => match args.get(1).and_then(|arg| arg.to_str()) {
            Some("password") => "get-password",
            Some("totp") => "get-totp",
            Some("item") => "get-item",
            _ => "get-field",
        },
        Some("sync") => "sync",
        Some("lock") => "lock",
        Some("status") => "status",
        _ => "other",
    }
}

fn log_external_io_error(program: &str, operation: &str, stage: &str, error: &io::Error) {
    process_log(
        "WARN",
        &format!(
            "event=external_command program={program} operation={operation} result=io_error stage={stage} error_kind={:?} error=\"{}\"",
            error.kind(),
            json_escape(&error.to_string())
        ),
    );
}

fn iso8601_utc(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = seconds / 3_600;
    let minute = seconds % 3_600 / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn serve() -> io::Result<()> {
    harden_process();
    let paths = resolve_paths()?;
    runtime_log(
        &paths,
        "INFO",
        &format!(
            "event=server_starting profile=debug pid={} version={} rust_backtrace={}",
            std::process::id(),
            env!("CARGO_PKG_VERSION"),
            env::var("RUST_BACKTRACE").unwrap_or_else(|_| "unset".into())
        ),
    );
    secure_directory(&paths.runtime_dir)?;

    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&paths.lock)?;
    if unsafe { flock(lock_file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        runtime_log(&paths, "DEBUG", "event=server_already_running");
        return Ok(());
    }

    let _ = fs::remove_file(&paths.socket);
    let listener = UnixListener::bind(&paths.socket)?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    runtime_log(&paths, "INFO", "event=server_ready");

    let mut broker = Broker::new(paths);
    loop {
        broker.maybe_log_health();
        if broker.is_expired() {
            broker.lock_vault(true);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let request = read_packet(&mut stream);
                let (response, shutdown) = match request {
                    Ok(parts) => broker.dispatch(parts),
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                        runtime_log(
                            &broker.paths,
                            "DEBUG",
                            "event=connection_closed_before_request",
                        );
                        (error_json("invalid request").into_bytes(), false)
                    }
                    Err(error) => {
                        runtime_log(
                            &broker.paths,
                            "WARN",
                            &format!(
                                "event=request_invalid error_kind={:?} error=\"{}\"",
                                error.kind(),
                                json_escape(&error.to_string())
                            ),
                        );
                        (error_json("invalid request").into_bytes(), false)
                    }
                };
                let _ = stream.write_all(&response);
                if shutdown {
                    break;
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
    runtime_log(&broker.paths, "INFO", "event=server_stopped");
    let _ = fs::remove_file(&broker.paths.socket);
    Ok(())
}

impl Broker {
    fn new(paths: AppPaths) -> Self {
        let settings = load_settings(&paths.settings);
        let mut broker = Self {
            session: None,
            metadata: Vec::new(),
            field_cache: HashMap::new(),
            settings,
            paths,
            started_at: Instant::now(),
            last_health_log: Instant::now(),
            next_request_id: 1,
        };
        broker.remove_legacy_secrets();
        broker.restore_persistent_session();
        runtime_log(
            &broker.paths,
            "DEBUG",
            if broker.session.is_some() {
                "event=broker_initialized session=restored"
            } else {
                "event=broker_initialized session=none"
            },
        );
        broker
    }

    fn maybe_log_health(&mut self) {
        if self.last_health_log.elapsed() < HEALTH_LOG_INTERVAL {
            return;
        }
        self.last_health_log = Instant::now();
        self.log_health("periodic");
    }

    fn log_health(&self, reason: &str) {
        let metrics = process_metrics();
        runtime_log(
            &self.paths,
            "DEBUG",
            &format!(
                "event=health reason={reason} uptime_ms={} rss_kib={} peak_rss_kib={} locked_kib={} threads={} open_fds={} session={} metadata_bytes={} cached_fields={}",
                self.started_at.elapsed().as_millis(),
                metrics.rss_kib,
                metrics.peak_rss_kib,
                metrics.locked_kib,
                metrics.threads,
                metrics.open_fds,
                if self.session.is_some() {
                    "present"
                } else {
                    "none"
                },
                self.metadata.len(),
                self.field_cache.len()
            ),
        );
    }

    fn remove_legacy_secrets(&self) {
        let _ = fs::remove_file(self.paths.runtime_dir.join("items.json"));
        let _ = fs::remove_file(self.paths.runtime_dir.join("vault.enc"));
        let _ = fs::remove_file(self.paths.settings_dir.join("settings.json"));
        secret_clear(LEGACY_SESSION_ID);
        secret_clear(LEGACY_CACHE_KEY_ID);
    }

    fn restore_persistent_session(&mut self) {
        if !self.settings.persist {
            secret_clear(SESSION_KEY_ID);
            self.settings.last_activity_unix = 0;
            let _ = self.save_settings();
            return;
        }
        if self.settings.timeout_minutes > 0
            && (self.settings.last_activity_unix == 0
                || now_unix()
                    >= self.settings.last_activity_unix
                        + i64::from(self.settings.timeout_minutes) * 60)
        {
            secret_clear(SESSION_KEY_ID);
            self.settings.last_activity_unix = 0;
            let _ = self.save_settings();
            return;
        }
        if let Some(value) = secret_lookup(SESSION_KEY_ID) {
            match LockedSecret::new(value) {
                Ok(session) => self.session = Some(session),
                Err(_) => {
                    secret_clear(SESSION_KEY_ID);
                    self.settings.last_activity_unix = 0;
                    let _ = self.save_settings();
                }
            }
        } else {
            self.settings.last_activity_unix = 0;
            let _ = self.save_settings();
        }
    }

    fn dispatch(&mut self, parts: Vec<Vec<u8>>) -> (Vec<u8>, bool) {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let started = Instant::now();
        let command = parts
            .first()
            .map(|part| String::from_utf8_lossy(part))
            .unwrap_or_else(|| "status".into());
        let logged_command = match command.as_ref() {
            "status" | "set-session" | "configure" | "list" | "copy-username" | "copy-password"
            | "copy-totp" | "open-uri" | "sync" | "lock" | "shutdown" | "open-app"
            | "browser-extension" | "diagnostics" => command.as_ref(),
            _ => "unknown",
        };
        if logged_command != "status" {
            runtime_log(
                &self.paths,
                "DEBUG",
                &format!(
                    "event=request request_id={request_id} command={logged_command} parts={}",
                    parts.len()
                ),
            );
        }
        let result = match command.as_ref() {
            "status" => Ok(self.status_json().into_bytes()),
            "diagnostics" => {
                self.log_health("requested");
                Ok(self.diagnostics_json().into_bytes())
            }
            "set-session" => parts
                .get(1)
                .ok_or_else(|| "Bitwarden returned an empty session".to_string())
                .and_then(|value| self.set_session(value.clone()))
                .map(|_| ok_json().as_bytes().to_vec()),
            "configure" => self
                .configure_from_parts(&parts)
                .map(|_| self.status_json().into_bytes()),
            "list" => self.list_items(parts.get(1).is_some_and(|arg| arg == b"--refresh")),
            "copy-username" | "copy-password" | "copy-totp" => parts
                .get(1)
                .ok_or_else(|| "missing vault item ID".to_string())
                .and_then(|id| {
                    self.copy_field(command.trim_start_matches("copy-"), OsStr::from_bytes(id))
                })
                .map(|_| ok_json().as_bytes().to_vec()),
            "open-uri" => parts
                .get(1)
                .ok_or_else(|| "missing vault item ID".to_string())
                .and_then(|id| self.open_uri(OsStr::from_bytes(id)))
                .map(|_| ok_json().as_bytes().to_vec()),
            "sync" => self.sync_vault().map(|_| ok_json().as_bytes().to_vec()),
            "lock" => {
                self.lock_vault(false);
                Ok(ok_json().as_bytes().to_vec())
            }
            "shutdown" => {
                self.lock_vault(false);
                runtime_log(
                    &self.paths,
                    "DEBUG",
                    &format!(
                        "event=request_completed request_id={request_id} command=shutdown result=ok duration_ms={}",
                        started.elapsed().as_millis()
                    ),
                );
                return (ok_json().as_bytes().to_vec(), true);
            }
            "open-app" => open_bitwarden().map(|_| ok_json().as_bytes().to_vec()),
            "browser-extension" => Command::new("xdg-open")
                .arg("https://bitwarden.com/download/")
                .spawn()
                .map(|_| ok_json().as_bytes().to_vec())
                .map_err(|error| error.to_string()),
            _ => Err("unknown command".to_string()),
        };
        match result {
            Ok(response) => {
                if logged_command != "status" {
                    runtime_log(
                        &self.paths,
                        "DEBUG",
                        &format!(
                            "event=request_completed request_id={request_id} command={logged_command} result=ok duration_ms={}",
                            started.elapsed().as_millis()
                        ),
                    );
                }
                (response, false)
            }
            Err(error) => {
                let metrics = process_metrics();
                runtime_log(
                    &self.paths,
                    "WARN",
                    &format!(
                        "event=request_completed request_id={request_id} command={logged_command} result=error duration_ms={} rss_kib={} peak_rss_kib={} error=\"{}\"",
                        started.elapsed().as_millis(),
                        metrics.rss_kib,
                        metrics.peak_rss_kib,
                        json_escape(&error)
                    ),
                );
                (error_json(&error).into_bytes(), false)
            }
        }
    }

    fn status_json(&mut self) -> String {
        if self.is_expired() {
            self.lock_vault(true);
        }
        let status = if !command_exists("bw") {
            "missing"
        } else if self.session.is_some() {
            "unlocked"
        } else {
            "locked"
        };
        let expires = if self.session.is_some() && self.settings.timeout_minutes > 0 {
            (self.settings.last_activity_unix + i64::from(self.settings.timeout_minutes) * 60
                - now_unix())
            .max(0)
        } else {
            0
        };
        format!(
            "{{\"status\":\"{status}\",\"userEmail\":\"\",\"serverUrl\":\"\",\"timeoutMinutes\":{},\"persist\":{},\"expiresInSeconds\":{expires},\"debug\":{},\"pid\":{}}}",
            self.settings.timeout_minutes,
            self.settings.persist,
            cfg!(debug_assertions),
            std::process::id()
        )
    }

    fn diagnostics_json(&self) -> String {
        let metrics = process_metrics();
        format!(
            "{{\"ok\":true,\"debug\":{},\"pid\":{},\"version\":\"{}\",\"uptimeMs\":{},\"rssKiB\":{},\"peakRssKiB\":{},\"lockedKiB\":{},\"threads\":{},\"openFds\":{},\"sessionLoaded\":{},\"metadataBytes\":{},\"cachedFields\":{}}}",
            cfg!(debug_assertions),
            std::process::id(),
            env!("CARGO_PKG_VERSION"),
            self.started_at.elapsed().as_millis(),
            metrics.rss_kib,
            metrics.peak_rss_kib,
            metrics.locked_kib,
            metrics.threads,
            metrics.open_fds,
            self.session.is_some(),
            self.metadata.len(),
            self.field_cache.len()
        )
    }

    fn configure_from_parts(&mut self, parts: &[Vec<u8>]) -> Result<(), String> {
        if parts.len() != 3 {
            return Err("usage: configure <minutes> <true|false>".into());
        }
        let minutes = String::from_utf8_lossy(&parts[1])
            .parse::<u32>()
            .map_err(|_| "timeout must be a non-negative number of minutes".to_string())?;
        if minutes > MAX_TIMEOUT_MINUTES {
            return Err(format!(
                "timeout must be between 0 and {MAX_TIMEOUT_MINUTES} minutes"
            ));
        }
        let persist = match parts[2].as_slice() {
            b"true" => true,
            b"false" => false,
            _ => return Err("persist must be true or false".into()),
        };
        self.settings.timeout_minutes = minutes;
        self.settings.persist = persist;
        if let Some(session) = &self.session {
            self.settings.last_activity_unix = now_unix();
            if persist {
                if let Err(error) = secret_store(
                    SESSION_KEY_ID,
                    "Caelestia Vault - persistent session",
                    session.as_bytes(),
                ) {
                    self.settings.persist = false;
                    secret_clear(SESSION_KEY_ID);
                    let _ = self.save_settings();
                    return Err(format!("could not persist the session: {error}"));
                }
            } else {
                secret_clear(SESSION_KEY_ID);
            }
        } else if !persist {
            secret_clear(SESSION_KEY_ID);
        }
        self.save_settings().map_err(|error| error.to_string())
    }

    fn set_session(&mut self, mut value: Vec<u8>) -> Result<(), String> {
        trim_newline(&mut value);
        let session = LockedSecret::new(value)
            .map_err(|error| format!("could not lock session memory: {error}"))?;
        self.session = Some(session);
        zero_bytes(&mut self.metadata);
        self.metadata.clear();
        self.field_cache.clear();
        self.settings.last_activity_unix = now_unix();
        if self.settings.persist {
            let session = self.session.as_ref().unwrap();
            if let Err(error) = secret_store(
                SESSION_KEY_ID,
                "Caelestia Vault - persistent session",
                session.as_bytes(),
            ) {
                self.session = None;
                return Err(format!("could not persist the session: {error}"));
            }
        } else {
            secret_clear(SESSION_KEY_ID);
        }
        self.save_settings().map_err(|error| error.to_string())?;
        runtime_log(
            &self.paths,
            "INFO",
            &format!("event=session_loaded persistence={}", self.settings.persist),
        );
        Ok(())
    }

    fn session_copy(&mut self) -> Result<LockedSecret, String> {
        if self.is_expired() {
            self.lock_vault(true);
        }
        self.session
            .as_ref()
            .ok_or_else(|| "Vault is locked".to_string())?
            .copy()
            .map_err(|error| format!("could not lock session memory: {error}"))
    }

    fn touch(&mut self) {
        if self.session.is_some() {
            self.settings.last_activity_unix = now_unix();
            let _ = self.save_settings();
        }
    }

    fn list_items(&mut self, refresh: bool) -> Result<Vec<u8>, String> {
        if !refresh && !self.metadata.is_empty() {
            self.touch();
            return Ok(self.metadata.clone());
        }
        let session = self.session_copy()?;
        let filter = r#"
            ([.[] | select(.type == 1)]) as $items |
            ([$items[] | {id, name, type, username: (.login.username // ""), uri: (.login.uris[0].uri // ""), hasPassword: ((.login.password // "") != ""), hasTotp: ((.login.totp // "") != ""), passkeys: (.login.fido2Credentials // [] | length)}] | sort_by(.name | ascii_downcase) | tojson | @base64 | "M\t\(.)"),
            ($items[] | .id as $id |
                (["S", "username", $id, ((.login.username // "") | @base64)] | @tsv),
                (["S", "password", $id, ((.login.password // "") | @base64)] | @tsv),
                (["S", "totp", $id, ((.login.totp // "") | @base64)] | @tsv)
            )
        "#;
        let mut data = match run_bw_through_jq(&session, &["list", "items"], filter, true) {
            Ok(data) => data,
            Err(_) => {
                self.lock_vault(false);
                return Err("Session expired; connect again".into());
            }
        };
        let parsed = parse_vault_cache_payload(&data);
        zero_bytes(&mut data);
        let (metadata, field_cache) = parsed?;
        zero_bytes(&mut self.metadata);
        self.metadata = metadata;
        self.field_cache = field_cache;
        self.touch();
        Ok(self.metadata.clone())
    }

    fn copy_field(&mut self, kind: &str, id: &OsStr) -> Result<(), String> {
        let cache_key = field_cache_key(kind, id);
        if let Some(value) = self.field_cache.get(&cache_key) {
            copy_to_clipboard(value.as_bytes()).map_err(|error| error.to_string())?;
            self.touch();
            notify(
                "Copied for 30 seconds",
                "The clipboard will be cleared automatically.",
            );
            return Ok(());
        }

        let session = self.session_copy()?;
        let mut value = match kind {
            "username" => run_bw_through_jq_os(
                &session,
                &[OsStr::new("get"), OsStr::new("item"), id],
                ".login.username // empty",
                true,
            ),
            "password" => run_bw_os(&session, &[OsStr::new("get"), OsStr::new("password"), id]),
            "totp" => run_bw_os(&session, &[OsStr::new("get"), OsStr::new("totp"), id]),
            _ => return Err("invalid copy action".into()),
        }
        .map_err(|_| "could not retrieve that field".to_string())?;
        trim_newline(&mut value);
        if value.is_empty() {
            return Err("This item does not contain that field".into());
        }
        let value = LockedSecret::new(value)
            .map_err(|error| format!("could not lock field cache memory: {error}"))?;
        copy_to_clipboard(value.as_bytes()).map_err(|error| error.to_string())?;
        self.field_cache.insert(cache_key, value);
        self.touch();
        notify(
            "Copied for 30 seconds",
            "The clipboard will be cleared automatically.",
        );
        Ok(())
    }

    fn open_uri(&mut self, id: &OsStr) -> Result<(), String> {
        let session = self.session_copy()?;
        let mut output = run_bw_through_jq_os(
            &session,
            &[OsStr::new("get"), OsStr::new("item"), id],
            ".login.uris[0].uri // empty",
            true,
        )
        .map_err(|_| "could not retrieve the item URL".to_string())?;
        trim_newline(&mut output);
        let uri = OsString::from_vec(output);
        let uri_bytes = uri.as_bytes();
        if !uri_bytes.starts_with(b"https://") && !uri_bytes.starts_with(b"http://") {
            return Err("This item does not have an HTTP(S) URL".into());
        }
        Command::new("xdg-open")
            .arg(&uri)
            .spawn()
            .map_err(|error| error.to_string())?;
        self.touch();
        Ok(())
    }

    fn sync_vault(&mut self) -> Result<(), String> {
        let session = self.session_copy()?;
        let started = Instant::now();
        let output = Command::new("bw")
            .arg("sync")
            .env("BW_SESSION", session.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| error.to_string())?;
        process_log(
            if output.status.success() {
                "DEBUG"
            } else {
                "WARN"
            },
            &format!(
                "event=external_command program=bw operation=sync result={} {} duration_ms={} stderr_bytes={}",
                if output.status.success() {
                    "ok"
                } else {
                    "error"
                },
                exit_status(output.status),
                started.elapsed().as_millis(),
                output.stderr.len()
            ),
        );
        if !output.status.success() {
            return Err("Sync failed".into());
        }
        zero_bytes(&mut self.metadata);
        self.metadata.clear();
        self.field_cache.clear();
        self.touch();
        notify("Vault synced", "");
        Ok(())
    }

    fn is_expired(&self) -> bool {
        self.session.is_some()
            && self.settings.timeout_minutes > 0
            && self.settings.last_activity_unix > 0
            && now_unix()
                >= self.settings.last_activity_unix + i64::from(self.settings.timeout_minutes) * 60
    }

    fn lock_vault(&mut self, automatic: bool) {
        self.session = None;
        zero_bytes(&mut self.metadata);
        self.metadata.clear();
        self.field_cache.clear();
        self.settings.last_activity_unix = 0;
        let _ = self.save_settings();
        secret_clear(SESSION_KEY_ID);
        let _ = Command::new("bw")
            .arg("lock")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        clear_clipboard();
        runtime_log(
            &self.paths,
            "INFO",
            if automatic {
                "event=vault_locked reason=inactivity_timeout"
            } else {
                "event=vault_locked reason=request"
            },
        );
        if automatic {
            notify("Vault locked", "The inactivity timeout expired.");
        } else {
            notify("Vault locked", "");
        }
    }

    fn save_settings(&self) -> io::Result<()> {
        secure_directory(&self.paths.settings_dir)?;
        let temporary = self
            .paths
            .settings
            .with_extension(format!("tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        writeln!(file, "timeout_minutes={}", self.settings.timeout_minutes)?;
        writeln!(file, "persist={}", self.settings.persist)?;
        writeln!(
            file,
            "last_activity_unix={}",
            self.settings.last_activity_unix
        )?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(temporary, &self.paths.settings)
    }
}

fn field_cache_key(kind: &str, id: &OsStr) -> Vec<u8> {
    let mut key = Vec::with_capacity(kind.len() + id.as_bytes().len() + 1);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(id.as_bytes());
    key
}

fn parse_vault_cache_payload(payload: &[u8]) -> Result<(Vec<u8>, FieldCache), String> {
    let mut metadata = None;
    let mut field_cache = HashMap::new();

    for line in payload
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if let Some(encoded) = line.strip_prefix(b"M\t") {
            let decoded = base64_decode(encoded)?;
            if !decoded.starts_with(b"[") {
                return Err("invalid vault metadata payload".into());
            }
            metadata = Some(decoded);
            continue;
        }

        let Some(secret) = line.strip_prefix(b"S\t") else {
            return Err("invalid vault cache record".into());
        };
        let mut parts = secret.splitn(3, |byte| *byte == b'\t');
        let kind = parts.next().ok_or("missing cache field kind")?;
        let id = parts.next().ok_or("missing cache item ID")?;
        let encoded = parts.next().ok_or("missing cache field value")?;
        let kind = std::str::from_utf8(kind).map_err(|_| "invalid cache field kind")?;
        if !matches!(kind, "username" | "password" | "totp") {
            return Err("invalid cache field kind".into());
        }
        let value = base64_decode(encoded)?;
        if value.is_empty() {
            continue;
        }
        let value = LockedSecret::new(value)
            .map_err(|error| format!("could not lock vault cache memory: {error}"))?;
        field_cache.insert(field_cache_key(kind, OsStr::from_bytes(id)), value);
    }

    let metadata = metadata.ok_or("vault metadata is missing")?;
    Ok((metadata, field_cache))
}

fn base64_decode(encoded: &[u8]) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(4) {
        return Err("invalid base64 cache value".into());
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3);
    let chunks = encoded.chunks_exact(4);
    let chunk_count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        let a = base64_digit(chunk[0]).ok_or("invalid base64 cache value")?;
        let b = base64_digit(chunk[1]).ok_or("invalid base64 cache value")?;
        decoded.push((a << 2) | (b >> 4));

        if chunk[2] == b'=' {
            if chunk[3] != b'=' || index + 1 != chunk_count {
                return Err("invalid base64 cache padding".into());
            }
            continue;
        }
        let c = base64_digit(chunk[2]).ok_or("invalid base64 cache value")?;
        decoded.push((b << 4) | (c >> 2));

        if chunk[3] == b'=' {
            if index + 1 != chunk_count {
                return Err("invalid base64 cache padding".into());
            }
            continue;
        }
        let d = base64_digit(chunk[3]).ok_or("invalid base64 cache value")?;
        decoded.push((c << 6) | d);
    }
    Ok(decoded)
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn load_settings(path: &Path) -> Settings {
    let mut settings = Settings::default();
    let Ok(contents) = fs::read_to_string(path) else {
        return settings;
    };
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "timeout_minutes" => {
                if let Ok(minutes) = value.parse::<u32>()
                    && minutes <= MAX_TIMEOUT_MINUTES
                {
                    settings.timeout_minutes = minutes;
                }
            }
            "persist" => settings.persist = value == "true",
            "last_activity_unix" => settings.last_activity_unix = value.parse().unwrap_or_default(),
            _ => {}
        }
    }
    settings
}

fn run_bw_os(session: &LockedSecret, args: &[&OsStr]) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    let operation = safe_bw_operation(args);
    let output = Command::new("bw")
        .args(args)
        .env("BW_SESSION", session.as_os_str())
        .stderr(Stdio::piped())
        .output()
        .inspect_err(|error| log_external_io_error("bw", operation, "spawn-or-wait", error))?;
    process_log(
        if output.status.success() {
            "DEBUG"
        } else {
            "WARN"
        },
        &format!(
            "event=external_command program=bw operation={operation} result={} {} duration_ms={} stdout_bytes={} stderr_bytes={}",
            if output.status.success() {
                "ok"
            } else {
                "error"
            },
            exit_status(output.status),
            started.elapsed().as_millis(),
            output.stdout.len(),
            output.stderr.len()
        ),
    );
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(io::Error::other(format!(
            "Bitwarden command failed ({})",
            exit_status(output.status)
        )))
    }
}

fn run_bw_through_jq(
    session: &LockedSecret,
    args: &[&str],
    filter: &str,
    raw: bool,
) -> io::Result<Vec<u8>> {
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    run_bw_through_jq_os(session, &args, filter, raw)
}

fn run_bw_through_jq_os(
    session: &LockedSecret,
    args: &[&OsStr],
    filter: &str,
    raw: bool,
) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    let operation = safe_bw_operation(args);
    let mut bw = Command::new("bw")
        .args(args)
        .env("BW_SESSION", session.as_os_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .inspect_err(|error| log_external_io_error("bw", operation, "spawn", error))?;
    let stdout = bw
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Bitwarden stdout is unavailable"))?;
    let jq_mode = if raw { "-r" } else { "-c" };
    let jq_output = Command::new("jq")
        .args([jq_mode, filter])
        .stdin(Stdio::from(stdout))
        .stderr(Stdio::piped())
        .output();
    let bw_output = bw
        .wait_with_output()
        .inspect_err(|error| log_external_io_error("bw", operation, "wait", error))?;
    let jq_output = jq_output
        .inspect_err(|error| log_external_io_error("jq", operation, "spawn-or-wait", error))?;
    let success = bw_output.status.success() && jq_output.status.success();
    process_log(
        if success { "DEBUG" } else { "WARN" },
        &format!(
            "event=external_pipeline programs=bw,jq operation={operation} result={} bw_{} jq_{} duration_ms={} output_bytes={} bw_stderr_bytes={} jq_stderr_bytes={}",
            if success { "ok" } else { "error" },
            exit_status(bw_output.status),
            exit_status(jq_output.status),
            started.elapsed().as_millis(),
            jq_output.stdout.len(),
            bw_output.stderr.len(),
            jq_output.stderr.len()
        ),
    );
    if !success {
        return Err(io::Error::other(format!(
            "Bitwarden pipeline failed (bw {}; jq {})",
            exit_status(bw_output.status),
            exit_status(jq_output.status)
        )));
    }
    Ok(jq_output.stdout)
}

fn copy_to_clipboard(value: &[u8]) -> io::Result<()> {
    let started = Instant::now();
    let mut child = Command::new("wl-copy")
        // Clipboard watchers request the value once to inspect its MIME metadata.
        // With --paste-once that inspection consumes the user's only paste.
        .args(["--foreground", "--sensitive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .inspect_err(|error| log_external_io_error("wl-copy", "copy", "spawn", error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("clipboard stdin is unavailable"))?;
    stdin.write_all(value)?;
    drop(stdin);
    process_log(
        "DEBUG",
        &format!(
            "event=clipboard_started pid={} payload_bytes={} setup_duration_ms={} lifetime_seconds={}",
            child.id(),
            value.len(),
            started.elapsed().as_millis(),
            CLIPBOARD_LIFETIME.as_secs()
        ),
    );
    thread::spawn(move || wait_for_clipboard(child));
    Ok(())
}

fn wait_for_clipboard(mut child: Child) {
    let started = SystemTime::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                process_log(
                    "DEBUG",
                    &format!(
                        "event=clipboard_stopped reason=exited {} lifetime_ms={}",
                        exit_status(status),
                        started.elapsed().unwrap_or_default().as_millis()
                    ),
                );
                return;
            }
            Ok(None) => {}
            Err(error) => {
                process_log(
                    "WARN",
                    &format!(
                        "event=clipboard_wait_failed error=\"{}\"",
                        json_escape(&error.to_string())
                    ),
                );
                return;
            }
        }
        if started.elapsed().unwrap_or_default() >= CLIPBOARD_LIFETIME {
            let _ = child.kill();
            let _ = child.wait();
            process_log(
                "DEBUG",
                &format!(
                    "event=clipboard_stopped reason=timeout lifetime_ms={}",
                    started.elapsed().unwrap_or_default().as_millis()
                ),
            );
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn secret_lookup(id: &str) -> Option<Vec<u8>> {
    let started = Instant::now();
    let output = Command::new("secret-tool")
        .args(["lookup", "application", id])
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    process_log(
        if output.status.success() {
            "DEBUG"
        } else {
            "WARN"
        },
        &format!(
            "event=external_command program=secret-tool operation=lookup result={} {} duration_ms={} stdout_bytes={} stderr_bytes={}",
            if output.status.success() {
                "ok"
            } else {
                "error"
            },
            exit_status(output.status),
            started.elapsed().as_millis(),
            output.stdout.len(),
            output.stderr.len()
        ),
    );
    if !output.status.success() || output.stdout.is_empty() {
        return None;
    }
    let mut value = output.stdout;
    trim_newline(&mut value);
    Some(value)
}

fn secret_store(id: &str, label: &str, value: &[u8]) -> io::Result<()> {
    let started = Instant::now();
    let mut child = Command::new("secret-tool")
        .args(["store", &format!("--label={label}"), "application", id])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("keyring stdin is unavailable"))?
        .write_all(value)?;
    let output = child.wait_with_output()?;
    let status = output.status;
    process_log(
        if status.success() { "DEBUG" } else { "WARN" },
        &format!(
            "event=external_command program=secret-tool operation=store result={} {} duration_ms={} stderr_bytes={}",
            if status.success() { "ok" } else { "error" },
            exit_status(status),
            started.elapsed().as_millis(),
            output.stderr.len()
        ),
    );
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("keyring rejected the session"))
    }
}

fn secret_clear(id: &str) {
    let _ = Command::new("secret-tool")
        .args(["clear", "application", id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn open_terminal() -> io::Result<()> {
    let executable = env::current_exe()?;
    if command_exists("foot") {
        Command::new("foot")
            .args(["--app-id=caelestia-vault", "--title=Caelestia - Bitwarden"])
            .arg(executable)
            .arg("unlock-interactive")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        return Ok(());
    }
    if command_exists("kitty") {
        Command::new("kitty")
            .args(["--class", APP_ID, "--title", "Caelestia - Bitwarden"])
            .arg(executable)
            .arg("unlock-interactive")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        return Ok(());
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        "No supported terminal found (foot or kitty)",
    ))
}

fn unlock_interactive() -> Result<(), String> {
    print!("\x1b[H\x1b[2J\n  Caelestia Vault - Bitwarden\n\n");
    if !command_exists("bw") {
        return Err("Bitwarden CLI is not installed".into());
    }
    let state = Command::new("bw")
        .arg("status")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut bw| {
            let stdout = bw.stdout.take().unwrap();
            let jq = Command::new("jq")
                .args(["-r", ".status // \"unauthenticated\""])
                .stdin(Stdio::from(stdout))
                .output()?;
            let _ = bw.wait();
            Ok(jq.stdout)
        })
        .unwrap_or_else(|_| b"unauthenticated\n".to_vec());
    let unauthenticated = state.starts_with(b"unauthenticated");
    if unauthenticated {
        println!("Sign in to Bitwarden. Your master password is never stored by the widget.\n");
    } else {
        println!("Unlock the vault for this session:\n");
    }
    let action = if unauthenticated { "login" } else { "unlock" };
    let output = Command::new("bw")
        .args([action, "--raw"])
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("sign-in or unlock failed".into());
    }
    let mut session = output.stdout;
    trim_newline(&mut session);
    if session.is_empty() {
        return Err("Bitwarden did not return a session".into());
    }
    let locked = LockedSecret::new(session)
        .map_err(|error| format!("could not lock session memory: {error}"))?;
    let mut request = vec![b"set-session".to_vec(), locked.as_bytes().to_vec()];
    let response = send_request(&request).map_err(|error| error.to_string())?;
    zero_bytes(&mut request[1]);
    if response.starts_with(b"{\"error\"") {
        return Err(String::from_utf8_lossy(&response).into_owned());
    }
    notify(
        "Vault unlocked",
        "The session is available in the dashboard.",
    );
    println!("\nSession loaded into the local broker. This window will close automatically.");
    thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn open_bitwarden() -> Result<(), String> {
    if command_exists("bitwarden") {
        Command::new("bitwarden")
            .spawn()
            .map(|_| ())
            .map_err(|error| error.to_string())
    } else {
        Command::new("xdg-open")
            .arg("https://vault.bitwarden.com")
            .spawn()
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn notify(summary: &str, body: &str) {
    let mut command = Command::new("notify-send");
    command.args(["-a", "Caelestia Vault", "-i", "password-manager", summary]);
    if !body.is_empty() {
        command.arg(body);
    }
    let _ = command.stdout(Stdio::null()).stderr(Stdio::null()).spawn();
}

fn clear_clipboard() {
    let _ = Command::new("wl-copy")
        .arg("--clear")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn send_request(parts: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let paths = resolve_paths()?;
    let mut stream = match UnixStream::connect(&paths.socket) {
        Ok(stream) => stream,
        Err(error) => {
            runtime_log(
                &paths,
                "DEBUG",
                &format!(
                    "event=client_connect_failed error_kind={:?} error=\"{}\" action=start_server",
                    error.kind(),
                    json_escape(&error.to_string())
                ),
            );
            start_server(&paths)?;
            UnixStream::connect(&paths.socket).inspect_err(|retry_error| {
                runtime_log(
                    &paths,
                    "ERROR",
                    &format!(
                        "event=client_reconnect_failed error_kind={:?} error=\"{}\"",
                        retry_error.kind(),
                        json_escape(&retry_error.to_string())
                    ),
                );
            })?
        }
    };
    write_packet(&mut stream, parts).inspect_err(|error| {
        runtime_log(
            &paths,
            "ERROR",
            &format!(
                "event=client_write_failed error_kind={:?} error=\"{}\"",
                error.kind(),
                json_escape(&error.to_string())
            ),
        );
    })?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).inspect_err(|error| {
        runtime_log(
            &paths,
            "ERROR",
            &format!(
                "event=client_read_failed error_kind={:?} error=\"{}\"",
                error.kind(),
                json_escape(&error.to_string())
            ),
        );
    })?;
    Ok(response)
}

fn start_server(paths: &AppPaths) -> io::Result<()> {
    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if cfg!(debug_assertions) {
        command.env("RUST_BACKTRACE", "full");
    }
    let child = command.spawn()?;
    runtime_log(
        paths,
        "DEBUG",
        &format!("event=server_spawned child_pid={}", child.id()),
    );
    for _ in 0..40 {
        if UnixStream::connect(&paths.socket).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    runtime_log(
        paths,
        "ERROR",
        "event=server_start_timeout wait_ms=2000 hint=inspect_recent_server_failed_or_panic_event",
    );
    Err(io::Error::new(
        ErrorKind::TimedOut,
        "vault broker did not become ready",
    ))
}

fn write_packet(stream: &mut UnixStream, parts: &[Vec<u8>]) -> io::Result<()> {
    let count = u32::try_from(parts.len())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "too many request parts"))?;
    stream.write_all(&count.to_be_bytes())?;
    for part in parts {
        let length = u32::try_from(part.len())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "request part is too large"))?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(part)?;
    }
    Ok(())
}

fn read_packet(stream: &mut UnixStream) -> io::Result<Vec<Vec<u8>>> {
    let count = read_u32(stream)?;
    if count == 0 || count > MAX_PACKET_PARTS {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid part count"));
    }
    let mut parts = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let length = read_u32(stream)?;
        if length > MAX_PACKET_PART_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "request part is too large",
            ));
        }
        let mut part = vec![0; length as usize];
        stream.read_exact(&mut part)?;
        parts.push(part);
    }
    Ok(parts)
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn command_exists(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|directory| {
        let candidate = directory.join(name);
        candidate.is_file()
            && candidate
                .metadata()
                .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn trim_newline(value: &mut Vec<u8>) {
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
}

fn zero_bytes(value: &mut [u8]) {
    for byte in value {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn ok_json() -> &'static str {
    "{\"ok\":true}"
}

fn error_json(message: &str) -> String {
    format!("{{\"error\":\"{}\"}}", json_escape(message))
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_zero_never_expires() {
        let settings = Settings {
            timeout_minutes: 0,
            persist: false,
            last_activity_unix: now_unix() - 3600,
        };
        let broker = Broker {
            session: LockedSecret::new(b"test-session".to_vec()).ok(),
            metadata: Vec::new(),
            field_cache: HashMap::new(),
            settings,
            paths: resolve_paths().unwrap(),
            started_at: Instant::now(),
            last_health_log: Instant::now(),
            next_request_id: 1,
        };
        assert!(!broker.is_expired());
    }

    #[test]
    fn json_errors_are_escaped() {
        assert_eq!(
            error_json("bad \"value\""),
            "{\"error\":\"bad \\\"value\\\"\"}"
        );
    }

    #[test]
    fn status_reports_the_compiled_build_mode() {
        let mut broker = Broker {
            session: None,
            metadata: Vec::new(),
            field_cache: HashMap::new(),
            settings: Settings::default(),
            paths: resolve_paths().unwrap(),
            started_at: Instant::now(),
            last_health_log: Instant::now(),
            next_request_id: 1,
        };
        assert!(
            broker
                .status_json()
                .contains(&format!("\"debug\":{}", cfg!(debug_assertions)))
        );
    }

    #[test]
    fn diagnostics_report_contains_only_aggregate_runtime_state() {
        let broker = Broker {
            session: None,
            metadata: b"[]".to_vec(),
            field_cache: HashMap::new(),
            settings: Settings::default(),
            paths: resolve_paths().unwrap(),
            started_at: Instant::now(),
            last_health_log: Instant::now(),
            next_request_id: 1,
        };
        let diagnostics = broker.diagnostics_json();
        assert!(diagnostics.contains("\"rssKiB\":"));
        assert!(diagnostics.contains("\"peakRssKiB\":"));
        assert!(diagnostics.contains("\"cachedFields\":0"));
        assert!(!diagnostics.contains("BW_SESSION"));
    }

    #[test]
    fn bitwarden_operation_names_do_not_include_item_ids() {
        assert_eq!(
            safe_bw_operation(&[
                OsStr::new("get"),
                OsStr::new("password"),
                OsStr::new("private-item-id")
            ]),
            "get-password"
        );
    }

    #[test]
    fn debug_timestamps_use_iso_8601_utc() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_787_572_800), "2026-08-24T12:00:00Z");
    }

    #[test]
    fn runtime_log_rotates_at_the_size_limit() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "caelestia-vault-log-test-{}-{unique}",
            std::process::id()
        ));
        let paths = AppPaths {
            runtime_dir: root.join("runtime"),
            socket: root.join("runtime/broker.sock"),
            lock: root.join("runtime/broker.lock"),
            settings_dir: root.join("settings"),
            settings: root.join("settings/settings.conf"),
            state_dir: root.join("state"),
            debug_log: root.join("state/debug.log"),
        };
        fs::create_dir_all(&paths.state_dir).unwrap();
        let log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&paths.debug_log)
            .unwrap();
        log.set_len(DEBUG_LOG_MAX_BYTES).unwrap();
        drop(log);

        runtime_log(&paths, "DEBUG", "event=rotation_test");

        assert_eq!(
            fs::metadata(rotated_debug_log(&paths.debug_log, 1))
                .unwrap()
                .len(),
            DEBUG_LOG_MAX_BYTES
        );
        assert!(
            fs::read_to_string(&paths.debug_log)
                .unwrap()
                .contains("event=rotation_test")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn field_cache_separates_item_and_field() {
        let id = OsStr::new("item-1");
        assert_ne!(
            field_cache_key("username", id),
            field_cache_key("password", id)
        );
        assert_ne!(
            field_cache_key("password", id),
            field_cache_key("password", OsStr::new("item-2"))
        );
    }

    #[test]
    fn base64_cache_values_are_decoded() {
        assert_eq!(base64_decode(b"c2VjcmV0").unwrap(), b"secret");
        assert_eq!(base64_decode(b"YQ==").unwrap(), b"a");
        assert!(base64_decode(b"invalid").is_err());
    }
}
