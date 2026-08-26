//! Host system info for the admin console (ADR-0025 follow-up -- operator
//! feedback 2026-08-26, first time using the console live: "es waere toll,
//! wenn ich ein paar mehr informationen haette ueber das system auf dem der
//! cads tunnel gerade laeuft").
//!
//! Linux-only reads (`/proc`), matching this whole project's single
//! supported self-host target (see the workspace CLAUDE.md's own toolchain
//! assumptions) -- deliberately no `sysinfo`/`nix` dependency added for what
//! is a handful of plain-text file reads plus one `df` subprocess call
//! (`std` has no `statvfs`). Every field is `Option` (or, for disk, a
//! `Result`-shaped outcome) rather than defaulting to zero/empty on a read
//! failure -- an admin looking at this page needs to be able to tell "0
//! bytes free" from "couldn't read that", especially for disk space, where
//! the two look nothing alike in their operational implications.
//!
//! [`collect`] does blocking file/subprocess I/O -- callers on an async
//! handler must run it via `spawn_blocking`, the same convention
//! `cert_issuer::issue_cert`'s callers already follow for their own
//! subprocess call.

use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: Option<String>,
    pub kernel: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub load_avg_1m: Option<f64>,
    pub load_avg_5m: Option<f64>,
    pub load_avg_15m: Option<f64>,
    pub cpu_count: usize,
    pub mem_total_bytes: Option<u64>,
    pub mem_available_bytes: Option<u64>,
    /// The filesystem `disk_path_checked` actually resolves to, `df -P`'s own
    /// "Mounted on" column -- lets the page show what was actually measured
    /// rather than assuming the caller's requested path is the whole story.
    pub disk_mount: Option<String>,
    pub disk_total_bytes: Option<u64>,
    pub disk_available_bytes: Option<u64>,
    /// The path disk usage was measured for (`CT_CP_HOST_INFO_DISK_PATH`,
    /// default `/`) -- always present even when the `df` call itself failed,
    /// so a failure reads as "couldn't check {path}", not just "couldn't
    /// check disk".
    pub disk_path_checked: String,
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn parse_uptime_seconds() -> Option<u64> {
    let raw = read_trimmed("/proc/uptime")?;
    let first = raw.split_whitespace().next()?;
    first.parse::<f64>().ok().map(|f| f as u64)
}

fn parse_loadavg() -> (Option<f64>, Option<f64>, Option<f64>) {
    let Some(raw) = read_trimmed("/proc/loadavg") else {
        return (None, None, None);
    };
    let mut fields = raw.split_whitespace();
    let one = fields.next().and_then(|s| s.parse::<f64>().ok());
    let five = fields.next().and_then(|s| s.parse::<f64>().ok());
    let fifteen = fields.next().and_then(|s| s.parse::<f64>().ok());
    (one, five, fifteen)
}

/// `/proc/meminfo`'s `MemTotal`/`MemAvailable` lines are `NAME: N kB` --
/// `MemAvailable` (not `MemFree`) is the kernel's own "usable without
/// swapping" estimate, the number that actually answers "is this host under
/// memory pressure", not just "how much is currently untouched".
fn parse_meminfo() -> (Option<u64>, Option<u64>) {
    let Ok(raw) = fs::read_to_string("/proc/meminfo") else {
        return (None, None);
    };
    let mut total = None;
    let mut available = None;
    for line in raw.lines() {
        let Some((key, rest)) = line.split_once(':') else { continue };
        let kb = rest.trim().trim_end_matches(" kB").trim().parse::<u64>().ok();
        match key {
            "MemTotal" => total = kb.map(|k| k * 1024),
            "MemAvailable" => available = kb.map(|k| k * 1024),
            _ => {}
        }
    }
    (total, available)
}

/// `df -Pk <path>`'s second (data) line, POSIX output format (`-P`) so
/// column positions are stable across distros/coreutils versions rather
/// than depending on default (non-POSIX) formatting: `Filesystem
/// 1024-blocks Used Available Capacity Mounted-on`.
fn disk_usage(path: &str) -> Option<(String, u64, u64)> {
    let output = std::process::Command::new("df").arg("-Pk").arg(path).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let data_line = text.lines().nth(1)?;
    let fields: Vec<&str> = data_line.split_whitespace().collect();
    // Filesystem, 1024-blocks, Used, Available, Capacity, Mounted-on -- 6
    // fields, though a very long filesystem name can push df to wrap onto a
    // second line with the remaining 5 -- `df -P`'s own documented quirk.
    // Handle both shapes rather than assuming exactly 6.
    let (blocks, available, mount) = if fields.len() >= 6 {
        (fields[1], fields[3], fields[5])
    } else if fields.len() == 5 {
        (fields[0], fields[2], fields[4])
    } else {
        return None;
    };
    let total_bytes = blocks.parse::<u64>().ok()? * 1024;
    let available_bytes = available.parse::<u64>().ok()? * 1024;
    Some((mount.to_string(), total_bytes, available_bytes))
}

/// Blocking (see module doc) -- run via `spawn_blocking` from an async
/// handler. `disk_path` defaults to `/` when `None` (the whole self-host
/// deployment lives under one filesystem in every deployment this project
/// actually ships -- see `docker/deploy/compose.selfhost.yml`'s bind mounts).
pub fn collect(disk_path: Option<&str>) -> HostInfo {
    let disk_path = disk_path.unwrap_or("/").to_string();
    let (load_avg_1m, load_avg_5m, load_avg_15m) = parse_loadavg();
    let (mem_total_bytes, mem_available_bytes) = parse_meminfo();
    let disk = disk_usage(&disk_path);
    HostInfo {
        hostname: read_trimmed("/proc/sys/kernel/hostname"),
        kernel: read_trimmed("/proc/sys/kernel/osrelease"),
        uptime_seconds: parse_uptime_seconds(),
        load_avg_1m,
        load_avg_5m,
        load_avg_15m,
        cpu_count: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        mem_total_bytes,
        mem_available_bytes,
        disk_mount: disk.as_ref().map(|(m, ..)| m.clone()),
        disk_total_bytes: disk.as_ref().map(|(_, t, _)| *t),
        disk_available_bytes: disk.as_ref().map(|(_, _, a)| *a),
        disk_path_checked: disk_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `/proc` is always present on the Linux hosts this project ships on --
    /// a fail-first guard that `collect()` actually reads real kernel data,
    /// not just returning an all-`None` stub.
    #[test]
    fn collect_reads_real_host_data_on_linux() {
        let info = collect(None);
        assert!(info.hostname.is_some(), "hostname must be read from /proc/sys/kernel/hostname: {info:?}");
        assert!(info.uptime_seconds.is_some(), "uptime must be read from /proc/uptime: {info:?}");
        assert!(info.load_avg_1m.is_some(), "load average must be read from /proc/loadavg: {info:?}");
        assert!(info.mem_total_bytes.unwrap_or(0) > 0, "MemTotal must be a real positive byte count: {info:?}");
        assert!(info.cpu_count >= 1);
    }

    /// Disk usage for a path that cannot possibly exist must come back as an
    /// honest `None`, not a silent zero that would read as "this filesystem
    /// is full" -- the exact distinction this module's own doc comment
    /// promises.
    #[test]
    fn disk_usage_for_a_nonexistent_path_is_none_not_zero() {
        assert_eq!(disk_usage("/this/path/does/not/exist/ct-host-info-test"), None);
    }

    #[test]
    fn disk_usage_for_root_reports_a_real_positive_total() {
        let (mount, total, available) = disk_usage("/").expect("root filesystem must be readable via df -Pk /");
        assert!(!mount.is_empty());
        assert!(total > 0);
        assert!(available <= total, "available ({available}) must not exceed total ({total})");
    }

    #[test]
    fn parse_meminfo_matches_the_kb_documented_by_proc_meminfo_5() {
        let (total, available) = parse_meminfo();
        let total = total.expect("MemTotal must parse on a real Linux host");
        let available = available.expect("MemAvailable must parse on a real Linux host");
        assert!(available <= total, "MemAvailable ({available}) must not exceed MemTotal ({total})");
    }
}
