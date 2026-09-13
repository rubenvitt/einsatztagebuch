//! Small, read-only OS measurements. Raw output never leaves this module.

use crate::{DevicePostureReport, PostureCheck, PostureRequirement as R};
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: usize = 4096;
const MEASUREMENT_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn macos_report() -> DevicePostureReport {
    let mut report = DevicePostureReport::unresolved();
    if cfg!(target_os = "macos") {
        let mut command = Command::new("/usr/bin/fdesetup");
        command.arg("status");
        let output = run(command, MEASUREMENT_TIMEOUT);
        report.full_disk_encryption = filevault(output.as_deref());
    }
    report
}

fn filevault(output: Option<&str>) -> PostureCheck {
    match output.map(str::trim) {
        Some("FileVault is On.") => R::FullDiskEncryption.pass(),
        Some("FileVault is Off.") => R::FullDiskEncryption.fail(),
        _ => R::FullDiskEncryption.unknown(),
    }
}

pub(crate) fn ubuntu_report() -> DevicePostureReport {
    let mut report = DevicePostureReport::unresolved();
    if !cfg!(target_os = "linux") {
        return report;
    }
    let mut mount = Command::new("/usr/bin/findmnt");
    mount.args([
        "--noheadings",
        "--raw",
        "--output",
        "SOURCE",
        "--target",
        "/",
    ]);
    let Some(source) = run(mount, MEASUREMENT_TIMEOUT) else {
        return report;
    };
    let device = source.trim();
    // No names from an application setting and no shell. Subvolumes, multiple
    // mounts and non-block roots require a richer topology proof: Unknown.
    if !device.starts_with("/dev/")
        || !device
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
    {
        return report;
    }
    let mut topology = Command::new("/usr/bin/lsblk");
    topology.args([
        "--inverse",
        "--noheadings",
        "--raw",
        "--output",
        "TYPE",
        "--",
        device,
    ]);
    let output = run(topology, MEASUREMENT_TIMEOUT);
    report.full_disk_encryption = linux_encryption(output.as_deref());
    report
}

fn linux_encryption(output: Option<&str>) -> PostureCheck {
    let Some(output) = output else {
        return R::FullDiskEncryption.unknown();
    };
    let types: Vec<_> = output.lines().map(str::trim).collect();
    // Admit only a single familiar ancestry chain. Seeing "crypt" somewhere
    // in a RAID/multipath tree does not prove that every backing path is encrypted.
    if !matches!(
        types.as_slice(),
        ["crypt", "disk"]
            | ["crypt", "part", "disk"]
            | ["lvm", "crypt", "part", "disk"]
            | ["lvm", "crypt", "disk"]
            | ["crypt", "lvm", "part", "disk"]
            | ["crypt", "lvm", "disk"]
            | ["disk"]
            | ["part", "disk"]
            | ["lvm", "part", "disk"]
            | ["lvm", "disk"]
    ) {
        return R::FullDiskEncryption.unknown();
    }
    if types.contains(&"crypt") {
        R::FullDiskEncryption.pass()
    } else {
        R::FullDiskEncryption.fail()
    }
}

pub(crate) fn windows_host_report() -> DevicePostureReport {
    if !cfg!(target_os = "windows") {
        return DevicePostureReport::unresolved();
    }
    // The Object Manager's system root is independent of PATH, drive mappings
    // and caller-controlled SystemRoot. Same namespace as ADR-0006 validation.
    let mut command =
        Command::new(r"\\?\GLOBALROOT\SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe");
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        WINDOWS_MEASUREMENTS,
    ]);
    let output = run(command, MEASUREMENT_TIMEOUT);
    windows_report(output.as_deref())
}

const WINDOWS_MEASUREMENTS: &str = r"
$ErrorActionPreference = 'Stop'
$fde = 'unknown'; $lock = 'unknown'
try {
  Import-Module '\\?\GLOBALROOT\SystemRoot\System32\WindowsPowerShell\v1.0\Modules\BitLocker\BitLocker.psd1'
  $volumes = @(BitLocker\Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'OperatingSystem' -or $_.VolumeType -eq 'FixedData' })
  if ($volumes.Count -gt 0) {
    $fde = 'pass'
    foreach ($volume in $volumes) {
      if ($null -eq $volume.ProtectionStatus -or $null -eq $volume.VolumeStatus) { $fde = 'unknown'; break }
      if ($volume.ProtectionStatus -ne 'On' -or $volume.VolumeStatus -ne 'FullyEncrypted') { $fde = 'fail' }
    }
  }
} catch { $fde = 'unknown' }
try {
  $seconds = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs
  if ($seconds -is [int] -and $seconds -gt 0 -and $seconds -le 599940) { $lock = 'pass' }
} catch { $lock = 'unknown' }
[Console]::WriteLine('fde=' + $fde)
[Console]::WriteLine('lock=' + $lock)
";

fn windows_report(output: Option<&str>) -> DevicePostureReport {
    let unresolved = DevicePostureReport::unresolved();
    let Some(output) = output else {
        return unresolved;
    };
    let lines: Vec<_> = output.lines().collect();
    let [fde, lock] = lines.as_slice() else {
        return unresolved;
    };
    let (Some(fde), Some(lock)) = (fde.strip_prefix("fde="), lock.strip_prefix("lock=")) else {
        return unresolved;
    };
    let parse = |value, requirement: R| match value {
        "pass" => Some(requirement.pass()),
        "fail" => Some(requirement.fail()),
        "unknown" => Some(requirement.unknown()),
        _ => None,
    };
    let (Some(fde), Some(lock)) = (
        parse(fde, R::FullDiskEncryption),
        parse(lock, R::AutomaticScreenLock),
    ) else {
        return unresolved;
    };
    DevicePostureReport {
        full_disk_encryption: fde,
        automatic_screen_lock: lock,
        ..unresolved
    }
}

/// No input, inherited hooks, stderr, sensitive inventory or unbounded output.
/// A deadline covers both process exit and stdout EOF. Error output is discarded.
pub(crate) fn run(mut command: Command, timeout: Duration) -> Option<String> {
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .current_dir("/");
    if cfg!(windows) {
        let system = r"\\?\GLOBALROOT\SystemRoot";
        command
            .env("SystemRoot", system)
            .env("WINDIR", system)
            .env("PATH", format!(r"{system}\System32"))
            .current_dir(format!(r"{system}\System32"));
    }
    let start = Instant::now();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let result = (|| {
        let pipe = child.stdout.take()?;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let read = pipe
                .take((OUTPUT_LIMIT + 1) as u64)
                .read_to_end(&mut output);
            let _ = sender.send(if read.is_ok() && output.len() <= OUTPUT_LIMIT {
                Some(output)
            } else {
                None
            });
        });
        let mut output = None;
        let mut status = None;
        loop {
            if let Ok(received) = receiver.try_recv() {
                output = Some(received?);
            }
            if status.is_none() {
                status = child.try_wait().ok()?;
            }
            if start.elapsed() >= timeout {
                return None;
            }
            if let Some(status) = status {
                if !status.success() {
                    return None;
                }
                if let Some(output) = output {
                    return String::from_utf8(output).ok();
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_none() {
        let _ = child.kill();
        let cleanup = Instant::now();
        while child.try_wait().ok().flatten().is_none()
            && cleanup.elapsed() < Duration::from_secs(1)
        {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PostureRequirement as R;

    #[test]
    fn filevault_requires_an_exact_completed_status() {
        assert_eq!(
            filevault(Some("FileVault is On.\n")),
            R::FullDiskEncryption.pass()
        );
        assert_eq!(
            filevault(Some("FileVault is Off.\n")),
            R::FullDiskEncryption.fail()
        );
        for output in [
            None,
            Some(""),
            Some("FileVault is On.\nConversion in progress."),
            Some("Encryption in progress: 99%"),
            Some("FileVault is On. injected"),
        ] {
            assert_eq!(filevault(output), R::FullDiskEncryption.unknown());
        }
    }

    #[test]
    fn encryption_of_one_linux_ancestor_is_not_proof_for_a_mixed_tree() {
        assert_eq!(
            linux_encryption(Some("lvm\ncrypt\npart\ndisk\n")),
            R::FullDiskEncryption.pass()
        );
        assert_eq!(
            linux_encryption(Some("part\ndisk\n")),
            R::FullDiskEncryption.fail()
        );
        for output in [
            None,
            Some(""),
            Some("lvm\ncrypt\npart\ndisk\npart\ndisk\n"),
            Some("raid1\ncrypt\npart\ndisk\n"),
            Some("loop\n"),
            Some("crypt\n"),
        ] {
            assert_eq!(linux_encryption(output), R::FullDiskEncryption.unknown());
        }
    }

    #[test]
    fn windows_measurement_codes_are_closed_and_do_not_attest_human_or_patch_policy() {
        let report = windows_report(Some("fde=pass\nlock=pass\n"));
        assert_eq!(report.full_disk_encryption, R::FullDiskEncryption.pass());
        assert_eq!(report.automatic_screen_lock, R::AutomaticScreenLock.pass());
        assert_eq!(
            report.locked_non_shared_account,
            R::LockedNonSharedAccount.unknown()
        );
        assert_eq!(
            report.supported_os_patch_level,
            R::SupportedOsPatchLevel.unknown()
        );
        assert!(!report.is_production_ready());
        let failed = windows_report(Some("fde=fail\nlock=unknown\n"));
        assert_eq!(failed.full_disk_encryption, R::FullDiskEncryption.fail());
        for output in [
            None,
            Some("fde=pass\nlock=pass\nextra=1"),
            Some("fde=pass\nfde=pass"),
            Some("fde=0\nlock=pass"),
            Some("fde=pass"),
        ] {
            assert_eq!(
                windows_report(output),
                crate::DevicePostureReport::unresolved()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_oversized_and_timed_out_commands_produce_no_measurement() {
        use std::{
            process::Command,
            time::{Duration, Instant},
        };
        assert!(run(Command::new("/usr/bin/false"), Duration::from_secs(1)).is_none());
        assert!(run(Command::new("/usr/bin/yes"), Duration::from_secs(1)).is_none());
        let mut delayed = Command::new("/bin/sleep");
        delayed.arg("10");
        let start = Instant::now();
        assert!(run(delayed, Duration::from_millis(50)).is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
