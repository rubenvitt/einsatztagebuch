//! Read-only machine identity for the fresh-machine recovery comparison.
//! The OS measurement is not proof of hardware protection or user presence.
use ea_types::Hash32;
use std::{process::Command, time::Duration};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MeasuredMachineIdentity {
    fingerprint: Hash32,
}
impl MeasuredMachineIdentity {
    pub const fn fingerprint(self) -> Hash32 {
        self.fingerprint
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineIdentityError;
impl MachineIdentityError {
    pub const fn code(self) -> &'static str {
        "EA-MACHINE-IDENTITY-UNAVAILABLE"
    }
}
impl std::fmt::Display for MachineIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for MachineIdentityError {}

fn measured(identity: &str, uuid: bool) -> Result<MeasuredMachineIdentity, MachineIdentityError> {
    let identity = identity.trim_ascii();
    if identity.len() != if uuid { 36 } else { 32 }
        || identity.bytes().enumerate().any(|(i, b)| {
            if uuid && [8, 13, 18, 23].contains(&i) {
                b != b'-'
            } else {
                !b.is_ascii_hexdigit()
            }
        })
    {
        return Err(MachineIdentityError);
    }
    let normalized = identity.to_ascii_lowercase();
    if normalized.bytes().filter(|b| *b != b'-').all(|b| b == b'0')
        || normalized.bytes().filter(|b| *b != b'-').all(|b| b == b'f')
    {
        return Err(MachineIdentityError);
    }
    let mut bytes = b"EINSATZARCHIV-CEREMONY-MACHINE-v1".to_vec();
    bytes.extend_from_slice(normalized.as_bytes());
    let fingerprint = Hash32::try_from(ea_crypto::object_hash(&bytes).as_bytes().as_slice())
        .map_err(|_| MachineIdentityError)?;
    Ok(MeasuredMachineIdentity { fingerprint })
}
fn macos_identity(output: &str) -> Result<MeasuredMachineIdentity, MachineIdentityError> {
    let mut values = output
        .lines()
        .filter_map(|line| line.trim_ascii().strip_prefix("\"IOPlatformUUID\" = "));
    let value = values.next().ok_or(MachineIdentityError)?;
    if values.next().is_some() {
        return Err(MachineIdentityError);
    }
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or(MachineIdentityError)?;
    measured(value, true)
}
pub fn measure_native_machine_identity() -> Result<MeasuredMachineIdentity, MachineIdentityError> {
    if cfg!(target_os = "macos") {
        let mut command = Command::new("/usr/sbin/ioreg");
        command.args(["-rd1", "-c", "IOPlatformExpertDevice"]);
        return macos_identity(
            &crate::native_posture::run(command, Duration::from_secs(2))
                .ok_or(MachineIdentityError)?,
        );
    }
    if cfg!(target_os = "linux") {
        return read_linux_identity();
    }
    if cfg!(windows) {
        let mut command = Command::new(
            r"\\?\GLOBALROOT\SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        );
        command.args(["-NoLogo","-NoProfile","-NonInteractive","-Command",r"$ErrorActionPreference='Stop'; $v=Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid'; if ($v -isnot [string]) {exit 1}; [Console]::WriteLine($v)"]);
        return measured(
            &crate::native_posture::run(command, Duration::from_secs(2))
                .ok_or(MachineIdentityError)?,
            true,
        );
    }
    Err(MachineIdentityError)
}
#[cfg(unix)]
fn read_linux_identity() -> Result<MeasuredMachineIdentity, MachineIdentityError> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    let file = match std::fs::File::open("/etc/machine-id") {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::File::open("/var/lib/dbus/machine-id").map_err(|_| MachineIdentityError)?
        }
        Err(_) => return Err(MachineIdentityError),
    };
    let metadata = file.metadata().map_err(|_| MachineIdentityError)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > 128
    {
        return Err(MachineIdentityError);
    }
    let mut output = String::new();
    file.take(129)
        .read_to_string(&mut output)
        .map_err(|_| MachineIdentityError)?;
    measured(&output, false)
}
#[cfg(not(unix))]
fn read_linux_identity() -> Result<MeasuredMachineIdentity, MachineIdentityError> {
    Err(MachineIdentityError)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_measurement_parsers_reject_missing_ambiguous_and_placeholder_identities() {
        for value in [
            "",
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "caller-name",
            "1111111111111111111111111111111g",
        ] {
            assert!(measured(value, false).is_err());
        }
        assert!(measured("0123456789abcdef0123456789abcdef\n", false).is_ok());
        let output = "    \"IOPlatformUUID\" = \"01234567-89AB-CDEF-0123-456789ABCDEF\"";
        assert!(macos_identity(output).is_ok());
        assert!(macos_identity(&format!("{output}\n{output}")).is_err());
        assert!(macos_identity("\"IOPlatformUUID\" = \"not-a-machine\"").is_err());
    }
}
