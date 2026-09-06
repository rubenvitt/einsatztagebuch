//! Installed executable identity checked before the child receives private IPC.
use crate::native_provider::NativeProviderError;
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[cfg(any(target_os = "macos", windows))]
use std::{process::Command, time::Duration};
#[cfg(any(target_os = "macos", windows))]
use zeroize::Zeroizing;

pub struct NativeExecutableIdentity {
    identity: Identity,
}
enum Identity {
    #[cfg(target_os = "macos")]
    Mac(Box<MacIdentity>),
    #[cfg(target_os = "linux")]
    Linux { parent: UnixTree, helper: UnixTree },
    #[cfg(windows)]
    Windows(Box<WindowsIdentity>),
    #[cfg(any(test, feature = "test-support"))]
    Fixture,
}

impl NativeExecutableIdentity {
    /// `parent` must be this process's installed executable, with its sibling helper.
    /// This constructor never consults fixture flags, environment identity, or helper output.
    pub fn for_installed(parent: &Path, helper: &Path) -> Result<Self, NativeProviderError> {
        absolute_file(parent)?;
        absolute_file(helper)?;
        let current = std::env::current_exe().map_err(|_| NativeProviderError::Unavailable)?;
        if fs::canonicalize(parent).map_err(io_error)?
            != fs::canonicalize(current).map_err(io_error)?
            || parent.parent() != helper.parent()
            || parent == helper
        {
            return Err(NativeProviderError::Denied);
        }
        #[cfg(target_os = "macos")]
        let identity = Identity::Mac(Box::new(MacIdentity::new(parent, helper)?));
        #[cfg(target_os = "linux")]
        let identity = {
            let parent = UnixTree::capture(parent)?;
            parent.verify_process(std::process::id())?;
            Identity::Linux {
                parent,
                helper: UnixTree::capture(helper)?,
            }
        };
        #[cfg(windows)]
        let identity = Identity::Windows(Box::new(WindowsIdentity::new(parent, helper)?));
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        return Err(NativeProviderError::Unavailable);
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Ok(Self { identity })
    }

    /// Call from the runner's check callback while it still withholds stdin.
    pub fn verify_child(&self, helper: &Path, pid: u32) -> Result<(), NativeProviderError> {
        match &self.identity {
            #[cfg(any(test, feature = "test-support"))]
            Identity::Fixture => Ok(()),
            #[cfg(target_os = "macos")]
            Identity::Mac(identity) => {
                valid_child_pid(pid)?;
                identity.verify_child(helper, pid)
            }
            #[cfg(target_os = "linux")]
            Identity::Linux {
                parent,
                helper: installed,
            } => {
                valid_child_pid(pid)?;
                if helper != installed.path() {
                    return Err(NativeProviderError::Denied);
                }
                parent.recheck()?;
                parent.verify_process(std::process::id())?;
                installed.recheck()?;
                installed.verify_process(pid)?;
                parent.recheck()?;
                installed.recheck()
            }
            #[cfg(windows)]
            Identity::Windows(identity) => {
                valid_child_pid(pid)?;
                identity.verify_child(helper, pid)
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture() -> Self {
        Self {
            identity: Identity::Fixture,
        }
    }
}

fn io_error(error: std::io::Error) -> NativeProviderError {
    if error.kind() == std::io::ErrorKind::NotFound {
        NativeProviderError::Unavailable
    } else {
        NativeProviderError::Denied
    }
}
fn absolute_file(path: &Path) -> Result<(), NativeProviderError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        || !fs::symlink_metadata(path)
            .map_err(io_error)?
            .file_type()
            .is_file()
    {
        return Err(NativeProviderError::Denied);
    }
    Ok(())
}
fn valid_child_pid(pid: u32) -> Result<(), NativeProviderError> {
    if pid == 0 || pid == std::process::id() {
        Err(NativeProviderError::Denied)
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "macos", test))]
fn codesign_field<'a>(output: &'a [u8], name: &str) -> Result<&'a str, NativeProviderError> {
    let text = std::str::from_utf8(output).map_err(|_| NativeProviderError::Denied)?;
    let mut fields = text.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key == name).then_some(value)
    });
    let value = fields
        .next()
        .filter(|v| !v.is_empty())
        .ok_or(NativeProviderError::Denied)?;
    if fields.next().is_some() {
        return Err(NativeProviderError::Denied);
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
struct MacIdentity {
    parent: PathBuf,
    helper: PathBuf,
    parent_stamp: UnixStamp,
    helper_stamp: UnixStamp,
    team: String,
    helper_cdhash: String,
}
#[cfg(target_os = "macos")]
impl MacIdentity {
    fn new(parent: &Path, helper: &Path) -> Result<Self, NativeProviderError> {
        let parent_stamp = UnixStamp::file(parent)?;
        let helper_stamp = UnixStamp::file(helper)?;
        let parent_info = mac_verified_code(parent.as_os_str(), "org.einsatzarchiv.cli", None)?;
        let pid = std::process::id().to_string();
        let running =
            mac_verified_code(pid.as_ref(), "org.einsatzarchiv.cli", Some(&parent_info.0))?;
        if running != parent_info {
            return Err(NativeProviderError::Denied);
        }
        let helper_info = mac_verified_code(
            helper.as_os_str(),
            "org.einsatzarchiv.operator.native",
            Some(&parent_info.0),
        )?;
        parent_stamp.recheck(parent)?;
        helper_stamp.recheck(helper)?;
        Ok(Self {
            parent: parent.into(),
            helper: helper.into(),
            parent_stamp,
            helper_stamp,
            team: parent_info.0,
            helper_cdhash: helper_info.1,
        })
    }
    fn verify_child(&self, helper: &Path, pid: u32) -> Result<(), NativeProviderError> {
        if helper != self.helper {
            return Err(NativeProviderError::Denied);
        }
        self.parent_stamp.recheck(&self.parent)?;
        self.helper_stamp.recheck(helper)?;
        let pid = pid.to_string();
        let info = mac_verified_code(
            pid.as_ref(),
            "org.einsatzarchiv.operator.native",
            Some(&self.team),
        )?;
        if info.1 != self.helper_cdhash {
            return Err(NativeProviderError::Denied);
        }
        self.parent_stamp.recheck(&self.parent)?;
        self.helper_stamp.recheck(helper)
    }
}

#[cfg(target_os = "macos")]
fn mac_verified_code(
    target: &std::ffi::OsStr,
    identifier: &str,
    team: Option<&str>,
) -> Result<(String, String), NativeProviderError> {
    let mut requirement = format!("anchor apple generic and identifier \"{identifier}\"");
    if let Some(team) = team {
        valid_team(team)?;
        requirement.push_str(&format!(" and certificate leaf[subject.OU] = \"{team}\""));
    }
    let mut verify = mac_command();
    verify
        .args(["--verify", "--strict", "-R", &requirement])
        .arg(target);
    checked_tool(verify, Vec::new())?;
    let mut display = mac_command();
    display.args(["--display", "--verbose=4"]).arg(target);
    let output = checked_tool(display, Vec::new())?;
    let actual_team = codesign_field(&output.stderr, "TeamIdentifier")?;
    valid_team(actual_team)?;
    let cdhash = codesign_field(&output.stderr, "CDHash")?;
    if codesign_field(&output.stderr, "Identifier")? != identifier
        || team.is_some_and(|t| actual_team != t)
        || !matches!(cdhash.len(), 40 | 64)
        || !cdhash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(NativeProviderError::Denied);
    }
    // Reverify after display: the extracted metadata must still satisfy the exact requirement.
    let mut verify = mac_command();
    verify
        .args(["--verify", "--strict", "-R", &requirement])
        .arg(target);
    checked_tool(verify, Vec::new())?;
    Ok((actual_team.to_owned(), cdhash.to_owned()))
}

#[cfg(any(target_os = "macos", test))]
fn valid_team(team: &str) -> Result<(), NativeProviderError> {
    if team.len() != 10
        || !team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(NativeProviderError::Denied);
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn mac_command() -> Command {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .current_dir("/");
    command
}
#[cfg(any(target_os = "macos", windows))]
fn checked_tool(
    command: Command,
    input: Vec<u8>,
) -> Result<crate::native_process::Output, NativeProviderError> {
    let output = crate::native_process::run(
        command,
        Zeroizing::new(input),
        Duration::from_secs(10),
        |_| Ok(()),
    )?;
    if !output.success {
        return Err(NativeProviderError::Denied);
    }
    Ok(output)
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct UnixStamp {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
#[cfg(unix)]
impl UnixStamp {
    fn metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
    #[cfg(any(target_os = "macos", test))]
    fn file(path: &Path) -> Result<Self, NativeProviderError> {
        absolute_file(path)?;
        Ok(Self::metadata(
            &fs::symlink_metadata(path).map_err(io_error)?,
        ))
    }
    #[cfg(any(target_os = "macos", test))]
    fn recheck(&self, path: &Path) -> Result<(), NativeProviderError> {
        if *self != Self::file(path)? {
            return Err(NativeProviderError::Denied);
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn protected_unix_mode(owner: u32, mode: u32, directory: bool) -> Result<(), NativeProviderError> {
    let expected_kind = if directory { 0o040000 } else { 0o100000 };
    if owner != 0 || mode & 0o022 != 0 || mode & 0o111 == 0 || mode & 0o170000 != expected_kind {
        return Err(NativeProviderError::Denied);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
struct UnixTree(Vec<(PathBuf, UnixStamp)>);
#[cfg(any(target_os = "linux", all(test, unix)))]
impl UnixTree {
    fn capture(path: &Path) -> Result<Self, NativeProviderError> {
        absolute_file(path)?;
        let mut tree = Vec::new();
        for (i, component) in path.ancestors().enumerate() {
            let stamp = UnixStamp::metadata(&fs::symlink_metadata(component).map_err(io_error)?);
            protected_unix_mode(stamp.owner, stamp.mode, i != 0)?;
            tree.push((component.to_owned(), stamp));
        }
        let result = Self(tree);
        result.recheck()?;
        Ok(result)
    }
    fn path(&self) -> &Path {
        &self.0[0].0
    }
    fn recheck(&self) -> Result<(), NativeProviderError> {
        for (path, stamp) in &self.0 {
            if *stamp != UnixStamp::metadata(&fs::symlink_metadata(path).map_err(io_error)?) {
                return Err(NativeProviderError::Denied);
            }
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn verify_process(&self, pid: u32) -> Result<(), NativeProviderError> {
        // This kernel-owned link is the one permitted symlink: inspect its open image's inode.
        let image = fs::metadata(format!("/proc/{pid}/exe")).map_err(io_error)?;
        if self.0[0].1 != UnixStamp::metadata(&image) {
            return Err(NativeProviderError::Denied);
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn matching_signer(parent: &str, helper: &str) -> Result<Vec<u8>, NativeProviderError> {
    let parent = hex::decode(parent).map_err(|_| NativeProviderError::Denied)?;
    let helper = hex::decode(helper).map_err(|_| NativeProviderError::Denied)?;
    if !(128..=16_384).contains(&parent.len()) || parent != helper {
        return Err(NativeProviderError::Denied);
    }
    Ok(parent)
}

#[cfg(any(windows, test))]
const WINDOWS_RELEASE_MANIFEST: &str = "ea-native-operator.release.psd1";
#[cfg(any(windows, test))]
const WINDOWS_RELEASE_ASSETS: [&str; 9] = [
    "einsatzarchiv.exe",
    "ea-native-operator.exe",
    "ea-native-operator.dll",
    "ea-native-operator.deps.json",
    "ea-native-operator.runtimeconfig.json",
    "NSec.Cryptography.dll",
    "libsodium.dll",
    "WinRT.Runtime.dll",
    "Microsoft.Windows.SDK.NET.dll",
];

#[cfg(any(windows, test))]
fn verified_windows_release(
    evidence: &serde_json::Value,
    version: &str,
    architecture: &str,
) -> Result<Vec<u8>, NativeProviderError> {
    use serde_json::Value;
    let parent = evidence
        .get("parent_signer")
        .and_then(Value::as_str)
        .ok_or(NativeProviderError::Denied)?;
    let certificate = matching_signer(
        parent,
        evidence
            .get("helper_signer")
            .and_then(serde_json::Value::as_str)
            .ok_or(NativeProviderError::Denied)?,
    )?;
    matching_signer(
        parent,
        evidence
            .get("manifest_signer")
            .and_then(Value::as_str)
            .ok_or(NativeProviderError::Denied)?,
    )?;
    let manifest = evidence
        .get("manifest")
        .and_then(Value::as_object)
        .ok_or(NativeProviderError::Denied)?;
    let machine = match architecture {
        "win-x64" => 0x8664,
        "win-arm64" => 0xaa64,
        _ => return Err(NativeProviderError::Denied),
    };
    if manifest.len() != 7
        || manifest.get("Schema").and_then(Value::as_u64) != Some(1)
        || manifest.get("Product").and_then(Value::as_str) != Some("org.einsatzarchiv")
        || manifest.get("ParentRole").and_then(Value::as_str) != Some("org.einsatzarchiv.cli")
        || manifest.get("HelperRole").and_then(Value::as_str)
            != Some("org.einsatzarchiv.operator.native")
        || manifest.get("Version").and_then(Value::as_str) != Some(version)
        || manifest.get("Architecture").and_then(Value::as_str) != Some(architecture)
        || evidence.get("parent_machine").and_then(Value::as_u64) != Some(machine)
        || evidence.get("helper_machine").and_then(Value::as_u64) != Some(machine)
    {
        return Err(NativeProviderError::Denied);
    }
    let authorized = manifest
        .get("Assets")
        .and_then(Value::as_object)
        .ok_or(NativeProviderError::Denied)?;
    let actual = evidence
        .get("files")
        .and_then(Value::as_object)
        .ok_or(NativeProviderError::Denied)?;
    if authorized.len() != WINDOWS_RELEASE_ASSETS.len()
        || actual.len() != WINDOWS_RELEASE_ASSETS.len() + 1
        || !actual
            .get(WINDOWS_RELEASE_MANIFEST)
            .and_then(Value::as_str)
            .is_some_and(release_hash)
    {
        return Err(NativeProviderError::Denied);
    }
    for asset in WINDOWS_RELEASE_ASSETS {
        let expected = authorized
            .get(asset)
            .and_then(Value::as_str)
            .ok_or(NativeProviderError::Denied)?;
        if !release_hash(expected) || actual.get(asset).and_then(Value::as_str) != Some(expected) {
            return Err(NativeProviderError::Denied);
        }
    }
    Ok(certificate)
}

#[cfg(any(windows, test))]
fn release_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(windows)]
struct WindowsIdentity {
    parent: PathBuf,
    helper: PathBuf,
    certificate: Vec<u8>,
    // FILE_SHARE_READ only, including the signed manifest, all DLLs and runtime configuration.
    _bundle_locks: Vec<fs::File>,
}
#[cfg(windows)]
impl WindowsIdentity {
    fn new(parent: &Path, helper: &Path) -> Result<Self, NativeProviderError> {
        use std::os::windows::fs::OpenOptionsExt;
        if parent.file_name().and_then(|n| n.to_str()) != Some("einsatzarchiv.exe")
            || helper.file_name().and_then(|n| n.to_str()) != Some("ea-native-operator.exe")
        {
            return Err(NativeProviderError::Denied);
        }
        let directory = parent.parent().ok_or(NativeProviderError::Denied)?;
        let bundle_locks = WINDOWS_RELEASE_ASSETS
            .iter()
            .copied()
            .chain([WINDOWS_RELEASE_MANIFEST])
            .map(|name| {
                let path = directory.join(name);
                absolute_file(&path).map_err(|_| NativeProviderError::Denied)?;
                fs::OpenOptions::new()
                    .read(true)
                    .share_mode(1)
                    .open(path)
                    .map_err(|_| NativeProviderError::Denied)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let certificate = windows_evidence(parent, helper, None)?;
        Ok(Self {
            parent: parent.into(),
            helper: helper.into(),
            certificate,
            _bundle_locks: bundle_locks,
        })
    }
    fn verify_child(&self, helper: &Path, pid: u32) -> Result<(), NativeProviderError> {
        if helper != self.helper
            || windows_evidence(&self.parent, helper, Some(pid))? != self.certificate
        {
            return Err(NativeProviderError::Denied);
        }
        Ok(())
    }
}

#[cfg(windows)]
fn windows_evidence(
    parent: &Path,
    helper: &Path,
    child: Option<u32>,
) -> Result<Vec<u8>, NativeProviderError> {
    // GLOBALROOT selects the real system Object Manager namespace, not an environment or drive override.
    // https://learn.microsoft.com/windows/win32/fileio/naming-a-file#nt-namespaces
    let system = r"\\?\GLOBALROOT\SystemRoot";
    let mut command = Command::new(format!(
        r"{system}\System32\WindowsPowerShell\v1.0\powershell.exe"
    ));
    command
        .env_clear()
        .env("SystemRoot", system)
        .env("WINDIR", system)
        .env("PATH", format!(r"{system}\System32"))
        .current_dir(format!(r"{system}\System32"))
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_VERIFY,
        ]);
    let input = serde_json::to_vec(&serde_json::json!({
        "parent": parent.to_str().ok_or(NativeProviderError::Denied)?,
        "helper": helper.to_str().ok_or(NativeProviderError::Denied)?,
        "parent_pid": std::process::id(), "child_pid": child,
    }))
    .map_err(|_| NativeProviderError::Denied)?;
    let output = checked_tool(command, input)?;
    let evidence: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| NativeProviderError::Denied)?;
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "win-x64",
        "aarch64" => "win-arm64",
        _ => return Err(NativeProviderError::Unavailable),
    };
    verified_windows_release(&evidence, env!("CARGO_PKG_VERSION"), architecture)
}

#[cfg(windows)]
const WINDOWS_VERIFY: &str = r#"
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module ($PSHOME + '\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1')
Import-Module ($PSHOME + '\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
function Full-Image([string]$value) {
    if ($value.StartsWith('\\?\')) { $value = $value.Substring(4) }
    if ($value -notmatch '^[A-Za-z]:\\' -or $value.Substring(2).Contains(':')) { throw 'image path' }
    return [IO.Path]::GetFullPath($value)
}
function Protected-Tree([string]$value) {
    $path = Full-Image $value
    $depth = 0
    while ($null -ne $path) {
        $attributes = [IO.File]::GetAttributes($path)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse point' }
        if ($depth -eq 0 -and ($attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw 'not executable' }
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path
        $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'owner' }
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $raw.DiscretionaryAcl) { throw 'null DACL' }
        [long]$write = 0x500D0156
        # Creating unrelated entries at a volume root does not permit replacing a protected child.
        if ($path -eq [IO.Path]::GetPathRoot($path)) { $write = $write -band (-bnot 6) }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ([long]$rule.FileSystemRights -band $write) -ne 0 -and $rule.IdentityReference.Value -notin $trusted) {
                throw 'writable installation'
            }
        }
        $parent = [IO.Directory]::GetParent($path)
        $path = if ($null -eq $parent) { $null } else { $parent.FullName }
        $depth++
        if ($depth -gt 128) { throw 'depth' }
    }
}
function Signer([string]$path) {
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) { throw 'signature' }
    return [BitConverter]::ToString($signature.SignerCertificate.RawData).Replace('-', '')
}
function File-Sha256([string]$path) {
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Image-Machine([string]$path) {
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'DOS header' }
        $stream.Position = 0x3c
        $offset = $reader.ReadUInt32()
        if ($offset -gt ($stream.Length - 6)) { throw 'PE offset' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'PE header' }
        return $reader.ReadUInt16()
    } finally { $reader.Dispose() }
}
try {
    $request = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
    $parentPath = Full-Image $request.parent
    $helperPath = Full-Image $request.helper
    $parentProcess = [Diagnostics.Process]::GetProcessById([int]$request.parent_pid)
    if (-not [String]::Equals((Full-Image $parentProcess.MainModule.FileName), $parentPath, [StringComparison]::OrdinalIgnoreCase)) { throw 'parent image' }
    Protected-Tree $parentPath
    Protected-Tree $helperPath
    $parentSigner = Signer $parentPath
    $helperSigner = Signer $helperPath
    if ($helperSigner -cne $parentSigner) { throw 'different signer' }
    $directory = [IO.Path]::GetDirectoryName($parentPath)
    if ([IO.Path]::GetDirectoryName($helperPath) -cne $directory) { throw 'helper directory' }
    $manifestPath = [IO.Path]::Combine($directory, 'ea-native-operator.release.psd1')
    Protected-Tree $manifestPath
    if ([IO.FileInfo]::new($manifestPath).Length -gt 65536) { throw 'manifest length' }
    $manifestSigner = Signer $manifestPath
    if ($manifestSigner -cne $parentSigner) { throw 'manifest signer' }
    # Restricted data import occurs only after OS signature verification; never invoke the manifest.
    $manifest = Microsoft.PowerShell.Utility\Import-PowerShellDataFile -LiteralPath $manifestPath
    $entries = [IO.Directory]::GetFileSystemEntries($directory)
    if ($entries.Count -ne 10) { throw 'bundle inventory' }
    $files = @{}
    foreach ($path in $entries) {
        Protected-Tree $path
        $files[[IO.Path]::GetFileName($path)] = File-Sha256 $path
    }
    if ($null -ne $request.child_pid) {
        $child = [Diagnostics.Process]::GetProcessById([int]$request.child_pid)
        $childPath = Full-Image $child.MainModule.FileName
        if (-not [String]::Equals($childPath, $helperPath, [StringComparison]::OrdinalIgnoreCase)) { throw 'child image' }
        Protected-Tree $childPath
        if ((Signer $childPath) -cne $parentSigner -or $child.HasExited) { throw 'child signature' }
    }
    Protected-Tree $parentPath
    Protected-Tree $helperPath
    $response = @{parent_signer=$parentSigner; helper_signer=$helperSigner; manifest_signer=$manifestSigner;
        manifest=$manifest; files=$files; parent_machine=(Image-Machine $parentPath); helper_machine=(Image-Machine $helperPath)}
    [Console]::Out.Write((Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $response -Depth 6 -Compress))
    exit 0
} catch { exit 1 }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    // Receipt from the trusted OS-validator port, not a mock signing authority.
    fn windows_release_receipt() -> serde_json::Value {
        let digest = "ab".repeat(32);
        let mut files = serde_json::json!({
            "einsatzarchiv.exe": digest, "ea-native-operator.exe": digest,
            "ea-native-operator.dll": digest, "ea-native-operator.deps.json": digest,
            "ea-native-operator.runtimeconfig.json": digest, "NSec.Cryptography.dll": digest,
            "libsodium.dll": digest, "WinRT.Runtime.dll": digest,
            "Microsoft.Windows.SDK.NET.dll": digest,
        });
        let manifest = serde_json::json!({
            "Schema": 1, "Product": "org.einsatzarchiv", "ParentRole": "org.einsatzarchiv.cli",
            "HelperRole": "org.einsatzarchiv.operator.native", "Version": "0.1.0",
            "Architecture": "win-x64", "Assets": files,
        });
        files["ea-native-operator.release.psd1"] = serde_json::json!(digest);
        serde_json::json!({
            "parent_signer": "30".repeat(256), "helper_signer": "30".repeat(256),
            "manifest_signer": "30".repeat(256), "manifest": manifest, "files": files,
            "parent_machine": 0x8664, "helper_machine": 0x8664,
        })
    }

    #[test]
    fn windows_release_binds_product_roles_version_and_both_apphost_architectures() {
        let receipt = windows_release_receipt();
        assert_eq!(
            verified_windows_release(&receipt, "0.1.0", "win-x64").unwrap(),
            vec![0x30; 256]
        );
        for field in [
            "Product",
            "ParentRole",
            "HelperRole",
            "Version",
            "Architecture",
        ] {
            let mut changed = receipt.clone();
            changed["manifest"][field] = serde_json::json!("another-product-role-or-release");
            assert!(
                verified_windows_release(&changed, "0.1.0", "win-x64").is_err(),
                "{field}"
            );
        }
        for field in ["parent_machine", "helper_machine"] {
            let mut changed = receipt.clone();
            changed[field] = serde_json::json!(0xaa64);
            assert!(
                verified_windows_release(&changed, "0.1.0", "win-x64").is_err(),
                "{field}"
            );
        }
        let mut arm = receipt;
        arm["manifest"]["Architecture"] = serde_json::json!("win-arm64");
        arm["parent_machine"] = serde_json::json!(0xaa64);
        arm["helper_machine"] = serde_json::json!(0xaa64);
        assert!(verified_windows_release(&arm, "0.1.0", "win-arm64").is_ok());
    }

    #[test]
    fn windows_release_rejects_same_publisher_substitution_and_every_changed_bundle_asset() {
        let receipt = windows_release_receipt();
        for asset in [
            "einsatzarchiv.exe",
            "ea-native-operator.exe",
            "ea-native-operator.dll",
            "ea-native-operator.deps.json",
            "ea-native-operator.runtimeconfig.json",
            "NSec.Cryptography.dll",
            "libsodium.dll",
            "WinRT.Runtime.dll",
            "Microsoft.Windows.SDK.NET.dll",
        ] {
            let mut changed = receipt.clone();
            changed["files"][asset] = serde_json::json!("cd".repeat(32));
            assert!(
                verified_windows_release(&changed, "0.1.0", "win-x64").is_err(),
                "{asset}"
            );
        }
    }

    #[test]
    fn windows_release_requires_the_parent_signed_manifest_and_exact_asset_inventory() {
        let receipt = windows_release_receipt();
        for field in ["manifest", "manifest_signer"] {
            let mut missing = receipt.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                verified_windows_release(&missing, "0.1.0", "win-x64").is_err(),
                "{field}"
            );
        }
        let mut other_signer = receipt.clone();
        other_signer["manifest_signer"] = serde_json::json!("31".repeat(256));
        assert!(verified_windows_release(&other_signer, "0.1.0", "win-x64").is_err());
        for key in ["files", "manifest"] {
            let mut extra = receipt.clone();
            extra[key]["unexpected.dll"] = serde_json::json!("ab".repeat(32));
            assert!(
                verified_windows_release(&extra, "0.1.0", "win-x64").is_err(),
                "{key}"
            );
        }
        let mut missing = receipt.clone();
        missing["files"]
            .as_object_mut()
            .unwrap()
            .remove("ea-native-operator.release.psd1");
        assert!(verified_windows_release(&missing, "0.1.0", "win-x64").is_err());
        let mut malformed = receipt;
        malformed["manifest"]["Assets"]["libsodium.dll"] = serde_json::json!("not-a-sha256");
        assert!(verified_windows_release(&malformed, "0.1.0", "win-x64").is_err());
    }

    #[test]
    fn team_identifier_cannot_inject_a_code_requirement() {
        valid_team("AB12CD34EF").unwrap();
        for team in [
            "not set",
            "AB12CD34E",
            "AB12CD34EF0",
            "ab12cd34ef",
            "AB\" or true",
            "AB12CD34E\n",
        ] {
            assert_eq!(valid_team(team), Err(NativeProviderError::Denied));
        }
    }

    #[test]
    fn a_child_identity_cannot_name_this_process_or_pid_zero() {
        assert_eq!(valid_child_pid(0), Err(NativeProviderError::Denied));
        assert_eq!(
            valid_child_pid(std::process::id()),
            Err(NativeProviderError::Denied)
        );
    }

    #[cfg(unix)]
    struct Files(PathBuf);
    #[cfg(unix)]
    impl Files {
        fn new() -> Self {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).unwrap();
            let path =
                std::env::temp_dir().join(format!("ea-native-identity-{}", hex::encode(random)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    #[cfg(unix)]
    impl Drop for Files {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn executable_replacement_and_final_symlinks_invalidate_the_snapshot() {
        let files = Files::new();
        let helper = files.0.join("helper");
        fs::write(&helper, b"installed bytes").unwrap();
        let stamp = UnixStamp::file(&helper).unwrap();
        stamp.recheck(&helper).unwrap();
        let replacement = files.0.join("replacement");
        fs::write(&replacement, b"installed bytes").unwrap();
        fs::rename(&replacement, &helper).unwrap();
        assert_eq!(stamp.recheck(&helper), Err(NativeProviderError::Denied));
        let link = files.0.join("helper-link");
        std::os::unix::fs::symlink(&helper, &link).unwrap();
        assert_eq!(UnixStamp::file(&link), Err(NativeProviderError::Denied));
        assert!(UnixTree::capture(&helper).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unix_tree_accepts_root_protected_system_installation() {
        let tree = UnixTree::capture(Path::new("/usr/bin/codesign")).unwrap();
        assert_eq!(tree.path(), Path::new("/usr/bin/codesign"));
        tree.recheck().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apple_system_signature_does_not_authorize_an_operator_identifier() {
        assert_eq!(
            mac_verified_code(
                Path::new("/usr/bin/true").as_os_str(),
                "org.einsatzarchiv.operator.native",
                None
            ),
            Err(NativeProviderError::Denied)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dynamic_pid_verification_rejects_the_uninstalled_test_process() {
        let pid = std::process::id().to_string();
        assert_eq!(
            mac_verified_code(pid.as_ref(), "org.einsatzarchiv.cli", None),
            Err(NativeProviderError::Denied)
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_installation_requires_root_ownership_execute_and_no_unprivileged_writes() {
        protected_unix_mode(0, 0o100755, false).unwrap();
        protected_unix_mode(0, 0o040755, true).unwrap();
        for (owner, mode, directory) in [
            (501, 0o100755, false),
            (0, 0o100775, false),
            (0, 0o100757, false),
            (0, 0o100644, false),
            (0, 0o040775, true),
            (0, 0o120755, false),
        ] {
            assert!(protected_unix_mode(owner, mode, directory).is_err());
        }
    }

    #[test]
    fn windows_signer_identity_requires_the_exact_certificate_not_a_publisher_label() {
        let certificate = "30".repeat(256);
        assert_eq!(
            matching_signer(&certificate, &certificate).unwrap(),
            vec![0x30; 256]
        );
        for other in ["31".repeat(256), "Publisher Name".to_owned(), String::new()] {
            assert!(matching_signer(&certificate, &other).is_err());
        }
        assert!(matching_signer("", "").is_err());
    }

    #[test]
    fn codesign_metadata_requires_one_exact_team_field() {
        assert_eq!(
            codesign_field(
                b"Identifier=org.einsatzarchiv.cli\nTeamIdentifier=AB12CD34EF\n",
                "TeamIdentifier"
            ),
            Ok("AB12CD34EF")
        );
        for input in [
            b"Authority=TeamIdentifier=AB12CD34EF\n".as_slice(),
            b"TeamIdentifier=AB12CD34EF\nTeamIdentifier=ZZ12CD34EF\n",
            b"TeamIdentifier=\n",
            b"TeamIdentifier=AB12CD34EF\n\xff",
        ] {
            assert_eq!(
                codesign_field(input, "TeamIdentifier"),
                Err(NativeProviderError::Denied)
            );
        }
    }

    #[test]
    fn fixture_constructor_does_not_relax_production_installation_checks() {
        let relative = Path::new("ea-native-operator");
        NativeExecutableIdentity::fixture()
            .verify_child(relative, 1)
            .unwrap();
        assert!(NativeExecutableIdentity::for_installed(relative, relative).is_err());
    }
}
