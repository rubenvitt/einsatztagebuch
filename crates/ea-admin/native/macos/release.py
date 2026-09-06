#!/usr/bin/env python3
"""Explicit signed build/install/restore. Never called by native verification.

No production test override, PATH tool lookup, identity discovery, profile
fallback, snapshot claim, automatic permission request or Keychain operation.
"""
import argparse
import contextlib
import datetime
import fcntl
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
HELPER = "org.einsatzarchiv.operator.native"
MONITOR = "org.einsatzarchiv.operator.monitor"
PARENT = "org.einsatzarchiv.cli"
ROOT = Path("/Library/Application Support/Einsatzarchiv")
APP = "EinsatzarchivNative.app"
SERVICE = "EinsatzarchivMonitor.app"
PLIST = Path("/Library/LaunchDaemons") / (MONITOR + ".plist")
UNSAFE = {"com.apple.security.get-task-allow", "get-task-allow",
          "com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-jit",
          "com.apple.security.cs.allow-dyld-environment-variables",
          "com.apple.security.cs.allow-unsigned-executable-memory",
          "com.apple.security.cs.disable-executable-page-protection"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(arguments):
    require(str(arguments[0]).startswith("/"), "tool path must be absolute")
    result = subprocess.run([str(x) for x in arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"})
    require(result.returncode == 0, "required release tool failed: " + Path(arguments[0]).name)
    return result.stdout


def identity(team):
    require(re.fullmatch(r"[A-Z0-9]{10}", team) is not None, "explicit Apple Team ID required")


def entitlements(team, identifier):
    value = {"com.apple.application-identifier": team + "." + identifier,
             "com.apple.developer.team-identifier": team}
    if identifier == HELPER:
        value["keychain-access-groups"] = [team + "." + HELPER]
    else:
        value["com.apple.developer.endpoint-security.client"] = True
    return value


def validate_profile(profile, team, identifier):
    require(profile.get("TeamIdentifier") == [team], "provisioning profile Team mismatch")
    expiry = profile.get("ExpirationDate")
    require(isinstance(expiry, datetime.datetime) and expiry.replace(tzinfo=datetime.timezone.utc) >
            datetime.datetime.now(datetime.timezone.utc), "expired or undated provisioning profile")
    granted = profile.get("Entitlements", {})
    for key, expected in entitlements(team, identifier).items():
        require(granted.get(key) == expected, "profile lacks exact entitlement: " + key)
    require(not any(granted.get(key) for key in UNSAFE), "development or unsafe profile refused")


def profile_at(path, team, identifier):
    validate_profile(plistlib.loads(run(["/usr/bin/security", "cms", "-D", "-i", path])), team, identifier)


def dump(path, value):
    path.write_bytes(plistlib.dumps(value, sort_keys=True))


def requirement(team, identifier):
    identity(team)
    require(identifier in (HELPER, MONITOR, PARENT), "unexpected signing identifier")
    return 'anchor apple generic and identifier "' + identifier + '" and certificate leaf[subject.OU] = "' + team + '"'


def verify_code(path, team, identifier):
    run(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R", requirement(team, identifier), path])
    # Runtime peer checks independently validate dynamic code and these flags.
    details = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    flags = re.search(rb"^CodeDirectory .*?flags=0x([0-9a-fA-F]+)", details.stderr, re.MULTILINE)
    require(details.returncode == 0 and flags is not None and int(flags.group(1), 16) & 0x10000 != 0,
            "Hardened Runtime required")
    raw = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", path])
    granted = plistlib.loads(raw) if raw.strip() else {}
    require(not any(granted.get(key) for key in UNSAFE), "unsafe signed entitlement")
    if identifier != PARENT:
        require(granted == entitlements(team, identifier), "unexpected signed entitlements")


def reject_links(tree):
    require(tree.is_dir() and not tree.is_symlink(), "real release directory required")
    for parent, directories, files in os.walk(tree, followlinks=False):
        for name in directories + files:
            info = os.lstat(Path(parent) / name)
            require(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                    "release contains link or special file")


def verify_release(directory, team):
    identity(team)
    reject_links(directory)
    require({p.name for p in directory.iterdir()} == {APP, SERVICE, MONITOR + ".plist"}, "unexpected release files")
    for bundle, identifier, executable in ((APP, HELPER, "ea-native-operator"), (SERVICE, MONITOR, "ea-native-monitor")):
        root = directory / bundle
        info = plistlib.loads((root / "Contents/Info.plist").read_bytes())
        require(info.get("CFBundleIdentifier") == identifier and info.get("CFBundleExecutable") == executable,
                "bundle layout mismatch")
        profile_at(root / "Contents/embedded.provisionprofile", team, identifier)
        verify_code(root, team, identifier)
    verify_code(directory / APP / "Contents/MacOS/ea-cli", team, PARENT)
    expected = launch_plist()
    require(plistlib.loads((directory / (MONITOR + ".plist")).read_bytes()) == expected, "launchd contract mismatch")


def launch_plist():
    return {"Label": MONITOR, "ProgramArguments": [str(ROOT / SERVICE / "Contents/MacOS/ea-native-monitor")],
            "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": True,
            "ThrottleInterval": 30, "ProcessType": "Interactive", "Umask": 0o077,
            "SoftResourceLimits": {"NumberOfFiles": 128, "Core": 0},
            "HardResourceLimits": {"NumberOfFiles": 128, "Core": 0}}


def stop_service():
    target = "system/" + MONITOR
    result = subprocess.run(["/bin/launchctl", "print", target], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    if result.returncode == 0:
        run(["/bin/launchctl", "bootout", target])
    else:
        # This is launchctl's specific service-not-found result, not a generic
        # permission, launchd, parsing or transport error. Unknown results stop.
        missing = ('Could not find service "' + MONITOR + '" in domain for system').encode()
        require(result.returncode == 113 and missing in result.stderr, "cannot determine monitor service state")


def build(args):
    # Keep caller cwd semantics across build.sh's chdir. absolute() preserves
    # final symlinks for the existing validation instead of resolving them away.
    for name in ("output", "cli", "helper_profile", "monitor_profile"):
        setattr(args, name, getattr(args, name).absolute())
    identity(args.team)
    require(re.fullmatch(r"[A-Fa-f0-9]{40}", args.identity) is not None, "explicit signing-certificate SHA-1 required")
    require(not args.output.exists(), "build output must not exist")
    require(args.cli.is_file() and not args.cli.is_symlink(), "compiled Rust CLI required")
    profile_at(args.helper_profile, args.team, HELPER)
    profile_at(args.monitor_profile, args.team, MONITOR)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ea-signed-build-", dir=args.output.parent) as temporary:
        work = Path(temporary)
        run(["/bin/sh", HERE / "build.sh", work / "binaries"])
        release = work / "release"
        release.mkdir()
        for bundle, identifier, executable, profile in ((APP, HELPER, "ea-native-operator", args.helper_profile),
                                                        (SERVICE, MONITOR, "ea-native-monitor", args.monitor_profile)):
            root = release / bundle
            (root / "Contents/MacOS").mkdir(parents=True)
            shutil.copyfile(work / "binaries" / executable, root / "Contents/MacOS" / executable)
            os.chmod(root / "Contents/MacOS" / executable, 0o755)
            shutil.copyfile(profile, root / "Contents/embedded.provisionprofile")
            dump(root / "Contents/Info.plist", {"CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
                 "CFBundleName": bundle[:-4], "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
                 "LSUIElement": True, "LSMinimumSystemVersion": "13.0"})
            if identifier == HELPER:
                sibling = root / "Contents/MacOS/ea-cli"
                shutil.copyfile(args.cli, sibling)
                os.chmod(sibling, 0o755)
                run(["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp", "--sign", args.identity,
                     "--identifier", PARENT, sibling])
            entitlement_file = work / (identifier + ".entitlements")
            dump(entitlement_file, entitlements(args.team, identifier))
            run(["/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp", "--sign", args.identity,
                 "--identifier", identifier, "--entitlements", entitlement_file, root])
        dump(release / (MONITOR + ".plist"), launch_plist())
        verify_release(release, args.team)
        os.rename(release, args.output)
    print("Signed release built and statically verified; entitled runtime acceptance is still required.")


def protected_directory(path):
    for current in [path] + list(path.parents):
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
                "installation ancestors must be root-owned and not group/world writable")


@contextlib.contextmanager
def invalidate_namespace(uid):
    """Hold the same native marker lock until installation publication finishes."""
    require(uid > 0, "explicit non-root affected OS UID required")
    account = pwd.getpwuid(uid)
    directory = Path(account.pw_dir) / "Library/Application Support/Einsatzarchiv/NativeOperator"
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    lock_fd = None
    try:
        for component in directory.parts[1:]:
            require(component not in (".", ".."), "invalid account home")
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                yield
                return
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700, "invalid namespace directory")
        try:
            lock_fd = os.open("lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            require(not os.path.lexists(directory / "installation-v1"), "unlocked namespace marker exists")
            yield
            return
        lock_info = os.fstat(lock_fd)
        require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == uid and lock_info.st_nlink == 1 and
                stat.S_IMODE(lock_info.st_mode) == 0o600, "invalid namespace lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = directory.lstat()
        require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), "namespace directory changed")
        try:
            marker = os.stat("installation-v1", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            marker = None
        if marker is not None:
            require(stat.S_ISREG(marker.st_mode) and marker.st_uid == uid and marker.st_nlink == 1 and
                    stat.S_IMODE(marker.st_mode) == 0o600 and marker.st_size == 136, "invalid namespace marker")
            os.unlink("installation-v1", dir_fd=fd)
            os.fsync(fd)
        yield
        require(not os.path.lexists(directory / "installation-v1"), "namespace recreated during install")
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(fd)


def install(args):
    args.release = args.release.absolute()
    require(os.getuid() == 0 and os.geteuid() == 0, "installer must be explicitly run as root")
    verify_release(args.release, args.team)
    protected_directory(ROOT.parent)
    if not ROOT.exists():
        ROOT.mkdir(mode=0o755)
    protected_directory(ROOT)
    protected_directory(PLIST.parent)
    # A second installer cannot race namespace invalidation or publication.
    lock_fd = os.open(ROOT / ".install-lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(lock_fd)
        require(lock_info.st_uid == 0 and stat.S_ISREG(lock_info.st_mode) and lock_info.st_nlink == 1 and
                stat.S_IMODE(lock_info.st_mode) == 0o600, "invalid installer lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix=".pending-", dir=ROOT) as temporary:
            stage = Path(temporary)
            incoming = stage / "incoming"
            shutil.copytree(args.release, incoming, symlinks=True)
            reject_links(incoming)
            for parent, directories, files in os.walk(incoming):
                os.chown(parent, 0, 0); os.chmod(parent, 0o755)
                for name in files:
                    path = Path(parent) / name
                    os.chown(path, 0, 0)
                    os.chmod(path, 0o755 if "/MacOS/" in str(path) else 0o644)
            verify_release(incoming, args.team)
            stop_service()
            # Hide old signed launch paths in a root-only staging directory.
            # On any later failure they stay unavailable; never silently roll
            # back to a marker/key namespace already declared invalid.
            with contextlib.ExitStack() as locks:
                for uid in sorted(set(args.account_uid)):
                    locks.enter_context(invalidate_namespace(uid))
                for name in (APP, SERVICE):
                    target = ROOT / name
                    if target.exists():
                        require(not target.is_symlink(), "installed bundle is a symlink")
                        os.rename(target, stage / ("old-" + name))
                    os.rename(incoming / name, target)
                temporary_plist = stage / "launchd.plist"
                shutil.copyfile(incoming / (MONITOR + ".plist"), temporary_plist)
                os.chmod(temporary_plist, 0o644)
                os.replace(temporary_plist, PLIST)
                for name in (APP, SERVICE):
                    protected_directory(ROOT / name)
            print("Namespaces invalidated and signed bundles installed. External reidentification and old-binding revocation are required.")
            print("Service is not started automatically. After entitlement/FDA deployment approval, run: /bin/launchctl bootstrap system " + str(PLIST))
            print("Profile restore must finish BEFORE this command; later snapshot/marker rollback is not solved.")
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build")
    for flag in ("team", "identity"):
        build_parser.add_argument("--" + flag, required=True)
    for flag in ("cli", "helper-profile", "monitor-profile", "output"):
        build_parser.add_argument("--" + flag, type=Path, required=True)
    for command in ("install", "restore"):
        install_parser = commands.add_parser(command)
        install_parser.add_argument("--release", type=Path, required=True)
        install_parser.add_argument("--team", required=True)
        install_parser.add_argument("--account-uid", type=int, action="append", required=True,
                                    help="every affected actual OS account; repeat for each account")
    args = parser.parse_args()
    try:
        (build if args.command == "build" else install)(args)
    except (ValueError, OSError, subprocess.SubprocessError, plistlib.InvalidFileException):
        parser.exit(1, "Release operation refused; deployment remains unaccepted. Inspect explicit inputs and protected paths.\n")


if __name__ == "__main__":
    main()
