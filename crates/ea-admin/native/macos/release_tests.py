"""Release validation fixtures. No codesign, root install, launchctl or Keychain."""
import copy
import datetime
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import subprocess
import unittest
from unittest import mock

import release


class ReleaseTests(unittest.TestCase):
    team = "ABCDE12345"

    def profile(self, identifier):
        return {"TeamIdentifier": [self.team], "Entitlements": release.entitlements(self.team, identifier),
                "ExpirationDate": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)}

    def test_helper_exact_group(self):
        value = self.profile(release.HELPER)
        release.validate_profile(value, self.team, release.HELPER)
        value["Entitlements"]["keychain-access-groups"] = [self.team + ".*"]
        with self.assertRaises(ValueError):
            release.validate_profile(value, self.team, release.HELPER)

    def test_es_entitlement_required(self):
        value = self.profile(release.MONITOR)
        release.validate_profile(value, self.team, release.MONITOR)
        del value["Entitlements"]["com.apple.developer.endpoint-security.client"]
        with self.assertRaises(ValueError):
            release.validate_profile(value, self.team, release.MONITOR)

    def test_wrong_team_expiry_unsafe_profile(self):
        profile = self.profile(release.MONITOR)
        for key in release.UNSAFE:
            value = copy.deepcopy(profile)
            value["Entitlements"][key] = True
            with self.assertRaises(ValueError):
                release.validate_profile(value, self.team, release.MONITOR)
        for key, bad in (("TeamIdentifier", ["OTHER12345"]), ("ExpirationDate", datetime.datetime(2000, 1, 1))):
            value = copy.deepcopy(profile)
            value[key] = bad
            with self.assertRaises(ValueError):
                release.validate_profile(value, self.team, release.MONITOR)

    def test_requirement_pins_all_three_parts(self):
        for identifier in (release.HELPER, release.MONITOR, release.PARENT):
            value = release.requirement(self.team, identifier)
            self.assertIn('anchor apple generic', value)
            self.assertIn('identifier "' + identifier + '"', value)
            self.assertIn('subject.OU] = "' + self.team + '"', value)
        with self.assertRaises(ValueError):
            release.requirement('A" or true', release.HELPER)

    def test_caller_relative_build_paths(self):
        # Run the actual build.sh chdir and release copy/rename operations.
        # Only compilation, signatures and profile validation are fixtures.
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            source = root / "native"
            source.mkdir()
            (source / "build.sh").write_bytes((release.HERE / "build.sh").read_bytes())
            tools = root / "tools"
            tools.mkdir()
            compiler = tools / "xcrun"
            compiler.write_text('#!/bin/sh\nwhile [ $# -gt 0 ]; do\n'
                                '  if [ "$1" = "-o" ]; then\n    shift\n'
                                '    printf fixture > "$1"\n    exit 0\n  fi\n  shift\ndone\nexit 1\n')
            compiler.chmod(0o700)
            (root / "cli").write_bytes(b"fixture CLI")
            (root / "helper.profile").write_bytes(b"fixture profile")
            (root / "monitor.profile").write_bytes(b"fixture profile")
            previous = Path.cwd()
            os.chdir(root)
            try:
                def tool(arguments):
                    if arguments[0] == "/bin/sh":
                        subprocess.run([str(x) for x in arguments], check=True, timeout=10,
                                       env={"PATH": str(tools) + ":/usr/bin:/bin", "TMPDIR": str(root)})
                    else:
                        self.assertEqual(arguments[0], "/usr/bin/codesign")
                    return b""
                with mock.patch.object(release, "HERE", source), mock.patch.object(release, "profile_at") as profile, \
                     mock.patch.object(release, "verify_release"), mock.patch.object(release, "run", side_effect=tool), \
                     mock.patch("builtins.print"):
                    for output in (root / "absolute-release", Path("dist/relative-release")):
                        args = SimpleNamespace(team=self.team, identity="1" * 40, output=output,
                                               cli=Path("cli"), helper_profile=Path("helper.profile"),
                                               monitor_profile=Path("monitor.profile"))
                        release.build(args)
                        self.assertTrue((root / output / release.APP / "Contents/MacOS/ea-native-operator").is_file())
                        self.assertTrue((root / output / release.SERVICE / "Contents/MacOS/ea-native-monitor").is_file())
                        for name in ("output", "cli", "helper_profile", "monitor_profile"):
                            self.assertTrue(getattr(args, name).is_absolute())
                    self.assertTrue(all(call.args[0].is_absolute() for call in profile.call_args_list))
                self.assertEqual({item.name for item in source.iterdir()}, {"build.sh"})
            finally:
                os.chdir(previous)

    def test_relative_cli_symlink_stays_rejected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            (root / "cli").write_bytes(b"fixture CLI")
            (root / "link").symlink_to("cli")
            previous = Path.cwd()
            os.chdir(root)
            try:
                args = SimpleNamespace(team=self.team, identity="1" * 40, output=Path("output"),
                                       cli=Path("link"), helper_profile=Path("profile"), monitor_profile=Path("profile"))
                with mock.patch.object(release, "profile_at") as profile:
                    with self.assertRaisesRegex(ValueError, "compiled Rust CLI required"):
                        release.build(args)
                    profile.assert_not_called()
            finally:
                os.chdir(previous)

    def test_fixed_launchd_program(self):
        value = release.launch_plist()
        self.assertEqual(value["UserName"], "root")
        self.assertEqual(value["ProgramArguments"], [str(release.ROOT / release.SERVICE / "Contents/MacOS/ea-native-monitor")])
        self.assertEqual(value["HardResourceLimits"]["NumberOfFiles"], 128)
        self.assertNotIn("EnvironmentVariables", value)

    def test_service_absence_is_specific(self):
        message = ('Could not find service "' + release.MONITOR + '" in domain for system').encode()
        with mock.patch.object(release.subprocess, "run", return_value=SimpleNamespace(returncode=113, stderr=message)):
            with mock.patch.object(release, "run") as mutate:
                release.stop_service()
                mutate.assert_not_called()
        with mock.patch.object(release.subprocess, "run", return_value=SimpleNamespace(returncode=1, stderr=b"permission denied")):
            with self.assertRaises(ValueError):
                release.stop_service()

    def test_running_service_is_stopped(self):
        with mock.patch.object(release.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
            with mock.patch.object(release, "run") as mutate:
                release.stop_service()
                mutate.assert_called_once_with(["/bin/launchctl", "bootout", "system/" + release.MONITOR])

    def test_links_and_hardlinks_refused(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            target = root / "original"
            target.write_bytes(b"fixture")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                release.reject_links(root)
            link.unlink()
            os.link(target, link)
            with self.assertRaises(ValueError):
                release.reject_links(root)

    def test_invalidation_retained_marker_and_lock(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            home = Path(temporary)
            directory = home / "Library/Application Support/Einsatzarchiv/NativeOperator"
            directory.mkdir(parents=True, mode=0o700)
            marker = directory / "installation-v1"
            marker.write_bytes(b"fixture".ljust(136, b"x"))
            marker.chmod(0o600)
            lock = directory / "lock"
            lock.touch(mode=0o600)
            uid = os.getuid()
            with mock.patch.object(release.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))):
                with release.invalidate_namespace(uid):
                    self.assertFalse(marker.exists())
                    import fcntl
                    with lock.open("rb") as competing:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(lock.exists())

    def test_invalidation_refuses_marker_symlink(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            home = Path(temporary)
            directory = home / "Library/Application Support/Einsatzarchiv/NativeOperator"
            directory.mkdir(parents=True, mode=0o700)
            (directory / "lock").touch(mode=0o600)
            target = home / "untouched"
            target.write_bytes(b"fixture")
            (directory / "installation-v1").symlink_to(target)
            with mock.patch.object(release.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))):
                with self.assertRaises(ValueError):
                    with release.invalidate_namespace(os.getuid()):
                        self.fail("unsafe marker accepted")
            self.assertEqual(target.read_bytes(), b"fixture")


if __name__ == "__main__":
    unittest.main()
