"""Explicit disposable-container integration gate; refuses ordinary hosts.

Tests installation/backup mechanics with a fixture PAM file, never PAM presence.
"""
import os
import hashlib
import json
import pathlib
import select
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parent.parent
BUILD = pathlib.Path(sys.argv.pop(1)).resolve()


class InstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not pathlib.Path("/.dockerenv").exists() or os.getuid() != 0 or os.environ.get("EA_DISPOSABLE_TEST") != "1":
            raise unittest.SkipTest("requires the explicitly owned disposable container")
        cls.pam = pathlib.Path("/etc/pam.d/gdm-password")
        cls.base = pathlib.Path("/var/lib/ea-native-operator")
        cls.policy = pathlib.Path("/etc/ea-native-operator")
        if any(path.exists() for path in [cls.pam, cls.base, cls.policy]):
            raise RuntimeError("refusing to adopt preexisting desktop or native installation state")
        cls.pam.write_text("auth optional pam_gnome_keyring.so\nsession optional pam_gnome_keyring.so auto_start\n")
        cls.pam.chmod(0o644)
        cls.machine = pathlib.Path("/etc/machine-id")
        cls.original_machine = cls.machine.read_bytes() if cls.machine.exists() else None
        cls.machine.write_bytes(b"0123456789abcdef0123456789abcdef\n")
        cls.machine.chmod(0o444)
        cls.temp = tempfile.TemporaryDirectory(prefix="ea-native-install-")
        cls.source = pathlib.Path(cls.temp.name) / "source"
        shutil.copytree(SOURCE, cls.source)
        (cls.source / "build").mkdir(exist_ok=True)
        shutil.copy2(BUILD / "ea-native-operator", cls.source / "build/ea-native-operator")
        cls.destination = pathlib.Path(cls.temp.name) / "installed"
        subprocess.run(["sh", str(cls.source / "install.sh"), "0", str(cls.destination), "gnu-tar"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.pam.unlink()
        if cls.original_machine is None:
            cls.machine.unlink()
        else:
            cls.machine.write_bytes(cls.original_machine)
        shutil.rmtree(cls.base)
        shutil.rmtree(cls.policy)
        pathlib.Path("/usr/libexec/ea-native-backup").unlink()
        pathlib.Path("/usr/libexec/ea-native-restore").unlink()
        pathlib.Path("/usr/share/polkit-1/actions/org.einsatzarchiv.operator.policy").unlink()
        cls.temp.cleanup()

    def test_marker_native_filesystem_lifecycle(self):
        subprocess.run([str(BUILD / "test-marker")], check=True)

    def test_existing_account_directory_is_never_silently_adopted(self):
        run = subprocess.run(["sh", str(self.source / "install.sh"), "0", str(self.destination), "gnu-tar"], capture_output=True)
        self.assertNotEqual(run.returncode, 0)

    def test_real_account_bytes_id_crosscheck_and_headless_lock(self):
        public_id = os.urandom(32)
        wrapping_key = os.urandom(32)
        instance_hash = hashlib.sha256(os.urandom(32)).digest()
        machine = self.machine.read_bytes()
        binding = hashlib.sha256(machine + os.getuid().to_bytes(4, "big")).digest()
        marker = self.base / "0/marker"
        marker.write_bytes(b"EANAT01\0" + public_id + wrapping_key + instance_hash + binding)
        marker.chmod(0o600)
        subprocess.run(["chattr", "+d", str(marker)], check=True)
        try:
            run = subprocess.run([str(BUILD / "ea-native-operator")], input=b'{"op":"account"}', capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0)
            response = json.loads(run.stdout)
            self.assertEqual(response, {"ok": True, "platform": "linux", "uid": os.getuid(),
                "machine_id_bytes": machine.hex(), "locked": True, "installation_id": public_id.hex()})
            self.assertNotIn(wrapping_key.hex().encode(), run.stdout + run.stderr)
            self.assertEqual(run.stderr, b"")
            # Wrong expected ID must fail before any presence or key-store call.
            request = json.dumps({"op": "sign", "slot": "operator-instance", "presence": True,
                                  "data": "00", "installation_id": "00" * 32}).encode()
            run = subprocess.run([str(BUILD / "ea-native-operator")], input=request, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(json.loads(run.stdout), {"ok": False, "code": "installation-changed"})
            original = marker.read_bytes()
            # The actual reset path cannot delete a marker merely because the
            # parent supplies presence:true. This headless account has no
            # native session/Polkit presence; no positive presence is simulated.
            request = json.dumps({"op": "reset", "presence": True, "installation_id": public_id.hex()}).encode()
            run = subprocess.run([str(BUILD / "ea-native-operator")], input=request, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(json.loads(run.stdout), {"ok": False, "code": "locked"})
            self.assertEqual(marker.read_bytes(), original)
            self.assertEqual(run.stderr, b"")
            # Even a valid installed marker never produces watcher readiness
            # without actual native session/keyring coverage.
            child = subprocess.Popen([str(BUILD / "ea-native-operator")], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                child.stdin.write(json.dumps({"op": "watch-session", "installation_id": public_id.hex()}).encode() + b"\n")
                child.stdin.flush()
                self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                self.assertEqual(json.loads(child.stdout.readline()), {"ok": False, "code": "watch-unavailable"})
                self.assertEqual(child.wait(timeout=5), 1)
                self.assertEqual(child.stdout.read(), b"")
                self.assertEqual(child.stderr.read(), b"")
                self.assertEqual(marker.read_bytes(), original)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdin.close()
                child.stdout.close()
                child.stderr.close()
        finally:
            marker.unlink()

    def test_real_tar_archive_excludes_both_marker_and_temporary_publication(self):
        # Independent fixed payloads; not actual instance secrets.
        marker = self.base / "0/marker"
        pending = self.base / "0/.pending"
        marker.write_bytes(b"must-not-be-in-backup")
        pending.write_bytes(b"also-excluded-during-publication")
        archive = pathlib.Path(self.temp.name) / "backup.tar"
        try:
            # Hostile caller-supplied options must not override the wrapper.
            env = dict(os.environ, TAR_OPTIONS="--no-wildcards --anchored")
            subprocess.run(["sh", "/usr/libexec/ea-native-backup", str(archive), "/var/lib"], env=env, check=True, capture_output=True)
            with tarfile.open(archive) as tar:
                names = tar.getnames()
                self.assertTrue(names)
                self.assertFalse(any("ea-native-operator" in name for name in names))
        finally:
            marker.unlink()
            pending.unlink()

    def test_backup_of_marker_subtree_or_symlink_to_it_is_rejected(self):
        marker = self.base / "0/marker"
        marker.write_bytes(b"must-not-be-in-backup")
        alias = pathlib.Path(self.temp.name) / "alias"
        alias.symlink_to(self.base / "0", target_is_directory=True)
        try:
            for directory in [self.base, self.base / "0", alias]:
                archive = pathlib.Path(self.temp.name) / "forbidden.tar"
                run = subprocess.run(["sh", "/usr/libexec/ea-native-backup", str(archive), str(directory)], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(archive.exists())
        finally:
            marker.unlink()
            alias.unlink()

    def test_policy_removal_fails_closed(self):
        policy = self.policy / "backup-policy"
        moved = self.policy / "temporarily-absent"
        policy.rename(moved)
        try:
            run = subprocess.run([str(BUILD / "ea-native-operator")], input=b'{"op":"account"}', capture_output=True)
            result = json.loads(run.stdout)
            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "backup-policy-required")
        finally:
            moved.rename(policy)


unittest.main()
