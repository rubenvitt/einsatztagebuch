"""Managed restore fixtures only: no host install, native reset or root tree.

Exercise real filesystem locks and disposable shell jobs beneath our owned
temporary directory. The production CLI has no fixture-root/owner override.
"""
import fcntl
import importlib.util
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parent.parent / "restore.py"
restore = None
if SOURCE.is_file():
    spec = importlib.util.spec_from_file_location("ea_linux_restore", SOURCE)
    restore = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(restore)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(restore, "managed Linux restore entry point is missing")
        self.temp = tempfile.TemporaryDirectory(prefix="ea-linux-restore-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "var/lib/ea-native-operator"
        self.jobs = self.root / "etc/ea-native-operator/restore.d"
        self.base.mkdir(parents=True)
        self.jobs.mkdir(parents=True)
        self.uid = os.getuid() if os.getuid() else 1234
        self.namespace = self.base / str(self.uid)
        self.namespace.mkdir(mode=0o700)
        if os.getuid() == 0:
            os.chown(self.namespace, self.uid, -1)
        self.marker = self.namespace / "marker"
        self.write_marker(b"old-excluded-wrapping-key-fixture")
        self.guard = self.base / (".restore-" + str(self.uid))
        self.job = self.jobs / str(self.uid)
        self.job.write_text("exit 0\n")
        self.job.chmod(0o700)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.root_fd)

    def write_marker(self, data):
        self.marker.write_bytes(data)
        self.marker.chmod(0o600)
        if os.getuid() == 0:
            os.chown(self.marker, self.uid, -1)

    def manage(self, mode="restore", dry_run=False):
        return restore.manage(self.root_fd, str(self.uid), mode, dry_run=dry_run)

    def test_dry_run_is_read_only_and_never_executes_job(self):
        output = self.root / "job-ran"
        self.job.write_text("touch " + shlex.quote(str(output)) + "\n")
        before = self.marker.read_bytes(), self.namespace.stat().st_uid, self.namespace.stat().st_mode
        result = self.manage(dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(before, (self.marker.read_bytes(), self.namespace.stat().st_uid, self.namespace.stat().st_mode))
        self.assertFalse(self.guard.exists())
        self.assertFalse(output.exists())

    def test_final_restore_bytes_are_invalidated_before_gate_reopens(self):
        output = self.root / "job-ran"
        # Restore deliberately writes a formerly retained marker. Removing only
        # BEFORE this job would let the old namespace survive and fail this test.
        self.job.write_text("test -f " + shlex.quote(str(self.guard)) + " || exit 4\n"
                            "printf restored-old-marker > " + shlex.quote(str(self.marker)) + "\n"
                            "touch " + shlex.quote(str(output)) + "\n")
        self.manage()
        self.assertTrue(output.exists())
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.guard.exists())
        self.assertEqual(list(self.namespace.iterdir()), [])
        self.assertEqual(self.namespace.stat().st_uid, self.uid)
        self.assertEqual(stat.S_IMODE(self.namespace.stat().st_mode), 0o700)

    def test_failed_job_leaves_persistent_gate_and_requires_explicit_reenrollment(self):
        self.job.write_text("exit 7\n")
        with self.assertRaises(restore.Refused):
            self.manage()
        self.assertTrue(self.guard.is_file())
        self.assertEqual(stat.S_IMODE(self.guard.stat().st_mode), 0o600)
        self.assertEqual(self.guard.stat().st_uid, os.getuid())
        self.assertEqual(self.marker.read_bytes(), b"old-excluded-wrapping-key-fixture")
        # A fresh process can finish explicit administrator reenrollment. It
        # never creates a new marker or substitutes an interactive reset.
        self.manage("reenroll")
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.guard.exists())

    def test_background_restore_writer_prevents_success_and_keeps_gate(self):
        started = self.root / "background-group"
        self.job.write_text("echo $$ > " + shlex.quote(str(started)) + "\n/bin/sleep 30 &\nexit 0\n")
        try:
            with self.assertRaises(restore.Refused):
                self.manage()
            self.assertTrue(self.guard.exists())
            self.assertTrue(self.marker.exists())
        finally:
            if started.exists():
                try:
                    os.killpg(int(started.read_text().strip()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_reaped_job_never_signals_a_potentially_reused_process_group(self):
        self.job.write_text("exit 0\n")
        def group_lookup(_pid, sent_signal):
            self.assertEqual(sent_signal, 0, "must not signal a group ID after its leader was reaped")
            raise ProcessLookupError()
        with mock.patch.object(restore.os, "killpg", side_effect=group_lookup):
            self.manage()
        self.assertFalse(self.marker.exists())

    def test_killed_manager_does_not_release_running_jobs_directory_leases(self):
        started = self.root / "job-pid"
        self.job.write_text("echo $$ > " + shlex.quote(str(started)) + "\nexec /bin/sleep 30\n")
        code = """import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('ea_restore', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
module.manage(fd, sys.argv[3], 'restore')
"""
        manager = subprocess.Popen([sys.executable, "-I", "-B", "-c", code, str(SOURCE), str(self.root), str(self.uid)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        job_pid = None
        try:
            deadline = time.monotonic() + 5
            while not started.exists() and manager.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(started.exists())
            job_pid = int(started.read_text().strip())
            manager.kill()
            manager.wait(timeout=5)
            with self.assertRaises((restore.Refused, BlockingIOError)):
                self.manage("reenroll")
            self.assertTrue(self.guard.exists())
            self.assertTrue(self.marker.exists())
        finally:
            if manager.poll() is None:
                manager.kill()
                manager.wait(timeout=5)
            if job_pid is not None:
                try:
                    os.killpg(job_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_ongoing_native_directory_lock_prevents_job_and_marker_change(self):
        fd = os.open(self.namespace, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises((restore.Refused, BlockingIOError)):
                self.manage()
            self.assertTrue(self.marker.exists())
            self.assertFalse(self.guard.exists())
        finally:
            os.close(fd)

    def test_concurrent_maintenance_is_serialized(self):
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises((restore.Refused, BlockingIOError)):
                self.manage("reenroll")
            self.assertTrue(self.marker.exists())
        finally:
            os.close(fd)

    def test_symlink_marker_does_not_touch_target(self):
        self.marker.unlink()
        outside = self.root / "untouched"
        outside.write_bytes(b"do-not-delete")
        self.marker.symlink_to(outside)
        with self.assertRaises((restore.Refused, OSError)):
            self.manage("reenroll")
        self.assertTrue(self.marker.is_symlink())
        self.assertEqual(outside.read_bytes(), b"do-not-delete")

    def test_symlink_namespace_and_job_are_refused(self):
        original = self.root / "saved-namespace"
        self.namespace.rename(original)
        self.namespace.symlink_to(original, target_is_directory=True)
        with self.assertRaises((restore.Refused, OSError)):
            self.manage()
        self.assertTrue((original / "marker").exists())
        self.namespace.unlink()
        original.rename(self.namespace)
        original_job = self.root / "saved-job"
        self.job.rename(original_job)
        self.job.symlink_to(original_job)
        with self.assertRaises((restore.Refused, OSError)):
            self.manage()
        self.assertFalse(self.guard.exists())

    def test_writable_ancestor_or_job_is_refused(self):
        for path in (self.base.parent, self.jobs, self.job):
            with self.subTest(path=path.name):
                previous = path.stat().st_mode
                path.chmod(0o777)
                try:
                    with self.assertRaises(restore.Refused):
                        self.manage()
                    self.assertTrue(self.marker.exists())
                finally:
                    path.chmod(stat.S_IMODE(previous))

    def test_guard_symlink_or_hardlink_is_never_followed_or_removed(self):
        outside = self.root / "guard-target"
        outside.write_bytes(b"protected")
        outside.chmod(0o600)
        for linked in ("symlink", "hardlink"):
            if linked == "symlink":
                self.guard.symlink_to(outside)
            else:
                os.link(outside, self.guard)
            try:
                with self.assertRaises((restore.Refused, OSError)):
                    self.manage("reenroll")
                self.assertEqual(outside.read_bytes(), b"protected")
                self.assertTrue(self.marker.exists())
            finally:
                self.guard.unlink()

    def test_external_hardlink_is_refused_but_atomic_publication_pair_is_removed(self):
        outside = self.root / "external-marker-link"
        os.link(self.marker, outside)
        with self.assertRaises(restore.Refused):
            self.manage("reenroll")
        self.assertTrue(self.marker.exists())
        outside.unlink()
        pending = self.namespace / ".pending"
        os.link(self.marker, pending)
        self.manage("reenroll")
        self.assertFalse(self.marker.exists())
        self.assertFalse(pending.exists())

    def test_new_namespace_inode_after_restore_is_also_invalidated(self):
        replacement = self.base / "replacement"
        replacement.mkdir(mode=0o700)
        if os.getuid() == 0:
            os.chown(replacement, self.uid, -1)
        new_marker = replacement / "marker"
        new_marker.write_bytes(b"restored-old-marker")
        new_marker.chmod(0o600)
        if os.getuid() == 0:
            os.chown(new_marker, self.uid, -1)
        self.job.write_text("mv " + shlex.quote(str(self.namespace)) + " " + shlex.quote(str(self.root / "old-directory")) + "\n"
                            "mv " + shlex.quote(str(replacement)) + " " + shlex.quote(str(self.namespace)) + "\n")
        self.manage()
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.guard.exists())

    def test_invalid_state_after_restore_keeps_gate_closed(self):
        self.job.write_text("touch " + shlex.quote(str(self.namespace / "unexpected")) + "\n")
        with self.assertRaises(restore.Refused):
            self.manage()
        self.assertTrue(self.guard.exists())
        self.assertTrue(self.marker.exists())

    def test_reenroll_is_idempotent_without_implicit_initialization(self):
        self.manage("reenroll")
        self.manage("reenroll")
        self.assertEqual(list(self.namespace.iterdir()), [])
        self.assertFalse(self.guard.exists())

    def test_uid_is_explicit_canonical_numeric_and_has_no_path_controls(self):
        for uid in ("", "0", "01", "-1", "+1", "1/../../2", "../1", "/1000", "1000 ", "１", "4294967295"):
            with self.subTest(uid=uid), self.assertRaises(restore.Refused):
                restore.manage(self.root_fd, uid, "reenroll", dry_run=True)
        run = subprocess.run([sys.executable, "-I", str(SOURCE), "reenroll", "--account-uid", str(self.uid),
                              "--root", str(self.root), "--dry-run"], capture_output=True, timeout=5)
        self.assertNotEqual(run.returncode, 0)
        self.assertTrue(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
