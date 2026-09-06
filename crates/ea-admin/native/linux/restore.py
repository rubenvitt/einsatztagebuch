#!/usr/bin/python3 -I
"""Explicit administrator-managed restore/reenrollment, never a native login.

The CLI uses / only. No environment, profile, backup or command-line argument
can choose a namespace, job path, owner, helper or authentication result.
"""
import argparse
import contextlib
import fcntl
import os
import re
import signal
import stat
import subprocess
import sys

BASE = ("var", "lib", "ea-native-operator")
JOBS = ("etc", "ea-native-operator", "restore.d")
GUARD_PREFIX = ".restore-"
GUARD_BYTES = b"ea-native-operator-managed-restore-v1\n"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def numeric_uid(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None,
            "explicit-canonical-uid-required")
    uid = int(value)
    require(uid < 4294967295, "uid-out-of-range")
    return uid


def same(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def protected_directory(fd, owner):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and info.st_mode & 0o022 == 0,
            "unprotected-directory")


def open_chain(root_fd, components, owner):
    fd = os.dup(root_fd)
    try:
        protected_directory(fd, owner)
        for component in components:
            require(component not in ("", ".", "..") and "/" not in component, "invalid-component")
            next_fd = os.open(component, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            protected_directory(fd, owner)
        return fd
    except BaseException:
        os.close(fd)
        raise


def namespace(base_fd, uid, owner, recovering):
    fd = os.open(str(uid), DIR_FLAGS, dir_fd=base_fd)
    info = os.fstat(fd)
    if stat.S_IMODE(info.st_mode) != 0o700 or not (info.st_uid == uid or (recovering and info.st_uid == owner)):
        os.close(fd)
        raise Refused("invalid-namespace-directory")
    return fd


def guard(base_fd, name, owner, create=False):
    try:
        fd = os.open(name, FILE_FLAGS | (os.O_CREAT | os.O_EXCL if create else 0), 0o600, dir_fd=base_fd)
    except FileExistsError:
        fd = os.open(name, FILE_FLAGS, dir_fd=base_fd)
    except FileNotFoundError:
        if not create:
            return None
        raise
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= len(GUARD_BYTES), "invalid-maintenance-record")
        data = os.read(fd, len(GUARD_BYTES) + 1)
        require(data in (b"", GUARD_BYTES), "invalid-maintenance-record")
        if create:
            os.lseek(fd, 0, os.SEEK_SET)
            require(os.write(fd, GUARD_BYTES) == len(GUARD_BYTES), "maintenance-write-failed")
            os.fsync(fd)
            os.fsync(base_fd)
        return fd
    except BaseException:
        # A partially created record deliberately remains a native deny gate.
        os.close(fd)
        raise


def entry_names(fd):
    # A fresh open-file description avoids reusing a directory enumeration
    # cursor/cache across the restore job (including Linux overlayfs fixtures).
    scan = os.open(".", DIR_FLAGS, dir_fd=fd)
    try:
        return os.listdir(scan)
    finally:
        os.close(scan)


def marker_entries(fd, uid):
    names = entry_names(fd)
    require(set(names) <= {"marker", ".pending"}, "unexpected-namespace-entry")
    entries = {name: os.stat(name, dir_fd=fd, follow_symlinks=False) for name in names}
    for name, info in entries.items():
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o600,
                "invalid-marker-entry")
        # Accept only the native publisher's interrupted two-name link pair;
        # external hardlinks must never be mistaken for this namespace's data.
        pair = (len(entries) == 2 and info.st_nlink == 2 and
                same(entries["marker"], entries[".pending"]))
        require(info.st_nlink == 1 or pair, "external-marker-hardlink")
    return entries


def job_at(root_fd, uid, owner):
    directory = open_chain(root_fd, JOBS, owner)
    fd = None
    try:
        fd = os.open(str(uid), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o700 and 0 < info.st_size <= 65536, "invalid-restore-job")
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        os.close(directory)


def run_job(fd, uid, leases):
    # Pin the checked script inode instead of reopening a mutable path. Child
    # processes inherit the directory leases: killing this manager does not
    # release maintenance serialization while its restore job is still alive.
    child = subprocess.Popen(["/bin/sh", "/dev/fd/" + str(fd)], pass_fds=(fd, *leases),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd="/", start_new_session=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "EA_RESTORE_UID": str(uid)})
    try:
        result = child.wait(timeout=1800)
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise Refused("restore-descendants-still-running")
        require(result == 0, "restore-job-failed")
    finally:
        # A reaped leader's numeric group ID can be reused by an unrelated
        # process. Never signal that group. Stop only this still-owned child;
        # surviving descendants keep the inherited leases and durable deny gate
        # until an administrator finishes/stops the failed foreground job.
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def manage(root_fd, uid_text, mode, *, dry_run=False):
    """Descriptor-relative filesystem transaction; CLI always supplies real /.

    Unit fixtures supply their own already-open temporary directory. There is
    no production CLI or environment switch for a different filesystem root.
    """
    uid = numeric_uid(uid_text)
    require(mode in ("restore", "reenroll"), "invalid-maintenance-operation")
    owner = os.fstat(root_fd).st_uid
    with contextlib.ExitStack() as cleanup:
        def retain(fd):
            if fd is not None:
                cleanup.callback(os.close, fd)
            return fd

        base_fd = retain(open_chain(root_fd, BASE, owner))
        # Directory-inode lock has no deletable lock-file race. This serializes
        # administrator maintenance; normal operations lock only their UID dir.
        fcntl.flock(base_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        name = GUARD_PREFIX + str(uid)
        guard_fd = retain(guard(base_fd, name, owner))
        directory_fd = retain(namespace(base_fd, uid, owner, guard_fd is not None))
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = marker_entries(directory_fd, uid)
        job_fd = retain(job_at(root_fd, uid, owner)) if mode == "restore" else None
        result = {"dry_run": dry_run, "marker_present": "marker" in before,
                  "guard_present": guard_fd is not None, "mode": mode}
        if dry_run:
            return result

        # Crash/failure leaves this root-owned, fsynced gate in place. Every
        # updated native helper checks its presence before and during operations.
        armed_fd = retain(guard(base_fd, name, owner, create=True))
        if job_fd is not None:
            run_job(job_fd, uid, (base_fd, directory_fd, armed_fd))

        live_base = retain(open_chain(root_fd, BASE, owner))
        require(same(os.fstat(base_fd), os.fstat(live_base)), "control-tree-replaced")
        require(same(os.fstat(armed_fd), os.stat(name, dir_fd=base_fd, follow_symlinks=False)), "maintenance-record-replaced")
        current = os.stat(str(uid), dir_fd=base_fd, follow_symlinks=False)
        if not same(os.fstat(directory_fd), current):
            directory_fd = retain(namespace(base_fd, uid, owner, True))
            fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        # Freeze the final directory against the affected non-root account.
        # Even a restored directory inode is handled before allowing initialize.
        os.fchown(directory_fd, owner, -1)
        os.fchmod(directory_fd, 0o700)
        entries = marker_entries(directory_fd, uid)
        for entry, observed in entries.items():
            require(same(observed, os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)), "marker-entry-changed")
            os.unlink(entry, dir_fd=directory_fd)
        os.fsync(directory_fd)
        require(not entry_names(directory_fd), "namespace-recreated")
        require(same(os.fstat(directory_fd), os.stat(str(uid), dir_fd=base_fd, follow_symlinks=False)), "namespace-replaced")
        # Reuse the now-empty enrolled directory (including its nodump flag).
        # Never generate/adopt a marker, touch Secret Service, or claim presence.
        os.fchown(directory_fd, uid, -1)
        os.fsync(directory_fd)
        os.unlink(name, dir_fd=base_fd)
        os.fsync(base_fd)
        return result


def interrupted(_signum, _frame):
    raise InterruptedError("maintenance interrupted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("restore", "reenroll"))
    parser.add_argument("--account-uid", required=True, help="explicit affected non-root numeric UID")
    parser.add_argument("--dry-run", action="store_true", help="check paths and locks without running a job or changing state")
    args = parser.parse_args()
    try:
        numeric_uid(args.account_uid)
        require(sys.platform.startswith("linux"), "linux-required")
        require(os.getuid() == 0 and os.geteuid() == 0, "explicit-root-administrator-required")
        os.umask(0o077)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
        fd = os.open("/", DIR_FLAGS)
        try:
            manage(fd, args.account_uid, args.mode, dry_run=args.dry_run)
        finally:
            os.close(fd)
    except (Refused, OSError, subprocess.SubprocessError, KeyboardInterrupt):
        parser.exit(1, "Managed restore refused. Any pending maintenance gate remains closed; inspect the configured job and protected namespace.\n")
    if args.dry_run:
        print("Dry run passed: no job, marker, ownership or maintenance state changed.")
    else:
        print("Old native namespace invalidated. Initialize fresh keys in the actual user session; external revocation and reidentification are required.")


if __name__ == "__main__":
    main()
