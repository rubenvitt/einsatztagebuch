"""A real private D-Bus/keyring fixture; never OS authentication evidence."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

if not pathlib.Path("/.dockerenv").exists() or os.getuid() != 0 or os.environ.get("EA_DISPOSABLE_TEST") != "1":
    raise SystemExit("requires explicitly owned disposable container")
runtime = pathlib.Path("/run/user/0")
if runtime.exists():
    raise SystemExit("refusing to adopt existing user bus/runtime state")
runtime.mkdir(parents=True, mode=0o700)
bus = keyring = None
try:
    with tempfile.TemporaryDirectory(prefix="ea-keyring-fixture-") as directory:
        env = dict(os.environ, HOME=directory, XDG_DATA_HOME=directory + "/data",
                   XDG_RUNTIME_DIR=str(runtime), DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(runtime / "bus"))
        bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--nopidfile",
                                "--address=" + env["DBUS_SESSION_BUS_ADDRESS"]], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if (runtime / "bus").exists():
                break
            if bus.poll() is not None:
                raise RuntimeError("test bus failed")
            time.sleep(0.05)
        keyring = subprocess.Popen(["gnome-keyring-daemon", "--foreground", "--components=secrets", "--unlock"],
                                    env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Independent random test-keyring passphrase, not any OS account password.
        # Production code has no unlock/password path. This is never PAM evidence.
        keyring.stdin.write(os.urandom(32).hex().encode())
        keyring.stdin.close()
        for _ in range(100):
            ready = subprocess.run(["gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
                "--object-path", "/org/freedesktop/DBus", "--method", "org.freedesktop.DBus.NameHasOwner",
                "org.freedesktop.secrets"], env=env, capture_output=True)
            if ready.returncode == 0 and ready.stdout.strip() == b"(true,)":
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("test keyring unavailable")
        subprocess.run([str(pathlib.Path(sys.argv[1]).resolve())], env=env, check=True, timeout=30)
finally:
    for process in [keyring, bus]:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    shutil.rmtree(runtime)
