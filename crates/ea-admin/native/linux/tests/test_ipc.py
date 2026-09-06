"""Real helper subprocess tests; no fake desktop/presence success."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import select

HELPER = str(pathlib.Path(sys.argv.pop(1)).resolve())


class ProtocolTests(unittest.TestCase):
    def invoke(self, raw, expected=None, env=None):
        run = subprocess.run([HELPER], input=raw, capture_output=True, timeout=5, env=env)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.stderr, b"")
        self.assertLessEqual(len(run.stdout), 65536)
        self.assertEqual(run.stdout.count(b"\n"), 1)
        result = json.loads(run.stdout)
        self.assertEqual(set(result), {"ok", "code"})
        self.assertIs(result["ok"], False)
        if expected:
            self.assertEqual(result["code"], expected)
        return result

    def test_untrusted_json_never_reaches_native_services(self):
        for raw in [b"", b"[]", b'{"op":"account","op":"initialize"}',
                    b'{"op":"account","presence":1}', b'{"op":"account"}{}',
                    b'{"op":"account","installation_id":"00"}',
                    b'{"op":"sign","slot":"writer-signing","data":"0F"}',
                    b'{"op":"account","data":"password-do-not-echo"}',
                    b'{"op":"account"}\x00']:
            with self.subTest(raw=raw):
                self.invoke(raw, "invalid-request")

    def test_65536_byte_bound_is_enforced_before_desktop_access(self):
        self.invoke(b" " * 65537, "request-too-large")
        self.invoke(b" " * 65536, "invalid-request")

    def test_nonwriter_signing_and_reset_require_presence(self):
        for slot in ["operator-instance", "admin-signing", "root-signing"]:
            self.invoke(json.dumps({"op": "sign", "slot": slot, "data": "00"}).encode(), "presence-required")
        self.invoke(b'{"op":"reset"}', "presence-required")

    def test_regular_file_transport_is_rejected(self):
        with tempfile.TemporaryFile() as source:
            source.write(b'{"op":"account"}')
            source.seek(0)
            run = subprocess.run([HELPER], stdin=source, capture_output=True, timeout=5)
            self.assertEqual(json.loads(run.stdout), {"ok": False, "code": "protected-pipe-required"})
            self.assertEqual(run.stderr, b"")

    def test_named_fifo_is_not_an_anonymous_private_pipe(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = pathlib.Path(directory) / "fifo"
            os.mkfifo(fifo)
            descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                run = subprocess.run([HELPER], stdin=descriptor, capture_output=True, timeout=5)
                self.assertEqual(json.loads(run.stdout), {"ok": False, "code": "protected-pipe-required"})
            finally:
                os.close(descriptor)

    def test_headless_process_and_uninstalled_policy_never_fake_success(self):
        env = dict(os.environ, HOME="/nonexistent", USER="root", XDG_SESSION_ID="1",
                   DBUS_SYSTEM_BUS_ADDRESS="unix:path=/nonexistent", DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent")
        self.invoke(b'{"op":"account"}', env=env)
        self.invoke(b'{"op":"initialize"}', env=env)

    def test_waits_for_eof_before_processing_even_a_complete_object(self):
        child = subprocess.Popen([HELPER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child.stdin.write(b'{"op":"account"}')
        child.stdin.flush()
        import select
        self.assertEqual(select.select([child.stdout], [], [], 0.1)[0], [])
        child.stdin.write(b'{}')
        child.stdin.close()
        self.assertEqual(json.loads(child.stdout.read()), {"ok": False, "code": "invalid-request"})
        self.assertEqual(child.stderr.read(), b"")
        self.assertEqual(child.wait(timeout=5), 1)
        child.stdout.close()
        child.stderr.close()

    def test_normal_request_with_newline_still_requires_eof(self):
        child = subprocess.Popen([HELPER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            child.stdin.write(b'{"op":"account"}\n')
            child.stdin.flush()
            self.assertEqual(select.select([child.stdout], [], [], 0.1)[0], [])
        finally:
            child.stdin.close()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()

    def test_watch_handshake_is_newline_framed_and_headless_fails_closed(self):
        child = subprocess.Popen([HELPER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            request = {"op": "watch-session", "installation_id": "00" * 32}
            child.stdin.write(json.dumps(request).encode() + b"\n")
            child.stdin.flush()  # Keep this alive: a normal EOF request would hang.
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            response = json.loads(child.stdout.readline())
            self.assertEqual(set(response), {"ok", "code"})
            self.assertFalse(response["ok"])
            self.assertNotEqual(response["code"], "invalid-request")
            self.assertEqual(child.wait(timeout=5), 1)
            self.assertEqual(child.stdout.read(), b"")
            self.assertEqual(child.stderr.read(), b"")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()

    def test_watch_never_accepts_an_eof_only_handshake(self):
        self.invoke(json.dumps({"op": "watch-session", "installation_id": "00" * 32}).encode(), "invalid-request")

    def test_watch_does_not_discard_pipelined_data(self):
        raw = json.dumps({"op": "watch-session", "installation_id": "00" * 32}).encode()
        self.invoke(raw + b'\n{"op":"account"}\n', "invalid-request")

    def test_watch_parent_eof_before_readiness_is_silent(self):
        raw = json.dumps({"op": "watch-session", "installation_id": "00" * 32}).encode() + b"\n"
        # Fill and close before starting, so EOF is already observable when the
        # watch handler starts. Both transport endpoints remain anonymous pipes.
        reader, writer = os.pipe()
        os.write(writer, raw)
        os.close(writer)
        try:
            run = subprocess.run([HELPER], stdin=reader, capture_output=True, timeout=5)
            self.assertEqual(run.stdout, b"")
            self.assertEqual(run.stderr, b"")
            self.assertEqual(run.returncode, 1)
        finally:
            os.close(reader)


unittest.main()
