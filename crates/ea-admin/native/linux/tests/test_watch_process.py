"""Real process/loop stalls in the test executable, NOT desktop acceptance.

The shipped helper has no fixture switch; test_ipc.py proves headless denial.
These tests never install services, authenticate, or change native key state.
"""
import json
import os
import select
import signal
import subprocess
import sys
import time
import unittest


BINARY = sys.argv.pop(1)
INSTALLATION = "00" * 32
NONCE = "12" * 32


class WatchProcess(unittest.TestCase):
    def launch(self, mode="--test-challenge-loop"):
        child = subprocess.Popen([BINARY, mode], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.addCleanup(self.cleanup, child)
        self.assertEqual(self.line(child.stdout),
                         dict(ok=True, installation_id=INSTALLATION, ready=True))
        return child

    @staticmethod
    def cleanup(child):
        if child.poll() is None:
            child.kill()  # Only this newly spawned test process, including SIGSTOP.
        child.wait(timeout=3)
        for pipe in (child.stdin, child.stdout, child.stderr):
            pipe.close()

    def line(self, pipe, timeout=3):
        deadline = time.monotonic() + timeout
        frame = bytearray()
        while not frame.endswith(b"\n"):
            self.assertTrue(select.select([pipe], [], [], max(0, deadline - time.monotonic()))[0])
            byte = os.read(pipe.fileno(), 1)
            self.assertTrue(byte, "unexpected EOF")
            frame += byte
            self.assertLessEqual(len(frame), 1024)
        return json.loads(frame)

    def challenge(self, child, nonce=NONCE):
        child.stdin.write(json.dumps(dict(challenge=nonce), separators=(",", ":")).encode() + b"\n")

    def invalidated(self, child):
        self.assertEqual(self.line(child.stdout),
                         dict(ok=True, installation_id=INSTALLATION, invalidated=True))
        self.assertEqual(child.wait(timeout=3), 0)
        self.assertEqual(child.stdout.read(), b"")

    def test_fresh_nonce_ack_and_old_nonce_rejection(self):
        child = self.launch()
        for nonce in (NONCE, "34" * 32):
            started = time.monotonic()
            self.challenge(child, nonce)
            self.assertEqual(self.line(child.stdout, 1),
                             dict(ok=True, installation_id=INSTALLATION, challenge=nonce))
            self.assertLess(time.monotonic() - started, 1)
        self.challenge(child)
        self.invalidated(child)

    def test_sigstop_resume_never_acknowledges_queued_challenge(self):
        child = self.launch()
        os.kill(child.pid, signal.SIGSTOP)
        self.challenge(child)
        self.assertFalse(select.select([child.stdout], [], [], 1.2)[0])
        os.kill(child.pid, signal.SIGCONT)
        self.invalidated(child)

    def test_blocked_actual_event_loop_does_not_acknowledge(self):
        child = self.launch("--test-blocked-loop")
        self.assertTrue(select.select([child.stderr], [], [], 1)[0])
        self.assertEqual(child.stderr.readline(), b"blocked\n")
        self.challenge(child)
        self.assertFalse(select.select([child.stdout], [], [], 1.05)[0])
        self.invalidated(child)

    def test_unfinished_frame_expires_without_renewal(self):
        child = self.launch()
        child.stdin.write(b'{"challenge":"')
        self.invalidated(child)

    def test_queued_second_frame_invalidates_without_ack(self):
        child = self.launch()
        frame = json.dumps(dict(challenge=NONCE)).encode() + b"\n"
        child.stdin.write(frame + frame)
        self.invalidated(child)

    def test_eof_is_parent_gone(self):
        child = self.launch()
        child.stdin.close()
        self.assertEqual(child.wait(timeout=3), 0)
        self.assertEqual(child.stdout.read(), b"")


if __name__ == "__main__":
    unittest.main()
