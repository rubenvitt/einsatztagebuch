"""Anonymous-pipe fixtures; no native Keychain, LA, ES client, or daemon runs."""
import json
import os
import subprocess
import sys
import select
import signal
import socket
import time

binary = os.path.abspath(sys.argv[1])
identity = "ab" * 32
request = json.dumps({"op": "watch-session", "installation_id": identity}).encode() + b"\n"
ready = {"ok": True, "ready": True, "installation_id": identity}
invalidated = {"ok": True, "invalidated": True, "installation_id": identity}
checks = 0

for mode in ("lock-unlock", "lost", "expiry", "disconnect", "extra-input", "uncertain", "startup-event", "locked"):
    run = subprocess.Popen([binary, mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        run.stdin.write(request)
        run.stdin.flush()  # retained stdin is essential to readiness
        assert select.select([run.stdout], [], [], 3)[0], "missing bounded first frame"
        first = json.loads(run.stdout.readline())
        if mode in ("uncertain", "startup-event", "locked"):
            assert first == {"ok": False, "code": "locked" if mode == "locked" else "watch-unavailable"}
            assert run.wait(timeout=3) == 1
            assert run.stdout.read() == b""
        else:
            assert first == ready
            if mode == "disconnect":
                run.stdin.close()
            elif mode == "extra-input":
                run.stdin.write(b"another request\n")
                run.stdin.flush()
            assert run.wait(timeout=3) == 0
            rest = run.stdout.read()
            assert rest == b"" if mode == "disconnect" else [json.loads(x) for x in rest.splitlines()] == [invalidated]
        assert run.stderr.read() == b""
        checks += 1
    finally:
        if run.poll() is None:
            run.kill()
            run.wait()
        for pipe in (run.stdin, run.stdout, run.stderr):
            pipe.close()

def frame(pipe, timeout=1):
    assert select.select([pipe], [], [], timeout)[0], "missing current challenge response"
    return json.loads(pipe.readline())


for case in ("fresh", "replay", "duplicate-key", "unknown", "uppercase", "short", "oversize", "pipelined", "partial", "stopped",
             "stalled-native", "lock-on-challenge", "challenge-expiry", "exact-limit", "fragmented"):
    mode = case if case in ("stalled-native", "lock-on-challenge", "challenge-expiry") else "challenge"
    # The stalled fixture reports its stall on this barrier and waits for the
    # release, so the check below does not depend on a wall-clock window.
    barrier, fixture_end = socket.socketpair() if case == "stalled-native" else (None, None)
    extra = {} if fixture_end is None else {
        "pass_fds": (fixture_end.fileno(),),
        "env": {**os.environ, "EA_WATCH_BARRIER_FD": str(fixture_end.fileno())},
    }
    run = subprocess.Popen([binary, mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                           **extra)
    if fixture_end is not None:
        fixture_end.close()
    nonce = "12" * 32
    payload = json.dumps({"challenge": nonce}, separators=(",", ":")).encode() + b"\n"
    try:
        run.stdin.write(request)
        assert frame(run.stdout) == ready
        if case == "fresh" or case == "replay":
            run.stdin.write(payload)
            assert frame(run.stdout) == {"ok": True, "installation_id": identity, "challenge": nonce}
            run.stdin.write(payload if case == "replay" else payload.replace(b"12", b"34"))
            if case == "fresh":
                assert frame(run.stdout) == {"ok": True, "installation_id": identity, "challenge": "34" * 32}
                run.stdin.close()
            else:
                assert frame(run.stdout) == invalidated
        elif case == "stopped":
            os.kill(run.pid, signal.SIGSTOP)
            run.stdin.write(payload)
            assert not select.select([run.stdout], [], [], 1.1)[0], "stopped subscriber acknowledged"
            os.kill(run.pid, signal.SIGCONT)
            assert frame(run.stdout) == invalidated, "resume rehabilitated stopped watch"
        elif case == "stalled-native":
            run.stdin.write(payload)
            assert select.select([barrier], [], [], 5)[0] and barrier.recv(1) == b"S", "native callback never stalled"
            # The fixture is blocked inside the drain before the ACK; any frame
            # already written would be an acknowledgement ahead of that drain.
            assert not select.select([run.stdout], [], [], 0)[0], "challenge acknowledged before native event drain"
            barrier.sendall(b"R")
            # Whatever the fixture writes next must be terminal, never an ACK.
            assert frame(run.stdout, 5) == invalidated, "stalled native callback acknowledged"
        elif case == "lock-on-challenge":
            run.stdin.write(payload)
            assert frame(run.stdout) == invalidated, "challenge bypassed native event drain"
        elif case == "challenge-expiry":
            started = time.monotonic()
            for value in (nonce, "34" * 32):
                run.stdin.write(json.dumps({"challenge": value}).encode() + b"\n")
                assert frame(run.stdout) == {"ok": True, "installation_id": identity, "challenge": value}
                time.sleep(0.2)
            assert frame(run.stdout, 0.3) == invalidated, "challenge renewed the fixed lifetime"
            assert time.monotonic() - started < 0.72
        elif case in ("exact-limit", "fragmented"):
            if case == "exact-limit":
                run.stdin.write(payload[:-1] + b" " * (1024 - len(payload)) + b"\n")
            else:
                run.stdin.write(payload[:12])
                assert not select.select([run.stdout], [], [], 0.08)[0], "partial challenge acknowledged"
                run.stdin.write(payload[12:])
            assert frame(run.stdout) == {"ok": True, "installation_id": identity, "challenge": nonce}
            run.stdin.close()
        else:
            bad = {
                "duplicate-key": b'{"challenge":"' + nonce.encode() + b'","challenge":"' + nonce.encode() + b'"}\n',
                "unknown": b'{"challenge":"' + nonce.encode() + b'","extra":true}\n',
                "uppercase": payload.replace(b"12", b"AA"),
                "short": b'{"challenge":"ab"}\n',
                "oversize": b" " * 1025,
                "pipelined": payload + payload.replace(b"12", b"34"),
                "partial": payload[:-1],
            }[case]
            run.stdin.write(bad)
            assert frame(run.stdout, 1.5 if case == "partial" else 1) == invalidated
        assert run.wait(timeout=2) == 0
        assert run.stdout.read() == b"" and run.stderr.read() == b""
        checks += 1
    finally:
        if run.poll() is None:
            os.kill(run.pid, signal.SIGCONT)
            run.kill()
            run.wait()
        for pipe in (run.stdin, run.stdout, run.stderr):
            pipe.close()
        if barrier is not None:
            barrier.close()
print(json.dumps({"ok": True, "watch_protocol_tests": checks}, separators=(",", ":")))
