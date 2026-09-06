"""Test-only controlling terminal. Never logs terminal bytes or private input."""
import errno
import json
import os
import pty
import re
import select
import signal
import sys
import termios
import time


def emit(value):
    print(json.dumps(value), flush=True)


pid, terminal = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])

stopping = False


def stop(_signal, _frame):
    global stopping
    stopping = True


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
prompts = [
    b"extern-geprueft eingeben: ",
    b"aus Organisationsunterlagen: ",
    b"Name (Eingabe verborgen): ",
    b"Funktion (Eingabe verborgen): ",
]
buffer = b""
control = b""
private = []
index = 0
deadline = time.monotonic() + 90
emit({"started": pid})
try:
    while not stopping and time.monotonic() < deadline:
        readable, _, _ = select.select([terminal, sys.stdin], [], [], 0.05)
        if terminal in readable:
            try:
                chunk = os.read(terminal, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    chunk = b""
                else:
                    raise
            if not chunk:
                break
            buffer = (buffer + chunk)[-65536:]
            if any(value and value in buffer for value in private):
                emit({"private_echo": True})
                break
            for error in re.findall(rb"EA-[A-Z0-9-]+", chunk):
                emit({"error": error.decode("ascii")})
            prompt = prompts[index % len(prompts)]
            position = buffer.find(prompt)
            if position >= 0:
                buffer = buffer[position + len(prompt):]
                echo_disabled = not (termios.tcgetattr(terminal)[3] & termios.ECHO)
                emit({"prompt": index % len(prompts), "echo_disabled": echo_disabled})
                if not echo_disabled:
                    break
                index += 1
        if sys.stdin in readable:
            chunk = os.read(sys.stdin.fileno(), 8192)
            if not chunk:
                break
            control += chunk
            while b"\n" in control:
                line, control = control.split(b"\n", 1)
                command = json.loads(line)
                if command.get("stop"):
                    stopping = True
                elif "line" in command:
                    if termios.tcgetattr(terminal)[3] & termios.ECHO:
                        emit({"private_echo": True})
                        stopping = True
                        break
                    value = command["line"].encode("utf8")
                    # Only names/functions are checked as private echo. The
                    # confirmation token is also part of the public prompt.
                    if command.get("private"):
                        private.append(value)
                    os.write(terminal, value + b"\n")
        exited, status = os.waitpid(pid, os.WNOHANG)
        if exited:
            emit({"exit": os.waitstatus_to_exitcode(status)})
            break
    else:
        if not stopping:
            emit({"driver_timeout": True})
except BaseException as error:
    emit({"driver_error": type(error).__name__})
finally:
    # The whole group belongs to this pty.fork: CLI and its fixture helpers.
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    os.close(terminal)
