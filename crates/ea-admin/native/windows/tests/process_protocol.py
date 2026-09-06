"""Exercise the real compiled helper's parser without invoking native OS state.

Usage: python3 process_protocol.py /path/to/dotnet /path/to/ea-native-operator.dll
Also works with a Windows .exe as the sole argument. All cases fail before any
native account, session, marker, registry or credential operation is reached.
The valid watch-line dispatch probe runs on non-Windows hosts ONLY, where the
compiled helper's OS guard refuses it before native APIs.
"""
import json
import subprocess
import sys

cases = [
    (b'', 'invalid-request'),
    (b'{"op":"account","op":"initialize"}', 'invalid-request'),
    (b'{"op":"account","\\u006fp":"initialize"}', 'invalid-request'),
    (b'{"op":"account"}{}', 'invalid-request'),
    (b'{"op":"account","presence":1}', 'invalid-request'),
    (b'{"op":"account","sid":"SECRET-CALLER-ACCOUNT"}', 'invalid-request'),
    (b'{"op":"unwrap-secret","slot":"database-key"}', 'installation-required'),
    (b'{"op":"sign","slot":"admin-signing","data":""}', 'installation-required'),
    (b'{"op":"initialize","data":"PRIVATE-PAYLOAD"}', 'invalid-request'),
    (b'{"op":"account","presence":true}', 'invalid-request'),
    (b'{"op":"account","installation_id":"AA"}', 'invalid-request'),
    (b'{"op":"account","unknown":[{}]}', 'invalid-request'),
    (b'{"op":"account","unknown":"\xff"}', 'invalid-request'),
    (b' ' * 65537, 'request-too-large'),
]
pin = 'a' * 64
console = dict(op='private-console-line', installation_id=pin, prompt='display-name', max_bytes=32, timeout_ms=1000)
for changes in [dict(prompt='password'), dict(prompt=None), dict(max_bytes=0), dict(max_bytes=4097),
                dict(timeout_ms=0), dict(timeout_ms=300001), dict(max_bytes='32'), dict(timeout_ms=1.0),
                dict(line='MUST-NOT-BE-INPUT'), dict(presence=False), dict(label='display-name')]:
    cases.append((json.dumps(console | changes).encode(), 'invalid-request'))
watch = dict(op='watch-session', installation_id=pin)
for changes in [dict(timeout_ms=300000), dict(presence=False), dict(slot='database-key'), dict(ready=True)]:
    cases.append((json.dumps(watch | changes).encode() + b'\n', 'invalid-request'))
cases.extend([
    (json.dumps(watch).encode(), 'invalid-request'),  # EOF without request newline
    (json.dumps(watch).encode() + b'\n{}', 'invalid-request'),
    (b'{"op":"watch-session"}\n', 'installation-required'),
])
for payload, expected in cases:
    result = subprocess.run(sys.argv[1:], input=payload, capture_output=True, timeout=15)
    assert result.returncode == 1, (expected, result.returncode)
    assert len(result.stdout) <= 65536 and result.stderr == b'', 'unbounded output or stderr'
    assert json.loads(result.stdout) == {'ok': False, 'code': expected}, expected
def held_open(payload, expected, limit):
    child = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        child.stdin.write(payload)
        child.stdin.flush()
        child.wait(timeout=limit)  # stdin is still held open
        assert child.returncode == 1
        assert json.loads(child.stdout.read()) == {'ok': False, 'code': expected}
        assert child.stderr.read() == b''
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate()

# Ordinary requests STILL need EOF even if they already have a trailing newline.
held_open(b'', 'io-failed', 13)
held_open(b'{"op":"account"}\n', 'io-failed', 13)
held_open(b'{"op":"watch-session"}\n', 'installation-required', 3)
extra = 3
if sys.platform != 'win32':
    held_open(json.dumps(watch).encode() + b'\n', 'platform-unavailable', 3)
    extra += 1
print(f'{len(cases) + extra} real-helper process protocol checks passed; no native state accessed.')
