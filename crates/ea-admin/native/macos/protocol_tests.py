"""Production-binary parser/transport probes; never initialize or access keys."""
import json
import os
import subprocess
import sys
import tempfile

binary = os.path.abspath(sys.argv[1])
checks = 0


def rejected(payload, code):
    global checks
    run = subprocess.run([binary], input=payload, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=10, check=False)
    assert run.returncode == 1, "unexpected exit"
    assert run.stderr == b"", "unexpected diagnostics"
    assert json.loads(run.stdout) == {"ok": False, "code": code}, "unexpected response"
    assert run.stdout.count(b"\n") == 1, "multiple responses"
    checks += 1


for payload in [b"", b"[]", b"null", b"{}", b'{"op":"account","presence":1}',
                b'{"op":"account","op":"initialize"}', b'{"op":"account"}{}',
                b'{"op":"account","presence":true}', b'{"op":"account","uid":"501"}',
                b'{"op":"unwrap-secret","slot":"root-signing"}',
                b'{"op":"generate","slot":"admin-signing","kind":"ed25519","replace":true}',
                b'{"op":"contains","slot":"../root-signing"}',
                b'{"op":"contains","slot":"' + b"a" * 65 + b'"}',
                b'{"op":"sign","slot":"writer-signing","data":"FF"}',
                b'{"op":"sign","slot":"writer-signing","data":"0"}',
                b'{"op":"account","x":' + b"[" * 1000 + b"]" * 1000 + b"}",
                b'{"op":"account","presence":', b'{"op":"acco\\',
                b'{"op":"account","pres\\u0065nce":false,"presence":false}']:
    rejected(payload, "invalid-request")
for slot in ["operator-instance", "admin-signing", "root-signing"]:
    rejected(json.dumps({"op": "sign", "slot": slot, "data": ""}).encode(), "presence-required")
rejected(b'{"op":"reset"}', "presence-required")
rejected(b" " * 65_537, "request-too-large")
rejected(b" " * 65_536, "invalid-request")
watch_id = b"ab" * 32
for payload in [b'{"op":"watch-session"}',
                b'{"op":"watch-session","installation_id":"00"}',
                b'{"op":"watch-session","installation_id":"' + watch_id + b'"}',
                b'{"op":"watch-session","installation_id":"' + watch_id + b'","presence":false}',
                b'{"op":"watch-session","installation_id":"' + watch_id + b'","slot":"writer-signing"}',
                b'{"op":"watch-session","installation_id":"' + watch_id + b'"}\n{}',
                b'{"op":"account"}\n{}']:
    rejected(payload, "invalid-request")


backup = dict(op="backup-signing-seed", slot="admin-signing", installation_id="ab" * 32,
              expected_public_key="bc" * 32, presence=True)
for field in list(backup):
    missing = dict(backup); del missing[field]
    rejected(json.dumps(missing).encode(), "invalid-request")
for change in [dict(slot=s) for s in ["operator-instance", "writer-signing", "database-key", "draft-key", "unknown"]] + [
        dict(kind="ed25519"), dict(replace=False), dict(data=""), dict(prompt="SECRET-CANARY"),
        dict(expected_public_key="AB" * 32), dict(expected_public_key="ab" * 31),
        dict(installation_id="ab" * 31), dict(presence=1), dict(presence="true")]:
    rejected(json.dumps(dict(backup, **change)).encode(), "invalid-request")
rejected(json.dumps(dict(backup, presence=False)).encode(), "presence-required")
wire = json.dumps(backup).encode()
rejected(wire + b" " * (513 - len(wire)), "request-too-large")
rejected(wire[:-1] + b',"expected_public_key":"' + b"bc" * 32 + b'"}', "invalid-request")
rejected(wire[:-1] + b',"expected_public_\\u006bey":"' + b"bc" * 32 + b'"}', "invalid-request")

# Redirected output is rejected before account/marker/Keychain access. No identity
# or secret can be written to this file: only the stable transport error.
with tempfile.TemporaryFile() as destination:
    run = subprocess.run([binary], input=b'{"op":"account"}', stdout=destination,
                         stderr=subprocess.PIPE, timeout=10, check=False)
    destination.seek(0)
    assert json.load(destination) == {"ok": False, "code": "protected-pipe-required"}
    assert run.returncode == 1 and run.stderr == b""
    checks += 1
print(json.dumps({"ok": True, "protocol_tests": checks}, separators=(",", ":")))
