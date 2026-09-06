using System.Security.Cryptography;
using System.Text;
using Ea.NativeOperator;

var passed = 0;
void Check(bool value, string name) { if (!value) throw new Exception(name); passed++; }
void Reject(string json, string code = "invalid-request") {
    try { using var ignored = Request.Parse(Encoding.UTF8.GetBytes(json)); throw new Exception("accepted invalid request"); }
    catch (Failure f) { Check(f.Code == code, "stable error: " + code); }
}
var id = new string('a', 64);
using (var watch = Request.Parse(Encoding.UTF8.GetBytes($"{{\"op\":\"watch-session\",\"installation_id\":\"{id}\"}}")))
    Check(watch.Op == "watch-session", "pinned persistent watch request accepted");
// Microsoft's explicit-token API contract, not a claim that Windows was run.
Check((Win32.KnownFolderTokenAccess & 0x000e) == 0x000e,
    "Known Folder token requires QUERY, IMPERSONATE and DUPLICATE rights");
foreach (var label in new[] { "external-identity-confirmation", "authority-subject-id", "display-name", "function-label" }) {
    using var request = Request.Parse(Encoding.UTF8.GetBytes($"{{\"op\":\"private-console-line\",\"prompt\":\"{label}\",\"max_bytes\":1024,\"timeout_ms\":300000,\"installation_id\":\"{id}\"}}"));
    Check(request.Op == "private-console-line", "bounded console request accepted");
}
using (var r = Request.Parse(Encoding.UTF8.GetBytes("{\"op\":\"account\"}")))
    Check(r.InstallationId == null, "bootstrap account");
using (var r = Request.Parse(Encoding.UTF8.GetBytes("{\"op\":\"initialize\"}")))
    Check(r.Op == "initialize", "explicit initialization");
Reject("{\"op\":\"account\",\"op\":\"initialize\"}");
Reject("{\"op\":\"account\",\"\\u006fp\":\"initialize\"}");
Reject("{\"op\":\"account\",\"uid\":0}");
Reject("{\"op\":\"account\",\"presence\":true}");
Reject("{\"op\":\"account\",\"presence\":1}");
Reject("{\"op\":\"account\",\"installation_id\":\"AA\"}");
Reject("{\"op\":\"account\"}{}");
Reject("{\"op\":\"account\",}");
Reject("{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"\"}", "installation-required");
Reject($"{{\"op\":\"sign\",\"slot\":\"admin-signing\",\"data\":\"\",\"installation_id\":\"{id}\"}}", "presence-required");
Reject($"{{\"op\":\"generate\",\"slot\":\"writer-signing\",\"kind\":\"ed25519\",\"replace\":true,\"presence\":true,\"installation_id\":\"{id}\"}}");
Reject($"{{\"op\":\"generate\",\"slot\":\"operator-instance\",\"kind\":\"ed25519\",\"replace\":true,\"installation_id\":\"{id}\"}}", "presence-required");
Reject($"{{\"op\":\"unwrap-secret\",\"slot\":\"operator-instance\",\"installation_id\":\"{id}\"}}");
Reject($"{{\"op\":\"generate\",\"slot\":\"database-key\",\"kind\":\"ed25519\",\"installation_id\":\"{id}\"}}");
Reject($"{{\"op\":\"contains\",\"slot\":\"../other\",\"installation_id\":\"{id}\"}}");
Reject($"{{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"AA\",\"installation_id\":\"{id}\"}}");
Reject($"{{\"op\":\"wrap-secret\",\"slot\":\"database-key\",\"data\":\"aa\",\"installation_id\":\"{id}\"}}");
Reject(new string(' ', Request.MaximumBytes + 1), "request-too-large");
foreach (var slot in new[] { "operator-instance", "writer-signing", "admin-signing", "root-signing" }) {
    using var r = Request.Parse(Encoding.UTF8.GetBytes($"{{\"op\":\"sign\",\"slot\":\"{slot}\",\"presence\":true,\"data\":\"00ff\",\"installation_id\":\"{id}\"}}"));
    Check(r.Data!.SequenceEqual(new byte[] { 0, 255 }), "valid signing protocol");
}
var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
Check(Hex.Encode(Crypto.PublicKey(seed)) == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "RFC8032 public key");
Check(Hex.Encode(Crypto.Sign(seed, [])) == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", "RFC8032 signature");
var secretKey = RandomNumberGenerator.GetBytes(32);
var publicId = RandomNumberGenerator.GetBytes(32);
var pub = Crypto.PublicKey(seed);
var aad = Crypto.Context(publicId, "operator-instance", "ed25519", pub);
var sealedSeed = Crypto.Seal(secretKey, seed, aad);
Check(Crypto.Open(secretKey, sealedSeed, aad).SequenceEqual(seed), "secret marker key unwraps");
void Denied(byte[] key, byte[] ciphertext, byte[] context, string name) {
    try { Crypto.Open(key, ciphertext, context); throw new Exception(name); }
    catch (CryptographicException) { passed++; }
}
Denied(publicId, sealedSeed, aad, "PUBLIC installation id must not unwrap");
Denied(RandomNumberGenerator.GetBytes(32), sealedSeed, aad, "fresh marker cannot restore slots");
Denied(secretKey, sealedSeed, Crypto.Context(publicId, "writer-signing", "ed25519", pub), "slot substitution");
Denied(secretKey, sealedSeed, Crypto.Context(RandomNumberGenerator.GetBytes(32), "operator-instance", "ed25519", pub), "installation substitution");
Denied(secretKey, sealedSeed, Crypto.Context(publicId, "operator-instance", "ed25519", RandomNumberGenerator.GetBytes(32)), "public metadata substitution");
sealedSeed[^1] ^= 1;
Denied(secretKey, sealedSeed, aad, "ciphertext tampering");
using (var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"op\":\"account\"}")))
    { using var frame = await Transport.ReadAsync(stream); Check(frame.Bytes.Length == 16 && !frame.Watch, "bounded read through EOF"); }
try { await Transport.ReadAsync(new MemoryStream(new byte[65537])); throw new Exception("oversize stream accepted"); }
catch (Failure f) { Check(f.Code == "request-too-large", "bounded stream"); }
Check(Encoding.UTF8.GetString(Transport.Error(new IOException("PRIVATE DATA"))) == "{\"ok\":false,\"code\":\"native-failed\"}", "errors never include exception details");
using (var response = System.Text.Json.JsonDocument.Parse(Transport.SecretReply(id, new byte[32]))) {
    Check(response.RootElement.GetProperty("installation_id").GetString() == id, "secret response echoes public id");
    Check(response.RootElement.GetProperty("secret").GetString() == new string('0', 64), "secret32 encodes exactly");
    Check(response.RootElement.EnumerateObject().Count() == 3 && response.RootElement.GetProperty("ok").GetBoolean(), "closed secret reply");
}
try { Transport.SecretReply(id, new byte[31]); throw new Exception("invalid secret response"); }
catch (Failure f) { Check(f.Code == "native-failed", "invalid secret output fails closed"); }
var sensitiveRequest = Request.Parse(Encoding.UTF8.GetBytes($"{{\"op\":\"wrap-secret\",\"slot\":\"database-key\",\"data\":\"{id}\",\"installation_id\":\"{id}\"}}"));
var sensitiveBytes = sensitiveRequest.Data!;
sensitiveRequest.Dispose();
Check(sensitiveBytes.All(b => b == 0), "request secret cleared on disposal");
ConsoleLineTests.Run(Check);
await WatchTests.Run(Check);
Console.WriteLine($"{passed} protocol/crypto checks passed; no Windows OS store or session API executed.");
