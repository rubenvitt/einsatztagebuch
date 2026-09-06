Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Initialize-EaRestoreTransport {
    if ('Ea.Release.RestoreTransport' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
namespace Ea.Release {
    public static class RestoreTransport {
        public static void RequireAccount(string expectedSid) {
            using (var identity = WindowsIdentity.GetCurrent()) {
                if (identity.User == null || identity.User.Value != expectedSid ||
                    new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException("Unelevated affected account required");
            }
        }
        public static void CheckResponse(byte[] bytes, string operation, string installation, byte[] sid) {
            using (var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth=4 })) {
                var root = json.RootElement;
                var names = new HashSet<string>(StringComparer.Ordinal);
                var expected = operation == "account"
                    ? new HashSet<string>(new[]{"ok","installation_id","platform","sid","identifier_authority","subauthorities","locked"},StringComparer.Ordinal)
                    : new HashSet<string>(new[]{"ok","installation_id","reset"},StringComparer.Ordinal);
                if (operation != "account" && operation != "reset") throw new InvalidOperationException("Invalid restore operation");
                foreach (var field in root.EnumerateObject()) if (!names.Add(field.Name) || !expected.Contains(field.Name))
                    throw new InvalidOperationException("Invalid restore response fields");
                if (!names.SetEquals(expected) || root.GetProperty("ok").ValueKind != JsonValueKind.True ||
                    root.GetProperty("installation_id").GetString() != installation) throw new InvalidOperationException("Restore response pin mismatch");
                if (operation == "reset") {
                    if (root.GetProperty("reset").ValueKind != JsonValueKind.True) throw new InvalidOperationException("Reset not acknowledged");
                    return;
                }
                if (sid.Length < 8 || sid[0] != 1 || sid[1] > 15 || sid.Length != 8 + 4*sid[1] ||
                    root.GetProperty("platform").GetString() != "windows" || root.GetProperty("locked").ValueKind != JsonValueKind.False ||
                    root.GetProperty("sid").GetString() != Convert.ToHexString(sid).ToLowerInvariant() ||
                    root.GetProperty("identifier_authority").GetString() != Convert.ToHexString(sid.AsSpan(2,6)).ToLowerInvariant())
                    throw new InvalidOperationException("Affected account response mismatch");
                var sub = root.GetProperty("subauthorities");
                if (sub.ValueKind != JsonValueKind.Array || sub.GetArrayLength() != sid[1]) throw new InvalidOperationException("Invalid binary SID");
                for (int i=0; i<sid[1]; ++i) if (!sub[i].TryGetUInt32(out uint actual) || actual != System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(sid.AsSpan(8+4*i,4)))
                    throw new InvalidOperationException("Invalid binary SID components");
            }
        }
        static async Task<byte[]> ReadBounded(Stream input, int limit, CancellationToken token) {
            byte[] buffer = new byte[limit+1]; int count=0;
            try {
                while (true) {
                    int read = await input.ReadAsync(buffer.AsMemory(count, buffer.Length-count),token).ConfigureAwait(false);
                    if (read == 0) return buffer.AsSpan(0,count).ToArray();
                    count += read; if (count > limit) throw new InvalidOperationException("Restore output limit");
                }
            } finally { Array.Clear(buffer); }
        }
        static async Task Invoke(string helper, string operation, string installation, string expectedSid) {
            RequireAccount(expectedSid);
            byte[] sid;
            using (var identity = WindowsIdentity.GetCurrent()) {
                sid = new byte[identity.User.BinaryLength]; identity.User.GetBinaryForm(sid,0);
            }
            var start = new ProcessStartInfo(helper) { UseShellExecute=false, WorkingDirectory=Path.GetDirectoryName(helper),
                RedirectStandardInput=true, RedirectStandardOutput=true, RedirectStandardError=true, CreateNoWindow=true };
            start.Environment.Clear();
            string system = Environment.SystemDirectory, windows = Path.GetDirectoryName(system);
            start.Environment["SystemRoot"]=windows; start.Environment["WINDIR"]=windows; start.Environment["PATH"]=system;
            // No inherited startup hooks, profiler, dependency, runtime-root, or user PATH inputs.
            start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"]="1";
            start.Environment["DOTNET_GENERATE_ASPNET_CERTIFICATE"]="false";
            using (var deadline = new CancellationTokenSource(60000))
            using (var child = new Process { StartInfo=start }) {
                byte[] output=null, error=null;
                Task<byte[]> stdout=null, stderr=null;
                try {
                    if (!child.Start()) throw new InvalidOperationException("Restore launch failed");
                    stdout=ReadBounded(child.StandardOutput.BaseStream,65536,deadline.Token);
                    stderr=ReadBounded(child.StandardError.BaseStream,2048,deadline.Token);
                    if (child.HasExited || !String.Equals(Path.GetFullPath(child.MainModule.FileName),Path.GetFullPath(helper),StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Restore child image mismatch");
                    RequireAccount(expectedSid); deadline.Token.ThrowIfCancellationRequested();
                    byte[] request=Encoding.UTF8.GetBytes(operation == "account"
                        ? "{\"op\":\"account\",\"installation_id\":\""+installation+"\"}"
                        : "{\"op\":\"reset\",\"installation_id\":\""+installation+"\",\"presence\":true}");
                    await child.StandardInput.BaseStream.WriteAsync(request,deadline.Token).ConfigureAwait(false);
                    child.StandardInput.Close(); // ordinary requests use EOF framing
                    await Task.WhenAll(stdout,stderr,child.WaitForExitAsync(deadline.Token)).WaitAsync(deadline.Token).ConfigureAwait(false);
                    output=stdout.Result; error=stderr.Result;
                    deadline.Token.ThrowIfCancellationRequested(); RequireAccount(expectedSid);
                    if (child.ExitCode != 0 || error.Length != 0) throw new InvalidOperationException("Native restore refused or failed");
                    CheckResponse(output,operation,installation,sid);
                } finally {
                    deadline.Cancel();
                    try { if (!child.HasExited) child.Kill(true); } catch (InvalidOperationException) { }
                    // Kill is only a last resort. Never retry an uncertain reset.
                    if (stdout != null && stdout.IsCompletedSuccessfully) Array.Clear(stdout.Result);
                    if (stderr != null && stderr.IsCompletedSuccessfully) Array.Clear(stderr.Result);
                    if (output != null) Array.Clear(output); if (error != null) Array.Clear(error);
                }
            }
        }
        public static void Reset(string helper, string installation, string expectedSid) {
            if (installation == null || installation.Length != 64) throw new InvalidOperationException("Installation pin required");
            foreach (char c in installation) if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) throw new InvalidOperationException("Invalid installation pin");
            Invoke(helper,"account",installation,expectedSid).GetAwaiter().GetResult();
            // Existing native reset binds Hello to its HWND/current account, rechecks
            // WTS/account/marker and invalidates ONLY that marker. No slot enumeration.
            Invoke(helper,"reset",installation,expectedSid).GetAwaiter().GetResult();
        }
    }
}
'@
}
Export-ModuleMember -Function Initialize-EaRestoreTransport
