using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Ea.NativeOperator;

internal static class Dpapi
{
    internal static byte[] Protect(byte[] input, byte[] entropy) => Transform(input, entropy, true);
    internal static byte[] Unprotect(byte[] input, byte[] entropy) => Transform(input, entropy, false);
    private static unsafe byte[] Transform(byte[] input, byte[] entropy, bool protect)
    {
        fixed (byte* data = input, extra = entropy)
        {
            var source = new Win32.Blob { Length = input.Length, Data = (nint)data };
            var additional = new Win32.Blob { Length = entropy.Length, Data = (nint)extra };
            // CRYPTPROTECT_UI_FORBIDDEN only. NEVER CRYPTPROTECT_LOCAL_MACHINE.
            // Credential Manager's persistence constant has a different meaning.
            Win32.Blob output;
            bool success = protect
                ? Win32.CryptProtectData(ref source, 0, ref additional, 0, 0, 1, out output)
                : Win32.CryptUnprotectData(ref source, 0, ref additional, 0, 0, 1, out output);
            if (!success) throw new Failure("protection-failed");
            try
            {
                if (output.Length is < 1 or > 8192 || output.Data == 0) throw new Failure("protection-failed");
                var result = new byte[output.Length];
                Marshal.Copy(output.Data, result, 0, result.Length);
                return result;
            }
            finally
            {
                if (output.Data != 0)
                {
                    if (output.Length is > 0 and <= 8192) CryptographicOperations.ZeroMemory(new Span<byte>((void*)output.Data, output.Length));
                    Win32.LocalFree(output.Data);
                }
            }
        }
    }
}
