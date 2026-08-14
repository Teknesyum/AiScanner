using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ProcWitness.Infrastructure;

public sealed record SecretSaveResult(bool Persisted, string Status);

public sealed class SecretStore(string dataDirectory)
{
    private string? _sessionSecret;
    private string WindowsPath => System.IO.Path.Combine(dataDirectory, "ai-key.bin");

    public async Task<SecretSaveResult> SaveAsync(string secret, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secret)) return await ClearAsync(cancellationToken);
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dataDirectory);
            await File.WriteAllBytesAsync(WindowsPath, Protect(Encoding.UTF8.GetBytes(secret)), cancellationToken);
            _sessionSecret = null;
            return new(true, "Stored with Windows DPAPI for the current user.");
        }
        if (OperatingSystem.IsMacOS() && await PipeSecretAsync("/usr/bin/security", ["add-generic-password", "-a", Environment.UserName, "-s", "ProcWitness.AiKey", "-U", "-w"], secret, cancellationToken))
        {
            _sessionSecret = null;
            return new(true, "Stored in macOS Keychain.");
        }
        if (OperatingSystem.IsLinux() && await PipeSecretAsync("secret-tool", ["store", "--label=ProcWitness AI key", "service", "ProcWitness", "account", "ai-key"], secret, cancellationToken))
        {
            _sessionSecret = null;
            return new(true, "Stored with libsecret.");
        }
        _sessionSecret = secret;
        return new(false, "Secure OS storage is unavailable; key retained for this session only.");
    }

    public async Task<string?> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (_sessionSecret is not null) return _sessionSecret;
        if (OperatingSystem.IsWindows() && File.Exists(WindowsPath))
        {
            try { return Encoding.UTF8.GetString(Unprotect(await File.ReadAllBytesAsync(WindowsPath, cancellationToken))); }
            catch (CryptographicException) { return null; }
        }
        if (OperatingSystem.IsMacOS()) return await ReadSecretAsync("/usr/bin/security", ["find-generic-password", "-a", Environment.UserName, "-s", "ProcWitness.AiKey", "-w"], cancellationToken);
        if (OperatingSystem.IsLinux()) return await ReadSecretAsync("secret-tool", ["lookup", "service", "ProcWitness", "account", "ai-key"], cancellationToken);
        return null;
    }

    public async Task<SecretSaveResult> ClearAsync(CancellationToken cancellationToken = default)
    {
        _sessionSecret = null;
        if (OperatingSystem.IsWindows())
        {
            if (File.Exists(WindowsPath)) File.Delete(WindowsPath);
            return new(true, "Key removed.");
        }
        if (OperatingSystem.IsMacOS()) await RunAsync("/usr/bin/security", ["delete-generic-password", "-a", Environment.UserName, "-s", "ProcWitness.AiKey"], cancellationToken);
        if (OperatingSystem.IsLinux()) await RunAsync("secret-tool", ["clear", "service", "ProcWitness", "account", "ai-key"], cancellationToken);
        return new(true, "Key removed.");
    }

    private static byte[] Protect(byte[] plaintext) => Transform(plaintext, true);
    private static byte[] Unprotect(byte[] ciphertext) => Transform(ciphertext, false);

    private static byte[] Transform(byte[] input, bool protect)
    {
        var inputBlob = ToBlob(input);
        try
        {
            DataBlob output;
            var success = protect
                ? CryptProtectData(ref inputBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out output)
                : CryptUnprotectData(ref inputBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out output);
            if (!success) throw new CryptographicException(Marshal.GetLastWin32Error());
            try
            {
                var result = new byte[output.Length];
                Marshal.Copy(output.Data, result, 0, output.Length);
                return result;
            }
            finally { LocalFree(output.Data); }
        }
        finally { Marshal.FreeHGlobal(inputBlob.Data); }
    }

    private static DataBlob ToBlob(byte[] bytes)
    {
        var pointer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, pointer, bytes.Length);
        return new(bytes.Length, pointer);
    }

    private static async Task<bool> PipeSecretAsync(string fileName, IReadOnlyList<string> arguments, string secret, CancellationToken cancellationToken)
    {
        try
        {
            using var process = Start(fileName, arguments, redirectInput: true);
            if (process is null) return false;
            await process.StandardInput.WriteAsync(secret.AsMemory(), cancellationToken);
            process.StandardInput.Close();
            await process.WaitForExitAsync(cancellationToken);
            return process.ExitCode == 0;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
    }

    private static async Task<string?> ReadSecretAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        try
        {
            using var process = Start(fileName, arguments, false);
            if (process is null) return null;
            var value = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            return process.ExitCode == 0 ? value.TrimEnd('\r', '\n') : null;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { return null; }
    }

    private static async Task RunAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        try { using var process = Start(fileName, arguments, false); if (process is not null) await process.WaitForExitAsync(cancellationToken); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    private static Process? Start(string fileName, IReadOnlyList<string> arguments, bool redirectInput)
    {
        var info = new ProcessStartInfo(fileName) { UseShellExecute = false, RedirectStandardInput = redirectInput, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        return Process.Start(info);
    }

    [StructLayout(LayoutKind.Sequential)] private readonly struct DataBlob(int length, IntPtr data) { public readonly int Length = length; public readonly IntPtr Data = data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref DataBlob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
