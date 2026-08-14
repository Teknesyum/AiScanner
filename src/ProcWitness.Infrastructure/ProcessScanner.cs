using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using ProcWitness.Core;

namespace ProcWitness.Infrastructure;

public sealed class ProcessScanner
{
    private readonly Dictionary<int, (TimeSpan Cpu, DateTimeOffset At)> _previous = [];
    private readonly Dictionary<string, FileEvidence> _fileEvidence = OperatingSystem.IsWindows()
        ? new(StringComparer.OrdinalIgnoreCase)
        : new(StringComparer.Ordinal);

    public async Task<IReadOnlyList<ProcessObservation>> ScanAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var observations = new List<ProcessObservation>();

        foreach (var process in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var cpu = CalculateCpu(process, now);
                var path = TryGet(() => process.MainModule?.FileName);
                var evidence = await GetFileEvidenceAsync(path, cancellationToken);
                var isWindows = OperatingSystem.IsWindows();
                observations.Add(new(
                    process.Id,
                    process.ProcessName,
                    path,
                    TryGet<DateTimeOffset?>(() => process.StartTime),
                    cpu,
                    TryGet(() => process.WorkingSet64),
                    isWindows && TryGet(() => process.MainWindowHandle != IntPtr.Zero),
                    evidence.SignatureStatus,
                    evidence.Publisher,
                    evidence.Sha256,
                    now)
                {
                    WindowVisibilityAvailable = isWindows,
                    FileCreatedAt = TryGet<DateTimeOffset?>(() => path is null ? null : File.GetCreationTimeUtc(path))
                });
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
                // Süreç tarama sırasında kapanabilir veya erişim korumalı olabilir.
            }
            finally
            {
                process.Dispose();
            }
        }

        var activeIds = observations.Select(x => x.ProcessId).ToHashSet();
        foreach (var stale in _previous.Keys.Where(x => !activeIds.Contains(x)).ToArray()) _previous.Remove(stale);
        if (_fileEvidence.Count > 4096) _fileEvidence.Clear();
        return observations;
    }

    private async Task<FileEvidence> GetFileEvidenceAsync(string? path, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path)) return new(null, 0, DateTimeOffset.MinValue, SignatureStatus.Unavailable, null);
        try
        {
            var file = new FileInfo(path);
            var length = file.Length;
            var lastWrite = file.LastWriteTimeUtc;
            if (_fileEvidence.TryGetValue(path, out var cached) && cached.Length == length && cached.LastWriteUtc == lastWrite) return cached;
            var signature = GetSignature(path);
            var evidence = new FileEvidence(await HashFileAsync(path, cancellationToken), length, lastWrite, signature.Status, signature.Publisher);
            _fileEvidence[path] = evidence;
            return evidence;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return new(null, 0, DateTimeOffset.MinValue, SignatureStatus.Unavailable, null);
        }
    }

    private double CalculateCpu(Process process, DateTimeOffset now)
    {
        var total = process.TotalProcessorTime;
        var result = 0d;
        if (_previous.TryGetValue(process.Id, out var previous))
        {
            var elapsedMs = (now - previous.At).TotalMilliseconds;
            if (elapsedMs > 0)
                result = (total - previous.Cpu).TotalMilliseconds / elapsedMs / Environment.ProcessorCount * 100;
        }
        _previous[process.Id] = (total, now);
        return Math.Clamp(result, 0, 100);
    }

    internal static (SignatureStatus Status, string? Publisher) GetSignature(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return (SignatureStatus.Unavailable, null);
        if (OperatingSystem.IsMacOS()) return GetMacSignature(path);
        if (!OperatingSystem.IsWindows()) return (SignatureStatus.Unavailable, null);
        try
        {
#pragma warning disable SYSLIB0057 // Authenticode gömülü sertifikasını dosyadan okuyan modern eşdeğer API henüz yok.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            using var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck } };
            var valid = chain.Build(certificate);
            var publisher = certificate.GetNameInfo(X509NameType.SimpleName, false);
            return (ClassifyChain(valid, chain.ChainStatus.Select(x => x.Status)), publisher);
        }
        catch (CryptographicException) { return (SignatureStatus.Invalid, null); }
    }

    internal static SignatureStatus ClassifyChain(bool valid, IEnumerable<X509ChainStatusFlags> statuses)
    {
        if (valid) return SignatureStatus.Valid;
        var values = statuses.ToArray();
        var timeOnly = values.Length > 0 && values.All(x =>
            (x & ~(X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested)) == X509ChainStatusFlags.NoError);
        return timeOnly ? SignatureStatus.ValidButExpired : SignatureStatus.Invalid;
    }

    private static (SignatureStatus Status, string? Publisher) GetMacSignature(string path)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("/usr/bin/codesign")
            {
                UseShellExecute = false,
                RedirectStandardError = true,
                CreateNoWindow = true,
                ArgumentList = { "--verify", "--strict", path }
            });
            if (process is null) return (SignatureStatus.Unavailable, null);
            if (!process.WaitForExit(3000))
            {
                try { process.Kill(true); } catch (InvalidOperationException) { }
                return (SignatureStatus.Unavailable, null);
            }
            return (process.ExitCode == 0 ? SignatureStatus.Valid : SignatureStatus.Invalid, "Apple code signature");
        }
        catch { return (SignatureStatus.Unavailable, null); }
    }

    private static async Task<string?> HashFileAsync(string? path, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 81920, true);
            return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException) { return null; }
    }

    private static T TryGet<T>(Func<T> action, T fallback = default!)
    {
        try { return action(); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return fallback; }
    }

    private sealed record FileEvidence(string? Sha256, long Length, DateTimeOffset LastWriteUtc, SignatureStatus SignatureStatus, string? Publisher);
}
