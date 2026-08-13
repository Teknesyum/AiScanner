using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AiScanner.Core;

namespace AiScanner.Infrastructure;

public sealed class ProcessScanner
{
    private readonly Dictionary<int, (TimeSpan Cpu, DateTimeOffset At)> _previous = [];

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
                var signature = GetSignature(path);
                observations.Add(new(
                    process.Id,
                    process.ProcessName,
                    path,
                    TryGet<DateTimeOffset?>(() => process.StartTime),
                    cpu,
                    TryGet(() => process.WorkingSet64),
                    TryGet(() => process.MainWindowHandle != IntPtr.Zero),
                    signature.IsSigned,
                    signature.Publisher,
                    await HashFileAsync(path, cancellationToken),
                    now)
                {
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
        return observations;
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

    private static (bool IsSigned, string? Publisher) GetSignature(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return (false, null);
        try
        {
#pragma warning disable SYSLIB0057 // Authenticode gömülü sertifikasını dosyadan okuyan modern eşdeğer API henüz yok.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            using var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck } };
            return (chain.Build(certificate), certificate.GetNameInfo(X509NameType.SimpleName, false));
        }
        catch (CryptographicException) { return (false, null); }
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
}
