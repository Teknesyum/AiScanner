using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Input.Platform;
using Avalonia.Threading;
using AiScanner.Core;
using AiScanner.Infrastructure;

namespace AiScanner.App;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly ProcessScanner _scanner = new();
    private readonly IRiskEngine _riskEngine = new RiskEngine();
    private readonly AiAnalysisPromptBuilder _promptBuilder = new();
    private readonly TelemetryStore _store = new();
    private readonly NetworkTelemetryCollector _network = new();
    private readonly TcpConnectionInspector _connections = new();
    private readonly List<UsageSample> _history = [];
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(4) };
    private bool _scanning;
    private string _status = "Başlatılıyor";
    private string _scanButtonText = "Şimdi tara";
    private string _promptStatus = "Ölçüm seçin veya anlık tarama yapın";
    private string _promptButtonText = "Analiz için prompt oluştur";
    private string _localReport = "Süreli dinleme tamamlandığında yerel davranış raporu burada görünür.";
    private ProcessAssessment? _selected;
    private DateTimeOffset? _taskManagerStart;
    private DateTimeOffset? _captureStart;
    private CancellationTokenSource? _captureCancellation;
    private string? _bundlePath;
    private TimeSpan _bundleDuration;
    private int _bundleSnapshots;
    private int _bundleObservations;
    private bool _instantReady;
    private bool _hasCompletedAnalysis;

    public ObservableCollection<ProcessAssessment> Assessments { get; } = [];
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string ScanButtonText { get => _scanButtonText; private set => Set(ref _scanButtonText, value); }
    public string PromptStatus { get => _promptStatus; private set => Set(ref _promptStatus, value); }
    public string PromptButtonText { get => _promptButtonText; private set => Set(ref _promptButtonText, value); }
    public string LocalAnalysisReport { get => _localReport; private set => Set(ref _localReport, value); }
    public bool HasCompletedAnalysis { get => _hasCompletedAnalysis; private set => Set(ref _hasCompletedAnalysis, value); }
    public string VersionText
    {
        get
        {
            var version = typeof(MainWindow).Assembly.GetName().Version;
            return version is null ? "Sürüm bilinmiyor" : $"v{version.Major}.{version.Minor}.{Math.Max(0, version.Build)} • Windows · Linux · macOS";
        }
    }
    public string SummaryText => $"{Assessments.Count} süreç • {Assessments.Count(x => x.Level >= RiskLevel.High)} yüksek risk";
    public ProcessAssessment? SelectedAssessment { get => _selected; set { if (Set(ref _selected, value)) OnPropertyChanged(nameof(SelectedDetails)); } }
    public string SelectedDetails => SelectedAssessment is null ? "Dosya konumunu açmak için bir süreç seçin."
        : $"{SelectedAssessment.Process.ExecutablePath ?? "Dosya yolu erişilemiyor"}\nSHA-256: {SelectedAssessment.Process.Sha256 ?? "erişilemiyor"}\nYayıncı: {SelectedAssessment.Process.Publisher ?? (SelectedAssessment.Process.SignatureVerificationAvailable ? "doğrulanamadı" : "bu platformda ölçülemiyor")}";
    public new event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        InitializeComponent(); DataContext = this;
        _network.Start(); _timer.Tick += async (_, _) => await ScanAsync();
        Opened += async (_, _) => { await ScanAsync(); _timer.Start(); };
        Closed += (_, _) => { _timer.Stop(); _captureCancellation?.Cancel(); _network.Dispose(); };
    }

    private async void ScanNow_Click(object? sender, RoutedEventArgs e)
    {
        if (_captureStart is not null) { PromptStatus = "Süreli ölçüm devam ederken anlık tarama başlatılamaz"; return; }
        await ScanAsync(true); _instantReady = Assessments.Count > 0; HasCompletedAnalysis = _instantReady;
        _bundlePath = null;
        PromptStatus = _instantReady ? "Anlık tarama hazır • prompt oluşturabilirsiniz" : "Okunabilir süreç bulunamadı";
    }

    private async void Duration_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string value } && double.TryParse(value, out var minutes)) await StartTimedAsync(TimeSpan.FromMinutes(minutes));
    }

    private async void CustomDuration_Click(object? sender, RoutedEventArgs e)
    {
        if (!double.TryParse(CustomMinutes.Text, out var minutes) || minutes <= 0 || minutes > 10080) { PromptStatus = "Özel süre 0-10080 dakika arasında olmalı"; return; }
        await StartTimedAsync(TimeSpan.FromMinutes(minutes));
    }

    private async Task StartTimedAsync(TimeSpan duration)
    {
        if (_captureStart is not null) { PromptStatus = "Bir ölçüm zaten devam ediyor"; return; }
        _captureCancellation = new(); var token = _captureCancellation.Token;
        var started = DateTimeOffset.UtcNow; var ends = started + duration; _captureStart = started;
        HasCompletedAnalysis = false; _instantReady = false; _bundlePath = null;
        LocalAnalysisReport = $"ÖLÇÜM DEVAM EDİYOR\nBaşlangıç: {started.LocalDateTime:G}\nSüre: {duration.TotalMinutes:0.##} dakika\n\nCPU, RAM, dosya kimliği ve platformun erişebildiği ağ sinyalleri örnekleniyor.";
        try
        {
            await ScanAsync(true);
            while (DateTimeOffset.UtcNow < ends)
            {
                var left = ends - DateTimeOffset.UtcNow; ScanButtonText = $"Taranıyor • {(int)left.TotalMinutes:00}:{left.Seconds:00}"; PromptStatus = $"Dinleniyor • kalan {(int)left.TotalMinutes:00}:{left.Seconds:00}";
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(1, Math.Max(.1, left.TotalSeconds))), token);
            }
            await ScanAsync(true);
            var result = await _store.CreateAnalysisBundleAsync(started, DateTimeOffset.UtcNow, duration, token);
            _bundlePath = result.Path; _bundleDuration = duration; _bundleSnapshots = result.Snapshots; _bundleObservations = result.Observations;
            LocalAnalysisReport = result.LocalReport; HasCompletedAnalysis = true; PromptStatus = $"Yerel analiz tamamlandı • {result.Snapshots} örnek • {result.Observations} gözlem";
        }
        catch (OperationCanceledException) { PromptStatus = "Ölçüm iptal edildi"; }
        catch (Exception ex) { PromptStatus = $"Analiz oluşturulamadı: {ex.Message}"; }
        finally { _captureStart = null; ScanButtonText = "Şimdi tara"; _captureCancellation?.Dispose(); _captureCancellation = null; }
    }

    private async void CreatePrompt_Click(object? sender, RoutedEventArgs e)
    {
        string prompt; string path;
        if (_bundlePath is not null)
        {
            prompt = _promptBuilder.BuildForLocalBundle(_bundlePath, _bundleDuration, _bundleSnapshots, _bundleObservations); path = Path.ChangeExtension(_bundlePath, ".prompt.txt");
        }
        else if (_instantReady)
        {
            prompt = _promptBuilder.Build(Assessments.ToArray(), DateTimeOffset.UtcNow); Directory.CreateDirectory(_store.DataDirectory); path = Path.Combine(_store.DataDirectory, $"instant-analysis-{DateTime.Now:yyyyMMdd-HHmmss}.prompt.txt");
        }
        else { PromptStatus = "Önce tarama veya süreli ölçüm çalıştırın"; return; }
        await File.WriteAllTextAsync(path, prompt);
        var copied = false;
        try
        {
            if (TopLevel.GetTopLevel(this)?.Clipboard is { } clipboard) { await clipboard.SetTextAsync(prompt); copied = true; }
        }
        catch (Exception ex) { PromptStatus = $"Prompt dosyaya kaydedildi; pano kullanılamadı: {ex.Message} • {path}"; }
        PromptButtonText = copied ? "✓ Panoya kopyalandı" : "✓ Dosyaya kaydedildi";
        if (copied) PromptStatus = $"Prompt panoya kopyalandı • {path}";
        Status = copied ? "Prompt panoya kopyalandı" : "Prompt dosyaya kaydedildi";
        await Task.Delay(TimeSpan.FromSeconds(4));
        PromptButtonText = "Analiz için prompt oluştur";
    }

    private void OpenDataFolder_Click(object? sender, RoutedEventArgs e) { Directory.CreateDirectory(_store.DataDirectory); OpenPath(_store.DataDirectory, false); }
    private void OpenProcessLocation_Click(object? sender, RoutedEventArgs e)
    {
        var path = SelectedAssessment?.Process.ExecutablePath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { Status = "Seçili dosyaya erişilemiyor"; return; }
        OpenPath(path, true);
    }

    private void OpenPath(string path, bool selectFile)
    {
        try
        {
            ProcessStartInfo info;
            if (OperatingSystem.IsWindows()) { info = new("explorer.exe") { UseShellExecute = true }; if (selectFile) info.ArgumentList.Add("/select,"); info.ArgumentList.Add(path); }
            else if (OperatingSystem.IsMacOS()) { info = new("/usr/bin/open") { UseShellExecute = false }; if (selectFile) info.ArgumentList.Add("-R"); info.ArgumentList.Add(path); }
            else { info = new("xdg-open") { UseShellExecute = false }; info.ArgumentList.Add(selectFile ? Path.GetDirectoryName(path)! : path); }
            Process.Start(info); Status = "Konum açıldı";
        }
        catch (Exception ex) { Status = $"Konum açılamadı: {ex.Message}"; }
    }

    private async Task ScanAsync(bool persist = false)
    {
        if (_scanning) return; _scanning = true; Status = "Taranıyor";
        try
        {
            var endpoints = _connections.GetRemoteEndpoints();
            var processes = (await _scanner.ScanAsync()).Select(p => { var net = _network.GetUsage(p.ProcessId); var remote = endpoints.TryGetValue(p.ProcessId, out var ep) ? ep : []; return p with { SentBytes = net.SentBytes, ReceivedBytes = net.ReceivedBytes, ActiveConnections = remote.Count, RemoteEndpoints = remote }; }).ToArray();
            if (persist || _captureStart is not null) await _store.AppendAsync(processes, _network.IsAvailable, _network.Status);
            var taskmgr = processes.FirstOrDefault(x => x.Name.Equals("Taskmgr", StringComparison.OrdinalIgnoreCase)); if (taskmgr?.StartedAt is { } start) _taskManagerStart = start;
            _history.AddRange(processes.Select(x => new UsageSample(x.ProcessId, x.Name, x.CpuPercent, x.ObservedAt))); _history.RemoveAll(x => x.Timestamp < DateTimeOffset.UtcNow.AddMinutes(-2));
            var selectedPid = SelectedAssessment?.Process.ProcessId; var results = processes.Select(x => _riskEngine.Assess(x, _history, _taskManagerStart)).OrderByDescending(x => x.Score).ThenBy(x => x.Process.Name).ToArray();
            Assessments.Clear(); foreach (var item in results) Assessments.Add(item); SelectedAssessment = Assessments.FirstOrDefault(x => x.Process.ProcessId == selectedPid);
            Status = $"İzleniyor • {PlatformName()} • {_network.Status}"; OnPropertyChanged(nameof(SummaryText));
        }
        catch (Exception ex) { Status = $"Hata: {ex.Message}"; }
        finally { _scanning = false; }
    }

    private static string PlatformName() => OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsLinux() ? "Linux" : OperatingSystem.IsMacOS() ? "macOS" : "Bilinmeyen OS";
    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null) { if (EqualityComparer<T>.Default.Equals(field, value)) return false; field = value; OnPropertyChanged(name); return true; }
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}
