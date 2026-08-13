using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Navigation;
using System.Windows.Threading;
using AiScanner.Core;
using AiScanner.Infrastructure;

namespace AiScanner.App;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly ProcessScanner _scanner = new();
    private readonly IRiskEngine _riskEngine = new RiskEngine();
    private readonly AiAnalysisPromptBuilder _promptBuilder = new();
    private readonly TelemetryStore _telemetryStore = new();
    private readonly NetworkTelemetryCollector _networkCollector = new();
    private readonly TcpConnectionInspector _connectionInspector = new();
    private readonly List<UsageSample> _history = [];
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(4) };
    private bool _isScanning;
    private string _status = "Başlatılıyor";
    private string _lastScanText = "—";
    private ProcessAssessment? _selectedAssessment;
    private DateTimeOffset? _lastTaskManagerStart;
    private DateTimeOffset _lastPersistedAt = DateTimeOffset.MinValue;
    private DateTimeOffset? _activeCaptureStartedAt;
    private CancellationTokenSource? _captureCancellation;
    private string _promptStatus = "Henüz oluşturulmadı";
    private string _localAnalysisReport = "Bir süre seçtiğinizde uygulama yerel zaman serisini analiz edip raporu burada gösterecek.";
    private string _scanButtonText = "Şimdi tara";
    private string _maximizeGlyph = "□";
    private bool _isCaptureIdle = true;
    private bool _hasCompletedAnalysis;
    private string? _completedBundlePath;
    private TimeSpan _completedDuration;
    private int _completedSnapshots;
    private int _completedObservations;
    private bool _hasInstantAnalysis;

    public ObservableCollection<ProcessAssessment> Assessments { get; } = [];
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string LastScanText { get => _lastScanText; private set => Set(ref _lastScanText, value); }
    public int ProcessCount => Assessments.Count;
    public int HighRiskCount => Assessments.Count(x => x.Level >= RiskLevel.High);
    public string PromptStatus { get => _promptStatus; private set => Set(ref _promptStatus, value); }
    public string LocalAnalysisReport { get => _localAnalysisReport; private set => Set(ref _localAnalysisReport, value); }
    public string ScanButtonText { get => _scanButtonText; private set => Set(ref _scanButtonText, value); }
    public string MaximizeGlyph { get => _maximizeGlyph; private set => Set(ref _maximizeGlyph, value); }
    public bool IsCaptureIdle { get => _isCaptureIdle; private set => Set(ref _isCaptureIdle, value); }
    public bool HasCompletedAnalysis { get => _hasCompletedAnalysis; private set => Set(ref _hasCompletedAnalysis, value); }
    public string VersionText
    {
        get
        {
            var version = typeof(MainWindow).Assembly.GetName().Version;
            return version is null ? "Sürüm bilinmiyor" : $"Sürüm v{version.Major}.{version.Minor}.{Math.Max(0, version.Build)}";
        }
    }
    public ProcessAssessment? SelectedAssessment { get => _selectedAssessment; set { if (Set(ref _selectedAssessment, value)) OnPropertyChanged(nameof(SelectedDetails)); } }
    public string SelectedDetails => SelectedAssessment is null
        ? "Ayrıntıları görmek için bir süreç seçin."
        : $"{SelectedAssessment.Process.ExecutablePath ?? "Dosya yolu erişilemiyor"}\nSHA-256: {SelectedAssessment.Process.Sha256 ?? "erişilemiyor"}\nYayıncı: {SelectedAssessment.Process.Publisher ?? "doğrulanamadı"}";

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        _networkCollector.Start();
        Status = _networkCollector.Status;
        _timer.Tick += async (_, _) => await ScanAsync();
        StateChanged += (_, _) => MaximizeGlyph = WindowState == WindowState.Maximized ? "❐" : "□";
        Loaded += async (_, _) => { await ScanAsync(); _timer.Start(); };
        Closed += (_, _) => { _timer.Stop(); _captureCancellation?.Cancel(); _networkCollector.Dispose(); };
    }

    private async void ScanNow_Click(object sender, RoutedEventArgs e)
    {
        await ScanAsync();
        if (Assessments.Count > 0)
        {
            _hasInstantAnalysis = true;
            _completedBundlePath = null;
            HasCompletedAnalysis = true;
            PromptStatus = "Anlık tarama tamamlandı • analiz promptu oluşturabilirsiniz";
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left) return;
        if (e.ClickCount == 2) ToggleMaximize();
        else DragMove();
    }

    private void MinimizeWindow_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void ToggleMaximizeWindow_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void CloseWindow_Click(object sender, RoutedEventArgs e) => Close();
    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void FooterLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }

    private async void Duration_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string value } && double.TryParse(value, out var minutes))
            await StartTimedCaptureAsync(TimeSpan.FromMinutes(minutes));
    }

    private async void CustomDuration_Click(object sender, RoutedEventArgs e)
    {
        if (!double.TryParse(CustomMinutes.Text, out var minutes) || minutes <= 0 || minutes > 10080)
        {
            PromptStatus = "Özel süre 0-10080 dakika arasında olmalı";
            return;
        }
        await StartTimedCaptureAsync(TimeSpan.FromMinutes(minutes));
    }

    private async Task StartTimedCaptureAsync(TimeSpan duration)
    {
        if (_activeCaptureStartedAt is not null)
        {
            PromptStatus = "Bir ölçüm oturumu zaten devam ediyor";
            return;
        }

        _captureCancellation = new CancellationTokenSource();
        var cancellationToken = _captureCancellation.Token;
        var startedAt = DateTimeOffset.UtcNow;
        var endsAt = startedAt + duration;
        _activeCaptureStartedAt = startedAt;
        IsCaptureIdle = false;
        HasCompletedAnalysis = false;
        _completedBundlePath = null;
        LocalAnalysisReport = $"ÖLÇÜM DEVAM EDİYOR\nBaşlangıç: {startedAt.LocalDateTime:G}\nPlanlanan süre: {duration.TotalMinutes:0.##} dakika\n\nBu süre boyunca CPU, RAM, ağ bağlantıları, upload/download, imza ve süreç davranışları örnekleniyor.";
        try
        {
            await ScanAsync(forcePersist: true);
            while (DateTimeOffset.UtcNow < endsAt)
            {
                var remaining = endsAt - DateTimeOffset.UtcNow;
                PromptStatus = $"Dinleniyor • kalan {FormatRemaining(remaining)} • başlangıç {startedAt.LocalDateTime:T}";
                ScanButtonText = $"Taranıyor • {FormatRemaining(remaining)}";
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(1, Math.Max(.1, remaining.TotalSeconds))), cancellationToken);
            }
            await ScanAsync(forcePersist: true);
            var completedAt = DateTimeOffset.UtcNow;
            PromptStatus = "Ölçüm tamamlandı • yerel algoritma analiz ediyor…";
            var bundle = await _telemetryStore.CreateAnalysisBundleAsync(startedAt, completedAt, duration, cancellationToken);
            LocalAnalysisReport = bundle.LocalReport;
            _completedBundlePath = bundle.Path;
            _completedDuration = duration;
            _completedSnapshots = bundle.Snapshots;
            _completedObservations = bundle.Observations;
            HasCompletedAnalysis = true;
            PromptStatus = $"Yerel analiz tamamlandı • {bundle.Snapshots} örnek • {bundle.Observations} gözlem";
        }
        catch (OperationCanceledException) { PromptStatus = "Ölçüm iptal edildi"; }
        catch (Exception ex) { PromptStatus = $"Paket oluşturulamadı: {ex.Message}"; }
        finally
        {
            _activeCaptureStartedAt = null;
            ScanButtonText = "Şimdi tara";
            IsCaptureIdle = true;
            _captureCancellation?.Dispose();
            _captureCancellation = null;
        }
    }

    private static string FormatRemaining(TimeSpan remaining) => remaining.TotalSeconds <= 0
        ? "00:00"
        : $"{(int)remaining.TotalMinutes:00}:{remaining.Seconds:00}";

    private async void CreatePrompt_Click(object sender, RoutedEventArgs e)
    {
        if (!HasCompletedAnalysis || string.IsNullOrWhiteSpace(_completedBundlePath))
        {
            if (!_hasInstantAnalysis || Assessments.Count == 0)
            {
                PromptStatus = "Önce şimdi tara veya süreli ölçüm çalıştırın";
                return;
            }

            var instantPrompt = _promptBuilder.Build(Assessments.ToArray(), DateTimeOffset.UtcNow);
            var instantPromptPath = Path.Combine(_telemetryStore.DataDirectory, $"instant-analysis-{DateTime.Now:yyyyMMdd-HHmmss}.prompt.txt");
            Directory.CreateDirectory(_telemetryStore.DataDirectory);
            await File.WriteAllTextAsync(instantPromptPath, instantPrompt);
            Clipboard.SetText(instantPrompt);
            PromptStatus = $"Anlık analiz promptu oluşturuldu ve panoya kopyalandı • {instantPromptPath}";
            return;
        }

        var prompt = _promptBuilder.BuildForLocalBundle(_completedBundlePath, _completedDuration, _completedSnapshots, _completedObservations);
        var promptPath = Path.ChangeExtension(_completedBundlePath, ".prompt.txt");
        await File.WriteAllTextAsync(promptPath, prompt);
        Clipboard.SetText(prompt);
        PromptStatus = $"Analiz promptu oluşturuldu ve panoya kopyalandı • {promptPath}";
    }

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_telemetryStore.DataDirectory);
        Process.Start(new ProcessStartInfo("explorer.exe", _telemetryStore.DataDirectory) { UseShellExecute = true });
    }

    private void OpenProcessLocation_Click(object sender, RoutedEventArgs e) => OpenSelectedProcessLocation();

    private void ProcessGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left) OpenSelectedProcessLocation();
    }

    private void OpenSelectedProcessLocation()
    {
        var path = SelectedAssessment?.Process.ExecutablePath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            Status = "Seçili sürecin dosya konumuna erişilemiyor";
            return;
        }

        try
        {
            var startInfo = new ProcessStartInfo("explorer.exe") { UseShellExecute = true };
            startInfo.ArgumentList.Add("/select,");
            startInfo.ArgumentList.Add(path);
            Process.Start(startInfo);
            Status = $"Dosya konumu açıldı • {Path.GetFileName(path)}";
        }
        catch (Exception ex)
        {
            Status = $"Dosya konumu açılamadı: {ex.Message}";
        }
    }

    private async Task ScanAsync(bool forcePersist = false)
    {
        if (_isScanning) return;
        _isScanning = true;
        Status = "Taranıyor";
        try
        {
            var scannedProcesses = await _scanner.ScanAsync();
            var endpoints = _connectionInspector.GetRemoteEndpoints();
            var processes = scannedProcesses.Select(process =>
            {
                var network = _networkCollector.GetUsage(process.ProcessId);
                var remote = endpoints.TryGetValue(process.ProcessId, out var values) ? values : [];
                return process with
                {
                    SentBytes = network.SentBytes,
                    ReceivedBytes = network.ReceivedBytes,
                    ActiveConnections = remote.Count,
                    RemoteEndpoints = remote
                };
            }).ToArray();
            if (forcePersist || _activeCaptureStartedAt is not null || DateTimeOffset.UtcNow - _lastPersistedAt >= TimeSpan.FromSeconds(15))
            {
                await _telemetryStore.AppendAsync(processes, _networkCollector.IsAvailable, _networkCollector.Status);
                _lastPersistedAt = DateTimeOffset.UtcNow;
            }
            DetectTaskManagerStart(processes);
            _history.AddRange(processes.Select(x => new UsageSample(x.ProcessId, x.Name, x.CpuPercent, x.ObservedAt)));
            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-2);
            _history.RemoveAll(x => x.Timestamp < cutoff);

            var selectedPid = SelectedAssessment?.Process.ProcessId;
            var results = processes.Select(x => _riskEngine.Assess(x, _history, _lastTaskManagerStart))
                .OrderByDescending(x => x.Score).ThenBy(x => x.Process.Name).ToArray();
            Assessments.Clear();
            foreach (var assessment in results) Assessments.Add(assessment);
            SelectedAssessment = Assessments.FirstOrDefault(x => x.Process.ProcessId == selectedPid);
            LastScanText = DateTime.Now.ToString("HH:mm:ss");
            Status = $"İzleniyor • {_networkCollector.Status}";
            OnPropertyChanged(nameof(ProcessCount));
            OnPropertyChanged(nameof(HighRiskCount));
        }
        catch (Exception ex)
        {
            Status = $"Hata: {ex.Message}";
        }
        finally { _isScanning = false; }
    }

    private void DetectTaskManagerStart(IReadOnlyCollection<ProcessObservation> processes)
    {
        var taskManager = processes.FirstOrDefault(x => x.Name.Equals("Taskmgr", StringComparison.OrdinalIgnoreCase));
        if (taskManager?.StartedAt is { } started && (_lastTaskManagerStart is null || started > _lastTaskManagerStart))
            _lastTaskManagerStart = started;
    }

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}
