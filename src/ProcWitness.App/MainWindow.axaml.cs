using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Interactivity;
using Avalonia.Input.Platform;
using Avalonia.Input;
using Avalonia.LogicalTree;
using Avalonia.Threading;
using ProcWitness.Core;
using ProcWitness.Infrastructure;

namespace ProcWitness.App;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly CaptureSession _session = new();
    private readonly AiAnalysisPromptBuilder _promptBuilder = new();
    private readonly BaselineManager _baselineManager;
    private readonly AppSettingsStore _settingsStore;
    private readonly SecretStore _secretStore;
    private readonly AiReportService _aiReportService = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(4) };
    private bool _scanning;
private string _status = "Starting";
private string _scanButtonText = "Scan Now";
private string _promptStatus = "Choose a capture duration or run an instant scan";
    private string _promptButtonText = "Promptu Kopyala";
private string _localReport = "The local behavior report appears here after timed monitoring completes.";
    private ProcessAssessment? _selected;
    private DateTimeOffset? _captureStart;
    private CancellationTokenSource? _captureCancellation;
    private string? _bundlePath;
    private string? _promptPath;
    private TimeSpan _bundleDuration;
    private int _bundleSnapshots;
    private int _bundleObservations;
    private bool _instantReady;
    private bool _hasCompletedAnalysis;
    private bool _isPromptNotificationVisible;
    private string _promptButtonBackground = "#111522";
    private string _promptButtonForeground = "#00F3FF";
    private string _promptButtonBorder = "#00F3FF";
    private int _promptFeedbackVersion;
    private bool _isTimedReportVisible;
    private bool _isEnglish;
    private readonly Dictionary<Control, string> _originalTexts = [];
    private readonly Dictionary<Run, string> _originalRunTexts = [];
    private PersistenceEntry? _selectedPersistence;
private string _persistenceStatus = "Persistence inventory has not been scanned yet.";
    private BaselineComparison? _baselineComparison;
    private string? _selectedBaseline;
private string _baselineStatus = "No baseline selected; no comparison performed.";
    private AppSettings _settings = new();
    private string _settingsLanguage = "Auto";
    private int _sampleIntervalSeconds = 4;
    private bool _autoScanOnStartup = true;
    private int _retentionDays = 7;
    private double _defaultCaptureMinutes = 5;
    private bool _persistenceEnabled = true;
    private bool _publisherAllowlistEnabled = true;
    private bool _includeRawSnapshots;
    private bool _aiEnabled;
    private AiProvider _selectedAiProvider = AiProvider.Anthropic;
    private string _aiModel = "claude-opus-4-1-20250805";
    private string _aiEndpoint = "https://api.anthropic.com";
    private string _apiKey = string.Empty;
    private string _settingsStatus = "Settings are stored locally.";
    private string _aiReport = string.Empty;
    private string? _aiReportPath;
    private CancellationTokenSource? _aiCancellation;

    public ObservableCollection<ProcessAssessment> Assessments { get; } = [];
    public ObservableCollection<PersistenceEntry> PersistenceEntries { get; } = [];
    public ObservableCollection<string> BaselineFiles { get; } = [];
    public ObservableCollection<BaselineDifferenceItem> BaselineDifferences { get; } = [];
    public string? SelectedBaseline { get => _selectedBaseline; set => Set(ref _selectedBaseline, value); }
    public string BaselineStatus { get => _baselineStatus; private set => Set(ref _baselineStatus, value); }
    public IReadOnlyList<string> Languages { get; } = ["Auto", LocalizationService.TurkishName, "English"];
    public IReadOnlyList<int> SampleIntervals { get; } = [2, 4, 8];
    public IReadOnlyList<int> RetentionOptions { get; } = [1, 7, 30];
    public IReadOnlyList<AiProvider> AiProviders { get; } = Enum.GetValues<AiProvider>();
    public string SettingsLanguage { get => _settingsLanguage; set => Set(ref _settingsLanguage, value); }
    public int SampleIntervalSeconds { get => _sampleIntervalSeconds; set => Set(ref _sampleIntervalSeconds, value); }
    public bool AutoScanOnStartup { get => _autoScanOnStartup; set => Set(ref _autoScanOnStartup, value); }
    public int RetentionDays { get => _retentionDays; set => Set(ref _retentionDays, value); }
    public double DefaultCaptureMinutes { get => _defaultCaptureMinutes; set => Set(ref _defaultCaptureMinutes, value); }
    public bool PersistenceEnabled { get => _persistenceEnabled; set => Set(ref _persistenceEnabled, value); }
    public bool PublisherAllowlistEnabled { get => _publisherAllowlistEnabled; set => Set(ref _publisherAllowlistEnabled, value); }
    public bool IncludeRawSnapshots { get => _includeRawSnapshots; set => Set(ref _includeRawSnapshots, value); }
    public bool AiEnabled { get => _aiEnabled; set { if (Set(ref _aiEnabled, value)) OnPropertyChanged(nameof(CanRequestAiReport)); } }
    public AiProvider SelectedAiProvider { get => _selectedAiProvider; set => Set(ref _selectedAiProvider, value); }
    public string AiModel { get => _aiModel; set => Set(ref _aiModel, value); }
    public string AiEndpoint { get => _aiEndpoint; set => Set(ref _aiEndpoint, value); }
    public string ApiKey { get => _apiKey; set { if (Set(ref _apiKey, value)) OnPropertyChanged(nameof(CanRequestAiReport)); } }
    public string SettingsStatus { get => _settingsStatus; private set => Set(ref _settingsStatus, value); }
    public string DataDirectoryText => _session.Store.DataDirectory;
    public bool CanRequestAiReport => AiEnabled && !string.IsNullOrWhiteSpace(ApiKey) && !string.IsNullOrWhiteSpace(_bundlePath);
    public string AiReport { get => _aiReport; private set => Set(ref _aiReport, value); }
    public PersistenceEntry? SelectedPersistence { get => _selectedPersistence; set => Set(ref _selectedPersistence, value); }
    public string PersistenceStatus { get => _persistenceStatus; private set => Set(ref _persistenceStatus, value); }
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string ScanButtonText { get => _scanButtonText; private set => Set(ref _scanButtonText, value); }
    public string PromptStatus { get => _promptStatus; private set => Set(ref _promptStatus, value); }
    public string PromptButtonText { get => _promptButtonText; private set => Set(ref _promptButtonText, value); }
    public string PromptButtonBackground { get => _promptButtonBackground; private set => Set(ref _promptButtonBackground, value); }
    public string PromptButtonForeground { get => _promptButtonForeground; private set => Set(ref _promptButtonForeground, value); }
    public string PromptButtonBorder { get => _promptButtonBorder; private set => Set(ref _promptButtonBorder, value); }
    public bool IsPromptNotificationVisible { get => _isPromptNotificationVisible; private set => Set(ref _isPromptNotificationVisible, value); }
    public bool IsTimedReportVisible { get => _isTimedReportVisible; private set => Set(ref _isTimedReportVisible, value); }
    public bool HasPromptFile => !string.IsNullOrWhiteSpace(_promptPath) && File.Exists(_promptPath);
    public string LocalAnalysisReport { get => _localReport; private set => Set(ref _localReport, value); }
    public bool HasCompletedAnalysis { get => _hasCompletedAnalysis; private set => Set(ref _hasCompletedAnalysis, value); }
    public string VersionText
    {
        get
        {
            var version = typeof(MainWindow).Assembly.GetName().Version;
            return version is null ? "Version unavailable" : $"v{version.Major}.{version.Minor}.{Math.Max(0, version.Build)} • Windows · Linux · macOS";
        }
    }
    public string SummaryText => $"{Assessments.Count} processes • {Assessments.Count(x => x.Level >= RiskLevel.High)} high risk";
    public ProcessAssessment? SelectedAssessment { get => _selected; set { if (Set(ref _selected, value)) OnPropertyChanged(nameof(SelectedDetails)); } }
    public string SelectedDetails => SelectedAssessment is null ? "Select a process to open its file location."
        : $"{SelectedAssessment.Process.ExecutablePath ?? "Path unavailable"}\nSHA-256: {SelectedAssessment.Process.Sha256 ?? "unavailable"}\nPublisher: {SelectedAssessment.Process.Publisher ?? (SelectedAssessment.Process.SignatureVerificationAvailable ? "unverified" : "unavailable on this platform")}\nParent: {SelectedAssessment.Process.ParentName ?? "unavailable"} ({SelectedAssessment.Process.ParentProcessId?.ToString() ?? "?"})\nCommand: {(SelectedAssessment.Process.CommandLineAvailable ? SelectedAssessment.Process.CommandLine : "unavailable on this platform")}";
    public new event PropertyChangedEventHandler? PropertyChanged;

    public MainWindow()
    {
        _baselineManager = new(_session.Store.DataDirectory);
        var settingsDirectory = Path.GetDirectoryName(_session.Store.DataDirectory)!;
        _settingsStore = new(Path.Combine(settingsDirectory, "settings.json"));
        _secretStore = new(settingsDirectory);
        InitializeComponent(); DataContext = this; RefreshBaselineFiles();
        _timer.Tick += async (_, _) => await ScanAsync();
        Opened += async (_, _) => { await LoadSettingsAsync(); if (AutoScanOnStartup) await ScanAsync(); if (PersistenceEnabled) { await RefreshPersistenceAsync(); if (AutoScanOnStartup) await ScanAsync(); } if (AutoScanOnStartup) _timer.Start(); };
        Closed += (_, _) => { _timer.Stop(); _captureCancellation?.Cancel(); _session.Dispose(); };
    }

    private async void ScanNow_Click(object? sender, RoutedEventArgs e)
    {
        if (_captureStart is not null) { PromptStatus = "An instant scan cannot start during timed analysis"; return; }
        await ScanAsync(true); _instantReady = Assessments.Count > 0; HasCompletedAnalysis = _instantReady;
        _timer.Start();
        _bundlePath = null; _promptPath = null; OnPropertyChanged(nameof(HasPromptFile));
        PromptStatus = _instantReady ? "Instant scan ready • you can copy the prompt" : "No readable processes found";
    }

    private async void Duration_Click(object? sender, RoutedEventArgs e)
    {
        DurationMenuButton.Flyout?.Hide();
        if (sender is Button { Tag: string value } && double.TryParse(value, out var minutes)) await StartTimedAsync(TimeSpan.FromMinutes(minutes));
    }

    private async void CustomDuration_Click(object? sender, RoutedEventArgs e)
    {
        if (!double.TryParse(CustomMinutes.Text, out var minutes) || minutes <= 0 || minutes > 10080) { PromptStatus = "Custom duration must be between 0 and 10080 minutes"; return; }
        DurationMenuButton.Flyout?.Hide();
        await StartTimedAsync(TimeSpan.FromMinutes(minutes));
    }

    private async Task StartTimedAsync(TimeSpan duration)
    {
        if (_captureStart is not null) { PromptStatus = "A timed analysis is already running"; return; }
        _captureCancellation = new(); var token = _captureCancellation.Token;
        var started = DateTimeOffset.UtcNow; _captureStart = started;
        HasCompletedAnalysis = false; IsTimedReportVisible = false; _instantReady = false; _bundlePath = null; _promptPath = null; OnPropertyChanged(nameof(HasPromptFile));
        LocalAnalysisReport = $"CAPTURE IN PROGRESS\nStart: {started.LocalDateTime:G}\nDuration: {duration.TotalMinutes:0.##} minutes\n\nSampling CPU, RAM, file identity and available network signals.";
        try
        {
            _timer.Stop();
            var progress = new Progress<CaptureProgress>(update =>
            {
                var left = update.Remaining < TimeSpan.Zero ? TimeSpan.Zero : update.Remaining;
                ScanButtonText = $"{"Analyzing"} • {(int)left.TotalMinutes:00}:{left.Seconds:00}";
                PromptStatus = $"{"Monitoring • remaining"} {(int)left.TotalMinutes:00}:{left.Seconds:00}";
                ApplyScanResult(update.Latest);
            });
            var result = await _session.CaptureAsync(duration, progress, token);
            ApplyPersistenceInventory(_session.PersistenceInventory!);
            _bundlePath = result.Path; _bundleDuration = duration; _bundleSnapshots = result.Snapshots; _bundleObservations = result.Observations;
            LocalAnalysisReport = result.LocalReport; IsTimedReportVisible = true; HasCompletedAnalysis = true; PromptStatus = $"{"Local analysis completed"} • {result.Snapshots} {"snapshots"} • {result.Observations} {"observations"}";
            OnPropertyChanged(nameof(CanRequestAiReport));
        }
        catch (OperationCanceledException) { PromptStatus = "Capture cancelled"; }
        catch (Exception ex) { PromptStatus = $"Analysis could not be created: {ex.Message}"; }
        finally { _captureStart = null; ScanButtonText = "Scan Now"; _captureCancellation?.Dispose(); _captureCancellation = null; _timer.Start(); }
    }

    private async void CreatePrompt_Click(object? sender, RoutedEventArgs e)
    {
        string prompt; string path;
        if (_bundlePath is not null)
        {
            prompt = _promptBuilder.BuildForLocalBundle(_bundlePath, _bundleDuration, _bundleSnapshots, _bundleObservations, _isEnglish ? "en" : "tr"); path = Path.ChangeExtension(_bundlePath, ".prompt.txt");
        }
        else if (_instantReady)
        {
            prompt = _promptBuilder.Build(Assessments.ToArray(), DateTimeOffset.UtcNow, _isEnglish ? "en" : "tr"); Directory.CreateDirectory(_session.Store.DataDirectory); path = Path.Combine(_session.Store.DataDirectory, $"instant-analysis-{DateTime.Now:yyyyMMdd-HHmmss}.prompt.txt");
        }
        else { PromptStatus = "Run an instant scan or timed capture first"; return; }
        await File.WriteAllTextAsync(path, prompt);
        _promptPath = path;
        OnPropertyChanged(nameof(HasPromptFile));
        var copied = false;
        try
        {
            if (TopLevel.GetTopLevel(this)?.Clipboard is { } clipboard) { await clipboard.SetTextAsync(prompt); copied = true; }
        }
        catch (Exception ex) { PromptStatus = $"Prompt saved to file; clipboard unavailable: {ex.Message} • {path}"; }
        PromptButtonText = copied ? "✓ Copied to clipboard" : "✓ Saved to file";
        PromptButtonBackground = copied ? "#173D20" : "#3A3012";
        PromptButtonForeground = copied ? "#7CFF68" : "#FFD45C";
        PromptButtonBorder = copied ? "#39FF14" : "#FFB000";
        IsPromptNotificationVisible = copied;
        if (copied) PromptStatus = $"Prompt copied to clipboard • {path}";
        Status = copied ? "Prompt copied to clipboard" : "Prompt saved to file";
        var feedbackVersion = ++_promptFeedbackVersion;
        await Task.Delay(TimeSpan.FromSeconds(5));
        if (feedbackVersion != _promptFeedbackVersion) return;
        PromptButtonText = "Promptu Kopyala";
        PromptButtonBackground = "#111522";
        PromptButtonForeground = "#00F3FF";
        PromptButtonBorder = "#00F3FF";
        IsPromptNotificationVisible = false;
    }

    private void OpenDataFolder_Click(object? sender, RoutedEventArgs e) { Directory.CreateDirectory(_session.Store.DataDirectory); OpenPath(_session.Store.DataDirectory, false); }
    private async void RefreshPersistence_Click(object? sender, RoutedEventArgs e) => await RefreshPersistenceAsync();
    private async void SaveBaseline_Click(object? sender, RoutedEventArgs e)
    {
        if (_session.LatestProcesses.Count == 0) { BaselineStatus = "Run a scan before saving a baseline."; return; }
        var listening = _session.GetListeningEndpoints();
        var path = await _baselineManager.SaveAsync(_session.LatestProcesses, _session.PersistenceInventory, listening.Endpoints, listening.Available);
        RefreshBaselineFiles(); SelectedBaseline = path; BaselineStatus = $"Baseline kaydedildi: {Path.GetFileName(path)}";
    }
    private async void CompareBaseline_Click(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(SelectedBaseline) || !File.Exists(SelectedBaseline)) { BaselineStatus = "Select a baseline to compare."; return; }
        _baselineComparison = await _baselineManager.CompareAsync(SelectedBaseline, _session.LatestProcesses, _session.PersistenceInventory);
        _session.ApplyBaselineComparison(_baselineComparison);
        BaselineDifferences.Clear();
        foreach (var item in _baselineComparison.Added.Concat(_baselineComparison.Removed).Concat(_baselineComparison.Changed).Concat(_baselineComparison.NewPersistence)) BaselineDifferences.Add(item);
        BaselineStatus = $"Compared • added {_baselineComparison.Added.Count} • removed {_baselineComparison.Removed.Count} • changed {_baselineComparison.Changed.Count} • new persistence {_baselineComparison.NewPersistence.Count}";
        await ScanAsync();
    }
    private void OpenPersistenceLocation_Click(object? sender, RoutedEventArgs e)
    {
        var path = SelectedPersistence?.ResolvedPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { Status = "Persistence file is unavailable"; return; }
        OpenPath(path, true);
    }
    private void OpenPromptLocation_Click(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_promptPath) || !File.Exists(_promptPath))
        {
            Status = "Prompt file not found";
            _promptPath = null;
            OnPropertyChanged(nameof(HasPromptFile));
            return;
        }

        OpenPath(_promptPath, true);
        Status = "Prompt file location opened";
    }

    private void OpenAnalysis_Click(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_bundlePath) || !File.Exists(_bundlePath))
        {
            Status = "Analysis file not found";
            return;
        }

        try
        {
            if (OperatingSystem.IsWindows()) Process.Start(new ProcessStartInfo(_bundlePath) { UseShellExecute = true });
            else if (OperatingSystem.IsMacOS()) StartFileOpener("/usr/bin/open", _bundlePath);
            else StartFileOpener("xdg-open", _bundlePath);
            Status = "Analysis file opened";
        }
        catch (Exception ex) { Status = $"Analysis could not be opened: {ex.Message}"; }
    }

    private static void StartFileOpener(string executable, string path)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false };
        info.ArgumentList.Add(path);
        Process.Start(info);
    }

    private void OpenSponsor_Click(object? sender, RoutedEventArgs e) => OpenWebAddress("https://github.com/sponsors/Teknesyum");
    private void OpenGitHub_Click(object? sender, RoutedEventArgs e) => OpenWebAddress("https://github.com/Teknesyum");

    private void ToggleLanguage_Click(object? sender, RoutedEventArgs e)
    {
        _isEnglish = !_isEnglish;
        SettingsLanguage = _isEnglish ? "English" : LocalizationService.TurkishName;
        ApplyLanguage();
    }

    private void SettingsLanguageChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is not ComboBox || string.IsNullOrWhiteSpace(SettingsLanguage)) return;
        _isEnglish = SettingsLanguage switch
        {
            var value when value == LocalizationService.TurkishName => false,
            "English" => true,
            _ => !System.Globalization.CultureInfo.CurrentUICulture.Name.StartsWith("tr", StringComparison.OrdinalIgnoreCase)
        };
        ApplyLanguage();
    }

    private void ApplyLanguage()
    {
        CoreLocalization.SetLanguage(_isEnglish ? "en" : "tr");
        foreach (var control in this.GetLogicalDescendants().OfType<Control>())
        {
            switch (control)
            {
                case TextBlock text when !string.IsNullOrWhiteSpace(text.Text):
                    TranslateControl(text, text.Text, value => text.Text = value);
                    break;
                case Button button when button.Content is string content:
                    TranslateControl(button, content, value => button.Content = value);
                    break;
                case TabItem tab when tab.Header is string header:
                    TranslateControl(tab, header, value => tab.Header = value);
                    break;
                case TextBox box when !string.IsNullOrWhiteSpace(box.PlaceholderText):
                    TranslateControl(box, box.PlaceholderText, value => box.PlaceholderText = value);
                    break;
            }
        }

        foreach (var run in this.GetLogicalDescendants().OfType<Run>())
        {
            if (string.IsNullOrWhiteSpace(run.Text)) continue;
            if (!_originalRunTexts.ContainsKey(run)) _originalRunTexts[run] = run.Text;
            run.Text = LocalizationService.Translate(_originalRunTexts[run], _isEnglish);
        }

        LanguageButton.Content = _isEnglish ? "TR" : "EN";
        if (_captureStart is null) ScanButtonText = LocalizationService.Translate("Scan Now", _isEnglish);
        if (!IsPromptNotificationVisible) PromptButtonText = LocalizationService.Translate("Copy Prompt", _isEnglish);
        Status = _isEnglish ? "Language: English" : "Dil: T\u00FCrk\u00E7e";
    }

    private void TranslateControl(Control control, string current, Action<string> assign)
    {
        if (!_originalTexts.ContainsKey(control)) _originalTexts[control] = current;
        assign(LocalizationService.Translate(_originalTexts[control], _isEnglish));
    }

    private void OpenWebAddress(string address)
    {
        try { Process.Start(new ProcessStartInfo(address) { UseShellExecute = true }); }
        catch (Exception ex) { Status = $"Link could not be opened: {ex.Message}"; }
    }

    private void OpenProcessLocation_Click(object? sender, RoutedEventArgs e)
    {
        var path = SelectedAssessment?.Process.ExecutablePath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { Status = "Selected file is unavailable"; return; }
        OpenPath(path, true);
    }

    private void ProcessList_DoubleTapped(object? sender, TappedEventArgs e)
    {
        var path = SelectedAssessment?.Process.ExecutablePath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { Status = "Selected file is unavailable"; return; }
        OpenPath(path, true);
        e.Handled = true;
    }

    private void OpenPath(string path, bool selectFile)
    {
        try
        {
            ProcessStartInfo info;
            if (OperatingSystem.IsWindows()) { info = new("explorer.exe") { UseShellExecute = true }; if (selectFile) info.ArgumentList.Add("/select,"); info.ArgumentList.Add(path); }
            else if (OperatingSystem.IsMacOS()) { info = new("/usr/bin/open") { UseShellExecute = false }; if (selectFile) info.ArgumentList.Add("-R"); info.ArgumentList.Add(path); }
            else { info = new("xdg-open") { UseShellExecute = false }; info.ArgumentList.Add(selectFile ? Path.GetDirectoryName(path)! : path); }
            Process.Start(info); Status = "Location opened";
        }
        catch (Exception ex) { Status = $"Location could not be opened: {ex.Message}"; }
    }

    private async Task ScanAsync(bool persist = false)
    {
        if (_scanning) return; _scanning = true; Status = "Scanning";
        try
        {
            var result = await _session.ScanAsync(persist || _captureStart is not null);
            ApplyScanResult(result);
        }
        catch (Exception ex) { Status = $"Hata: {ex.Message}"; }
        finally { _scanning = false; }
    }

    private async Task RefreshPersistenceAsync()
    {
        PersistenceStatus = "Scanning persistence sources read-only...";
        try
        {
            ApplyPersistenceInventory(await _session.RefreshPersistenceAsync());
        }
        catch (Exception ex) { PersistenceStatus = $"Persistence scan could not be completed: {ex.Message}"; }
    }

    private void ApplyScanResult(CaptureScanResult result)
    {
        var selectedPid = SelectedAssessment?.Process.ProcessId;
        Assessments.Clear();
        foreach (var item in result.Assessments) Assessments.Add(item);
        SelectedAssessment = Assessments.FirstOrDefault(x => x.Process.ProcessId == selectedPid);
        Status = $"{"Monitoring"} • {PlatformName()} • {result.NetworkStatus}";
        OnPropertyChanged(nameof(SummaryText));
    }

    private void ApplyPersistenceInventory(PersistenceInventory inventory)
    {
        PersistenceEntries.Clear();
        foreach (var entry in inventory.Entries.OrderBy(x => x.Source).ThenBy(x => x.Name)) PersistenceEntries.Add(entry);
        var unavailable = inventory.Sources.Where(x => !x.Available).Select(x => x.Source).ToArray();
        PersistenceStatus = unavailable.Length == 0
            ? $"{PersistenceEntries.Count} persistence entries • all sources available"
            : $"{PersistenceEntries.Count} persistence entries • unavailable: {string.Join(", ", unavailable)}";
    }

    private void RefreshBaselineFiles()
    {
        var selected = SelectedBaseline;
        BaselineFiles.Clear();
        foreach (var path in _baselineManager.List()) BaselineFiles.Add(path);
        SelectedBaseline = selected is not null && BaselineFiles.Contains(selected) ? selected : BaselineFiles.FirstOrDefault();
    }

    private async Task LoadSettingsAsync()
    {
        _settings = await _settingsStore.LoadAsync();
        SettingsLanguage = _settings.Language;
        _isEnglish = SettingsLanguage switch { var value when value == LocalizationService.TurkishName => false, "English" => true, _ => !System.Globalization.CultureInfo.CurrentUICulture.Name.StartsWith("tr", StringComparison.OrdinalIgnoreCase) };
        ApplyLanguage();
        SampleIntervalSeconds = _settings.SampleIntervalSeconds;
        AutoScanOnStartup = _settings.AutoScanOnStartup;
        RetentionDays = _settings.RetentionDays;
        DefaultCaptureMinutes = _settings.DefaultCaptureMinutes;
        PersistenceEnabled = _settings.PersistenceEnabled;
        PublisherAllowlistEnabled = _settings.PublisherAllowlistEnabled;
        IncludeRawSnapshots = _settings.IncludeRawSnapshots;
        AiEnabled = _settings.AiEnabled;
        SelectedAiProvider = _settings.AiProvider;
        AiModel = _settings.AiModel;
        AiEndpoint = _settings.AiEndpoint;
        ApiKey = await _secretStore.LoadAsync() ?? string.Empty;
        _session.SampleInterval = TimeSpan.FromSeconds(SampleIntervalSeconds);
        _session.PersistenceEnabled = PersistenceEnabled;
        _session.PublisherAllowlistEnabled = PublisherAllowlistEnabled;
        _session.IncludeRawSnapshots = IncludeRawSnapshots;
        _session.RetentionDays = RetentionDays;
        SettingsStatus = string.IsNullOrWhiteSpace(ApiKey) ? "AI key is not configured; local analysis remains fully available." : "Secure AI key loaded from this machine.";
    }

    private AppSettings CurrentSettings() => new()
    {
        Language = SettingsLanguage,
        SampleIntervalSeconds = SampleIntervalSeconds,
        AutoScanOnStartup = AutoScanOnStartup,
        RetentionDays = RetentionDays,
        DefaultCaptureMinutes = DefaultCaptureMinutes,
        PersistenceEnabled = PersistenceEnabled,
        PublisherAllowlistEnabled = PublisherAllowlistEnabled,
        IncludeRawSnapshots = IncludeRawSnapshots,
        AiEnabled = AiEnabled,
        AiProvider = SelectedAiProvider,
        AiModel = AiModel.Trim(),
        AiEndpoint = AiEndpoint.Trim()
    };

    private async void SaveSettings_Click(object? sender, RoutedEventArgs e)
    {
        _settings = CurrentSettings();
        await _settingsStore.SaveAsync(_settings);
        var secretResult = await _secretStore.SaveAsync(ApiKey);
        _session.SampleInterval = TimeSpan.FromSeconds(SampleIntervalSeconds);
        _session.PersistenceEnabled = PersistenceEnabled;
        _session.PublisherAllowlistEnabled = PublisherAllowlistEnabled;
        _session.IncludeRawSnapshots = IncludeRawSnapshots;
        _session.RetentionDays = RetentionDays;
        SettingsStatus = $"Settings saved. {secretResult.Status}";
    }

    private void ProviderChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is not ComboBox { SelectedItem: AiProvider provider }) return;
        if (provider == AiProvider.Anthropic) { AiEndpoint = "https://api.anthropic.com"; AiModel = "claude-opus-4-1-20250805"; }
        else if (provider == AiProvider.OpenAI) { AiEndpoint = "https://api.openai.com"; AiModel = "gpt-5.2"; }
    }

    private async void PasteApiKey_Click(object? sender, RoutedEventArgs e)
    {
        if (TopLevel.GetTopLevel(this)?.Clipboard is { } clipboard) ApiKey = await clipboard.TryGetTextAsync() ?? string.Empty;
    }

    private void ToggleApiKey_Click(object? sender, RoutedEventArgs e) => ApiKeyBox.PasswordChar = ApiKeyBox.PasswordChar == '\0' ? '•' : '\0';

    private async void TestAiConnection_Click(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ApiKey)) { SettingsStatus = "✗ Enter an API key first."; return; }
        SettingsStatus = "Testing provider connection...";
        try { SettingsStatus = await _aiReportService.TestConnectionAsync(CurrentSettings(), ApiKey); }
        catch (HttpRequestException) { SettingsStatus = "✗ Network is unavailable or the endpoint could not be reached."; }
        catch (TaskCanceledException) { SettingsStatus = "✗ Connection test timed out."; }
    }

    private async void DeleteLocalData_Click(object? sender, RoutedEventArgs e)
    {
        if (!await ConfirmAsync("Delete local ProcWitness data?", "This permanently removes local telemetry, bundles, reports, and baselines. Settings and the encrypted API key are retained.")) return;
        try
        {
            if (Directory.Exists(_session.Store.DataDirectory))
                foreach (var path in Directory.EnumerateFileSystemEntries(_session.Store.DataDirectory))
                {
                    if (Directory.Exists(path)) Directory.Delete(path, true); else File.Delete(path);
                }
            _bundlePath = null; _promptPath = null; _baselineComparison = null; BaselineDifferences.Clear(); RefreshBaselineFiles();
            HasCompletedAnalysis = false; IsTimedReportVisible = false; OnPropertyChanged(nameof(HasPromptFile)); OnPropertyChanged(nameof(CanRequestAiReport));
            SettingsStatus = "All local analysis data was deleted.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { SettingsStatus = $"Local data could not be deleted: {ex.Message}"; }
    }

    private async void RequestAiReport_Click(object? sender, RoutedEventArgs e)
    {
        if (!CanRequestAiReport || _bundlePath is null) { SettingsStatus = "Configure and enable an AI provider, then complete a timed capture."; return; }
        var settings = CurrentSettings();
        var info = await _aiReportService.InspectAsync(_bundlePath, settings);
        var confirmation = $"File: {Path.GetFileName(info.BundlePath)}\nPrepared payload: {info.Bytes:N0} bytes\nProcesses: {info.ProcessCount}\nDestination: {info.Provider} • {info.Endpoint}\nModel: {info.Model}\nEstimated input: ~{info.EstimatedTokens:N0} tokens\n\nOnly meta, process summaries, persistence summary, baseline comparison{(IncludeRawSnapshots ? ", and raw snapshots" : string.Empty)} will be sent.";
        if (!await ConfirmAsync("Send evidence for AI report?", confirmation)) return;
        _aiCancellation = new(); SettingsStatus = "AI report is being generated...";
        try
        {
            var result = await _aiReportService.GenerateAsync(_bundlePath, settings, ApiKey, _aiCancellation.Token);
            _aiReportPath = result.Path; AiReport = result.Markdown; RenderMarkdown(result.Markdown); SettingsStatus = $"AI report saved: {result.Path}";
        }
        catch (OperationCanceledException) { SettingsStatus = "AI report request cancelled."; }
        catch (HttpRequestException ex) { SettingsStatus = ex.Message; }
        finally { _aiCancellation.Dispose(); _aiCancellation = null; }
    }

    private void CancelAiReport_Click(object? sender, RoutedEventArgs e) => _aiCancellation?.Cancel();
    private async void CopyAiReport_Click(object? sender, RoutedEventArgs e)
    {
        if (TopLevel.GetTopLevel(this)?.Clipboard is { } clipboard && !string.IsNullOrWhiteSpace(AiReport)) { await clipboard.SetTextAsync(AiReport); SettingsStatus = "AI report copied."; }
    }
    private void OpenAiReport_Click(object? sender, RoutedEventArgs e)
    {
        if (_aiReportPath is not null && File.Exists(_aiReportPath)) OpenPath(_aiReportPath, false);
    }

    private void RenderMarkdown(string markdown)
    {
        MarkdownReportPanel.Children.Clear();
        foreach (var line in markdown.Split('\n'))
        {
            var heading = line.StartsWith('#');
            var text = heading ? line.TrimStart('#', ' ') : line;
            MarkdownReportPanel.Children.Add(new TextBlock
            {
                Text = text,
                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                FontSize = heading ? 20 : 14,
                FontWeight = heading ? Avalonia.Media.FontWeight.Bold : Avalonia.Media.FontWeight.Normal,
                Foreground = heading ? Avalonia.Media.Brushes.Cyan : Avalonia.Media.Brushes.White,
                Margin = new Avalonia.Thickness(0, heading ? 12 : 2, 0, 2)
            });
        }
    }

    private async Task<bool> ConfirmAsync(string title, string message)
    {
        var result = false;
        var dialog = new Window { Title = title, Width = 560, Height = 360, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Avalonia.Media.Brushes.Black };
        var yes = new Button { Content = "Confirm", MinWidth = 110 };
        var no = new Button { Content = "Cancel", MinWidth = 110 };
        yes.Click += (_, _) => { result = true; dialog.Close(); };
        no.Click += (_, _) => dialog.Close();
        dialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(24), Spacing = 18,
            Children =
            {
                new TextBlock { Text = title, FontSize = 22, FontWeight = Avalonia.Media.FontWeight.Bold, Foreground = Avalonia.Media.Brushes.Cyan },
                new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap, Foreground = Avalonia.Media.Brushes.White },
                new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 12, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right, Children = { no, yes } }
            }
        };
        await dialog.ShowDialog(this);
        return result;
    }

    private static string PlatformName() => OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsLinux() ? "Linux" : OperatingSystem.IsMacOS() ? "macOS" : "Bilinmeyen OS";
    private string L(string turkish, string english) => _isEnglish ? english : turkish;
    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null) { if (EqualityComparer<T>.Default.Equals(field, value)) return false; field = value; OnPropertyChanged(name); return true; }
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}
