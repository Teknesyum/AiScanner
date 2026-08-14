namespace AiScanner.App;

internal static class UiTranslator
{
    private static readonly IReadOnlyDictionary<string, string> English = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["Tarama"] = "Scan",
        ["Nasıl Kullanılır?"] = "How to Use",
        ["Bilgi"] = "Information",
        ["Süreli Analiz ▼"] = "Timed Analysis ▼",
        ["Prompt Konumu"] = "Prompt Location",
        ["Analizi Aç"] = "Open Analysis",
        ["SÜREÇ"] = "PROCESS",
        ["AĞ"] = "NET",
        ["SKOR"] = "SCORE",
        ["RİSK"] = "RISK",
        ["YAYINCI"] = "PUBLISHER",
        ["BULGULAR"] = "FINDINGS",
        ["SÜRELİ ANALİZ RAPORU"] = "TIMED ANALYSIS REPORT",
        ["5 ADIMDA AI SCANNER"] = "AI SCANNER IN 5 STEPS",
        ["Tarama ve AI raporu için kısa kullanım rehberi"] = "Quick guide to scanning and AI reports",
        ["AI SCANNER TEKNİK REHBERİ"] = "AI SCANNER TECHNICAL GUIDE",
        ["Analiz süresini seçin"] = "Choose analysis duration",
        ["Seçimden sonra pencere kapanır ve geri sayım Şimdi Tara düğmesinde görünür."] = "The menu closes after selection and the countdown appears on Scan Now.",
        ["1 dakika"] = "1 minute",
        ["5 dakika"] = "5 minutes",
        ["10 dakika"] = "10 minutes",
        ["20 dakika"] = "20 minutes",
        ["Başlat"] = "Start",
        ["Veri klasörünü aç"] = "Open Data Folder",
        ["01 • VERİ TOPLAMA"] = "01 • DATA COLLECTION",
        ["02 • AĞ GÖZLEMİ"] = "02 • NETWORK OBSERVATION",
        ["03 • SÜRELİ DİNLEME"] = "03 • TIMED MONITORING",
        ["04 • DAVRANIŞ MOTORU"] = "04 • BEHAVIOR ENGINE",
        ["05 • AKILLI FİLTRE"] = "05 • SMART FILTER",
        ["06 • RAPOR ÇIKTILARI"] = "06 • REPORT OUTPUTS",
        ["07 • CANLI RİSK PUANLAMA"] = "07 • LIVE RISK SCORING",
        ["08 • ZAMAN SERİSİ VE KORELASYON"] = "08 • TIME SERIES AND CORRELATION",
        ["09 • MINER / KAÇINMA TESPİTİ"] = "09 • MINER / EVASION DETECTION",
        ["10 • AĞ VE VERİ AKIŞI"] = "10 • NETWORK AND DATA FLOW",
        ["11 • AI VERİ PAKETİ"] = "11 • AI EVIDENCE PACKAGE",
        ["12 • MAHREMİYET VE SINIRLAR"] = "12 • PRIVACY AND LIMITS",
        ["• PID, süreç adı ve başlangıç zamanı\n• CPU ve fiziksel RAM kullanımı\n• Dosya yolu, oluşturulma zamanı ve SHA-256\n• Windows Authenticode / macOS codesign\n• Ölçülemeyen özellikler risk sayılmaz"] = "• PID, process name and start time\n• CPU and physical RAM usage\n• Executable metadata and SHA-256\n• Windows Authenticode / macOS codesign\n• Unavailable signals never increase risk",
        ["• Windows: ETW upload/download + IP Helper\n• Linux: /proc soket–PID eşleştirmesi\n• macOS: lsof ile etkin TCP uçları\n• Uzak IP ve portlar süreçle ilişkilendirilir\n• Ölçüm yoksa 0 B güvenli kabul edilmez"] = "• Windows: ETW bytes + IP Helper\n• Linux: /proc socket-to-PID mapping\n• macOS: active TCP endpoints via lsof\n• Remote IPs and ports are linked to processes\n• Missing telemetry is never treated as zero traffic",
        ["• 1, 5, 10, 20 veya özel dakika\n• Yaklaşık 4 saniyede bir yeni örnek\n• Canlı geri sayım\n• Eski veriler oturuma karıştırılmaz\n• Yalnızca gerçek başlangıç–bitiş aralığı raporlanır"] = "• 1, 5, 10, 20 or custom minutes\n• New sample about every 4 seconds\n• Live countdown\n• Previous data is excluded\n• Only the exact capture window is reported",
        ["• Sabit ve düşük yük üreten süreçleri eler\n• CPU sıçraması olanları korur\n• Ağ / yeni dosya / imza sinyalini korur\n• PID değişimini gözden kaçırmaz\n• AI’a yalnızca anlamlı adayları verir"] = "• Removes stable low-load noise\n• Keeps CPU spikes\n• Keeps network, new-file and signature signals\n• Preserves PID changes\n• Sends only meaningful candidates to AI",
        ["• Tüm kayıtlar AiScanner/data içinde yereldir\n• Veriler otomatik olarak internete gönderilmez\n• 256 MB sonrası son 7 gün korunarak sıkıştırılır\n• Dosya silmez, karantinaya almaz, süreç kapatmaz\n• Son karar: hash + yayıncı + antivirüs/EDR"] = "• All evidence stays under AiScanner/data\n• Nothing is uploaded automatically\n• Above 256 MB, the latest 7 days are retained\n• No deletion, quarantine or process termination\n• Final decision: hash + publisher + antivirus/EDR"
    };

    public static string ToEnglish(string value) => English.TryGetValue(value, out var translated) ? translated : value;
}
