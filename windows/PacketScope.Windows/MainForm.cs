using System.Diagnostics;
using System.Text.Json;

namespace PacketScope.Windows;

public sealed class MainForm : Form
{
    // Theme (matches the macOS app)
    private static readonly Color Bg = Color.FromArgb(9, 13, 22);
    private static readonly Color SidebarBg = Color.FromArgb(14, 20, 29);
    private static readonly Color PanelBg = Color.FromArgb(19, 26, 37);
    private static readonly Color Elevated = Color.FromArgb(26, 34, 46);
    private static readonly Color PrimaryText = Color.FromArgb(237, 245, 252);
    private static readonly Color SecondaryText = Color.FromArgb(155, 176, 199);
    private static readonly Color Teal = Color.FromArgb(71, 224, 196);
    private static readonly Color Amber = Color.FromArgb(255, 189, 97);
    private static readonly Color Red = Color.FromArgb(255, 115, 125);
    private static readonly Color Blue = Color.FromArgb(107, 176, 255);
    private static readonly Color Border = Color.FromArgb(40, 48, 62);

    private readonly ListBox _nav = new();
    private readonly Panel _content = new();
    private readonly Label _stateLabel = new();
    private CaptureReport? _report;
    private CaptureResults? _results;
    private SessionContext? _context;
    private string? _sessionDir;
    private readonly CaptureService _capture = new();
    private Dictionary<string, (int Pid, string Name)> _processSnapshots = new();
    private System.Windows.Forms.Timer? _liveTimer;
    private System.Windows.Forms.Timer? _processTimer;
    private DateTimeOffset _captureStarted;
    private int _kernelDrops;
    private ThreatIntelSummary? _threatIntel;
    private AiSettings _aiSettings = AiSettings.Load();
    private ResultSummary? _aiSummary;
    private readonly Dictionary<string, Control> _anchors = new();
    private CaptureReport? _baselineReport;
    private SessionContext? _baselineContext;
    private string? _baselineName;
    private readonly FeedUpdater _feedUpdater = new(FeedUpdater.DefaultDirectory, new CredentialManagerKeyStore());
    private List<AllowlistEntry> _allowlist = new();
    private List<FeedMeta> _customFeeds = new();
    private string _packetSearch = "";

    private ComboBox _ifaceCombo = new();
    private ComboBox _durationCombo = new();
    private RadioButton[] _goalRadios = Array.Empty<RadioButton>();
    private TextBox _symptomBox = new();
    private Button _startButton = new(), _stopButton = new(), _markerButton = new();
    private Label _liveLabel = new();
    private DataGridView _packetGrid = new();
    private TextBox _packetSearchBox = new();
    private TextBox _chatInput = new();
    private ListBox _chatList = new();
    private CheckBox _useAiCheck = new();

    public MainForm()
    {
        Text = "PacketScope";
        MinimumSize = new Size(1120, 720);
        Size = new Size(1240, 820);
        BackColor = Bg;
        ForeColor = PrimaryText;
        Font = new Font("Segoe UI", 9.5f);
        BuildShell();
        LoadFeedPreferences();
        ShowPage("Capture");
        _ = Task.Run(() =>
        {
            try
            {
                foreach (var meta in FeedRegistry.All.Where(m => _feedUpdater.StateFor(m).Enabled))
                    _ = _feedUpdater.UpdateAsync(meta, DateTimeOffset.Now, false);
            }
            catch { /* updater never blocks the UI */ }
        });
    }

    private static string SessionsRoot
    {
        get
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PacketScope", "Sessions");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    private void BuildShell()
    {
        var sidebar = new Panel { Dock = DockStyle.Left, Width = 230, BackColor = SidebarBg, Padding = new Padding(14) };
        var title = new Label { Text = "PacketScope", Font = new Font("Segoe UI", 17, FontStyle.Bold), ForeColor = PrimaryText, Dock = DockStyle.Top, Height = 30 };
        var subtitle = new Label { Text = "NETWORK OBSERVATORY", Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), ForeColor = SecondaryText, Dock = DockStyle.Top, Height = 18 };
        _nav.Dock = DockStyle.Fill;
        _nav.BackColor = SidebarBg;
        _nav.ForeColor = SecondaryText;
        _nav.BorderStyle = BorderStyle.None;
        _nav.Font = new Font("Segoe UI", 11);
        _nav.Items.AddRange(new object[] { "Capture", "Results", "Timeline", "Apps", "Compare", "Ask capture", "Packet log", "Endpoints", "Threat feeds" });
        _nav.SelectedIndex = 0;
        _nav.SelectedIndexChanged += (_, _) => { if (_nav.SelectedItem is string page) ShowPage(page); };
        _stateLabel.Dock = DockStyle.Bottom;
        _stateLabel.ForeColor = SecondaryText;
        _stateLabel.Font = new Font("Segoe UI", 9);
        _stateLabel.Height = 40;
        _stateLabel.Text = "Ready";
        sidebar.Controls.Add(_nav);
        sidebar.Controls.Add(_stateLabel);
        sidebar.Controls.Add(subtitle);
        sidebar.Controls.Add(title);
        _content.Dock = DockStyle.Fill;
        _content.BackColor = Bg;
        _content.AutoScroll = true;
        Controls.Add(_content);
        Controls.Add(sidebar);
    }

    private void SetState(string text, Color? color = null)
    {
        _stateLabel.Text = text;
        _stateLabel.ForeColor = color ?? SecondaryText;
    }

    private static Label H(string text, float size = 20, Color? color = null)
        => new() { Text = text, Font = new Font("Segoe UI", size, FontStyle.Bold), ForeColor = color ?? PrimaryText, AutoSize = true };
    private static Label Body(string text, float size = 10, Color? color = null)
        => new() { Text = text, Font = new Font("Segoe UI", size), ForeColor = color ?? SecondaryText, AutoSize = true, MaximumSize = new Size(980, 0) };
    private static Panel Card()
        => new() { BackColor = PanelBg, BorderStyle = BorderStyle.FixedSingle, Padding = new Padding(16), Margin = new Padding(0, 0, 0, 14), Width = 980, AutoSize = true };
    private static Button StyledButton(string text, Color back, Color fore)
        => new() { Text = text, BackColor = back, ForeColor = fore, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 11, FontStyle.Bold), Height = 44, AutoSize = true, Padding = new Padding(14, 0, 14, 0) };
    private static FlowLayoutPanel Flow()
        => new() { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Width = 1010, Padding = new Padding(22) };

    private void ShowPage(string page)
    {
        _content.Controls.Clear();
        switch (page)
        {
            case "Capture": BuildCapturePage(); break;
            case "Results": BuildResultsPage(); break;
            case "Timeline": BuildTimelinePage(); break;
            case "Apps": BuildAppsPage(); break;
            case "Compare": BuildComparePage(); break;
            case "Ask capture": BuildAskPage(); break;
            case "Packet log": BuildPacketLogPage(); break;
            case "Endpoints": BuildEndpointsPage(); break;
            case "Threat feeds": BuildFeedsPage(); break;
        }
    }

    // ---------------- Capture page ----------------

    private void BuildCapturePage()
    {
        var flow = Flow();
        var heading = H("Start capture", 24);
        heading.TextAlign = ContentAlignment.MiddleCenter;
        flow.Controls.Add(heading);

        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        var options = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Anchor = AnchorStyles.Top };
        options.Controls.Add(new Label { Text = "Network interface", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(0, 6, 6, 0) });
        _ifaceCombo = new ComboBox { Width = 320, DropDownStyle = ComboBoxStyle.DropDownList };
        RefreshInterfaces();
        options.Controls.Add(_ifaceCombo);
        var refreshBtn = StyledButton("Refresh", Elevated, PrimaryText);
        refreshBtn.Click += (_, _) => RefreshInterfaces();
        options.Controls.Add(refreshBtn);
        options.Controls.Add(new Label { Text = "Duration", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(18, 6, 6, 0) });
        _durationCombo = new ComboBox { Width = 170, DropDownStyle = ComboBoxStyle.DropDownList };
        _durationCombo.Items.AddRange(new object[] { "30 seconds", "1 minute", "2 minutes", "5 minutes", "Until I stop (15 min max)" });
        _durationCombo.SelectedIndex = 1;
        options.Controls.Add(_durationCombo);
        layout.Controls.Add(options);
        layout.Controls.Add(Body("Capture shows traffic visible to the selected interface — usually this device's traffic, not the whole network. Live capture needs Npcap installed (npcap.com) and may need PacketScope running as administrator."));
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true };
        _startButton = StyledButton("●  Start capture", Teal, Color.Black);
        _startButton.Width = 240; _startButton.Height = 54;
        _startButton.Click += (_, _) => StartCapture();
        _stopButton = StyledButton("■  Stop && analyze", Red, Color.Black);
        _stopButton.Width = 240; _stopButton.Height = 54;
        _stopButton.Click += (_, _) => StopCapture();
        _markerButton = StyledButton("⚑  It happened just now", Amber, Color.Black);
        _markerButton.Width = 260; _markerButton.Height = 54;
        _markerButton.Click += (_, _) => AddMarker();
        var importBtn = StyledButton("Import log file", Elevated, PrimaryText);
        importBtn.Width = 200; importBtn.Height = 54;
        importBtn.Click += (_, _) => ImportWithDialog();
        buttons.Controls.AddRange(new Control[] { _startButton, _stopButton, _markerButton, importBtn });
        layout.Controls.Add(buttons);
        _liveLabel = Body("");
        layout.Controls.Add(_liveLabel);
        UpdateCaptureButtons();
        card.Controls.Add(layout);
        flow.Controls.Add(card);

        flow.Controls.Add(H("What are you troubleshooting?", 18));
        string[] goals = Enum.GetNames<CaptureGoal>();
        _goalRadios = new RadioButton[goals.Length];
        var goalFlow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
        for (int i = 0; i < goals.Length; i++)
        {
            var goal = (CaptureGoal)i;
            var rb = new RadioButton
            {
                Text = $"{GoalInfo.Title(goal)} — {GoalInfo.Guidance(goal)}",
                ForeColor = PrimaryText,
                AutoSize = true,
                MaximumSize = new Size(940, 0),
                Checked = i == 0,
                Padding = new Padding(4),
            };
            _goalRadios[i] = rb;
            goalFlow.Controls.Add(rb);
        }
        flow.Controls.Add(goalFlow);
        flow.Controls.Add(Body("Symptom (optional) — saved with the session:"));
        _symptomBox = new TextBox { Width = 700, BackColor = Elevated, ForeColor = PrimaryText, BorderStyle = BorderStyle.FixedSingle };
        flow.Controls.Add(_symptomBox);
        AllowDrop = true;
        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0) ImportUserLogFile(files[0]);
        };
        _content.Controls.Add(flow);
    }

    private void RefreshInterfaces()
    {
        try
        {
            var devices = PcapNative.ListDevices();
            _ifaceCombo.Items.Clear();
            foreach (var (name, desc) in devices)
                _ifaceCombo.Items.Add(string.IsNullOrEmpty(desc) ? name : $"{name} — {desc}");
            if (_ifaceCombo.Items.Count > 0) _ifaceCombo.SelectedIndex = 0;
            if (devices.Count == 0) _liveLabel.Text = "No capture interfaces found. Install Npcap to capture live, or import a capture file.";
        }
        catch (DllNotFoundException)
        {
            _liveLabel.Text = "Npcap was not found. Install Npcap from npcap.com to capture live traffic, or import an existing capture file — importing works without it.";
        }
    }

    private CaptureGoal SelectedGoal
    {
        get
        {
            for (int i = 0; i < _goalRadios.Length; i++) if (_goalRadios[i].Checked) return (CaptureGoal)i;
            return CaptureGoal.Website;
        }
    }

    private void UpdateCaptureButtons()
    {
        bool capturing = _capture.Running;
        _startButton.Enabled = !capturing;
        _stopButton.Enabled = capturing;
        _markerButton.Enabled = capturing;
    }

    private static string NewSessionDir(bool imported)
    {
        string stamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
        string dir = Path.Combine(SessionsRoot, $"{(imported ? "import_" : "")}{stamp}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private void SaveContextJson()
    {
        if (_sessionDir == null || _context == null) return;
        var dto = new Dictionary<string, object?>
        {
            ["goal"] = _context.Goal.ToString(),
            ["symptom"] = _context.Symptom,
            ["interface"] = _context.Interface,
            ["startedAt"] = _context.StartedAt,
            ["endedAt"] = _context.EndedAt,
            ["isImported"] = _context.IsImported,
            ["markers"] = _context.Markers.Select(m => new Dictionary<string, object?> { ["timestamp"] = m.Timestamp, ["note"] = m.Note }).ToList(),
        };
        File.WriteAllText(Path.Combine(_sessionDir, "context.json"), JsonSerializer.Serialize(dto));
    }

    private string SelectedDeviceName()
    {
        string text = _ifaceCombo.SelectedItem?.ToString() ?? "";
        return text.Split(" — ")[0];
    }

    private void StartCapture()
    {
        if (_capture.Running) return;
        string device = SelectedDeviceName();
        if (string.IsNullOrEmpty(device))
        {
            MessageBox.Show("Choose a network interface first (refresh the list if it is empty). PacketScope only captures on an enumerated interface.", "PacketScope", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        _sessionDir = NewSessionDir(false);
        _context = new SessionContext
        {
            Goal = SelectedGoal,
            Symptom = _symptomBox.Text.Trim(),
            Interface = device,
            StartedAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000.0,
        };
        SaveContextJson();
        _processSnapshots = new Dictionary<string, (int, string)>();
        int[] durations = { 30, 60, 120, 300, 900 };
        int duration = durations[Math.Max(0, _durationCombo.SelectedIndex)];
        try
        {
            _capture.Start(device, Path.Combine(_sessionDir, "traffic.pcap"), duration);
        }
        catch (Exception ex)
        {
            SetState($"Problem: {ex.Message}", Red);
            _liveLabel.Text = ex.Message;
            return;
        }
        _captureStarted = DateTimeOffset.Now;
        SetState($"Capturing on {device}", Teal);
        _processTimer = new System.Windows.Forms.Timer { Interval = 2000 };
        _processTimer.Tick += (_, _) =>
        {
            try { foreach (var kv in ProcessMap.Snapshot()) _processSnapshots[kv.Key] = kv.Value; } catch { }
        };
        _processTimer.Start();
        _liveTimer = new System.Windows.Forms.Timer { Interval = 500 };
        _liveTimer.Tick += (_, _) =>
        {
            _liveLabel.Text = $"Capturing on {device} — {_capture.Packets:N0} packets · {Format.Bytes(_capture.Bytes)} · {(DateTimeOffset.Now - _captureStarted).TotalSeconds:0} s · markers saved: {_context?.Markers.Count ?? 0} of 50\nNow reproduce the problem, and press “It happened just now” the moment it occurs. When you stop, your results will open automatically.";
            if (!_capture.Running)
            {
                _liveTimer?.Stop();
                FinishCaptureAnalysis();
            }
        };
        _liveTimer.Start();
        UpdateCaptureButtons();
    }

    private void StopCapture()
    {
        if (!_capture.Running) return;
        SetState("Stopping…", Amber);
        _capture.Stop();
    }

    private void AddMarker()
    {
        if (!_capture.Running || _context == null || _sessionDir == null) return;
        if (_context.Markers.Count >= 50)
        {
            _liveLabel.Text = "This session already has 50 markers (the per-session cap).";
            return;
        }
        _context.Markers.Add(new ProblemMarker { Timestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000.0 });
        SaveContextJson(); // saved immediately
    }

    private void FinishCaptureAnalysis()
    {
        _processTimer?.Stop();
        UpdateCaptureButtons();
        if (_sessionDir == null) return;
        string pcap = Path.Combine(_sessionDir, "traffic.pcap");
        _kernelDrops = (int)_capture.Dropped;
        if (!File.Exists(pcap))
        {
            SetState("The capture produced no data.", Red);
            return;
        }
        AnalyzeCurrentSession(pcap);
    }

    private void ImportWithDialog()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Import your own capture log file",
            Filter = "Packet capture logs (*.pcap;*.cap;*.log)|*.pcap;*.cap;*.log|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog() == DialogResult.OK) ImportUserLogFile(dialog.FileName);
    }

    public static string? LogFileValidationError(string path)
    {
        if (!File.Exists(path)) return "That file could not be read. Check that it still exists and that PacketScope can access it.";
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        Span<byte> head = stackalloc byte[4];
        if (fs.Read(head) < 4) return "That file is too short to be a packet capture log. PacketScope can analyze classic PCAP capture files (for example from Wireshark or tcpdump).";
        if (head.SequenceEqual(new byte[] { 0x0A, 0x0D, 0x0D, 0x0A }))
            return "That is a PCAPNG file, which this version cannot analyze yet. In Wireshark, use Save As and choose the classic PCAP format, then import it again.";
        var headBytes = head.ToArray();
        var classic = new[]
        {
            new byte[] { 0xD4, 0xC3, 0xB2, 0xA1 }, new byte[] { 0xA1, 0xB2, 0xC3, 0xD4 },
            new byte[] { 0x4D, 0x3C, 0xB2, 0xA1 }, new byte[] { 0xA1, 0xB2, 0x3C, 0x4D },
        };
        if (classic.Any(c => headBytes.SequenceEqual(c))) return null;
        return "That file does not look like a packet capture log. PacketScope can analyze classic PCAP capture files (for example exported from Wireshark or tcpdump); plain text logs cannot be turned into packet results.";
    }

    private void ImportUserLogFile(string path)
    {
        if (LogFileValidationError(path) is { } problem)
        {
            MessageBox.Show(problem, "PacketScope — import", MessageBoxButtons.OK, MessageBoxIcon.Information);
            SetState($"Problem: {problem}", Red);
            _nav.SelectedItem = "Capture";
            return;
        }
        _sessionDir = NewSessionDir(true);
        File.Copy(path, Path.Combine(_sessionDir, "traffic.pcap"));
        _context = new SessionContext
        {
            Goal = CaptureGoal.Background,
            Interface = $"Imported: {Path.GetFileName(path)}",
            StartedAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000.0,
            IsImported = true,
        };
        SaveContextJson();
        _kernelDrops = 0;
        AnalyzeCurrentSession(Path.Combine(_sessionDir, "traffic.pcap"));
    }

    private void AnalyzeCurrentSession(string pcap)
    {
        SetState("Analyzing…", Amber);
        var snapshots = _processSnapshots;
        var ctx = _context;
        _ = Task.Run(() =>
        {
            CaptureReport report;
            try { report = PacketAnalyzer.Analyze(pcap); }
            catch (Exception ex)
            {
                BeginInvoke(() => SetState($"Problem: {ex.Message} The saved capture file was kept.", Red));
                return;
            }
            // Windows process attribution by endpoint mapping (approximate,
            // labeled as such): match retained packets against the TCP/UDP
            // table snapshots taken while capturing.
            int attributed = 0;
            foreach (var pkt in report.Packets)
            {
                string key1 = $"{pkt.Source}:{pkt.SourcePort}|{pkt.Destination}:{pkt.DestinationPort}";
                string key2 = $"{pkt.Destination}:{pkt.DestinationPort}|{pkt.Source}:{pkt.SourcePort}";
                if (snapshots.TryGetValue(key1, out var hit) || snapshots.TryGetValue(key2, out hit))
                {
                    pkt.ProcessId = hit.Pid;
                    pkt.ProcessName = hit.Name;
                    attributed++;
                }
            }
            if (report.Facts != null)
            {
                report.Facts.AttributedPackets = attributed;
                report.Facts.UnattributedPackets = report.PacketCount - attributed;
                report.Facts.Applications = report.Packets
                    .GroupBy(p => (p.ProcessName ?? "Unknown", p.ProcessId))
                    .Select(g => (
                        Name: g.Key.Item1 == "Unknown" ? "Unknown" : g.Key.Item1,
                        Pid: g.Key.Item2,
                        Packets: g.Count(),
                        Bytes: g.Sum(p => (long)p.Length),
                        Sent: 0L, Received: 0L,
                        Destinations: g.Select(p => p.Destination).Distinct().Take(64).ToList(),
                        PacketNumbers: g.Select(p => p.Id).Take(100).ToList()))
                    .OrderByDescending(a => a.Bytes).ToList();
            }
            // Threat matching against one local snapshot of the feed store.
            var (store, perFeed) = _feedUpdater.LoadStore(DateTimeOffset.Now, _customFeeds);
            var feedRefs = FeedRegistry.All.Concat(_customFeeds).Select(meta =>
            {
                var s = _feedUpdater.StateFor(meta);
                if (!s.Enabled || _feedUpdater.StoredData(meta) == null) return null;
                return new FeedRef { Id = meta.Id, Name = meta.Name, UpdatedAt = s.LastSuccessAt, Stale = s.IsStale(meta, DateTimeOffset.Now), IndicatorCount = perFeed.GetValueOrDefault(meta.Id) };
            }).Where(f => f != null).Cast<FeedRef>().ToList();
            var metas = FeedRegistry.All.Concat(_customFeeds).ToDictionary(m => m.Id);
            bool anyEnabled = FeedRegistry.All.Concat(_customFeeds).Any(m => _feedUpdater.StateFor(m).Enabled);
            bool anyStored = FeedRegistry.All.Concat(_customFeeds).Any(m => _feedUpdater.StoredData(m) != null);
            var outcome = IntelMatcher.Match(report, store, metas, _allowlist, DateTimeOffset.Now);
            string status = !anyEnabled ? "disabled" : !anyStored ? "no_feeds" : "checked";
            var intel = ThreatIntelSummary.Make(outcome, feedRefs, status);
            BeginInvoke(() =>
            {
                _report = report;
                _context = ctx;
                _threatIntel = intel;
                _results = CaptureResultsBuilder.Build(report, ctx!, _kernelDrops, intel);
                if (_context != null && _sessionDir != null)
                {
                    _context.EndedAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000.0;
                    SaveContextJson();
                }
                SetState("Capture complete", PrimaryText);
                _nav.SelectedItem = "Results";
                StartAiSummary();
            });
        });
    }

    private void StartAiSummary()
    {
        _aiSummary = null;
        if (!_aiSettings.Enabled || _results == null) return;
        var results = _results;
        _ = Task.Run(async () =>
        {
            var summary = await ResultsSummaryService.SummarizeAsync(results, _aiSettings);
            BeginInvoke(() =>
            {
                if (!ReferenceEquals(_results, results)) return; // a newer session owns the page
                _aiSummary = summary;
                if (_nav.SelectedItem?.ToString() == "Results") ShowPage("Results");
            });
        });
    }

    // ---------------- Results page ----------------

    private void BuildResultsPage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Capture results", 24));
        if (_results == null || _report == null || _context == null)
        {
            var empty = Card();
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
            layout.Controls.Add(H("No results yet", 15));
            layout.Controls.Add(Body("Run a capture on the Capture page, or import a capture log file. When you stop a capture, the results will open here automatically."));
            var go = StyledButton("Go to Capture", Teal, Color.Black);
            go.Click += (_, _) => _nav.SelectedItem = "Capture";
            layout.Controls.Add(go);
            empty.Controls.Add(layout);
            flow.Controls.Add(empty);
            _content.Controls.Add(flow);
            return;
        }
        var r = _results;
        _anchors.Clear();
        if (r.SecurityAlert != "none" && r.ThreatIntel != null)
            flow.Controls.Add(SecurityCard(r, r.ThreatIntel));
        var verdictCard = VerdictCard(r);
        _anchors["#verdict"] = verdictCard;
        flow.Controls.Add(verdictCard);
        if (r.Verdict != "not_enough_traffic")
        {
            var coverage = CoverageCard(r); _anchors["#coverage"] = coverage; flow.Controls.Add(coverage);
            var path = PathCard(r); _anchors["#path"] = path; flow.Controls.Add(path);
            if (r.Findings.Count > 0) { var findings = FindingsCard(r); _anchors["#evidence"] = findings; flow.Controls.Add(findings); }
            var dnsChecks = DnsAndChecksCard(r); _anchors["#dns"] = dnsChecks; flow.Controls.Add(dnsChecks);
            var destinations = DestinationsCard(r); _anchors["#destinations"] = destinations; flow.Controls.Add(destinations);
            flow.Controls.Add(TimelineCard(r));
            flow.Controls.Add(Body("Built-in checks only see this device's traffic during the capture and can't read inside encrypted connections. Nothing flagged doesn't prove the network is healthy or secure.", 9));
        }
        _content.Controls.Add(flow);
    }

    private Panel SecurityCard(CaptureResults r, ThreatIntelSummary intel)
    {
        var card = Card();
        bool high = r.SecurityAlert == "high";
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H(high ? "⚠ Possible malware contact" : "⚠ Contact with a flagged address", 13, high ? Red : Amber));
        layout.Controls.Add(H(intel.SecurityHeadline, 16));
        layout.Controls.Add(Body("A feed listing is evidence to investigate, not proof that this device is infected. What to do: 1. Run a malware scan on this device. 2. If this is a work device, tell your IT or security team. 3. Share this report with them.", 10));
        var share = StyledButton("Share with support", Teal, Color.Black);
        share.Click += (_, _) => ExportSupportReport();
        layout.Controls.Add(share);
        card.Controls.Add(layout);
        return card;
    }

    private Panel VerdictCard(CaptureResults r)
    {
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        string status = r.Verdict switch
        {
            "cause_found" => "Likely cause found",
            "possible_issue" => "Possible issue",
            "inconclusive" => "Inconclusive",
            "no_problem_seen" => "No problem seen",
            _ => "Not enough traffic",
        };
        var summary = _aiSummary ?? r.TemplateSummary;
        layout.Controls.Add(H(status, 12, r.Verdict is "cause_found" ? Red : r.Verdict is "inconclusive" or "possible_issue" ? Amber : Teal));
        layout.Controls.Add(H(summary.Headline, 16));
        layout.Controls.Add(Body(summary.Body, 10.5f, PrimaryText));
        layout.Controls.Add(H(r.Verdict == "cause_found" ? "What to try" : "Next step", 11, Teal));
        if (r.Verdict == "cause_found" && r.Findings.FirstOrDefault(f => f.Category != "security") is { } top && top.NextSteps.Count > 1)
        {
            for (int i = 0; i < top.NextSteps.Count; i++) layout.Controls.Add(Body($"{i + 1}. {top.NextSteps[i]}", 10.5f, PrimaryText));
        }
        else layout.Controls.Add(Body(summary.NextStep, 10.5f, PrimaryText));
        var buttons = new FlowLayoutPanel { AutoSize = true };
        Button primary = r.Verdict switch
        {
            "cause_found" or "possible_issue" => StyledButton("Share with support", Teal, Color.Black),
            "inconclusive" => StyledButton("Capture again for 60 s", Teal, Color.Black),
            "no_problem_seen" => StyledButton("Back to Capture", Teal, Color.Black),
            _ => StyledButton("Capture again", Teal, Color.Black),
        };
        primary.Click += (_, _) =>
        {
            if (r.Verdict is "cause_found" or "possible_issue") ExportSupportReport();
            else if (r.Verdict == "inconclusive") { _nav.SelectedItem = "Capture"; _durationCombo.SelectedIndex = 1; }
            else _nav.SelectedItem = "Capture";
        };
        buttons.Controls.Add(primary);
        var exportBtn = StyledButton(r.Findings.Count > 0 ? "Export raw capture" : "Export capture", Elevated, PrimaryText);
        exportBtn.Click += (_, _) => ExportRawCapture();
        buttons.Controls.Add(exportBtn);
        layout.Controls.Add(buttons);
        if (summary.Citations.Count > 0)
        {
            var cites = new FlowLayoutPanel { AutoSize = true };
            foreach (var (text, anchor) in summary.Citations)
            {
                var btn = StyledButton(text, Elevated, Teal);
                string target = anchor;
                btn.Click += (_, _) => { if (_anchors.TryGetValue(target, out var card)) _content.ScrollControlIntoView(card); };
                cites.Controls.Add(btn);
            }
            layout.Controls.Add(cites);
        }
        layout.Controls.Add(Body($"Summary written from {Format.Count(r.Packets)} packets. {(summary.FromTemplate ? "Summary generated from checks" : $"Wording by your local model ({_aiSettings.Model}) · the verdict was decided by checks — verify important conclusions against the findings below")}. Goal: {r.GoalLabel} · {r.InterfaceName} · {Format.Duration(r.DurationSec)}", 9));
        card.Controls.Add(layout);
        return card;
    }

    private Panel CoverageCard(CaptureResults r)
    {
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("What this capture could see", 14));
        var grid = new TableLayoutPanel { ColumnCount = 5, AutoSize = true, Width = 940 };
        void Tile(string title, string value, string sub, bool warning)
        {
            var panel = new Panel { BackColor = Elevated, Padding = new Padding(10), Margin = new Padding(4), Width = 175, Height = 86 };
            panel.Controls.Add(new Label { Text = sub, ForeColor = warning ? Amber : SecondaryText, Font = new Font("Segoe UI", 8.5f), Dock = DockStyle.Bottom, AutoSize = false, Height = 28 });
            panel.Controls.Add(new Label { Text = value, ForeColor = PrimaryText, Font = new Font("Consolas", 15, FontStyle.Bold), Dock = DockStyle.Top, Height = 28 });
            panel.Controls.Add(new Label { Text = title, ForeColor = SecondaryText, Font = new Font("Segoe UI", 8.5f), Dock = DockStyle.Top, Height = 18 });
            grid.Controls.Add(panel);
        }
        Tile("Duration", Format.Duration(r.DurationSec), r.TooShort ? "Short. May miss the problem" : "Long enough to reproduce most problems", r.TooShort);
        var firstSkip = r.Skipped.FirstOrDefault();
        Tile("Checked by built-in checks", $"{Format.Count(r.CheckedPackets)} of {Format.Count(r.Packets)}", firstSkip.Reason == "encrypted_quic" ? $"{Format.Count(firstSkip.Packets)} QUIC packets (contents encrypted)" : "Everything could be checked", r.CheckedPercent < 70);
        Tile("Data", Format.Bytes(r.Bytes), $"{Format.Count(r.Packets)} packets", false);
        Tile("Interface", string.IsNullOrEmpty(r.InterfaceName) ? "—" : r.InterfaceName, "This device only", false);
        Tile("Dropped by capture", Format.Count(r.KernelDrops), r.KernelDrops > 0 ? "Some packets were lost" : "Nothing lost", r.KernelDrops > 0);
        if (r.ThreatIntel is { } intel)
        {
            bool stale = intel.Feeds.Any(f => f.Stale);
            Tile("Threat feeds", intel.Status == "checked" ? $"{intel.Feeds.Count} feeds" : "Didn't run",
                intel.Status == "no_feeds" ? "Threat matching didn't run" : stale ? "Feeds are stale; using the last good copies" : "Up to date",
                stale || intel.Status != "checked");
        }
        layout.Controls.Add(grid);
        layout.Controls.Add(Body("Mix: " + string.Join("   ", r.Mix.Select(m => $"{m.Name} {Format.Count(m.Count)} {(m.Name == "QUIC" ? "(contents encrypted)" : "checked")}")), 9));
        card.Controls.Add(layout);
        return card;
    }

    private Panel PathCard(CaptureResults r)
    {
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        var selector = new ComboBox { Width = 320, DropDownStyle = ComboBoxStyle.DropDownList };
        foreach (var (dest, _) in r.Paths) selector.Items.Add(dest);
        if (selector.Items.Count > 0) selector.SelectedIndex = 0;
        var stagesPanel = new FlowLayoutPanel { AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Connection path", 14));
        layout.Controls.Add(Body("Every connection passes these steps in order. The first failed step is usually the cause."));
        if (r.Paths.Count > 1) layout.Controls.Add(selector);
        layout.Controls.Add(stagesPanel);
        void RenderStages()
        {
            stagesPanel.Controls.Clear();
            int idx = Math.Max(0, selector.SelectedIndex);
            if (idx >= r.Paths.Count) return;
            var (_, stages) = r.Paths[idx];
            int firstFailed = stages.FindIndex(s => s.Status == "failed");
            for (int i = 0; i < stages.Count; i++)
            {
                var s = stages[i];
                var panel = new Panel { BackColor = Elevated, Padding = new Padding(10), Margin = new Padding(4), Width = 168, Height = 118, BorderStyle = i == firstFailed ? BorderStyle.Fixed3D : BorderStyle.FixedSingle };
                panel.Controls.Add(new Label { Text = s.Detail, ForeColor = SecondaryText, Font = new Font("Segoe UI", 8.5f), Dock = DockStyle.Bottom, Height = 40, AutoSize = false });
                panel.Controls.Add(new Label { Text = s.Result, ForeColor = PrimaryText, Font = new Font("Segoe UI", 9.5f), Dock = DockStyle.Top, Height = 34, AutoSize = false });
                panel.Controls.Add(new Label { Text = s.Title, ForeColor = PrimaryText, Font = new Font("Segoe UI", 10, FontStyle.Bold), Dock = DockStyle.Top, Height = 20 });
                string pillText = i == firstFailed ? "Failed here" : s.Status switch { "passed" => "Passed", "failed" => "Failed", "warning" => "Warning", "not_reached" => "Not reached", _ => "Not visible" };
                panel.Controls.Add(new Label { Text = $"STEP {i + 1} · {pillText}", ForeColor = s.Status switch { "passed" => Teal, "failed" => Red, "warning" => Amber, _ => SecondaryText }, Font = new Font("Segoe UI", 8, FontStyle.Bold), Dock = DockStyle.Top, Height = 16 });
                stagesPanel.Controls.Add(panel);
            }
        }
        selector.SelectedIndexChanged += (_, _) => RenderStages();
        RenderStages();
        card.Controls.Add(layout);
        return card;
    }

    private Panel FindingsCard(CaptureResults r)
    {
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        foreach (var f in r.Findings)
        {
            layout.Controls.Add(H($"Evidence: {f.Title}", 13, f.Severity switch { "likely_cause" => Red, "warning" => Amber, _ => PrimaryText }));
            layout.Controls.Add(Body($"Observed: {f.Observed}", 10, PrimaryText));
            layout.Controls.Add(Body($"What that usually means: {f.Interpretation}", 10));
            if (f.Category == "security")
            {
                foreach (var m in f.MatchedIndicators)
                {
                    string seen = m.Indicator.LastSeen != null ? $", last seen {m.Indicator.LastSeen}" : "";
                    layout.Controls.Add(Body($"{(string.IsNullOrEmpty(m.FeedName) ? m.Indicator.FeedId : m.FeedName)}: {m.MatchedOn} {Normalize.Defanged(m.Observed, m.MatchedOn)} (threat: {m.Indicator.Threat ?? "listed"}{seen}); severity because: {string.Join("; ", m.SeverityReasons)}", 9, Amber));
                }
            }
            var evidence = new FlowLayoutPanel { AutoSize = true };
            evidence.Controls.Add(new Label { Text = $"Filter  {f.Evidence.Filter}", Font = new Font("Consolas", 9), ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(0, 8, 8, 0) });
            var copyBtn = StyledButton("Copy filter", Elevated, PrimaryText);
            copyBtn.Click += (_, _) => Clipboard.SetText(f.Evidence.Filter);
            var openBtn = StyledButton("Open in packet view", Elevated, Teal);
            openBtn.Click += (_, _) => { _packetSearch = f.Evidence.Frames.FirstOrDefault() is int n && n > 0 ? $"#{n}" : ""; _nav.SelectedItem = "Packet log"; };
            var exportBtn = StyledButton("Export these packets", Elevated, PrimaryText);
            exportBtn.Click += (_, _) => ExportEvidencePackets(f.Evidence.Frames);
            evidence.Controls.AddRange(new Control[] { copyBtn, openBtn, exportBtn });
            layout.Controls.Add(evidence);
            // Up to 10 evidence rows
            var rows = (_report?.Packets ?? new List<PacketRecord>()).Where(p => f.Evidence.Frames.Contains(p.Id)).Take(10);
            foreach (var pkt in rows)
                layout.Controls.Add(Body($"#{pkt.Id}   {RelTime(pkt)}   {Endpoint(pkt.Source, pkt.SourcePort)} → {Endpoint(pkt.Destination, pkt.DestinationPort)}   {pkt.Summary}", 9, SecondaryText));
        }
        card.Controls.Add(layout);
        return card;
    }

    private string RelTime(PacketRecord pkt)
        => _report?.Facts?.FirstTimestamp is double f0 ? Format.PacketTime(pkt.Timestamp - f0) : "—";
    private static string Endpoint(string a, int? port) => port is int p ? $"{a}:{p}" : a;

    private Panel DnsAndChecksCard(CaptureResults r)
    {
        var card = Card();
        var facts = r.Report.Facts;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Name lookups (DNS)", 14));
        if (facts != null)
        {
            layout.Controls.Add(Body($"Answered {facts.DnsAnswered} of {facts.DnsQueries} · Average {Format.Ms(facts.AverageDnsMilliseconds ?? 0)} · Slowest {Format.Ms(facts.DnsMaxMilliseconds ?? 0)} · Resolver {facts.DnsResolvers.FirstOrDefault() ?? "—"}", 10, PrimaryText));
            double scale = Math.Max(100, facts.DnsMaxMilliseconds ?? 100);
            foreach (var l in facts.DnsLookups.Take(50))
            {
                string bar = new('█', (int)Math.Max(1, Math.Min(30, (l.Milliseconds ?? 0) / scale * 30)));
                layout.Controls.Add(Body($"{l.Name} {l.Type}   {bar}   {(l.Milliseconds is double ms ? Format.Ms(ms) : (string.IsNullOrEmpty(l.Rcode) ? "no answer" : l.Rcode))}", 9, l.Milliseconds == null ? Amber : SecondaryText));
            }
            layout.Controls.Add(Body($"Bars are scaled to {Format.Ms(scale)}. This measures name lookup only, not page load or internet speed.", 9));
        }
        layout.Controls.Add(H("Checks run", 14));
        if (facts != null)
        {
            foreach (var c in facts.Checks)
                layout.Controls.Add(Body($"{(c.Flagged ? "⚠" : "✓")}  {c.Label}   {Format.Count(c.Count)}   {c.Note}", 10, c.Flagged ? Amber : SecondaryText));
        }
        if (r.ThreatIntel is { } intel) layout.Controls.Add(ThreatChecksBody(intel));
        card.Controls.Add(layout);
        return card;
    }

    private Control ThreatChecksBody(ThreatIntelSummary intel)
    {
        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Threat feed checks", 12));
        void Row(string label, string detail) => layout.Controls.Add(Body($"{label} — {detail}", 10));
        if (intel.Status == "loading") Row("Threat matching didn't run (feeds still loading)", "The results were ready first; capture again to include threat matching");
        else if (intel.Status == "no_feeds") Row("Threat matching didn't run", "No feed copies have been downloaded yet");
        else if (intel.Status == "disabled") Row("Threat matching is off", "Enable feeds in Threat feeds settings");
        else
        {
            int On(params string[] types) => intel.Matches.Count(m => types.Contains(m.MatchedOn));
            Row($"Destinations checked against threat feeds: {(intel.CheckedIPsTotal > intel.CheckedIPs ? $"{intel.CheckedIPs} of {intel.CheckedIPsTotal}" : intel.CheckedIPs.ToString())}", $"{On("ipv4", "ipv6", "cidr", "ip_port")} matches");
            Row($"Domains checked against threat feeds: {intel.CheckedDomains}", $"{On("domain")} matches");
            Row($"URLs checked against threat feeds: {intel.CheckedUrls}", $"{On("url")} matches");
            Row($"Certificates checked against threat feeds: {intel.CheckedCerts}", $"{On("cert_sha1", "cert_sha256")} matches");
            Row($"TLS fingerprints checked against threat feeds: {intel.CheckedFingerprints}", $"{On("ja3", "ja4")} matches");
            Row("Files: not checked", "This app doesn't reconstruct transferred files, so file hashes can't be checked");
            if (intel.IgnoredByAllowlist > 0) Row($"Ignored by your allowlist: {intel.IgnoredByAllowlist}", "Allowlisted matches are counted, not hidden");
            if (intel.Matches.Count == 0)
                layout.Controls.Add(Body($"No matches in {intel.Feeds.Count} threat feeds. Feeds only list known threats, so this doesn't rule out new ones.", 10, Teal));
        }
        return layout;
    }

    private Panel DestinationsCard(CaptureResults r)
    {
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Who this device talked to", 14));
        var grid = Grid();
        grid.Columns.Add("dest", "Destination"); grid.Columns.Add("addr", "Address"); grid.Columns.Add("proto", "Protocol");
        grid.Columns.Add("result", "Result"); grid.Columns.Add("pkts", "Packets"); grid.Columns.Add("filter", "Evidence filter");
        foreach (var d in r.Report.Facts?.Destinations ?? new List<DestinationRecord>())
        {
            string result = d.Outcome switch { "connected" => "Connected", "refused" => "Refused", "no_reply" => "No reply", "reset_later" => "Reset later", "not_checked" => "Not checked", _ => "Background" };
            if (d.IntelTopSeverity != null)
            {
                var m = r.ThreatIntel?.Matches.FirstOrDefault(x => x.DestinationIP == d.Address);
                result += $" · Listed by {(string.IsNullOrEmpty(m?.FeedName) ? m?.Indicator.FeedId : m?.FeedName)}";
            }
            grid.Rows.Add(d.Name ?? d.Address, d.Port > 0 ? $"{d.Address}:{d.Port}" : d.Address, d.ProtocolLabel, result, Format.Count(d.Packets), d.EvidenceFilter);
        }
        layout.Controls.Add(grid);
        card.Controls.Add(layout);
        return card;
    }

    private Panel TimelineCard(CaptureResults r)
    {
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Timeline", 14));
        var buckets = r.Report.Facts?.Timeline ?? new List<TrafficBucket>();
        if (buckets.Count == 0) layout.Controls.Add(Body("No timeline data for this capture."));
        else
        {
            int max = Math.Max(1, buckets.Max(b => b.Packets));
            foreach (var b in buckets.Take(40))
            {
                string bar = new('█', Math.Max(1, b.Packets * 40 / max));
                layout.Controls.Add(Body($"+{b.Second}s  {bar}  {b.Packets} pkts · {b.DnsErrors} DNS err · {b.TcpResets} RST", 9, SecondaryText));
            }
            if (r.MarkedMomentsSec.Count == 0)
                layout.Controls.Add(Body("No moment marked. Press “It happened just now” during your next capture and the summary will focus on what happened around it.", 9, Amber));
            else
                foreach (var m in r.MarkedMomentsSec)
                    layout.Controls.Add(Body($"⚑ {Format.PacketTime(m)} · You marked the moment", 9, Amber));
        }
        card.Controls.Add(layout);
        return card;
    }

    private static DataGridView Grid()
    {
        var grid = new DataGridView
        {
            BackgroundColor = PanelBg, ForeColor = PrimaryText, GridColor = Border,
            EnableHeadersVisualStyles = false, ReadOnly = true, AllowUserToAddRows = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, Width = 940, Height = 260,
            ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Elevated, ForeColor = SecondaryText },
            DefaultCellStyle = new DataGridViewCellStyle { BackColor = PanelBg, ForeColor = PrimaryText, SelectionBackColor = Elevated },
        };
        return grid;
    }

    // ---------------- Packet log / Apps / Endpoints ----------------

    private void BuildPacketLogPage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Packet log", 24));
        if (_report == null) { flow.Controls.Add(Body("No capture loaded. Start a capture or import a PCAP file to inspect packets.")); _content.Controls.Add(flow); return; }
        flow.Controls.Add(Body($"Showing retained rows (first {PacketAnalyzer.DisplayLimit} of {_report.PacketCount} packets). Statistics cover the entire file. Raw payload contents are never shown."));
        _packetSearchBox = new TextBox { Width = 700, BackColor = Elevated, ForeColor = PrimaryText, Text = _packetSearch };
        _packetSearchBox.TextChanged += (_, _) => { _packetSearch = _packetSearchBox.Text; FillPacketGrid(); };
        flow.Controls.Add(_packetSearchBox);
        _packetGrid = Grid();
        _packetGrid.Height = 520;
        _packetGrid.Columns.Add("id", "#"); _packetGrid.Columns.Add("time", "Time"); _packetGrid.Columns.Add("flow", "From → to");
        _packetGrid.Columns.Add("proto", "Protocol"); _packetGrid.Columns.Add("len", "Bytes"); _packetGrid.Columns.Add("summary", "Summary");
        flow.Controls.Add(_packetGrid);
        FillPacketGrid();
        _content.Controls.Add(flow);
    }

    private void FillPacketGrid()
    {
        if (_report == null) return;
        _packetGrid.Rows.Clear();
        string q = _packetSearch.Trim().ToLowerInvariant();
        IEnumerable<PacketRecord> rows = _report.Packets;
        if (q.StartsWith('#') && int.TryParse(q[1..], out int n)) rows = rows.Where(p => p.Id == n);
        else if (q.Contains("ip.addr=="))
        {
            string ip = q.Split("ip.addr==")[1].Split(' ', '&')[0];
            rows = rows.Where(p => p.Source == ip || p.Destination == ip);
        }
        else if (q.StartsWith("dns")) rows = rows.Where(p => p.ProtocolName is "DNS" or "mDNS");
        else if (q.Length > 0)
            rows = rows.Where(p => p.Source.ToLowerInvariant().Contains(q) || p.Destination.ToLowerInvariant().Contains(q) || p.ProtocolName.ToLowerInvariant().Contains(q) || (p.ProcessName?.ToLowerInvariant().Contains(q) ?? false) || (p.Hostname?.ToLowerInvariant().Contains(q) ?? false));
        foreach (var p in rows.Take(2000))
            _packetGrid.Rows.Add($"#{p.Id}", RelTime(p), $"{Endpoint(p.Source, p.SourcePort)} → {Endpoint(p.Destination, p.DestinationPort)}", p.ProtocolName, p.Length, p.Summary + (p.ProcessName != null ? $"  [{p.ProcessName} ({p.ProcessId})]" : ""));
    }

    private void BuildAppsPage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Apps", 24));
        flow.Controls.Add(Body("On Windows, process names come from connection-table snapshots taken during the capture and matched by endpoint. That is approximate (a shared or reused socket can differ), unlike macOS PKTAP metadata. Missing identity is grouped as Unknown, which is not automatically suspicious."));
        var facts = _report?.Facts;
        if (facts == null || facts.Applications.Count == 0) { flow.Controls.Add(Body("No process data yet. Run a live capture to see per-app traffic.")); _content.Controls.Add(flow); return; }
        flow.Controls.Add(Body($"Attributed in retained rows: {facts.AttributedPackets} · Unknown: the rest"));
        foreach (var app in facts.Applications)
        {
            var card = Card();
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
            layout.Controls.Add(H($"{app.Name}{(app.Pid is int pid ? $" (PID {pid})" : "")} — {app.Packets} pkts · {Format.Bytes(app.Bytes)}", 12));
            layout.Controls.Add(Body($"Destinations: {string.Join(", ", app.Destinations.Take(12))}"));
            card.Controls.Add(layout);
            flow.Controls.Add(card);
        }
        _content.Controls.Add(flow);
    }

    private void BuildEndpointsPage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Endpoints", 24));
        if (_report == null) { flow.Controls.Add(Body("No capture loaded. Endpoints and protocol mix appear here after analysis.")); _content.Controls.Add(flow); return; }
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Protocol mix", 14));
        foreach (var p in _report.Protocols) layout.Controls.Add(Body($"{p.Name}: {p.Count} packets, {Format.Bytes(p.Bytes)}", 10, PrimaryText));
        layout.Controls.Add(H("Endpoints by captured bytes", 14));
        layout.Controls.Add(Body("Addresses are shown exactly as captured. No reverse-DNS or external lookup is performed."));
        foreach (var e in _report.Endpoints.Take(50)) layout.Controls.Add(Body($"{e.Address}: {e.Packets} packets, {Format.Bytes(e.Bytes)}", 10, PrimaryText));
        if (_report.Facts is { } facts && facts.Domains.Count > 0)
        {
            layout.Controls.Add(H("Observed DNS names", 14));
            layout.Controls.Add(Body("Only names and A/AAAA addresses decoded from visible DNS. An observed name does not establish a website visit or the destination's owner."));
            foreach (var d in facts.Domains.Take(100))
                layout.Controls.Add(Body($"{d.Name} — {d.QueryCount} queries, {d.ErrorCount} errors{(d.Addresses.Count > 0 ? ", " + string.Join(", ", d.Addresses) : "")}", 10, PrimaryText));
        }
        card.Controls.Add(layout);
        flow.Controls.Add(card);
        _content.Controls.Add(flow);
    }

    private void BuildTimelinePage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Timeline", 24));
        if (_results == null) { flow.Controls.Add(Body("No timeline yet. Buckets are built from the full capture file after analysis.")); _content.Controls.Add(flow); return; }
        flow.Controls.Add(TimelineCard(_results));
        _content.Controls.Add(flow);
    }

    // ---------------- Compare ----------------

    private void BuildComparePage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Compare", 24));
        flow.Controls.Add(Body("Make one change, then run the same check again. A before/after difference cannot establish causation or confirm a fix, and captured volume is not a speed test."));
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(Body(_baselineReport == null ? "Baseline: none selected" : $"Baseline: {_baselineName} · {_baselineReport.PacketCount} packets · {_baselineContext?.Interface}"));
        var buttons = new FlowLayoutPanel { AutoSize = true };
        var useCurrent = StyledButton("Use current as baseline", Elevated, PrimaryText);
        useCurrent.Enabled = _report != null;
        useCurrent.Click += (_, _) => { _baselineReport = _report; _baselineContext = _context; _baselineName = "Current capture"; _nav.SelectedItem = "Compare"; };
        var clear = StyledButton("Clear", Elevated, PrimaryText);
        clear.Click += (_, _) => { _baselineReport = null; _nav.SelectedItem = "Compare"; };
        buttons.Controls.AddRange(new Control[] { useCurrent, clear });
        layout.Controls.Add(buttons);
        layout.Controls.Add(H("Sessions", 13));
        foreach (var dir in ListSessionDirs())
        {
            var row = new FlowLayoutPanel { AutoSize = true };
            row.Controls.Add(new Label { Text = Path.GetFileName(dir), ForeColor = PrimaryText, AutoSize = true, Padding = new Padding(0, 8, 10, 0) });
            var open = StyledButton("Open", Elevated, PrimaryText);
            string captured = dir;
            open.Click += (_, _) => OpenSession(captured);
            var baseBtn = StyledButton("Set as baseline", Elevated, PrimaryText);
            baseBtn.Click += (_, _) => SetBaseline(captured);
            row.Controls.AddRange(new Control[] { open, baseBtn });
            layout.Controls.Add(row);
        }
        card.Controls.Add(layout);
        flow.Controls.Add(card);
        if (_baselineReport != null && _report != null && _baselineContext != null && _context != null)
            flow.Controls.Add(ComparisonCard(_baselineReport, _baselineContext, _report, _context));
        _content.Controls.Add(flow);
    }

    private List<string> ListSessionDirs()
    {
        try
        {
            return Directory.GetDirectories(SessionsRoot)
                .Where(d => File.Exists(Path.Combine(d, "traffic.pcap")))
                .OrderByDescending(d => d).Take(50).ToList();
        }
        catch { return new List<string>(); }
    }

    private void OpenSession(string dir)
    {
        _sessionDir = dir;
        _context = LoadContext(dir) ?? new SessionContext { Interface = "Saved session", IsImported = true };
        _processSnapshots = new Dictionary<string, (int, string)>();
        _kernelDrops = 0;
        AnalyzeCurrentSession(Path.Combine(dir, "traffic.pcap"));
    }

    private void SetBaseline(string dir)
    {
        try
        {
            var rep = PacketAnalyzer.Analyze(Path.Combine(dir, "traffic.pcap"));
            _baselineReport = rep;
            _baselineContext = LoadContext(dir) ?? new SessionContext { Interface = "Saved session", IsImported = true };
            _baselineName = Path.GetFileName(dir);
            _nav.SelectedItem = "Compare";
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "PacketScope", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    private SessionContext? LoadContext(string dir)
    {
        try
        {
            string path = Path.Combine(dir, "context.json");
            if (!File.Exists(path)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            var ctx = new SessionContext
            {
                Interface = root.TryGetProperty("interface", out var i) ? i.GetString() ?? "" : "",
                Symptom = root.TryGetProperty("symptom", out var s) ? s.GetString() ?? "" : "",
                IsImported = root.TryGetProperty("isImported", out var im) && im.GetBoolean(),
            };
            if (root.TryGetProperty("goal", out var g) && Enum.TryParse<CaptureGoal>(g.GetString(), out var goal)) ctx.Goal = goal;
            if (root.TryGetProperty("startedAt", out var st) && st.TryGetDouble(out var sd)) ctx.StartedAt = sd;
            if (root.TryGetProperty("markers", out var markers))
            {
                foreach (var m in markers.EnumerateArray())
                {
                    if (m.TryGetProperty("timestamp", out var ts) && ts.TryGetDouble(out var tv))
                        ctx.Markers.Add(new ProblemMarker { Timestamp = tv, Note = m.TryGetProperty("note", out var n) ? n.GetString() ?? "Problem noticed" : "Problem noticed" });
                }
            }
            return ctx;
        }
        catch { return null; }
    }

    private Panel ComparisonCard(CaptureReport baseline, SessionContext bctx, CaptureReport current, SessionContext cctx)
    {
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Baseline vs current", 14));
        var bf = baseline.Facts; var cf = current.Facts;
        string Share(int num, int den) => den > 0 ? $"{100.0 * num / den:0.0}% ({num} of {den})" : "No observed sample";
        void Row(string name, string b, string c) => layout.Controls.Add(Body($"{name} — baseline {b} · current {c}", 10.5f, PrimaryText));
        if (bf != null && cf != null)
        {
            Row("DNS error reply share", Share(bf.DnsErrors, bf.DnsResponses), Share(cf.DnsErrors, cf.DnsResponses));
            Row("TCP reset packet share", Share(bf.TcpResets, bf.TcpPackets), Share(cf.TcpResets, cf.TcpPackets));
            Row("Matched DNS response time", bf.AverageDnsMilliseconds is double ba ? $"{ba:0} ms ({bf.MatchedDnsPairs} pairs)" : "No matched pairs", cf.AverageDnsMilliseconds is double ca ? $"{ca:0} ms ({cf.MatchedDnsPairs} pairs)" : "No matched pairs");
        }
        Row("Captured traffic rate", baseline.Duration >= 1 ? $"{baseline.CapturedBytes / baseline.Duration / 1024:0.0} KiB/s" : "Not reported (span under 1 s)", current.Duration >= 1 ? $"{current.CapturedBytes / current.Duration / 1024:0.0} KiB/s" : "Not reported (span under 1 s)");
        Row("Observed packet span", $"{baseline.Duration:0.0} s", $"{current.Duration:0.0} s");
        if (bctx.Goal != cctx.Goal) layout.Controls.Add(Body("⚠ The two captures used different goals.", 10, Amber));
        if (bctx.Interface != cctx.Interface) layout.Controls.Add(Body("⚠ Different network interfaces were used.", 10, Amber));
        if (bctx.IsImported || cctx.IsImported) layout.Controls.Add(Body("⚠ An imported capture is included; its original capture conditions are unknown.", 10, Amber));
        layout.Controls.Add(Body("A before/after difference cannot establish causation or confirm a fix. Captured volume is not a speed test.", 9.5f, Amber));
        card.Controls.Add(layout);
        return card;
    }

    // ---------------- Ask ----------------

    private void BuildAskPage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Ask capture", 24));
        flow.Controls.Add(H("Results summary wording (optional, local model)", 13));
        flow.Controls.Add(Body("The verdict is always decided by the built-in checks. If you run a local model server on this device (for example Ollama), PacketScope can ask it to word the Results summary — validated against the measured numbers before it is shown, with the template summary as fallback. Only loopback endpoints are allowed, so summaries never leave this device. Ask answers always come from the local rules guide either way."));
        _useAiCheck = new CheckBox { Text = "Use local AI to word the Results summary when available", ForeColor = PrimaryText, AutoSize = true, Checked = _aiSettings.Enabled };
        flow.Controls.Add(_useAiCheck);
        var endpointBox = new TextBox { Width = 320, BackColor = Elevated, ForeColor = PrimaryText, Text = _aiSettings.Endpoint };
        var modelBox = new TextBox { Width = 220, BackColor = Elevated, ForeColor = PrimaryText, Text = _aiSettings.Model };
        var aiRow = new FlowLayoutPanel { AutoSize = true };
        aiRow.Controls.Add(new Label { Text = "Endpoint", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(0, 6, 6, 0) });
        aiRow.Controls.Add(endpointBox);
        aiRow.Controls.Add(new Label { Text = "Model", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(12, 6, 6, 0) });
        aiRow.Controls.Add(modelBox);
        var saveAi = StyledButton("Save AI settings", Elevated, PrimaryText);
        var aiStatus = Body("", 9);
        saveAi.Click += (_, _) =>
        {
            _aiSettings.Enabled = _useAiCheck.Checked;
            _aiSettings.Endpoint = endpointBox.Text.Trim();
            _aiSettings.Model = modelBox.Text.Trim();
            if (_aiSettings.ValidationError is { } problem)
            {
                aiStatus.Text = problem;
                aiStatus.ForeColor = Amber;
                return;
            }
            _aiSettings.Save();
            aiStatus.Text = _aiSettings.Enabled ? "Saved. New analyses will ask the local model to word the summary (validated, with template fallback)." : "Saved. AI wording is off; template summaries will be used.";
            aiStatus.ForeColor = Teal;
            StartAiSummary();
        };
        aiRow.Controls.Add(saveAi);
        flow.Controls.Add(aiRow);
        flow.Controls.Add(aiStatus);
        flow.Controls.Add(H("Ask about this capture", 13));
        _chatList = new ListBox { Width = 940, Height = 380, BackColor = PanelBg, ForeColor = PrimaryText, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10) };
        flow.Controls.Add(_chatList);
        foreach (var suggestion in new[] { "Why was this flagged?", "What should I check first?", "What happened near my marked moments?", "Which apps were communicating?", "What changed between captures?" })
        {
            var btn = StyledButton(suggestion, Elevated, PrimaryText);
            string q = suggestion;
            btn.Click += (_, _) => Ask(q);
            flow.Controls.Add(btn);
        }
        var inputRow = new FlowLayoutPanel { AutoSize = true };
        _chatInput = new TextBox { Width = 760, BackColor = Elevated, ForeColor = PrimaryText };
        _chatInput.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { Ask(_chatInput.Text); _chatInput.Clear(); e.SuppressKeyPress = true; } };
        var askBtn = StyledButton("Ask", Teal, Color.Black);
        askBtn.Click += (_, _) => { Ask(_chatInput.Text); _chatInput.Clear(); };
        inputRow.Controls.AddRange(new Control[] { _chatInput, askBtn });
        flow.Controls.Add(inputRow);
        _content.Controls.Add(flow);
    }

    private void Ask(string raw)
    {
        string question = raw.Trim();
        if (question.Length == 0) return;
        _chatList.Items.Add($"You: {question}");
        _chatList.Items.Add($"Local evidence guide · rules, no AI: {RulesAnswer(question)}");
        _chatList.TopIndex = _chatList.Items.Count - 1;
    }

    private string RulesAnswer(string question)
    {
        var report = _report;
        if (report == null) return "There is no capture loaded yet. Start a capture or import a PCAP file, then ask about what was measured.";
        string q = question.ToLowerInvariant();
        var facts = report.Facts;
        if (q.Contains("app") || q.Contains("process") || q.Contains("who"))
        {
            if (facts == null || facts.Applications.Count == 0) return "No process information is available in this capture. Without capture-time connection snapshots, ownership is Unknown rather than guessed from addresses or ports.";
            var parts = facts.Applications.Take(20).Select(a => $"{a.Name}{(a.Pid is int pid ? $" (PID {pid})" : "")}: {a.Packets} packets, {Format.Bytes(a.Bytes)}");
            return "Process attribution on Windows comes from connection-table snapshots matched by endpoint; it is never inferred from an address or domain. " + string.Join("; ", parts) + ". Unknown covers packets with no matched process and is not automatically suspicious.";
        }
        if (q.Contains("marker") || q.Contains("marked") || q.Contains("moment"))
        {
            if (_context == null || _context.Markers.Count == 0) return "No moments were marked in this session. The “It happened just now” button is available only while capturing.";
            if (facts?.FirstTimestamp is not double first) return "This capture has no observed packets, so marked moments cannot be related to packet times.";
            var lines = _context.Markers.Select(m => $"Marker at {m.Timestamp - first:0.0} s relative to the first observed packet").ToList();
            lines.Add("A marker records when you noticed a problem; it is not proof of a network fault.");
            return string.Join(" ", lines);
        }
        if (q.Contains("compar") || q.Contains("changed") || q.Contains("baseline"))
        {
            if (_baselineReport == null) return "No baseline is selected. In Compare, choose “Use current as baseline” or pick a session, make one change, then run the same check again.";
            return "A baseline is selected. Open the Compare page for the metric-by-metric comparison. A before/after difference cannot establish causation or confirm a fix.";
        }
        if (q.Contains("flag") || q.Contains("finding") || q.Contains("why"))
        {
            if (report.Findings.Count == 0) return $"Nothing in this capture matched the built-in checks across {report.PacketCount} packets. That does not prove the network is healthy — the symptom may involve encrypted traffic or fall outside this capture window.";
            var f = report.Findings[0];
            return $"{f.Title}. {f.Evidence} What to check next: {f.Recommendation}";
        }
        if (q.Contains("dns"))
        {
            if (facts == null) return "This capture has no detailed DNS facts.";
            string timing = facts.AverageDnsMilliseconds is double avg ? $" Matched exchanges averaged {avg:0} ms over {facts.MatchedDnsPairs} pair(s); that is DNS exchange time, not page-load time." : " No complete query/reply pairs could be matched.";
            return $"We observed {facts.DnsResponses} visible DNS replies, of which {facts.DnsErrors} were error replies.{timing} Encrypted DNS, cached lookups, and absent queries leave gaps.";
        }
        if (q.Contains("slow") || q.Contains("speed") || q.Contains("fast"))
            return $"This capture observed {Format.Bytes(report.CapturedBytes)} over {report.Duration:0.0} seconds. That is captured volume, not a speed test and not your connection's capacity. Compare matched DNS time and the timeline before and after a change instead.";
        if (q.Contains("privacy") || q.Contains("share") || q.Contains("upload"))
            return "Everything is analyzed on this device: no telemetry, external reputation lookups, reverse-DNS, or cloud inference. Threat feeds are downloaded as files and matched locally; no capture data is sent anywhere. The support report excludes payloads and the PCAP, with IP addresses, domains, and notes off by default.";
        if (q.Contains("unknown"))
            return "Unknown means no process could be matched to those packets from the capture-time connection snapshots. It is not automatically suspicious.";
        return "I can answer from this capture's measured evidence about: why something was flagged, what to check first, marked moments, which apps were communicating, what changed between captures, DNS, slowness, Unknown ownership, and privacy. I cannot establish a root cause, destination ownership, malware, or internet speed from this data.";
    }

    // ---------------- Threat feeds settings ----------------

    private void LoadFeedPreferences()
    {
        try
        {
            string allowPath = Path.Combine(_feedUpdater.DirectoryPath, "allowlist.json");
            if (File.Exists(allowPath))
                _allowlist = JsonSerializer.Deserialize<List<AllowlistEntry>>(File.ReadAllText(allowPath), FeedJson.Options) ?? new();
            string customPath = Path.Combine(_feedUpdater.DirectoryPath, "custom-feeds.json");
            if (File.Exists(customPath))
                _customFeeds = JsonSerializer.Deserialize<List<FeedMeta>>(File.ReadAllText(customPath), FeedJson.Options) ?? new();
        }
        catch { /* preferences are advisory */ }
    }
    private void SaveAllowlist()
    {
        try { File.WriteAllText(Path.Combine(_feedUpdater.DirectoryPath, "allowlist.json"), JsonSerializer.Serialize(_allowlist, FeedJson.Options)); } catch { }
    }

    private void SaveCustomFeeds()
    {
        try { File.WriteAllText(Path.Combine(_feedUpdater.DirectoryPath, "custom-feeds.json"), JsonSerializer.Serialize(_customFeeds, FeedJson.Options)); } catch { }
    }

    private void BuildFeedsPage()
    {
        var flow = Flow();
        flow.Controls.Add(H("Threat feeds", 24));
        flow.Controls.Add(Body("PacketScope can check destinations, names, certificates, and TLS fingerprints from your captures against threat feeds stored on this device. Matching is entirely local: no address, domain, URL, or hash from a capture is ever sent to an online service. The only downloads are the feed files below, from their registry URLs. Cleartext HTTP addresses from captures are checked locally against these feeds in the same way."));
        var card = Card();
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        layout.Controls.Add(H("Feeds", 14));
        foreach (var meta in FeedRegistry.All.Concat(_customFeeds).Where(m => !m.HiddenInSettings))
            layout.Controls.Add(FeedRow(meta));
        layout.Controls.Add(Body("ThreatFox and URLhaus are hidden until their export parsers can be verified against a real file with a user's own Auth-Key."));
        card.Controls.Add(layout);
        flow.Controls.Add(card);

        var allowCard = Card();
        var allowLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        allowLayout.Controls.Add(H("Allowlist", 14));
        allowLayout.Controls.Add(Body("Matches for these values are suppressed but counted under “Ignored by your allowlist” on the Results page."));
        var list = new ListBox { Width = 900, Height = 110, BackColor = PanelBg, ForeColor = PrimaryText };
        foreach (var e in _allowlist) list.Items.Add($"{e.Value} — {e.Reason} ({e.AddedAt:d})");
        allowLayout.Controls.Add(list);
        var addRow = new FlowLayoutPanel { AutoSize = true };
        var valueBox = new TextBox { Width = 300, BackColor = Elevated, ForeColor = PrimaryText };
        var reasonBox = new TextBox { Width = 200, BackColor = Elevated, ForeColor = PrimaryText };
        var addBtn = StyledButton("Add", Elevated, PrimaryText);
        addBtn.Click += (_, _) =>
        {
            if (valueBox.Text.Trim().Length == 0) return;
            _allowlist.Add(new AllowlistEntry { Value = valueBox.Text.Trim(), Reason = reasonBox.Text.Trim(), AddedAt = DateTimeOffset.Now });
            SaveAllowlist();
            _nav.SelectedItem = "Threat feeds";
        };
        var removeBtn = StyledButton("Remove selected", Elevated, PrimaryText);
        removeBtn.Click += (_, _) =>
        {
            if (list.SelectedIndex >= 0 && list.SelectedIndex < _allowlist.Count) { _allowlist.RemoveAt(list.SelectedIndex); SaveAllowlist(); _nav.SelectedItem = "Threat feeds"; }
        };
        addRow.Controls.AddRange(new Control[] { valueBox, reasonBox, addBtn, removeBtn });
        allowLayout.Controls.Add(addRow);
        allowCard.Controls.Add(allowLayout);
        flow.Controls.Add(allowCard);
        var customCard = Card();
        var customLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Width = 940 };
        customLayout.Controls.Add(H("Add a custom feed", 14));
        customLayout.Controls.Add(Body("Your own list, from a URL or a local file. You are responsible for its license."));
        var nameRow = new FlowLayoutPanel { AutoSize = true };
        var customNameBox = new TextBox { Width = 260, BackColor = Elevated, ForeColor = PrimaryText };
        var customUrlBox = new TextBox { Width = 380, BackColor = Elevated, ForeColor = PrimaryText };
        nameRow.Controls.AddRange(new Control[] { new Label { Text = "Name", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(0, 6, 6, 0) }, customNameBox, new Label { Text = "Feed URL", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(14, 6, 6, 0) }, customUrlBox });
        customLayout.Controls.Add(nameRow);
        var optRow = new FlowLayoutPanel { AutoSize = true };
        var formatBox = new ComboBox { Width = 260, DropDownStyle = ComboBoxStyle.DropDownList };
        formatBox.Items.AddRange(new object[] { "One indicator per line", "Typed CSV (type,value,threat,severity)" });
        formatBox.SelectedIndex = 0;
        var typeBox = new ComboBox { Width = 160, DropDownStyle = ComboBoxStyle.DropDownList };
        typeBox.Items.AddRange(new object[] { "Domain", "IPv4", "IPv6", "CIDR", "URL" });
        typeBox.SelectedIndex = 0;
        var severityBox = new ComboBox { Width = 160, DropDownStyle = ComboBoxStyle.DropDownList };
        severityBox.Items.AddRange(new object[] { "High", "Medium", "Low", "Info" });
        severityBox.SelectedIndex = 1;
        optRow.Controls.AddRange(new Control[] { new Label { Text = "Format", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(0, 6, 6, 0) }, formatBox, new Label { Text = "Type", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(14, 6, 6, 0) }, typeBox, new Label { Text = "Severity", ForeColor = SecondaryText, AutoSize = true, Padding = new Padding(14, 6, 6, 0) }, severityBox });
        customLayout.Controls.Add(optRow);
        FeedMeta MakeCustomMeta(string url) => new()
        {
            Id = "custom-" + Guid.NewGuid().ToString("N")[..8],
            Name = customNameBox.Text.Trim(),
            Url = url,
            License = "Custom feed (your responsibility)",
            EnabledByDefault = true,
            RefreshSec = 86400, MinRefreshSec = 300, MaxAgeSec = 259200,
            BaseSeverity = (severityBox.SelectedItem?.ToString() ?? "Medium").ToLowerInvariant(),
            Parser = formatBox.SelectedIndex == 1 ? "custom_csv" : "custom_lines",
        };
        var btnRow = new FlowLayoutPanel { AutoSize = true };
        var addUrlBtn = StyledButton("Add URL feed", Teal, Color.Black);
        addUrlBtn.Click += (_, _) =>
        {
            if (customNameBox.Text.Trim().Length == 0 || customUrlBox.Text.Trim().Length == 0) return;
            var meta = MakeCustomMeta(customUrlBox.Text.Trim());
            _customFeeds.Add(meta);
            SaveCustomFeeds();
            _ = _feedUpdater.UpdateAsync(meta, DateTimeOffset.Now, true);
            _nav.SelectedItem = "Threat feeds";
        };
        var chooseFileBtn = StyledButton("Choose local file…", Elevated, PrimaryText);
        chooseFileBtn.Click += (_, _) =>
        {
            if (customNameBox.Text.Trim().Length == 0)
            {
                MessageBox.Show("Give the feed a name first.", "PacketScope");
                return;
            }
            using var dialog = new OpenFileDialog { Title = "Choose a custom feed file" };
            if (dialog.ShowDialog() != DialogResult.OK) return;
            var meta = MakeCustomMeta("file://custom");
            _customFeeds.Add(meta);
            SaveCustomFeeds();
            try
            {
                var data = File.ReadAllBytes(dialog.FileName);
                _feedUpdater.ImportLocalCopy(meta, data, formatBox.SelectedIndex == 0 ? (typeBox.SelectedItem?.ToString() ?? "Domain").ToLowerInvariant() : null);
                MessageBox.Show($"Custom feed “{meta.Name}” imported.", "PacketScope");
            }
            catch (Exception ex) { MessageBox.Show($"Custom feed was not imported: {ex.Message}", "PacketScope"); }
            _nav.SelectedItem = "Threat feeds";
        };
        btnRow.Controls.AddRange(new Control[] { addUrlBtn, chooseFileBtn });
        customLayout.Controls.Add(btnRow);
        customCard.Controls.Add(customLayout);
        flow.Controls.Add(customCard);
        flow.Controls.Add(Body($"Feed content is untrusted data; indicator values are shown defanged and are never opened as links. Auth-Keys are stored in the Windows Credential Manager and never written to settings files or logs."));
        _content.Controls.Add(flow);
    }

    private Control FeedRow(FeedMeta meta)
    {
        var state = _feedUpdater.StateFor(meta);
        var panel = new Panel { BackColor = Elevated, Padding = new Padding(12), Margin = new Padding(0, 0, 0, 10), Width = 940, AutoSize = true };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true };
        var top = new FlowLayoutPanel { AutoSize = true };
        var toggle = new CheckBox { Checked = state.Enabled, AutoSize = true };
        toggle.CheckedChanged += (_, _) => { _feedUpdater.SetEnabled(toggle.Checked, meta); };
        top.Controls.Add(toggle);
        top.Controls.Add(new Label { Text = meta.Name, Font = new Font("Segoe UI", 11, FontStyle.Bold), ForeColor = PrimaryText, AutoSize = true, Padding = new Padding(4, 4, 10, 0) });
        var updateBtn = StyledButton("Update now", Elevated, PrimaryText);
        bool allowed = DateTimeOffset.Now >= _feedUpdater.NextAllowedUpdate(meta) || state.LastAttemptAt == null;
        updateBtn.Enabled = state.Enabled && allowed;
        updateBtn.Click += async (_, _) =>
        {
            updateBtn.Enabled = false;
            var (_, outcome) = await _feedUpdater.UpdateAsync(meta, DateTimeOffset.Now, true);
            updateBtn.Text = outcome.ToString();
            _nav.SelectedItem = "Threat feeds";
        };
        top.Controls.Add(updateBtn);
        layout.Controls.Add(top);
        string status = !state.Enabled ? "Off"
            : state.LastSuccessAt is not { } s ? "Never downloaded — threat matching will say it didn't run"
            : $"Updated {s} · {state.IndicatorCount} indicators{(state.NewestIndicatorAt != null ? $" · newest entry {state.NewestIndicatorAt}" : "")}{(state.IsStale(meta, DateTimeOffset.Now) ? " · STALE, using the last good copy" : "")}";
        layout.Controls.Add(Body(status, 9, state.IsStale(meta, DateTimeOffset.Now) && state.Enabled ? Amber : SecondaryText));
        if (state.LastError != null) layout.Controls.Add(Body(state.LastError, 9, Amber));
        layout.Controls.Add(Body($"License: {meta.License} · Refresh: {(meta.RefreshSec >= 86400 ? "daily" : "hourly")} · Base severity: {meta.BaseSeverity}{(meta.Attribution != null ? $"\n{meta.Attribution}" : "")}{(state.FeedCopyright != null ? $"\nFeed data: {state.FeedCopyright} · Terms: {state.FeedTerms}" : "")}", 8.5f));
        if (meta.RequiresKey)
        {
            var keyRow = new FlowLayoutPanel { AutoSize = true };
            var keyBox = new TextBox { Width = 300, BackColor = PanelBg, ForeColor = PrimaryText, UseSystemPasswordChar = true };
            var saveKey = StyledButton("Save key", Elevated, PrimaryText);
            saveKey.Click += (_, _) => { _feedUpdater.KeyStore.Set(keyBox.Text, meta.Id); keyBox.Clear(); MessageBox.Show("Key saved in the Windows Credential Manager.", "PacketScope"); };
            keyRow.Controls.AddRange(new Control[] { keyBox, saveKey });
            layout.Controls.Add(keyRow);
            layout.Controls.Add(Body("Free for non-profit use; commercial use may need a paid subscription. Get an Auth-Key at auth.abuse.ch. The key is stored only in the Windows Credential Manager.", 8.5f, Amber));
        }
        panel.Controls.Add(layout);
        return panel;
    }

    // ---------------- Exports ----------------

    private void ExportRawCapture()
    {
        if (_sessionDir == null) return;
        using var dialog = new SaveFileDialog { Title = "Export raw capture", FileName = "traffic.pcap", Filter = "PCAP files (*.pcap)|*.pcap" };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        try { File.Copy(Path.Combine(_sessionDir, "traffic.pcap"), dialog.FileName, true); }
        catch (Exception ex) { MessageBox.Show($"Raw export failed: {ex.Message}", "PacketScope"); }
    }

    private void ExportEvidencePackets(List<int> frames)
    {
        if (_sessionDir == null || frames.Count == 0) return;
        using var dialog = new SaveFileDialog { Title = "Export these packets", FileName = "evidence-packets.pcap", Filter = "PCAP files (*.pcap)|*.pcap" };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        try { PacketAnalyzer.ExportPacketSubset(Path.Combine(_sessionDir, "traffic.pcap"), new HashSet<int>(frames), dialog.FileName); }
        catch (Exception ex) { MessageBox.Show($"Packet export failed: {ex.Message}", "PacketScope"); }
    }

    private void ExportSupportReport()
    {
        if (_report == null || _context == null) return;
        using var preview = new SupportPreviewDialog(_report, _context, _threatIntel);
        preview.ShowDialog(this);
    }
}

// Live plain-text preview with the four privacy switches, then Save.
public sealed class SupportPreviewDialog : Form
{
    private readonly CaptureReport _report;
    private readonly SessionContext _ctx;
    private readonly ThreatIntelSummary? _intel;
    private readonly SupportOptions _options = new();
    private readonly RichTextBox _preview = new();
    private readonly CheckBox _ips = new() { Text = "IP addresses" };
    private readonly CheckBox _domains = new() { Text = "Domain names" };
    private readonly CheckBox _apps = new() { Text = "App / process names", Checked = true };
    private readonly CheckBox _notes = new() { Text = "Your notes & symptoms" };

    public SupportPreviewDialog(CaptureReport report, SessionContext ctx, ThreatIntelSummary? intel)
    {
        _report = report; _ctx = ctx; _intel = intel;
        Text = "Share with support";
        Size = new Size(860, 660);
        MinimumSize = new Size(720, 540);
        BackColor = Color.FromArgb(9, 13, 22);
        ForeColor = Color.FromArgb(237, 245, 252);
        Font = new Font("Segoe UI", 9.5f);
        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(14) };
        top.Controls.Add(new Label { Text = "Share with support", Font = new Font("Segoe UI", 15, FontStyle.Bold), AutoSize = true, Width = 820 });
        top.Controls.Add(new Label { Text = "Plain-text preview generated from structured facts. No raw payloads and no PCAP are included. This is selective redaction, not guaranteed anonymization — review the preview, especially any free-text notes you opt in.", ForeColor = Color.FromArgb(155, 176, 199), AutoSize = true, MaximumSize = new Size(820, 0) });
        foreach (var box in new[] { _ips, _domains, _apps, _notes })
        {
            box.AutoSize = true;
            box.Padding = new Padding(0, 4, 18, 0);
            box.CheckedChanged += (_, _) => RefreshPreview();
            top.Controls.Add(box);
        }
        top.Controls.Add(new Label { Text = "Identifiers are redacted across the whole report according to these controls, even inside notes you include. Turning notes on does not turn addresses or domains on.", ForeColor = Color.FromArgb(255, 189, 97), AutoSize = true, MaximumSize = new Size(820, 0) });
        _preview.Dock = DockStyle.Fill;
        _preview.ReadOnly = true;
        _preview.BackColor = Color.FromArgb(19, 26, 37);
        _preview.ForeColor = Color.FromArgb(237, 245, 252);
        _preview.Font = new Font("Consolas", 9.5f);
        _preview.BorderStyle = BorderStyle.FixedSingle;
        var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(14), FlowDirection = FlowDirection.LeftToRight };
        var save = new Button { Text = "Save support report…", BackColor = Color.FromArgb(71, 224, 196), ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 10, FontStyle.Bold), AutoSize = true, Height = 40 };
        save.Click += (_, _) =>
        {
            using var dialog = new SaveFileDialog { Title = "Save support report", FileName = "PacketScope-support-report.txt", Filter = "Text files (*.txt)|*.txt" };
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            try { File.WriteAllText(dialog.FileName, _preview.Text); Close(); }
            catch (Exception ex) { MessageBox.Show($"Save failed: {ex.Message}", "PacketScope"); }
        };
        var done = new Button { Text = "Done", FlatStyle = FlatStyle.Flat, AutoSize = true, Height = 40 };
        done.Click += (_, _) => Close();
        bottom.Controls.AddRange(new Control[] { save, done });
        Controls.Add(_preview);
        Controls.Add(bottom);
        Controls.Add(top);
        RefreshPreview();
    }

    private void RefreshPreview()
    {
        _options.IncludeIPs = _ips.Checked;
        _options.IncludeDomains = _domains.Checked;
        _options.IncludeApps = _apps.Checked;
        _options.IncludeNotes = _notes.Checked;
        _preview.Text = SupportReportText.Generate(_report, _ctx, _intel, _options);
    }
}
