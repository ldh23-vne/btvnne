using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AesApp;

// ======================= ĐIỂM VÀO =======================
static class Program
{
    [DllImport("kernel32.dll")] static extern bool FreeConsole();

    [STAThread]
    static void Main(string[] args)
    {
        // dotnet run -- console  => giao diện dòng lệnh
        if (args.Length > 0 && args[0].Equals("console", StringComparison.OrdinalIgnoreCase))
        {
            ConsoleApp.Run();
            return;
        }
        FreeConsole(); // ẩn cửa sổ console khi chạy giao diện form
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

// ======================= LÕI AES (dùng chung console + form) =======================
static class AesCore
{
    const int Buf = 4 * 1024 * 1024; // khối đọc 4 MB: RAM luôn ~4 MB dù file nặng nhiều GB

    // 1. Sinh khoá AES-256 = 32 byte ngẫu nhiên an toàn mật mã
    public static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    // 2. Lưu khoá ra file (Base64)
    public static void SaveKey(string path, byte[] key) =>
        File.WriteAllText(path, Convert.ToBase64String(key));

    // 3. Nạp khoá từ file
    public static byte[] LoadKey(string path)
    {
        var key = Convert.FromBase64String(File.ReadAllText(path).Trim());
        if (key.Length is not (16 or 24 or 32))
            throw new InvalidDataException($"Khoá không hợp lệ: {key.Length} byte (cần 16/24/32).");
        return key;
    }

    // 4. Mã hoá / giải mã văn bản: Base64( IV[16] || bản mã )
    public static string EncryptText(string text, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        var iv = aes.IV;
        var cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(text), iv);
        return Convert.ToBase64String(iv.Concat(cipher).ToArray());
    }

    public static string DecryptText(string base64, byte[] key)
    {
        var all = Convert.FromBase64String(base64.Trim());
        if (all.Length < 32) throw new InvalidDataException("Bản mã quá ngắn hoặc sai định dạng.");
        using var aes = Aes.Create();
        aes.Key = key;
        var plain = aes.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16));
        return Encoding.UTF8.GetString(plain);
    }

    // 5. Mã hoá file theo luồng: [IV 16 byte][bản mã]
    public static void EncryptFile(string src, string dst, byte[] key, IProgress<double>? p = null)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        fout.Write(aes.IV, 0, 16);
        using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
        Pump(fin, cs, fin, p);
    }

    public static void DecryptFile(string src, string dst, byte[] key, IProgress<double>? p = null)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        var iv = new byte[16];
        fin.ReadExactly(iv);
        aes.IV = iv;
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
        Pump(cs, fout, fin, p);
    }

    static void Pump(Stream from, Stream to, Stream progressOn, IProgress<double>? p)
    {
        var buf = new byte[Buf];
        double total = Math.Max(1, progressOn.Length);
        int n;
        while ((n = from.Read(buf, 0, buf.Length)) > 0)
        {
            to.Write(buf, 0, n);
            p?.Report(progressOn.Position / total);
        }
        p?.Report(1);
    }

    // So sánh 2 file theo từng byte. Trả về (giống nhau?, vị trí byte khác đầu tiên)
    public static (bool Same, long FirstDiff) CompareFiles(string a, string b)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        if (fa.Length != fb.Length) return (false, Math.Min(fa.Length, fb.Length));
        var ba = new byte[Buf];
        var bb = new byte[Buf];
        long pos = 0;
        while (true)
        {
            int na = fa.ReadAtLeast(ba, ba.Length, false);
            int nb = fb.ReadAtLeast(bb, bb.Length, false);
            if (na != nb) return (false, pos + Math.Min(na, nb));
            if (na == 0) return (true, -1);
            var sa = ba.AsSpan(0, na);
            var sb = bb.AsSpan(0, nb);
            if (!sa.SequenceEqual(sb)) return (false, pos + sa.CommonPrefixLength(sb));
            pos += na;
        }
    }

    // Tạo file thử nghiệm kích thước sizeMB (MB)
    public static void MakeTestFile(string path, long sizeMB, IProgress<double>? p = null)
    {
        var block = RandomNumberGenerator.GetBytes(1024 * 1024);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        for (long i = 0; i < sizeMB; i++)
        {
            BitConverter.TryWriteBytes(block.AsSpan(0, 8), i); // mỗi khối khác nhau một chút
            fs.Write(block, 0, block.Length);
            if (i % 16 == 0) p?.Report((double)i / sizeMB);
        }
        p?.Report(1);
    }

    // Chạy trọn bộ: mã hoá -> giải mã -> so sánh byte, đo thời gian
    public static string Benchmark(string src, byte[] key, IProgress<double>? p = null)
    {
        var enc = src + ".enc";
        var dec = src + ".dec";
        double mb = new FileInfo(src).Length / 1048576.0;

        var sw = Stopwatch.StartNew();
        EncryptFile(src, enc, key, p);
        var tE = sw.Elapsed;

        sw.Restart();
        DecryptFile(enc, dec, key, p);
        var tD = sw.Elapsed;

        sw.Restart();
        var (same, pos) = CompareFiles(src, dec);
        var tC = sw.Elapsed;

        var nl = Environment.NewLine;
        return $"Kích thước file nguồn : {mb:F2} MB" + nl +
               $"Thời gian mã hoá      : {tE.TotalSeconds:F3} s  ({mb / tE.TotalSeconds:F1} MB/s)" + nl +
               $"Thời gian giải mã     : {tD.TotalSeconds:F3} s  ({mb / tD.TotalSeconds:F1} MB/s)" + nl +
               $"Thời gian so sánh byte: {tC.TotalSeconds:F3} s" + nl +
               (same ? "Kết quả so sánh      : GIỐNG NHAU 100% từng byte (file giải mã == file nguồn)"
                     : $"Kết quả so sánh      : KHÁC NHAU tại byte thứ {pos}");
    }
}

// ======================= GIAO DIỆN CONSOLE =======================
static class ConsoleApp
{
    static byte[]? key;
    static byte[] Key => key ?? throw new InvalidOperationException("Chưa có khoá. Chọn chức năng 1 hoặc 3 trước.");

    static string Ask(string q)
    {
        Console.Write(q);
        return (Console.ReadLine() ?? "").Trim().Trim('"');
    }

    static IProgress<double> Prog() => new Progress<double>(v => Console.Write($"\r  Tiến độ: {v:P0}   "));

    public static void Run()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("========== AES-256 (CBC/PKCS7) - CONSOLE ==========");
            Console.WriteLine(" 1. Sinh khoá AES          2. Lưu khoá ra file");
            Console.WriteLine(" 3. Nạp khoá từ file       4. Mã hoá văn bản");
            Console.WriteLine(" 5. Giải mã văn bản        6. Mã hoá file");
            Console.WriteLine(" 7. Giải mã file           8. Tạo file test (MB)");
            Console.WriteLine(" 9. Benchmark (mã hoá + giải mã + so sánh byte)");
            Console.WriteLine(" 0. Thoát");
            var c = Ask("Chọn: ");
            if (c == "0") return;
            try
            {
                switch (c)
                {
                    case "1":
                        key = AesCore.NewKey();
                        Console.WriteLine("Khoá mới (Base64): " + Convert.ToBase64String(key));
                        break;
                    case "2":
                        AesCore.SaveKey(Ask("Đường dẫn lưu khoá (vd aes.key): "), Key);
                        Console.WriteLine("Đã lưu khoá.");
                        break;
                    case "3":
                        key = AesCore.LoadKey(Ask("Đường dẫn file khoá: "));
                        Console.WriteLine($"Đã nạp khoá {key.Length * 8} bit.");
                        break;
                    case "4":
                        Console.WriteLine("Bản mã: " + AesCore.EncryptText(Ask("Nhập văn bản: "), Key));
                        break;
                    case "5":
                        Console.WriteLine("Bản rõ: " + AesCore.DecryptText(Ask("Nhập bản mã Base64: "), Key));
                        break;
                    case "6":
                        {
                            var src = Ask("File cần mã hoá: ");
                            AesCore.EncryptFile(src, src + ".enc", Key, Prog());
                            Console.WriteLine($"\nĐã tạo {src}.enc");
                            break;
                        }
                    case "7":
                        {
                            var src = Ask("File .enc cần giải mã: ");
                            var dst = (src.EndsWith(".enc") ? src[..^4] : src) + ".dec";
                            AesCore.DecryptFile(src, dst, Key, Prog());
                            Console.WriteLine($"\nĐã tạo {dst}");
                            break;
                        }
                    case "8":
                        {
                            var path = Ask("Đường dẫn file test (vd test.bin): ");
                            var mb = long.Parse(Ask("Kích thước (MB): "));
                            AesCore.MakeTestFile(path, mb, Prog());
                            Console.WriteLine("\nĐã tạo file test.");
                            break;
                        }
                    case "9":
                        {
                            var src = Ask("File nguồn: ");
                            var res = AesCore.Benchmark(src, Key, Prog());
                            Console.WriteLine();
                            Console.WriteLine(res);
                            break;
                        }
                    default:
                        Console.WriteLine("Lựa chọn không hợp lệ.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nLỖI: " + ex.Message);
            }
        }
    }
}

// ======================= GIAO DIỆN FORM =======================
sealed class MainForm : Form
{
    static readonly Color Ink = Color.FromArgb(15, 23, 42);
    static readonly Color Accent = Color.FromArgb(20, 184, 166);
    static readonly Color Bg = Color.FromArgb(241, 245, 249);
    static readonly Color Blue = Color.FromArgb(59, 130, 246);
    static readonly Color Amber = Color.FromArgb(245, 158, 11);
    static readonly Color Rose = Color.FromArgb(244, 63, 94);
    static readonly Color Muted = Color.FromArgb(100, 116, 139);

    byte[]? key;
    bool busy;
    readonly List<Button> buttons = new();
    readonly TextBox txtKey = new() { ReadOnly = true, Width = 560, Font = new Font("Consolas", 10f), BorderStyle = BorderStyle.FixedSingle };
    readonly TextBox txtIn = Multi(330, 70);
    readonly TextBox txtOut = Multi(330, 70);
    readonly TextBox txtFile = new() { Width = 470, BorderStyle = BorderStyle.FixedSingle };
    readonly NumericUpDown numMb = new() { Minimum = 1, Maximum = 50000, Value = 1024, Width = 80 };
    readonly ProgressBar bar = new() { Dock = DockStyle.Fill, Height = 16, Style = ProgressBarStyle.Continuous };
    readonly TextBox log = new()
    {
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Both,
        WordWrap = false,
        Font = new Font("Consolas", 10f),
        BackColor = Color.White,
        BorderStyle = BorderStyle.FixedSingle
    };

    static TextBox Multi(int w, int h) => new()
    {
        Multiline = true,
        Width = w,
        Height = h,
        ScrollBars = ScrollBars.Vertical,
        Font = new Font("Consolas", 10f),
        BorderStyle = BorderStyle.FixedSingle
    };

    public MainForm()
    {
        Text = "AES-256 Lab - An toàn và bảo mật thông tin";
        Size = new Size(1120, 800);
        MinimumSize = new Size(960, 640);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);
        BackColor = Bg;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(0, 0, 0, 12) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        void Row(Control c, bool fill = false)
        {
            c.Dock = DockStyle.Fill;
            root.RowStyles.Add(fill ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
            root.RowCount = root.RowStyles.Count;
            root.Controls.Add(c, 0, root.RowStyles.Count - 1);
        }

        Row(new Label
        {
            Text = "   AES-256 LAB   ·   Mã hoá đối xứng CBC / PKCS7",
            Height = 64,
            AutoSize = false,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = Ink,
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 16f)
        });

        Row(Sec("1. QUẢN LÝ KHOÁ"));
        Row(Flow(
            Btn("Sinh khoá AES-256", Accent, () => { key = AesCore.NewKey(); ShowKey(); Log("Đã sinh khoá AES-256 mới (32 byte)."); }),
            Btn("Lưu khoá ra file", Blue, SaveKeyFile),
            Btn("Nạp khoá từ file", Blue, LoadKeyFile),
            txtKey));

        Row(Sec("2. MÃ HOÁ VĂN BẢN"));
        Row(Flow(
            Lbl("Bản rõ:"), txtIn,
            Btn("Mã hoá  ➜", Accent, () => { txtOut.Text = AesCore.EncryptText(txtIn.Text, Need()); Log("Đã mã hoá văn bản (IV ngẫu nhiên nên mỗi lần một kết quả khác)."); }),
            Btn("◀  Giải mã", Amber, () => { txtIn.Text = AesCore.DecryptText(txtOut.Text, Need()); Log("Đã giải mã văn bản."); }),
            Lbl("Bản mã (Base64):"), txtOut));

        Row(Sec("3. MÃ HOÁ FILE (file lớn hàng GB, đo thời gian, so sánh byte)"));
        Row(Flow(
            Lbl("File nguồn:"), txtFile,
            Btn("Chọn file...", Blue, BrowseFile),
            Lbl("Tạo file test (MB):"), numMb,
            Btn("Tạo file test", Muted, MakeTest),
            Btn("Mã hoá file", Accent, EncFile),
            Btn("Giải mã file", Amber, DecFile),
            Btn("So sánh byte", Blue, CmpFile),
            Btn("BENCHMARK ĐẦY ĐỦ", Rose, Bench)));

        Row(bar);
        Row(log, true);

        Controls.Add(root);
        Log("Sẵn sàng. Bắt đầu bằng cách sinh khoá hoặc nạp khoá từ file.");
    }

    // ----- hàm dựng giao diện -----
    static Label Sec(string t) => new()
    {
        Text = t,
        AutoSize = true,
        ForeColor = Ink,
        Font = new Font("Segoe UI Semibold", 10.5f),
        Margin = new Padding(16, 12, 0, 0)
    };

    static Label Lbl(string t) => new() { Text = t, AutoSize = true, ForeColor = Muted, Margin = new Padding(8, 9, 2, 0) };

    static FlowLayoutPanel Flow(params Control[] cs)
    {
        var f = new FlowLayoutPanel { AutoSize = true, WrapContents = true, Padding = new Padding(12, 4, 12, 0) };
        f.Controls.AddRange(cs);
        return f;
    }

    Button Btn(string text, Color color, Action a)
    {
        var b = new Button
        {
            Text = text,
            AutoSize = true,
            FlatStyle = FlatStyle.Flat,
            BackColor = color,
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 9.5f),
            Padding = new Padding(8, 3, 8, 3),
            Margin = new Padding(4),
            Cursor = Cursors.Hand
        };
        b.FlatAppearance.BorderSize = 0;
        b.Click += (_, _) =>
        {
            try { a(); }
            catch (Exception ex) { Log("LỖI: " + ex.Message); }
        };
        buttons.Add(b);
        return b;
    }

    // ----- tiện ích -----
    void Log(string s) => log.AppendText($"[{DateTime.Now:HH:mm:ss}] {s}{Environment.NewLine}");

    void ShowKey() => txtKey.Text = key == null ? "" : Convert.ToBase64String(key);

    byte[] Need() => key ?? throw new InvalidOperationException("Chưa có khoá. Hãy sinh khoá hoặc nạp khoá từ file.");

    string Src()
    {
        var s = txtFile.Text.Trim().Trim('"');
        if (!File.Exists(s)) throw new FileNotFoundException("Chưa chọn file nguồn hợp lệ.");
        return s;
    }

    void SaveKeyFile()
    {
        var k = Need();
        using var d = new SaveFileDialog { Filter = "Khoá AES (*.key)|*.key|Tất cả|*.*", FileName = "aes.key" };
        if (d.ShowDialog() != DialogResult.OK) return;
        AesCore.SaveKey(d.FileName, k);
        Log("Đã lưu khoá: " + d.FileName);
    }

    void LoadKeyFile()
    {
        using var d = new OpenFileDialog { Filter = "Khoá AES (*.key)|*.key|Tất cả|*.*" };
        if (d.ShowDialog() != DialogResult.OK) return;
        key = AesCore.LoadKey(d.FileName);
        ShowKey();
        Log($"Đã nạp khoá {key.Length * 8} bit từ: {d.FileName}");
    }

    void BrowseFile()
    {
        using var d = new OpenFileDialog { Filter = "Tất cả|*.*" };
        if (d.ShowDialog() == DialogResult.OK) txtFile.Text = d.FileName;
    }

    void MakeTest()
    {
        using var d = new SaveFileDialog { Filter = "File nhị phân (*.bin)|*.bin", FileName = $"test_{numMb.Value}MB.bin" };
        if (d.ShowDialog() != DialogResult.OK) return;
        var path = d.FileName;
        var mb = (long)numMb.Value;
        txtFile.Text = path;
        Job("Tạo file test", p =>
        {
            var sw = Stopwatch.StartNew();
            AesCore.MakeTestFile(path, mb, p);
            return $"Đã tạo {path} ({mb} MB) trong {sw.Elapsed.TotalSeconds:F2} s";
        });
    }

    void EncFile()
    {
        var k = Need();
        var src = Src();
        Job("Mã hoá file", p =>
        {
            var sw = Stopwatch.StartNew();
            AesCore.EncryptFile(src, src + ".enc", k, p);
            var mb = new FileInfo(src).Length / 1048576.0;
            return $"{src}.enc | {sw.Elapsed.TotalSeconds:F3} s | {mb / sw.Elapsed.TotalSeconds:F1} MB/s";
        });
    }

    void DecFile()
    {
        var k = Need();
        var src = Src();
        var inp = src.EndsWith(".enc", StringComparison.OrdinalIgnoreCase) ? src : src + ".enc";
        var dst = (inp.EndsWith(".enc", StringComparison.OrdinalIgnoreCase) ? inp[..^4] : inp) + ".dec";
        Job("Giải mã file", p =>
        {
            var sw = Stopwatch.StartNew();
            AesCore.DecryptFile(inp, dst, k, p);
            var mb = new FileInfo(dst).Length / 1048576.0;
            return $"{dst} | {sw.Elapsed.TotalSeconds:F3} s | {mb / sw.Elapsed.TotalSeconds:F1} MB/s";
        });
    }

    void CmpFile()
    {
        var src = Src();
        var dec = src + ".dec";
        if (!File.Exists(dec)) throw new FileNotFoundException("Chưa có file giải mã: " + dec);
        Job("So sánh byte", p =>
        {
            var sw = Stopwatch.StartNew();
            var (same, pos) = AesCore.CompareFiles(src, dec);
            return (same ? "GIỐNG NHAU 100% từng byte" : $"KHÁC NHAU tại byte thứ {pos}") + $" | {sw.Elapsed.TotalSeconds:F3} s";
        });
    }

    void Bench()
    {
        var k = Need();
        var src = Src();
        Job("Benchmark", p => Environment.NewLine + AesCore.Benchmark(src, k, p));
    }

    // chạy công việc nặng ở luồng nền, cập nhật thanh tiến trình
    async void Job(string title, Func<IProgress<double>, string> work)
    {
        if (busy) return;
        busy = true;
        foreach (var b in buttons) b.Enabled = false;
        bar.Value = 0;
        var prog = new Progress<double>(v => bar.Value = (int)Math.Clamp(v * 100, 0, 100));
        try
        {
            var res = await Task.Run(() => work(prog));
            bar.Value = 100;
            Log($"[{title}] {res}");
        }
        catch (Exception ex)
        {
            Log($"[{title}] LỖI: {ex.Message}");
        }
        finally
        {
            busy = false;
            foreach (var b in buttons) b.Enabled = true;
        }
    }
}