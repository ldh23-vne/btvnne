using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RsaApp;

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

// ======================= PHÂN TÍCH PEM / ASN.1 DER =======================
static class PemViewer
{
    public static string Dump(string pem)
    {
        var lines = pem.Replace("\r", "").Split('\n').Select(l => l.Trim()).ToList();
        var header = lines.FirstOrDefault(l => l.StartsWith("-----BEGIN")) ?? "(không có tiêu đề)";
        var footer = lines.FirstOrDefault(l => l.StartsWith("-----END")) ?? "(không có)";
        var b64 = string.Concat(lines.Where(l => l.Length > 0 && !l.StartsWith("-----")));
        var der = Convert.FromBase64String(b64);

        var sb = new StringBuilder();
        sb.AppendLine("CẤU TRÚC FILE PEM");
        sb.AppendLine($"  Dòng đầu : {header}");
        sb.AppendLine($"  Dòng cuối: {footer}");
        sb.AppendLine($"  Phần giữa: {b64.Length} ký tự Base64 (64 ký tự/dòng; 4 ký tự Base64 = 3 byte) => {der.Length} byte DER");
        sb.AppendLine();
        sb.AppendLine("MÃ HOÁ DER = các khối TLV: Tag (1 byte) - Length - Value");
        sb.AppendLine("  Tag: 30=SEQUENCE, 02=INTEGER, 03=BIT STRING, 04=OCTET STRING, 05=NULL, 06=OID");
        sb.AppendLine("  Length: < 0x80 là độ dài thật; 81 xx / 82 xx xx = độ dài nằm ở 1 / 2 byte sau");
        sb.AppendLine();
        sb.AppendLine("  Hex 16 byte đầu: " + Convert.ToHexString(der.AsSpan(0, Math.Min(16, der.Length))));
        sb.AppendLine();

        string[] names = header.Contains("PUBLIC")
            ? new[] { "n (modulus)", "e (publicExponent)" }
            : new[] { "version", "n (modulus)", "e (publicExponent)", "d (privateExponent)", "p (prime1)", "q (prime2)", "dP = d mod (p-1)", "dQ = d mod (q-1)", "qInv = q^-1 mod p" };

        sb.AppendLine("CÂY ASN.1");
        Parse(der, 0, der.Length, 0, sb, names);
        return sb.ToString();
    }

    static void Parse(byte[] d, int start, int end, int depth, StringBuilder sb, string[] names)
    {
        int p = start, idx = 0;
        while (p < end)
        {
            int tagPos = p;
            byte tag = d[p++];
            int len = d[p++];
            if (len >= 0x80)
            {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
            }
            int hdr = p - tagPos;
            var ind = new string(' ', depth * 2 + 2);
            var name = tag switch
            {
                0x30 => "SEQUENCE",
                0x02 => "INTEGER",
                0x03 => "BIT STRING",
                0x04 => "OCTET STRING",
                0x05 => "NULL",
                0x06 => "OBJECT IDENTIFIER",
                _ => $"TAG 0x{tag:X2}"
            };
            sb.Append($"{ind}[offset {tagPos,4}] {tag:X2} {name} (header {hdr} byte, nội dung {len} byte)");

            if (tag == 0x30)
            {
                sb.AppendLine();
                Parse(d, p, p + len, depth + 1, sb, names);
            }
            else if (tag == 0x02)
            {
                var label = idx < names.Length ? names[idx] : "";
                idx++;
                sb.AppendLine($" => {label}: {Short(d, p, len)}");
            }
            else if (tag == 0x06)
            {
                sb.AppendLine(" = " + Oid(d, p, len));
            }
            else if (tag == 0x03 && len > 1 && d[p + 1] == 0x30)
            {
                sb.AppendLine($" (byte đầu = {d[p]:X2}: số bit đệm) chứa DER lồng bên trong");
                Parse(d, p + 1, p + len, depth + 1, sb, names);
            }
            else if (tag == 0x04 && len > 0 && d[p] == 0x30)
            {
                sb.AppendLine(" chứa DER lồng bên trong");
                Parse(d, p, p + len, depth + 1, sb, names);
            }
            else sb.AppendLine();

            p += len;
        }
    }

    static string Short(byte[] d, int p, int len)
    {
        var hex = Convert.ToHexString(d, p, Math.Min(len, 8));
        return len > 8 ? $"{hex}... ({len} byte{(d[p] == 0 ? ", byte đầu 00 để số luôn dương" : "")})" : hex;
    }

    static string Oid(byte[] d, int p, int len)
    {
        var parts = new List<string>();
        long v = 0;
        for (int i = 0; i < len; i++)
        {
            byte b = d[p + i];
            if (i == 0)
            {
                parts.Add((b / 40).ToString());
                parts.Add((b % 40).ToString());
                continue;
            }
            v = (v << 7) | (long)(b & 0x7F);
            if ((b & 0x80) == 0)
            {
                parts.Add(v.ToString());
                v = 0;
            }
        }
        var s = string.Join('.', parts);
        return s == "1.2.840.113549.1.1.1" ? s + " (rsaEncryption)" : s;
    }
}

// ======================= GIAO DIỆN =======================
sealed class MainForm : Form
{
    static readonly Color SideBg = Color.FromArgb(15, 23, 42);
    static readonly Color Accent = Color.FromArgb(20, 184, 166);
    static readonly Color Bg = Color.FromArgb(241, 245, 249);
    static readonly Color Ink = Color.FromArgb(15, 23, 42);
    static readonly Color Muted = Color.FromArgb(100, 116, 139);
    static readonly Color Blue = Color.FromArgb(59, 130, 246);
    static readonly Color Amber = Color.FromArgb(245, 158, 11);
    static readonly Color Rose = Color.FromArgb(244, 63, 94);

    RSA? gen, priv;
    readonly Panel content = new() { Dock = DockStyle.Fill, BackColor = Bg };
    readonly FlowLayoutPanel side = new()
    {
        Dock = DockStyle.Left,
        Width = 230,
        FlowDirection = FlowDirection.TopDown,
        WrapContents = false,
        BackColor = SideBg
    };
    readonly List<(Button Btn, Control Page)> nav = new();

    public MainForm()
    {
        Text = "RSA · SHA-256 · Chữ ký số - An toàn và bảo mật thông tin";
        Size = new Size(1220, 820);
        MinimumSize = new Size(1000, 660);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);
        BackColor = Bg;

        Controls.Add(content);
        Controls.Add(side);

        side.Controls.Add(new Label
        {
            Text = "  RSA LAB",
            Width = 230,
            Height = 70,
            AutoSize = false,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Accent,
            Font = new Font("Segoe UI Semibold", 17f),
            Margin = Padding.Empty
        });

        AddPage("1 · Khoá & PEM", BuildKeyPage());
        AddPage("2 · Mã hoá / Giải mã", BuildCryptoPage());
        AddPage("3 · Tốc độ RSA", BuildSpeedPage());
        AddPage("4 · Băm SHA-256", BuildHashPage());
        AddPage("5 · Chữ ký số", BuildSignPage());

        ShowPage(nav[0].Btn);
    }

    // ---------- khung điều hướng ----------
    void AddPage(string title, Control page)
    {
        page.Dock = DockStyle.Fill;
        page.Visible = false;
        content.Controls.Add(page);
        var b = new Button
        {
            Text = "   " + title,
            Width = 230,
            Height = 50,
            FlatStyle = FlatStyle.Flat,
            ForeColor = Color.White,
            BackColor = SideBg,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI Semibold", 10.5f),
            Margin = Padding.Empty,
            Cursor = Cursors.Hand
        };
        b.FlatAppearance.BorderSize = 0;
        b.Click += (_, _) => ShowPage(b);
        nav.Add((b, page));
        side.Controls.Add(b);
    }

    void ShowPage(Button selected)
    {
        foreach (var (btn, pg) in nav)
        {
            bool on = btn == selected;
            pg.Visible = on;
            btn.BackColor = on ? Accent : SideBg;
        }
    }

    // ---------- hàm dựng giao diện ----------
    static TableLayoutPanel Page(string title, string desc, params Control[] rows)
    {
        var t = new TableLayoutPanel { ColumnCount = 1, Dock = DockStyle.Fill, Padding = new Padding(22, 16, 22, 16), BackColor = Bg };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        void Add(Control c, bool fill)
        {
            c.Dock = DockStyle.Fill;
            t.RowStyles.Add(fill ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
            t.RowCount = t.RowStyles.Count;
            t.Controls.Add(c, 0, t.RowStyles.Count - 1);
        }
        Add(new Label { Text = title, AutoSize = true, ForeColor = Ink, Font = new Font("Segoe UI Semibold", 17f) }, false);
        Add(new Label { Text = desc, AutoSize = true, MaximumSize = new Size(920, 0), ForeColor = Muted, Margin = new Padding(3, 0, 3, 8) }, false);
        for (int i = 0; i < rows.Length; i++) Add(rows[i], i == rows.Length - 1);
        return t;
    }

    static TextBox Out() => new()
    {
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Both,
        WordWrap = false,
        Font = new Font("Consolas", 10f),
        BackColor = Color.White,
        BorderStyle = BorderStyle.FixedSingle
    };

    static TextBox Input(int h) => new()
    {
        Multiline = true,
        Height = h,
        ScrollBars = ScrollBars.Vertical,
        Font = new Font("Consolas", 10f),
        BorderStyle = BorderStyle.FixedSingle
    };

    static Label Lbl(string t) => new() { Text = t, AutoSize = true, ForeColor = Muted, Margin = new Padding(4, 9, 4, 0) };

    static FlowLayoutPanel Bar(params Control[] cs)
    {
        var f = new FlowLayoutPanel { AutoSize = true, WrapContents = true, Padding = new Padding(0, 6, 0, 6) };
        f.Controls.AddRange(cs);
        return f;
    }

    static Button MakeBtn(string text, Color color)
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
        return b;
    }

    static Button Btn(string text, Color color, Action a, TextBox log)
    {
        var b = MakeBtn(text, color);
        b.Click += (_, _) =>
        {
            try { a(); }
            catch (Exception ex) { Say(log, "LỖI: " + ex.Message); }
        };
        return b;
    }

    static Button BtnAsync(string text, Color color, Func<Task> a, TextBox log)
    {
        var b = MakeBtn(text, color);
        b.Click += async (_, _) =>
        {
            b.Enabled = false;
            try { await a(); }
            catch (Exception ex) { Say(log, "LỖI: " + ex.Message); }
            finally { b.Enabled = true; }
        };
        return b;
    }

    static void Say(TextBox t, string s) => t.AppendText(s + Environment.NewLine);

    static string? OpenPath(string filter)
    {
        using var d = new OpenFileDialog { Filter = filter };
        return d.ShowDialog() == DialogResult.OK ? d.FileName : null;
    }

    static string? SavePath(string name, string filter)
    {
        using var d = new SaveFileDialog { Filter = filter, FileName = name };
        return d.ShowDialog() == DialogResult.OK ? d.FileName : null;
    }

    const string PemFilter = "Tệp PEM (*.pem)|*.pem|Văn bản (*.txt)|*.txt|Tất cả|*.*";

    static int BitLen(byte[] b) => (int)new BigInteger(b, true, true).GetBitLength();

    static string Wrap(string s, int w) =>
        string.Join(Environment.NewLine, Enumerable.Range(0, (s.Length + w - 1) / w).Select(i => s.Substring(i * w, Math.Min(w, s.Length - i * w))));

    static string Describe(RSAParameters p, bool withPrivate)
    {
        var sb = new StringBuilder();
        void Row(string name, byte[]? v)
        {
            if (v == null) return;
            sb.AppendLine($"{name}  [{BitLen(v)} bit, {v.Length} byte]");
            sb.AppendLine(Wrap(Convert.ToHexString(v), 64));
            sb.AppendLine();
        }
        Row("n  (modulus)", p.Modulus);
        sb.AppendLine($"e  (public exponent) = {new BigInteger(p.Exponent!, true, true)} = 0x{Convert.ToHexString(p.Exponent!)}  [{BitLen(p.Exponent!)} bit]");
        sb.AppendLine();
        if (withPrivate)
        {
            Row("d  (private exponent)", p.D);
            Row("p  (prime1)", p.P);
            Row("q  (prime2)", p.Q);
            Row("dP = d mod (p-1)", p.DP);
            Row("dQ = d mod (q-1)", p.DQ);
            Row("qInv = q^-1 mod p", p.InverseQ);
        }
        return sb.ToString();
    }

    // =====================================================================
    // TRANG 1: SINH KHOÁ, XUẤT PEM, XEM PEM, NHẬP PEM
    // =====================================================================
    Control BuildKeyPage()
    {
        var log = Out();
        var cbo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 90 };
        cbo.Items.AddRange(new object[] { 1024, 2048, 3072, 4096 });
        cbo.SelectedItem = 2048;

        var bar = Bar(
            Lbl("Độ dài khoá (bit):"), cbo,
            BtnAsync("Sinh cặp khoá", Accent, async () =>
            {
                int bits = (int)cbo.SelectedItem!;
                log.Clear();
                Say(log, $"Đang sinh khoá RSA {bits} bit ...");
                var sw = Stopwatch.StartNew();
                var k = await Task.Run(() => RSA.Create(bits));
                gen?.Dispose();
                gen = k;
                Say(log, $"Hoàn tất sau {sw.ElapsedMilliseconds} ms.");
                Say(log, "");
                Say(log, Describe(k.ExportParameters(true), true));
            }, log),
            Btn("Xuất ra file PEM", Blue, () =>
            {
                var g = gen ?? throw new InvalidOperationException("Chưa sinh khoá.");
                using var d = new FolderBrowserDialog { Description = "Chọn thư mục để lưu public.pem và private.pem" };
                if (d.ShowDialog() != DialogResult.OK) return;
                var pubP = Path.Combine(d.SelectedPath, "public.pem");
                var priP = Path.Combine(d.SelectedPath, "private.pem");
                File.WriteAllText(pubP, g.ExportSubjectPublicKeyInfoPem());
                File.WriteAllText(priP, g.ExportRSAPrivateKeyPem());
                Say(log, $"Đã xuất: {pubP}  (BEGIN PUBLIC KEY - SPKI)");
                Say(log, $"Đã xuất: {priP}  (BEGIN RSA PRIVATE KEY - PKCS#1)");
            }, log),
            Btn("Xem PEM (ý nghĩa byte)", Amber, () =>
            {
                var p = OpenPath(PemFilter);
                if (p == null) return;
                var text = File.ReadAllText(p);
                log.Clear();
                Say(log, "FILE: " + p);
                Say(log, "");
                Say(log, text);
                Say(log, PemViewer.Dump(text));
            }, log),
            Btn("Nhập public.pem → n, e", Blue, () =>
            {
                var p = OpenPath(PemFilter);
                if (p == null) return;
                using var r = RSA.Create();
                r.ImportFromPem(File.ReadAllText(p));
                log.Clear();
                Say(log, "Đã nhập KHOÁ CÔNG KHAI từ: " + p);
                Say(log, "");
                Say(log, Describe(r.ExportParameters(false), false));
            }, log),
            Btn("Nhập private.pem → n, e, d ...", Rose, () =>
            {
                var p = OpenPath(PemFilter);
                if (p == null) return;
                using var r = RSA.Create();
                r.ImportFromPem(File.ReadAllText(p));
                log.Clear();
                Say(log, "Đã nhập KHOÁ BÍ MẬT từ: " + p);
                Say(log, "");
                Say(log, Describe(r.ExportParameters(true), true));
            }, log));

        return Page("Khoá RSA & định dạng PEM",
            "Sinh cặp khoá, xuất ra file PEM, xem cấu trúc ASN.1/DER của PEM và nhập lại khoá từ file để lấy các thành phần n, e, d, p, q ...",
            bar, log);
    }

    // =====================================================================
    // TRANG 2: MÃ HOÁ / GIẢI MÃ (OAEP-SHA256, <= 190 byte với khoá 2048)
    // =====================================================================
    Control BuildCryptoPage()
    {
        var log = Out();
        var txt = Input(90);
        var chk = new CheckBox { Text = "Dữ liệu nhập là Base64 (vd khoá AES)", AutoSize = true, Margin = new Padding(8, 9, 8, 0) };
        var lblLen = new Label { AutoSize = true, ForeColor = Blue, Margin = new Padding(8, 9, 8, 0), Font = new Font("Segoe UI Semibold", 9.5f) };

        byte[] Data() => chk.Checked ? Convert.FromBase64String(txt.Text.Trim()) : Encoding.UTF8.GetBytes(txt.Text);
        void Count()
        {
            try { lblLen.Text = $"Độ dài dữ liệu: {Data().Length} byte"; }
            catch { lblLen.Text = "Base64 không hợp lệ"; }
        }
        txt.TextChanged += (_, _) => Count();
        chk.CheckedChanged += (_, _) => Count();
        txt.Text = "Xin chao, day la du lieu duoc ma hoa bang RSA!";

        var bar = Bar(
            Btn("Sinh khoá AES-256 (32 byte)", Muted, () =>
            {
                chk.Checked = true;
                txt.Text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            }, log),
            chk, lblLen,
            Btn("Mã hoá (chọn public.pem)", Accent, () =>
            {
                var data = Data();
                var pp = OpenPath(PemFilter);
                if (pp == null) return;
                using var r = RSA.Create();
                r.ImportFromPem(File.ReadAllText(pp));
                int max = r.KeySize / 8 - 2 * 32 - 2; // OAEP-SHA256: k - 2*hLen - 2
                if (data.Length > max)
                    throw new InvalidOperationException($"Dữ liệu {data.Length} byte vượt giới hạn {max} byte (OAEP-SHA256, khoá {r.KeySize} bit).");
                var b64 = Convert.ToBase64String(r.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
                var sp = SavePath("cipher.b64.txt", "Văn bản (*.txt)|*.txt");
                if (sp == null) return;
                File.WriteAllText(sp, b64);
                log.Clear();
                Say(log, $"Khoá công khai: {r.KeySize} bit | giới hạn dữ liệu: {max} byte | dữ liệu: {data.Length} byte");
                Say(log, "Bản mã (Base64):");
                Say(log, Wrap(b64, 80));
                Say(log, "");
                Say(log, "Đã lưu file: " + sp);
            }, log),
            Btn("Giải mã (private.pem + file bản mã)", Amber, () =>
            {
                var expect = Data();
                var pp = OpenPath(PemFilter);
                if (pp == null) return;
                var cp = OpenPath("Văn bản (*.txt)|*.txt|Tất cả|*.*");
                if (cp == null) return;
                using var r = RSA.Create();
                r.ImportFromPem(File.ReadAllText(pp));
                var plain = r.Decrypt(Convert.FromBase64String(File.ReadAllText(cp).Trim()), RSAEncryptionPadding.OaepSHA256);
                log.Clear();
                Say(log, $"Kết quả giải mã ({plain.Length} byte), Base64:");
                Say(log, Convert.ToBase64String(plain));
                Say(log, "");
                Say(log, $"Dữ liệu nguồn ({expect.Length} byte), Base64:");
                Say(log, Convert.ToBase64String(expect));
                Say(log, "");
                Say(log, plain.AsSpan().SequenceEqual(expect)
                    ? "=> SO SÁNH TỪNG BYTE: KHỚP 100% (giải mã đúng)"
                    : "=> SO SÁNH TỪNG BYTE: KHÔNG KHỚP");
            }, log));

        return Page("Mã hoá & giải mã bằng RSA-OAEP (SHA-256)",
            "Nhập dữ liệu ≤ 190 byte (khoá 2048 bit; ví dụ khoá AES-256 = 32 byte dạng Base64). Mã hoá bằng public.pem, lưu bản mã Base64; giải mã bằng private.pem rồi so sánh với dữ liệu nguồn đang nhập ở ô bên dưới.",
            bar, txt, log);
    }

    // =====================================================================
    // TRANG 3: TỐC ĐỘ RSA
    // =====================================================================
    Control BuildSpeedPage()
    {
        var log = Out();
        var num = new NumericUpDown { Minimum = 20, Maximum = 5000, Value = 200, Width = 80, Margin = new Padding(4, 6, 4, 0) };
        var bar = Bar(
            Lbl("Số vòng lặp mỗi phép đo:"), num,
            BtnAsync("Chạy đánh giá tốc độ", Accent, async () =>
            {
                int n = (int)num.Value;
                log.Clear();
                Say(log, "Đang đo (sinh khoá 1024/2048/3072 bit, vui lòng đợi vài giây) ...");
                var res = await Task.Run(() => Bench(n));
                Say(log, "");
                Say(log, res);
            }, log));

        return Page("Đánh giá tốc độ: khoá công khai (e nhỏ) và khoá bí mật (d lớn)",
            "Mã hoá bằng public key chỉ cần luỹ thừa với e (≈17 bit); giải mã bằng private key luỹ thừa với d (≈ bằng độ dài n). So sánh thời gian trung bình mỗi lần.",
            bar, log);
    }

    static string Bench(int n)
    {
        var pad = RSAEncryptionPadding.OaepSHA256;
        var sb = new StringBuilder();
        sb.AppendLine($"Mỗi phép đo lặp {n} lần | dữ liệu 32 byte | OAEP-SHA256 | e = 65537");
        sb.AppendLine();
        sb.AppendLine("Khoá(bit) | e(bit) | d(bit) | Mã hoá-public(ms/lần) | Giải mã-private(ms/lần) | Private chậm hơn (lần)");
        sb.AppendLine(new string('-', 105));
        foreach (var bits in new[] { 1024, 2048, 3072 })
        {
            using var full = RSA.Create(bits);
            using var pubOnly = RSA.Create();
            pubOnly.ImportParameters(full.ExportParameters(false));
            var pr = full.ExportParameters(true);
            var data = RandomNumberGenerator.GetBytes(32);

            var ct = pubOnly.Encrypt(data, pad); // khởi động
            full.Decrypt(ct, pad);

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < n; i++) pubOnly.Encrypt(data, pad);
            double te = sw.Elapsed.TotalMilliseconds / n;

            sw.Restart();
            for (int i = 0; i < n; i++) full.Decrypt(ct, pad);
            double td = sw.Elapsed.TotalMilliseconds / n;

            sb.AppendLine($"{bits,9} | {BitLen(pr.Exponent!),6} | {BitLen(pr.D!),6} | {te,21:F4} | {td,23:F4} | {td / te,22:F1}");
        }
        sb.AppendLine();
        sb.AppendLine("Nhận xét: e chỉ ~17 bit nên mã hoá bằng khoá công khai rất nhanh; d có độ dài xấp xỉ n nên giải mã bằng khoá bí mật chậm hơn nhiều lần,");
        sb.AppendLine("và khoá càng dài thì chênh lệch càng lớn (chi phí luỹ thừa module tăng theo luỹ thừa 3 của độ dài khoá).");
        return sb.ToString();
    }

    // =====================================================================
    // TRANG 4: SHA-256 VÀ HIỆU ỨNG THÁC
    // =====================================================================
    Control BuildHashPage()
    {
        var log = Out();
        var txt = Input(110);
        byte[]? prev = null;

        void Update()
        {
            var h = SHA256.HashData(Encoding.UTF8.GetBytes(txt.Text));
            var cur = Convert.ToHexString(h);
            var sb = new StringBuilder();
            sb.AppendLine($"Đầu vào hiện tại : {Encoding.UTF8.GetByteCount(txt.Text)} byte");
            sb.AppendLine($"SHA-256 (mới)    : {cur}");
            if (prev != null)
            {
                var old = Convert.ToHexString(prev);
                int bits = 0;
                for (int i = 0; i < 32; i++) bits += BitOperations.PopCount((uint)(h[i] ^ prev[i]));
                var mark = new string(Enumerable.Range(0, 64).Select(i => cur[i] == old[i] ? ' ' : '^').ToArray());
                int hexDiff = mark.Count(c => c == '^');
                sb.AppendLine($"SHA-256 (trước)  : {old}");
                sb.AppendLine($"Chỗ khác nhau    : {mark}");
                sb.AppendLine();
                sb.AppendLine($"Số ký tự hex khác: {hexDiff}/64 ({hexDiff * 100.0 / 64:F1}%)");
                sb.AppendLine($"Số bit khác      : {bits}/256 ({bits * 100.0 / 256:F1}%)  (lý thuyết ≈ 50% = 128 bit)");
            }
            else sb.AppendLine("(Hãy sửa dữ liệu để so sánh với mã băm trước đó)");
            prev = h;
            log.Text = sb.ToString();
        }

        txt.TextChanged += (_, _) => Update();
        txt.Text = "Hello World";

        var bar = Bar(
            Btn("Mẫu: Hello World", Muted, () => txt.Text = "Hello World", log),
            Btn("Mẫu: Hello World. (thêm dấu chấm)", Muted, () => txt.Text = "Hello World.", log),
            Btn("Mẫu: hello World (đổi chữ H → h)", Muted, () => txt.Text = "hello World", log));

        return Page("Băm SHA-256 và hiệu ứng thác (avalanche effect)",
            "Gõ hoặc sửa dữ liệu ở ô bên dưới: mã băm được tính lại tức thì và so sánh với lần băm liền trước để thấy một thay đổi rất nhỏ làm thay đổi gần một nửa số bit.",
            bar, txt, log);
    }

    // =====================================================================
    // TRANG 5: CHỮ KÝ SỐ
    // =====================================================================
    static string Sign(RSA r, byte[] data, int mode)
    {
        switch (mode)
        {
            case 0:
                return Convert.ToBase64String(r.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            case 1:
                return Convert.ToBase64String(r.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            default:
                var nonce = RandomNumberGenerator.GetBytes(16);
                var sig = r.SignData(data.Concat(nonce).ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(nonce) + "." + Convert.ToBase64String(sig);
        }
    }

    static bool Verify(RSA r, byte[] data, string sig, int mode)
    {
        try
        {
            switch (mode)
            {
                case 0:
                    return r.VerifyData(data, Convert.FromBase64String(sig), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                case 1:
                    return r.VerifyData(data, Convert.FromBase64String(sig), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                default:
                    var parts = sig.Split('.');
                    var nonce = Convert.FromBase64String(parts[0]);
                    var s = Convert.FromBase64String(parts[1]);
                    return r.VerifyData(data.Concat(nonce).ToArray(), s, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        catch
        {
            return false;
        }
    }

    Control BuildSignPage()
    {
        var log = Out();
        var txt = Input(90);
        txt.Text = "Hợp đồng số 01: Bên A chuyển cho Bên B 1.000.000 VND";
        var cbo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 330, Margin = new Padding(4, 6, 4, 0) };
        cbo.Items.AddRange(new object[]
        {
            "1. PKCS#1 v1.5 (xác định - chữ ký luôn giống nhau)",
            "2. RSA-PSS (salt ngẫu nhiên) - khuyến nghị",
            "3. Nonce ngẫu nhiên + PKCS#1 v1.5"
        });
        cbo.SelectedIndex = 1;
        string? s1 = null, s2 = null;
        int mode = 1;

        RSA Priv() => priv ?? throw new InvalidOperationException("Hãy bấm 'Nạp private.pem' trước.");

        void Check(string title)
        {
            var data = Encoding.UTF8.GetBytes(txt.Text);
            var r = Priv();
            Say(log, $"{title}: SHA-256 dữ liệu = {Convert.ToHexString(SHA256.HashData(data))}");
            Say(log, $"  Chữ ký 1: {(s1 != null && Verify(r, data, s1, mode) ? "ĐÚNG" : "SAI")}");
            Say(log, $"  Chữ ký 2: {(s2 != null && Verify(r, data, s2, mode) ? "ĐÚNG" : "SAI")}");
        }

        var bar = Bar(
            Btn("Nạp private.pem", Blue, () =>
            {
                var p = OpenPath(PemFilter);
                if (p == null) return;
                var r = RSA.Create();
                r.ImportFromPem(File.ReadAllText(p));
                priv?.Dispose();
                priv = r;
                Say(log, $"Đã nạp khoá bí mật {r.KeySize} bit từ: {p}");
            }, log),
            Lbl("Phương pháp:"), cbo,
            Btn("Ký 2 lần (cùng dữ liệu)", Accent, () =>
            {
                var r = Priv();
                mode = cbo.SelectedIndex;
                var data = Encoding.UTF8.GetBytes(txt.Text);
                s1 = Sign(r, data, mode);
                s2 = Sign(r, data, mode);
                log.Clear();
                Say(log, $"Phương pháp: {cbo.SelectedItem}");
                Say(log, "");
                Say(log, "Chữ ký lần 1:");
                Say(log, Wrap(s1, 100));
                Say(log, "");
                Say(log, "Chữ ký lần 2:");
                Say(log, Wrap(s2, 100));
                Say(log, "");
                Say(log, s1 == s2 ? "=> Hai chữ ký GIỐNG NHAU (tính xác định)" : "=> Hai chữ ký KHÁC NHAU dù cùng dữ liệu, cùng private key");
                Say(log, "");
                Check("Xác minh");
            }, log),
            Btn("Xác minh lại với dữ liệu hiện tại", Amber, () =>
            {
                if (s1 == null) throw new InvalidOperationException("Chưa ký. Bấm 'Ký 2 lần' trước.");
                Say(log, "");
                Check("Xác minh lại (nếu bạn đã sửa dữ liệu thì kết quả phải SAI)");
            }, log));

        return Page("Chữ ký số = RSA(khoá bí mật) trên mã băm SHA-256 của dữ liệu",
            "Chọn phương pháp rồi bấm 'Ký 2 lần'. Phương pháp 1 luôn cho cùng chữ ký; phương pháp 2 (RSA-PSS) và 3 (nonce) cho chữ ký khác nhau ở mỗi lần ký nhưng vẫn xác minh ĐÚNG. Sửa dữ liệu rồi xác minh lại để thấy chữ ký trở nên SAI.",
            bar, txt, log);
    }
}