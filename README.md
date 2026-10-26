# BÀI TẬP MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN


**Sinh viên thực hiện:** Lù Đình Hưng

**Lớp:** K59KMT — Trường Đại học Kỹ thuật Công nghiệp Thái Nguyên (TNUT)


# PHẦN I. PHÂN TÍCH TỪNG YÊU CẦU

## BÀI 1. MÃ HOÁ AES (ĐỐI XỨNG)

### 1.0. Cơ sở lý thuyết

AES (Advanced Encryption Standard) là mã khối đối xứng: **một khoá duy nhất** dùng cho cả mã hoá và giải mã.

Kích thước khối cố định là 128 bit (16 byte); kích thước khoá là 128, 192 hoặc 256 bit.

Vì AES chỉ xử lý từng khối 16 byte nên cần một **chế độ hoạt động (mode)** để mã hoá dữ liệu dài. Bài này chọn **AES-256-CBC với đệm PKCS#7**.

Ở chế độ CBC, mỗi khối bản rõ được XOR với khối bản mã liền trước rồi mới mã hoá, khối đầu tiên dùng vector khởi tạo IV (16 byte, ngẫu nhiên cho mỗi lần mã hoá).

Công thức: `C[i] = E_K(P[i] XOR C[i-1])`, với `C[0] = IV`.

IV không cần giữ bí mật nên được ghi ngay đầu file/chuỗi bản mã để giải mã đọc lại.

Tạo project

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/8b28578a-f77b-4b47-bebf-45731969358a" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/98e34534-9b14-4d07-85ef-48b68da63c34" />

Giao diện App

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/0219b381-93ab-41ed-b1cd-32eb712d7021" />

### 1.1. Yêu cầu 1 — Sinh khoá AES

Khoá AES-256 là **32 byte ngẫu nhiên** (256 bit).

Phải dùng bộ sinh số ngẫu nhiên an toàn mật mã `RandomNumberGenerator`, không dùng `System.Random` vì `Random` có thể đoán trước được.

Sinh khóa mới 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/6c2fa5c6-b788-4599-821d-7a5299e1ae86" />


### 1.2. Yêu cầu 2 — Lưu khoá ra file

Khoá là dữ liệu nhị phân nên được mã hoá **Base64** rồi ghi ra file văn bản `aes.key` (32 byte → 44 ký tự Base64).

Cách này giúp file khoá mở được bằng Notepad, dễ sao chép và đúng với ghi chú trong đề bài (khoá AES 256 bit ⇔ 32 byte ⇔ Base64).

Lưu khóa ra 1 file

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/70cbcc11-f257-4708-b8c3-439a056b9d9f" />


<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/143ec659-bfe6-42a9-b45b-29be93991f58" />


### 1.3. Yêu cầu 3 — Import khoá từ file

Đọc file, giải mã Base64 và **kiểm tra độ dài** (16/24/32 byte) trước khi dùng.

Nếu sai độ dài hoặc sai định dạng, chương trình báo lỗi thay vì mã hoá bằng khoá hỏng.

Nạp khóa từ file đã lưu

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/1e717dcb-a42f-4eb3-8ef2-c6785ca21a2c" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/fa8f6cec-116a-49d2-98b6-b9c5a225eec3" />


### 1.4. Yêu cầu 4 — Mã hoá một đoạn văn bản, hiển thị kết quả ra màn hình

Quy trình: văn bản → byte UTF-8 → sinh IV ngẫu nhiên → mã hoá AES-CBC → ghép `IV (16 byte) ‖ bản mã` → Base64 → hiển thị.

Giải mã làm ngược lại: Base64 → tách 16 byte đầu làm IV → giải mã → UTF-8.

Do IV ngẫu nhiên nên **cùng một văn bản, cùng một khoá, mỗi lần mã hoá cho một kết quả khác nhau** — đây là tính chất mong muốn để chống phân tích mẫu.


Mã hóa và giải mã đoạn văn Tôi là hưng

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/378f2b61-83d8-48bd-bd99-06ff73954580" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/deb212ae-cb6f-46d7-800c-da43cd4cf637" />


### 1.5. Yêu cầu 5 — Mã hoá một file và lưu ra file

Cấu trúc file `.enc`: `[16 byte IV][bản mã CBC/PKCS7]`.

**Điểm then chốt khi file lớn (hàng GB):** tuyệt đối không dùng `File.ReadAllBytes`, vì mảng .NET bị giới hạn khoảng 2 GB và tốn RAM tương ứng.

Giải pháp là **mã hoá theo luồng (streaming)**: đọc từng khối 4 MB → đưa qua `CryptoStream` → ghi ra file đích. Bộ nhớ sử dụng luôn xấp xỉ 4 MB bất kể file nặng bao nhiêu.

Mã hóa 1 file nhỏ 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/5ce162d9-74ad-4343-a996-0020f77b666b" />

 Giải mã file nhỏ 
 
 <img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/5a1cb538-ec5b-478e-a18b-f7e4e76469fd" />


### 1.6. Yêu cầu thử nghiệm — file hàng GB, đo thời gian, so sánh byte

**Tạo file thử nghiệm:** chương trình có nút "Tạo file test" sinh file nhị phân kích thước tuỳ chọn (ví dụ 1024 MB, 3072 MB) để không cần tìm file lớn có sẵn.

**Đo thời gian:** dùng `Stopwatch`, đo riêng ba giai đoạn — mã hoá, giải mã, so sánh byte — và tính **tốc độ (MB/s) = dung lượng / thời gian**.

**So sánh theo byte:** đọc song song hai file theo khối 4 MB, so sánh bằng `SequenceEqual`; nếu khác thì báo **vị trí byte khác đầu tiên**. Kiểm tra cả độ dài file trước.

**Lưu ý dung lượng đĩa:** cần khoảng 3 × kích thước file gốc (file gốc + file `.enc` + file `.dec`).

**Kết luận dựa trên số liệu:** cần điền số liệu thực đo vào bảng ở Phần V; các nhận định mẫu được viết sẵn để thay số.

Tạo file test 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/6e246999-44d1-4291-912d-4825868d6900" />


## BÀI 2. MÃ HOÁ RSA (BẤT ĐỐI XỨNG), SHA-256 VÀ CHỮ KÝ SỐ

### 2.0. Cơ sở lý thuyết

RSA dùng **cặp khoá**: khoá công khai `(n, e)` và khoá bí mật `(n, d)`.

Chọn hai số nguyên tố lớn `p`, `q`; tính `n = p·q`; `φ(n) = (p−1)(q−1)`; chọn `e` nguyên tố cùng nhau với `φ(n)` (thường `e = 65537 = 0x010001`); tính `d = e⁻¹ mod φ(n)`.

Mã hoá: `C = M^e mod n`. Giải mã: `M = C^d mod n`.

Vì `e` rất nhỏ (17 bit) còn `d` có kích thước xấp xỉ `n` (2048 bit) nên **phép dùng khoá công khai nhanh hơn rất nhiều so với phép dùng khoá bí mật** — được kiểm chứng ở yêu cầu 7.

### 2.1. Yêu cầu 1 — Sinh cặp khoá

Dùng `RSA.Create(keySizeInBits)`; cho phép chọn 1024/2048/3072/4096 bit, mặc định 2048 bit.

### 2.2. Yêu cầu 2 — Xuất cặp khoá ra file PEM

Xuất hai file:

- `public.pem` — định dạng **SubjectPublicKeyInfo** (SPKI), tiêu đề `-----BEGIN PUBLIC KEY-----`;

- `private.pem` — định dạng **PKCS#1**, tiêu đề `-----BEGIN RSA PRIVATE KEY-----`.

### 2.3. Yêu cầu 3 — Xem PEM và ý nghĩa từng byte

**PEM = dòng BEGIN + Base64(DER) + dòng END.**

Nội dung giữa hai dòng tiêu đề là dữ liệu **DER** (mã hoá nhị phân ASN.1) được chuyển sang Base64, mỗi dòng 64 ký tự (4 ký tự Base64 = 3 byte).

DER mã hoá mọi thứ theo cấu trúc **TLV**: `Tag` (1 byte, loại dữ liệu) – `Length` (độ dài) – `Value` (nội dung).

Các tag thường gặp:

| Tag (hex) | Ý nghĩa |
|---|---|
| `30` | SEQUENCE — dãy các thành phần |
| `02` | INTEGER — số nguyên lớn (n, e, d, p, q ...) |
| `03` | BIT STRING — chuỗi bit (chứa khoá công khai trong SPKI) |
| `04` | OCTET STRING |
| `05` | NULL |
| `06` | OBJECT IDENTIFIER — định danh thuật toán |

Quy tắc độ dài: nếu byte đầu `< 0x80` thì chính là độ dài; nếu `0x81`, `0x82` thì 1 hoặc 2 byte tiếp theo mới là độ dài (ví dụ `82 01 22` = 0x0122 = 290 byte).

**Cấu trúc khoá công khai (SPKI) 2048 bit:**

| Byte | Ý nghĩa |
|---|---|
| `30 82 01 22` | SEQUENCE ngoài cùng, dài 290 byte |
| `30 0D` | SEQUENCE định danh thuật toán, dài 13 byte |
| `06 09 2A 86 48 86 F7 0D 01 01 01` | OID `1.2.840.113549.1.1.1` = rsaEncryption |
| `05 00` | NULL (tham số rỗng) |
| `03 82 01 0F 00` | BIT STRING dài 271 byte, `00` = số bit đệm |
| `30 82 01 0A` | SEQUENCE chứa n và e |
| `02 82 01 01 00 …` | INTEGER n (256 byte, thêm byte `00` đầu để số luôn dương) |
| `02 03 01 00 01` | INTEGER e = 0x010001 = 65537 |

**Cấu trúc khoá bí mật (PKCS#1):** một SEQUENCE gồm 9 INTEGER theo thứ tự: `version (0)`, `n`, `e`, `d`, `p`, `q`, `dP = d mod (p−1)`, `dQ = d mod (q−1)`, `qInv = q⁻¹ mod p`.

Ứng dụng có chức năng **"Xem PEM"** tự phân tích DER và in ra từng phần tử kèm offset, tag, độ dài và tên trường.

### 2.4. Yêu cầu 4 — Nhập PEM để lấy n, e (và d, p, q …)

Dùng `RSA.ImportFromPem()` rồi `ExportParameters()`:

- nhập `public.pem` → lấy được `n`, `e`;

- nhập `private.pem` → lấy được `n`, `e`, `d`, `p`, `q`, `dP`, `dQ`, `qInv`.

Các số được hiển thị dạng hex kèm độ dài bit.

### 2.5. Yêu cầu 5 — Mã hoá dữ liệu ≤ 190 byte bằng khoá vừa import

Dùng **RSA-OAEP với SHA-256**.

Dung lượng tối đa của OAEP: `k − 2·hLen − 2`, với `k` = độ dài khoá tính bằng byte, `hLen` = 32 byte (SHA-256).

Với khoá 2048 bit: `256 − 2·32 − 2 = 190 byte` — **khớp chính xác giới hạn 190 byte của đề bài**.

Khoá AES-256 chỉ 32 byte nên hoàn toàn nằm trong giới hạn; đây cũng là cách thực tế dùng RSA để **trao đổi khoá AES**.

Kết quả mã hoá là mảng byte 256 → chuyển Base64 → lưu file `.txt`.

### 2.6. Yêu cầu 6 — Giải mã và so sánh với nguồn

Đầu vào: file `private.pem` và file bản mã Base64.

Quy trình: đọc Base64 → giải mã bằng khoá bí mật → so sánh **từng byte** với dữ liệu nguồn ban đầu (`SequenceEqual`) → in kết quả KHỚP / KHÔNG KHỚP.

### 2.7. Yêu cầu 7 — Đánh giá tốc độ mã hoá/giải mã

Lặp lại `N` lần (mặc định 200) hai phép: mã hoá bằng khoá công khai và giải mã bằng khoá bí mật, với các khoá 1024/2048/3072 bit; in thời gian trung bình (ms/lần), độ dài bit của `e` và `d`, và tỉ lệ chậm hơn.

**Nhận định kỳ vọng:** `e` chỉ 17 bit (vài phép nhân bình phương) trong khi `d` ~ 2048 bit (hàng nghìn phép nhân modulo) nên giải mã bằng khoá bí mật chậm hơn mã hoá bằng khoá công khai nhiều lần; khoá càng dài, khoảng cách càng lớn.

Lưu ý: thư viện giải mã bằng khoá bí mật dùng thêm tối ưu **CRT** (định lý số dư Trung Hoa với `p`, `q`, `dP`, `dQ`, `qInv`) nên nhanh hơn so với lý thuyết thuần `M = C^d mod n`, nhưng vẫn chậm hơn phép công khai.

### 2.8. Yêu cầu 8 — Giao diện sinh chuỗi băm SHA-256

Gõ dữ liệu vào ô nhập, mỗi lần thay đổi (từng ký tự) chương trình tính lại SHA-256 ngay lập tức, đồng thời hiển thị:

- mã băm mới và mã băm ngay trước đó;

- dòng đánh dấu `^` dưới các ký tự hex khác nhau;

- số bit khác nhau trên tổng 256 bit và tỉ lệ phần trăm.

**Nhận định kỳ vọng — hiệu ứng thác (avalanche effect):** chỉ đổi 1 ký tự đầu vào, mã băm thay đổi hoàn toàn, số bit khác xấp xỉ 50% (~128/256 bit). Không có mối liên hệ nào giữa mức độ thay đổi của đầu vào và đầu ra, nên không thể suy ngược dữ liệu từ mã băm.

### 2.9. Yêu cầu 9 — Chữ ký số và đề xuất để cùng dữ liệu, cùng người ký vẫn cho chữ ký khác nhau

**Bản chất:** chữ ký số = RSA dùng **khoá bí mật** trên **mã băm** của dữ liệu: `S = (Hash(M))^d mod n`. Người nhận kiểm tra bằng khoá công khai: `Hash(M) =? S^e mod n`.

**Vấn đề:** chuẩn **PKCS#1 v1.5** có tính **xác định (deterministic)** — cùng dữ liệu, cùng khoá bí mật luôn ra đúng một chữ ký. Điều này lộ thông tin (kẻ quan sát biết hai văn bản giống nhau) và dễ bị phân tích.

**Mong muốn:** cùng dữ liệu, cùng private key, mỗi lần ký ra một chữ ký khác nhau nhưng **tất cả đều xác minh đúng**.

**Phương pháp đề xuất 1 (khuyến nghị) — RSA-PSS (Probabilistic Signature Scheme, RFC 8017):**

Trước khi luỹ thừa bằng `d`, thông điệp được mã hoá theo EMSA-PSS có chèn **salt ngẫu nhiên**:

`M' = 0x00×8 ‖ Hash(M) ‖ salt`, rồi `H = Hash(M')`, sau đó dùng hàm sinh mặt nạ MGF1 trộn salt vào khối `EM`, cuối cùng `S = EM^d mod n`.

Mỗi lần ký sinh `salt` mới (32 byte) ⇒ `EM` khác ⇒ chữ ký khác. Khi xác minh, bên nhận khôi phục `salt` từ `EM` nên vẫn kiểm tra đúng. PSS còn có chứng minh an toàn chặt chẽ hơn PKCS#1 v1.5.

**Phương pháp đề xuất 2 — Nonce ngẫu nhiên đi kèm:**

Sinh `nonce` 16 byte, ký `Hash(M ‖ nonce)` bằng PKCS#1 v1.5 và gửi kèm: `chữ ký số = Base64(nonce) . Base64(S)`. Bên nhận băm lại `M ‖ nonce` rồi kiểm tra.

Có thể thay `nonce` bằng **dấu thời gian** (timestamp) để vừa khác nhau vừa chống phát lại (replay).

Ứng dụng cài đặt cả **3 chế độ** (PKCS#1 cố định, RSA-PSS, Nonce + PKCS#1) để so sánh: nút "Ký 2 lần" cho thấy chế độ 1 ra hai chữ ký **giống nhau**, chế độ 2 và 3 ra hai chữ ký **khác nhau** nhưng đều xác minh `ĐÚNG`; sửa dữ liệu rồi xác minh lại thì `SAI`.

---


# PHẦN III. MÃ NGUỒN TỔNG

## Cấu trúc thư mục (chỉ 4 file mã nguồn)

```text
ATBMTT/
├── AesApp/
│   ├── AesApp.csproj
│   └── Program.cs
└── RsaApp/
    ├── RsaApp.csproj
    └── Program.cs
```

## 3.1. Bài 1 — `AesApp/AesApp.csproj`

```xml

```

## 3.2. Bài 1 — `AesApp/Program.cs`

```csharp

```

## 3.3. Bài 2 — `RsaApp/RsaApp.csproj`

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <UseWindowsForms>true</UseWindowsForms>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AssemblyName>RsaApp</AssemblyName>
  </PropertyGroup>

</Project>
```

## 3.4. Bài 2 — `RsaApp/Program.cs`

```csharp
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
        Dock = DockStyle.Left, Width = 230, FlowDirection = FlowDirection.TopDown,
        WrapContents = false, BackColor = SideBg
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
            Text = "  RSA LAB", Width = 230, Height = 70, AutoSize = false,
            TextAlign = ContentAlignment.MiddleLeft, ForeColor = Accent,
            Font = new Font("Segoe UI Semibold", 17f), Margin = Padding.Empty
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
            Text = "   " + title, Width = 230, Height = 50, FlatStyle = FlatStyle.Flat,
            ForeColor = Color.White, BackColor = SideBg, TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI Semibold", 10.5f), Margin = Padding.Empty, Cursor = Cursors.Hand
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
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false,
        Font = new Font("Consolas", 10f), BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle
    };

    static TextBox Input(int h) => new()
    {
        Multiline = true, Height = h, ScrollBars = ScrollBars.Vertical,
        Font = new Font("Consolas", 10f), BorderStyle = BorderStyle.FixedSingle
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
            Text = text, AutoSize = true, FlatStyle = FlatStyle.Flat, BackColor = color, ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 9.5f), Padding = new Padding(8, 3, 8, 3),
            Margin = new Padding(4), Cursor = Cursors.Hand
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
```

---

# PHẦN IV. HƯỚNG DẪN BIÊN DỊCH VÀ CHẠY

**Yêu cầu:** cài **.NET 8 SDK** (https://dotnet.microsoft.com/download) trên Windows 10/11.

**Kiểm tra:** mở PowerShell, gõ `dotnet --version`, kết quả phải bắt đầu bằng `8.`.

## 4.1. Chạy Bài 1 (AES)

```powershell
cd ATBMTT\AesApp
dotnet run                # mở giao diện form
dotnet run -- console     # mở giao diện console
```

## 4.2. Chạy Bài 2 (RSA)

```powershell
cd ATBMTT\RsaApp
dotnet run
```

## 4.3. Quy trình thử nghiệm gợi ý

**Bài 1 (form):**

1. Bấm **Sinh khoá AES-256** → **Lưu khoá ra file** → **Nạp khoá từ file**.

2. Nhập văn bản ở ô "Bản rõ", bấm **Mã hoá** hai lần để thấy hai bản mã khác nhau, bấm **Giải mã** để lấy lại bản rõ.

3. Đặt "Tạo file test (MB)" = 1024 (rồi 3072), bấm **Tạo file test**.

4. Bấm **BENCHMARK ĐẦY ĐỦ** và ghi lại số liệu vào bảng ở Phần V.

**Bài 2:**

1. Trang 1: **Sinh cặp khoá** → **Xuất ra file PEM** → **Xem PEM** (mở `public.pem`, rồi `private.pem`) → nhập lại hai file.

2. Trang 2: bấm **Sinh khoá AES-256** → **Mã hoá** (chọn `public.pem`, lưu file) → **Giải mã** (chọn `private.pem` và file bản mã).

3. Trang 3: **Chạy đánh giá tốc độ**.

4. Trang 4: sửa 1 ký tự trong ô dữ liệu và quan sát mã băm.

5. Trang 5: **Nạp private.pem** → chọn phương pháp 1 rồi **Ký 2 lần** → chọn phương pháp 2 rồi **Ký 2 lần** → sửa dữ liệu → **Xác minh lại**.

## 4.4. Đưa lên GitHub

Đặt file này tên `README.md` (hoặc giữ nguyên tên), tạo thư mục `images/` cùng cấp và chép 15 ảnh vào với đúng tên file đã ghi ở Phần II.

---

# PHẦN V. BẢNG SỐ LIỆU VÀ KẾT LUẬN

> Điền số liệu thực đo từ máy của bạn vào các ô `…`, sau đó thay số vào phần nhận xét.

## 5.1. Bài 1 — Kết quả thử nghiệm AES-256-CBC

| Kích thước file | Thời gian mã hoá (s) | Tốc độ mã hoá (MB/s) | Thời gian giải mã (s) | Tốc độ giải mã (MB/s) | So sánh byte |
|---|---|---|---|---|---|
| 100 MB | … | … | … | … | Giống 100% |
| 1 GB (1024 MB) | … | … | … | … | Giống 100% |
| 3 GB (3072 MB) | … | … | … | … | Giống 100% |

**Kết luận (thay số sau khi đo):**

1. **Tính đúng đắn:** file giải mã trùng khớp từng byte với file nguồn ở mọi kích thước ⇒ thuật toán và cách xử lý IV, đệm PKCS#7 đúng; AES là phép biến đổi khả nghịch hoàn toàn.

2. **Độ phức tạp tuyến tính:** khi kích thước tăng 10 lần (100 MB → 1 GB), thời gian tăng xấp xỉ 10 lần, tốc độ MB/s gần như không đổi ⇒ thời gian mã hoá là **O(n)** theo kích thước dữ liệu.

3. **Bộ nhớ không đổi:** nhờ xử lý theo luồng với khối 4 MB, chương trình xử lý file hàng GB mà RAM vẫn ở mức vài chục MB; cách đọc toàn bộ file vào mảng không khả thi với file lớn.

4. **Tốc độ cao:** AES có tăng tốc phần cứng (AES-NI) nên tốc độ thường đạt từ vài trăm MB/s đến hàng GB/s; khi tốc độ gần bằng tốc độ đọc/ghi đĩa thì **nút thắt là ổ đĩa**, không phải thuật toán.

5. **Đối xứng, chia sẻ khoá là điểm yếu:** hai bên phải có chung khoá bí mật, do đó cần RSA (Bài 2) để trao đổi khoá AES an toàn.

## 5.2. Bài 2 — Tốc độ RSA (chép từ trang "Tốc độ RSA")

| Khoá (bit) | e (bit) | d (bit) | Mã hoá – public (ms/lần) | Giải mã – private (ms/lần) | Private chậm hơn (lần) |
|---|---|---|---|---|---|
| 1024 | 17 | … | … | … | … |
| 2048 | 17 | … | … | … | … |
| 3072 | 17 | … | … | … | … |

**Kết luận:**

1. **Mã hoá bằng khoá công khai nhanh hơn nhiều so với giải mã bằng khoá bí mật** vì `e` chỉ 17 bit còn `d` xấp xỉ độ dài `n`; khoá càng dài chênh lệch càng lớn.

2. **RSA chậm và giới hạn dung lượng** (tối đa 190 byte với khoá 2048 bit, OAEP-SHA256), nên chỉ dùng để mã hoá khoá AES 32 byte hoặc băm; dữ liệu lớn dùng AES (Bài 1).

3. **Mô hình lai (hybrid):** sinh khoá AES ngẫu nhiên → mã hoá dữ liệu bằng AES (nhanh) → mã hoá khoá AES bằng RSA public key của người nhận (an toàn) → người nhận giải mã khoá AES bằng private key.

## 5.3. SHA-256 — Hiệu ứng thác

Khi đổi một ký tự đầu vào (ví dụ `Hello World` → `Hello World.`), mã băm đổi hoàn toàn: số bit khác nhau ở các lần thử xấp xỉ **128/256 bit (~50%)**, các ký tự hex khác nhau rải đều khắp chuỗi.

Vì vậy mã băm đóng vai trò "dấu vân tay" của dữ liệu: chỉ cần sai lệch rất nhỏ là phát hiện được, và không thể suy ngược dữ liệu từ mã băm.

## 5.4. Chữ ký số — Kết luận về đề xuất

| Phương pháp | Cùng dữ liệu + cùng private key | Xác minh | Nhận xét |
|---|---|---|---|
| PKCS#1 v1.5 | Luôn **giống nhau** | ĐÚNG | Xác định, lộ việc hai văn bản trùng nhau |
| **RSA-PSS (salt ngẫu nhiên)** | **Khác nhau** mỗi lần ký | ĐÚNG | **Khuyến nghị**: chuẩn RFC 8017, có chứng minh an toàn |
| Nonce + PKCS#1 v1.5 | **Khác nhau** mỗi lần ký | ĐÚNG | Đơn giản, phải gửi kèm nonce (có thể dùng timestamp) |

**Kết luận:** muốn cùng một dữ liệu, cùng một người ký mà chữ ký mỗi lần một khác, cần đưa **yếu tố ngẫu nhiên** (salt hoặc nonce) vào quá trình ký. Phương pháp tốt nhất là **RSA-PSS**; khi dữ liệu bị sửa dù chỉ 1 bit thì mã băm đổi hoàn toàn (hiệu ứng thác) và chữ ký lập tức **không còn xác minh đúng**, đảm bảo tính toàn vẹn và xác thực nguồn gốc.

---

*— Hết —*
