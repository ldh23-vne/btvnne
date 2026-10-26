# BÀI TẬP MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN


**Sinh viên thực hiện:** Lù Đình Hưng

**Lớp:** K59KMT — Trường Đại học Kỹ thuật Công nghiệp Thái Nguyên (TNUT)


# PHÂN TÍCH TỪNG YÊU CẦU

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


## Quy trình thử nghiệm 


1. Bấm **Sinh khoá AES-256** → **Lưu khoá ra file** → **Nạp khoá từ file**.

2. Nhập văn bản ở ô "Bản rõ", bấm **Mã hoá** hai lần để thấy hai bản mã khác nhau, bấm **Giải mã** để lấy lại bản rõ.

3. Đặt "Tạo file test (MB)" = 1024 (rồi 3072), bấm **Tạo file test**.

4. Bấm **BENCHMARK ĐẦY ĐỦ** và ghi lại số liệu vào bảng.

Kết quả thử nghiệm AES-256-CBC

Tạo file test nhỏ và lớn

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/ee6c9259-f005-4c14-8698-4dbcd1ee5391" />

Mã hóa và giải mã file 
<img width="1910" height="171" alt="image" src="https://github.com/user-attachments/assets/ff7c9756-107e-4b06-81d6-11f31a516cdd" />


Tạo mã hóa và giải mã file 2GB

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/a5c686d7-1e0d-4925-8029-61fd0eb2cfe3" />
<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/31a7c777-cad8-4af1-8491-eab3b48299d0" />



**Kết luận:**

1. **Tính đúng đắn:** file giải mã trùng khớp từng byte với file nguồn ở mọi kích thước ⇒ thuật toán và cách xử lý IV, đệm PKCS#7 đúng; AES là phép biến đổi khả nghịch hoàn toàn.

2. **Độ phức tạp tuyến tính:** khi kích thước tăng 10 lần (100 MB → 1 GB), thời gian tăng xấp xỉ 10 lần, tốc độ MB/s gần như không đổi ⇒ thời gian mã hoá là **O(n)** theo kích thước dữ liệu.

3. **Bộ nhớ không đổi:** nhờ xử lý theo luồng với khối 4 MB, chương trình xử lý file hàng GB mà RAM vẫn ở mức vài chục MB; cách đọc toàn bộ file vào mảng không khả thi với file lớn.

4. **Tốc độ cao:** AES có tăng tốc phần cứng (AES-NI) nên tốc độ thường đạt từ vài trăm MB/s đến hàng GB/s; khi tốc độ gần bằng tốc độ đọc/ghi đĩa thì **nút thắt là ổ đĩa**, không phải thuật toán.

5. **Đối xứng, chia sẻ khoá là điểm yếu:** hai bên phải có chung khoá bí mật, do đó cần RSA (Bài 2) để trao đổi khoá AES an toàn.

   
## BÀI 2. MÃ HOÁ RSA (BẤT ĐỐI XỨNG), SHA-256 VÀ CHỮ KÝ SỐ

### 2.0. Cơ sở lý thuyết

RSA dùng **cặp khoá**: khoá công khai `(n, e)` và khoá bí mật `(n, d)`.

Chọn hai số nguyên tố lớn `p`, `q`; tính `n = p·q`; `φ(n) = (p−1)(q−1)`; chọn `e` nguyên tố cùng nhau với `φ(n)` (thường `e = 65537 = 0x010001`); tính `d = e⁻¹ mod φ(n)`.

Mã hoá: `C = M^e mod n`. Giải mã: `M = C^d mod n`.

Vì `e` rất nhỏ (17 bit) còn `d` có kích thước xấp xỉ `n` (2048 bit) nên **phép dùng khoá công khai nhanh hơn rất nhiều so với phép dùng khoá bí mật** — được kiểm chứng ở yêu cầu 7.

Tạo project 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/577af1e1-bf55-45cb-836b-3ee74b888f01" />

### 2.1. Yêu cầu 1 — Sinh cặp khoá

Dùng `RSA.Create(keySizeInBits)`; cho phép chọn 1024/2048/3072/4096 bit, mặc định 2048 bit.

Sinh cặp khóa 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/9c32df61-7031-498c-8ce5-c5f94fd3ee90" />


### 2.2. Yêu cầu 2 — Xuất cặp khoá ra file PEM

Xuất hai file:

- `public.pem` — định dạng **SubjectPublicKeyInfo** (SPKI), tiêu đề `-----BEGIN PUBLIC KEY-----`;

- `private.pem` — định dạng **PKCS#1**, tiêu đề `-----BEGIN RSA PRIVATE KEY-----`.

Xuất ra 2 file PEM 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/3ac845fc-7bc7-4cea-a83e-f9160b2cb290" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/6349478e-9b7a-438a-bacd-95e7c157986b" />



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

Xem ý nghĩa public key 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/7d7ea122-e5f1-4233-b440-ade31937c81c" />

Xem ý nghĩa private key

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/e13f61fe-83ed-4990-8959-1cda0fbb6d4d" />



### 2.4. Yêu cầu 4 — Nhập PEM để lấy n, e (và d, p, q …)

Dùng `RSA.ImportFromPem()` rồi `ExportParameters()`:

- nhập `public.pem` → lấy được `n`, `e`;

- nhập `private.pem` → lấy được `n`, `e`, `d`, `p`, `q`, `dP`, `dQ`, `qInv`.

Các số được hiển thị dạng hex kèm độ dài bit.

Nhập public key lấy n,e

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/817fbd40-2a56-4c4f-afc2-93e373491dc7" />

Nhập private key lấy n,e, d ,p ,q

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/a378ad22-e017-4bc7-aed6-a93f05412562" />


### 2.5. Yêu cầu 5 — Mã hoá dữ liệu ≤ 190 byte bằng khoá vừa import

Dùng **RSA-OAEP với SHA-256**.

Dung lượng tối đa của OAEP: `k − 2·hLen − 2`, với `k` = độ dài khoá tính bằng byte, `hLen` = 32 byte (SHA-256).

Với khoá 2048 bit: `256 − 2·32 − 2 = 190 byte` — **khớp chính xác giới hạn 190 byte của đề bài**.

Khoá AES-256 chỉ 32 byte nên hoàn toàn nằm trong giới hạn; đây cũng là cách thực tế dùng RSA để **trao đổi khoá AES**.

Kết quả mã hoá là mảng byte 256 → chuyển Base64 → lưu file `.txt`.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/c1827515-41b8-4df8-9db4-de4a573bff75" />


### 2.6. Yêu cầu 6 — Giải mã và so sánh với nguồn

Đầu vào: file `private.pem` và file bản mã Base64.

Quy trình: đọc Base64 → giải mã bằng khoá bí mật → so sánh **từng byte** với dữ liệu nguồn ban đầu (`SequenceEqual`) → in kết quả KHỚP / KHÔNG KHỚP.

Giải mã

<img width="1913" height="1078" alt="image" src="https://github.com/user-attachments/assets/be4596a0-f0ac-4698-b28e-d304abf83e81" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/2006ed95-f6b3-4091-8a3b-c75c9881ecb5" />


### 2.7. Yêu cầu 7 — Đánh giá tốc độ mã hoá/giải mã

Lặp lại `N` lần (mặc định 200) hai phép: mã hoá bằng khoá công khai và giải mã bằng khoá bí mật, với các khoá 1024/2048/3072 bit; in thời gian trung bình (ms/lần), độ dài bit của `e` và `d`, và tỉ lệ chậm hơn.

**Nhận định kỳ vọng:** `e` chỉ 17 bit (vài phép nhân bình phương) trong khi `d` ~ 2048 bit (hàng nghìn phép nhân modulo) nên giải mã bằng khoá bí mật chậm hơn mã hoá bằng khoá công khai nhiều lần; khoá càng dài, khoảng cách càng lớn.

Lưu ý: thư viện giải mã bằng khoá bí mật dùng thêm tối ưu **CRT** (định lý số dư Trung Hoa với `p`, `q`, `dP`, `dQ`, `qInv`) nên nhanh hơn so với lý thuyết thuần `M = C^d mod n`, nhưng vẫn chậm hơn phép công khai.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/cb7e9435-f451-43cc-925f-f0297c616dca" />


### 2.8. Yêu cầu 8 — Giao diện sinh chuỗi băm SHA-256

Gõ dữ liệu vào ô nhập, mỗi lần thay đổi (từng ký tự) chương trình tính lại SHA-256 ngay lập tức, đồng thời hiển thị:

- mã băm mới và mã băm ngay trước đó;

- dòng đánh dấu `^` dưới các ký tự hex khác nhau;

- số bit khác nhau trên tổng 256 bit và tỉ lệ phần trăm.

**Nhận định kỳ vọng — hiệu ứng thác (avalanche effect):** chỉ đổi 1 ký tự đầu vào, mã băm thay đổi hoàn toàn, số bit khác xấp xỉ 50% (~128/256 bit). Không có mối liên hệ nào giữa mức độ thay đổi của đầu vào và đầu ra, nên không thể suy ngược dữ liệu từ mã băm.

Giao diện sinh chuỗi băm

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/bbd6cca7-95d2-4b93-96bb-c5a5ae2ed0a0" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/72e7a902-9727-4386-b903-f3b6a8e9892d" />


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

Tạo chữ ký

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/409d0edf-038e-43bf-9013-987218d4404f" />

Xác minh chữ ký

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/f24f6425-3516-4222-be17-2cd29774a19d" />


**Kết luận:**

1. **Mã hoá bằng khoá công khai nhanh hơn nhiều so với giải mã bằng khoá bí mật** vì `e` chỉ 17 bit còn `d` xấp xỉ độ dài `n`; khoá càng dài chênh lệch càng lớn.

2. **RSA chậm và giới hạn dung lượng** (tối đa 190 byte với khoá 2048 bit, OAEP-SHA256), nên chỉ dùng để mã hoá khoá AES 32 byte hoặc băm; dữ liệu lớn dùng AES (Bài 1).

3. **Mô hình lai (hybrid):** sinh khoá AES ngẫu nhiên → mã hoá dữ liệu bằng AES (nhanh) → mã hoá khoá AES bằng RSA public key của người nhận (an toàn) → người nhận giải mã khoá AES bằng private key.

## HA-256 — Hiệu ứng thác

Khi đổi một ký tự đầu vào (ví dụ `Hello World` → `Hello World.`), mã băm đổi hoàn toàn: số bit khác nhau ở các lần thử xấp xỉ **128/256 bit (~50%)**, các ký tự hex khác nhau rải đều khắp chuỗi.

Vì vậy mã băm đóng vai trò "dấu vân tay" của dữ liệu: chỉ cần sai lệch rất nhỏ là phát hiện được, và không thể suy ngược dữ liệu từ mã băm.

## Chữ ký số 

| Phương pháp | Cùng dữ liệu + cùng private key | Xác minh | Nhận xét |
|---|---|---|---|
| PKCS#1 v1.5 | Luôn **giống nhau** | ĐÚNG | Xác định, lộ việc hai văn bản trùng nhau |
| **RSA-PSS (salt ngẫu nhiên)** | **Khác nhau** mỗi lần ký | ĐÚNG | **Khuyến nghị**: chuẩn RFC 8017, có chứng minh an toàn |
| Nonce + PKCS#1 v1.5 | **Khác nhau** mỗi lần ký | ĐÚNG | Đơn giản, phải gửi kèm nonce (có thể dùng timestamp) |

Muốn cùng một dữ liệu, cùng một người ký mà chữ ký mỗi lần một khác, cần đưa **yếu tố ngẫu nhiên** (salt hoặc nonce) vào quá trình ký. Phương pháp tốt nhất là **RSA-PSS**; khi dữ liệu bị sửa dù chỉ 1 bit thì mã băm đổi hoàn toàn (hiệu ứng thác) và chữ ký lập tức **không còn xác minh đúng**, đảm bảo tính toàn vẹn và xác thực nguồn gốc.

---

*— Hết —*
