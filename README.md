# Deobfuscator Tool

Giải mã các file Python bị obfuscate theo cấu trúc:
`exec(marshal.loads(lzma.decompress(base64.b85decode(blob[::-1]))))`

## Cách dùng trên GitHub Actions

1. **Tạo repo GitHub mới** và upload toàn bộ thư mục này vào
2. Để file Python cần giải mã vào thư mục `files/` trong repo
3. Vào tab **Actions** → chọn workflow **"Deobfuscate Python Files"**
4. Bấm **"Run workflow"** → nhập tên file → bấm **Run**
5. Sau khi chạy xong, tải file kết quả ở mục **Artifacts**

## Cách dùng thủ công (cần Python 3.13)

```bash
# Cài decompiler (tùy chọn, cho kết quả tốt hơn)
pip install decompile3

# Chạy
python deob.py target.py output.py
```

## Kết quả trả về

- Nếu có decompiler: **mã nguồn Python** gần như gốc
- Nếu không có: **bytecode disassembly** — vẫn đọc được logic chính

## Lưu ý

- File gốc yêu cầu Python 3.13; GitHub Actions có hỗ trợ sẵn
- Tên hàm bị obfuscate bằng ký tự Unicode — decompiler sẽ giữ nguyên tên đó
- Các chuỗi bên trong có thể còn một lớp mã hóa nữa (zlib + base85)
