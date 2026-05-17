"""
Trích xuất marshal bytes từ file obfuscated và lưu thành .pyc
để pycdc có thể decompile.
"""

import sys
import base64
import lzma
import marshal
import struct
import os
import time


def decode_to_pyc(input_path: str, output_dir: str):
    print(f"[*] Đọc: {input_path}")
    with open(input_path, "rb") as f:
        content = f.read()

    idx = content.index(b"b85decode(b'")
    start = idx + len(b"b85decode(b'")
    end = start
    while end < len(content):
        if content[end:end+1] == b"'":
            break
        end += 1

    blob = content[start:end]
    decoded = base64.b85decode(blob[::-1])
    decompressed = lzma.decompress(decoded)

    # Tạo file .pyc hợp lệ để pycdc đọc được
    # .pyc format: magic (4 bytes) + flags (4) + timestamp (4) + size (4) + marshal data
    # Magic number Python 3.13: 0x0D0D (cần kiểm tra thực tế)
    # Dùng magic number từ sys.implementation
    import importlib.util
    magic = importlib.util.MAGIC_NUMBER  # magic number của Python đang chạy

    # Header .pyc
    flags = struct.pack("<I", 0)
    timestamp = struct.pack("<I", int(time.time()))
    source_size = struct.pack("<I", len(decompressed))

    pyc_content = magic + flags + timestamp + source_size + decompressed

    name = os.path.basename(input_path).replace(".py", "")
    out_path = os.path.join(output_dir, f"{name}.pyc")
    with open(out_path, "wb") as f:
        f.write(pyc_content)

    print(f"[+] Đã tạo: {out_path} ({len(pyc_content):,} bytes)")
    return out_path


def main():
    if len(sys.argv) < 2:
        print("Dùng: python extract_marshal.py <thư_mục_chứa_file_py>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = "results"
    os.makedirs(output_dir, exist_ok=True)

    found = 0
    for fname in os.listdir(input_dir):
        if fname.endswith(".py"):
            try:
                decode_to_pyc(os.path.join(input_dir, fname), output_dir)
                found += 1
            except Exception as e:
                print(f"[!] Lỗi với {fname}: {e}")

    print(f"\n[+] Xong: {found} file đã xuất ra {output_dir}/")


if __name__ == "__main__":
    main()
