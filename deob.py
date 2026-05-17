"""
Deobfuscator - giải mã toàn bộ các lớp mã hóa một lần:
  Lớp 1: blob[::-1]  (đảo ngược)
  Lớp 2: base64.b85decode
  Lớp 3: lzma.decompress
  Lớp 4: marshal.loads  -> code object
  Lớp 5: các chuỗi bytes bên trong (zlib / base85 / hex lồng nhau)
"""

import sys
import base64
import lzma
import marshal
import dis
import zlib
import io
import binascii


# ── Lớp 1-4: giải mã file gốc ────────────────────────────────────────────────

def decode_outer(path: str):
    with open(path, "rb") as f:
        content = f.read()

    idx = content.index(b"b85decode(b'")
    start = idx + len(b"b85decode(b'")
    end = start
    while end < len(content):
        if content[end:end+1] == b"'":
            break
        end += 1

    blob = content[start:end]
    log(f"Blob: {len(blob):,} bytes")

    decoded = base64.b85decode(blob[::-1])
    log(f"Sau base85: {len(decoded):,} bytes")

    decompressed = lzma.decompress(decoded)
    log(f"Sau LZMA: {len(decompressed):,} bytes")

    code_obj = marshal.loads(decompressed)
    log(f"Marshal OK: {code_obj.co_name}")
    return code_obj


# ── Lớp 5: giải mã chuỗi bytes bên trong ────────────────────────────────────

def try_decode_bytes(b: bytes) -> str | None:
    """Thử nhiều cách giải mã một bytes constant."""
    # zlib
    try:
        return zlib.decompress(b).decode("utf-8", errors="replace")
    except Exception:
        pass
    # zlib wbits=-15
    try:
        return zlib.decompress(b, -15).decode("utf-8", errors="replace")
    except Exception:
        pass
    # base85 -> zlib
    try:
        return zlib.decompress(base64.b85decode(b)).decode("utf-8", errors="replace")
    except Exception:
        pass
    # base85 -> lzma
    try:
        return lzma.decompress(base64.b85decode(b)).decode("utf-8", errors="replace")
    except Exception:
        pass
    # hex -> zlib
    try:
        return zlib.decompress(binascii.unhexlify(b)).decode("utf-8", errors="replace")
    except Exception:
        pass
    # base64 -> zlib
    try:
        return zlib.decompress(base64.b64decode(b)).decode("utf-8", errors="replace")
    except Exception:
        pass
    # thuần utf-8
    try:
        s = b.decode("utf-8")
        if s.isprintable() and len(s) > 3:
            return s
    except Exception:
        pass
    return None


# ── Thu thập toàn bộ thông tin từ code object ────────────────────────────────

def collect_all(co, out: io.StringIO, depth=0, seen=None):
    if seen is None:
        seen = set()
    if id(co) in seen:
        return
    seen.add(id(co))

    indent = "    " * depth
    sep = "=" * (60 - depth * 4)

    out.write(f"\n{indent}{sep}\n")
    out.write(f"{indent}HÀM: {co.co_name}  "
              f"(dòng {co.co_firstlineno}, file: {co.co_filename})\n")
    if co.co_argcount:
        out.write(f"{indent}Tham số: {co.co_varnames[:co.co_argcount]}\n")

    # Hằng số
    decoded_any = False
    for i, c in enumerate(co.co_consts):
        if isinstance(c, str) and len(c) > 1:
            # Bỏ qua tên hàm Unicode thuần
            if not all(ord(ch) > 3000 for ch in c[:8] if c):
                out.write(f"{indent}  [chuỗi]: {repr(c)}\n")
                decoded_any = True
        elif isinstance(c, bytes) and len(c) > 3:
            result = try_decode_bytes(c)
            if result:
                out.write(f"{indent}  [bytes giải mã #{i}]: {repr(result)}\n")
                decoded_any = True
            else:
                out.write(f"{indent}  [bytes thô #{i}]: {c[:60]!r}{'...' if len(c)>60 else ''}\n")
                decoded_any = True

    # Tên biến / hàm được gọi (lọc bỏ Unicode rác)
    readable_names = [n for n in co.co_names
                      if n and not all(ord(ch) > 3000 for ch in n[:5])]
    if readable_names:
        out.write(f"{indent}  [names]: {readable_names}\n")

    # Bytecode
    out.write(f"\n{indent}  -- BYTECODE --\n")
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        dis.dis(co)
    finally:
        sys.stdout = old
    for line in buf.getvalue().splitlines():
        out.write(f"{indent}  {line}\n")

    # Thử decompile nếu có
    src = try_decompile(co)
    if src:
        out.write(f"\n{indent}  -- MÃ NGUỒN (decompile) --\n")
        for line in src.splitlines():
            out.write(f"{indent}  {line}\n")

    # Đệ quy hàm con
    for c in co.co_consts:
        if hasattr(c, "co_name"):
            collect_all(c, out, depth + 1, seen)


def try_decompile(co) -> str | None:
    try:
        import decompile  # type: ignore
        buf = io.StringIO()
        decompile.decompile_code(co, buf)
        return buf.getvalue()
    except Exception:
        pass
    try:
        import uncompyle6.main as u6  # type: ignore
        buf = io.StringIO()
        u6.decompile_code(sys.version_info[:2], co, buf)
        return buf.getvalue()
    except Exception:
        pass
    return None


# ── Tóm tắt nhanh ────────────────────────────────────────────────────────────

def quick_summary(co, out: io.StringIO, seen=None):
    """In ngắn gọn tất cả chuỗi có thể đọc được (không bytecode)."""
    if seen is None:
        seen = set()
    if id(co) in seen:
        return
    seen.add(id(co))

    for c in co.co_consts:
        if isinstance(c, str) and len(c) > 2:
            if not all(ord(ch) > 3000 for ch in c[:8] if c):
                out.write(f"[STR | {co.co_name}] {repr(c)}\n")
        elif isinstance(c, bytes) and len(c) > 3:
            result = try_decode_bytes(c)
            if result and len(result) > 2:
                out.write(f"[DECODED | {co.co_name}] {repr(result)}\n")
        elif hasattr(c, "co_name"):
            quick_summary(c, out, seen)


# ── Main ─────────────────────────────────────────────────────────────────────

def log(msg: str):
    print(f"[*] {msg}", file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        print("Dùng: python deob.py <input.py> [output.py]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "deobfuscated_output.py"

    log(f"Đang xử lý: {input_path}")
    code_obj = decode_outer(input_path)

    out = io.StringIO()

    # Phần 1: Tóm tắt nhanh - dễ đọc
    out.write("=" * 70 + "\n")
    out.write("TÓM TẮT NHANH - TẤT CẢ CHUỖI CÓ THỂ ĐỌC ĐƯỢC\n")
    out.write("=" * 70 + "\n\n")
    quick_summary(code_obj, out)

    # Phần 2: Chi tiết đầy đủ với bytecode
    out.write("\n\n" + "=" * 70 + "\n")
    out.write("CHI TIẾT ĐẦY ĐỦ - BYTECODE + GIẢI MÃ TỪNG HÀM\n")
    out.write("=" * 70 + "\n")
    collect_all(code_obj, out)

    result = out.getvalue()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result)

    log(f"Xong! Kết quả: {output_path}")


if __name__ == "__main__":
    main()
