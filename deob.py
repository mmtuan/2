import sys
import base64
import lzma
import marshal
import dis
import zlib
import io
import binascii
import builtins
import types


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str):
    print(f"[*] {msg}", file=sys.stderr)


# ── Lớp 1-4: giải mã file gốc ────────────────────────────────────────────────

def decode_outer(path: str) -> types.CodeType:
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


# ── Thử giải mã bytes constant bằng nhiều cách ───────────────────────────────

def try_decode_bytes(b: bytes) -> str | None:
    attempts = [
        lambda: zlib.decompress(b).decode("utf-8", errors="replace"),
        lambda: zlib.decompress(b, -15).decode("utf-8", errors="replace"),
        lambda: lzma.decompress(b).decode("utf-8", errors="replace"),
        lambda: zlib.decompress(base64.b85decode(b)).decode("utf-8", errors="replace"),
        lambda: lzma.decompress(base64.b85decode(b)).decode("utf-8", errors="replace"),
        lambda: zlib.decompress(base64.b64decode(b)).decode("utf-8", errors="replace"),
        lambda: zlib.decompress(binascii.unhexlify(b)).decode("utf-8", errors="replace"),
        lambda: b.decode("utf-8") if b.decode("utf-8").isprintable() else None,
    ]
    for fn in attempts:
        try:
            result = fn()
            if result and len(result) > 2:
                return result
        except Exception:
            pass
    return None


# ── Patch exec/eval để bắt code bên trong ────────────────────────────────────

_captured_codes: list[tuple[str, object]] = []
_original_exec = builtins.exec
_original_eval = builtins.eval
_original_compile = builtins.compile


def _safe_exec(obj, globs=None, locs=None):
    if isinstance(obj, types.CodeType):
        _captured_codes.append(("exec:code", obj))
    elif isinstance(obj, str) and len(obj) > 10:
        _captured_codes.append(("exec:str", obj))
    # Không thực thi thật sự


def _safe_eval(obj, globs=None, locs=None):
    if isinstance(obj, types.CodeType):
        _captured_codes.append(("eval:code", obj))
    elif isinstance(obj, str) and len(obj) > 10:
        _captured_codes.append(("eval:str", obj))
    return None


def _safe_compile(source, filename, mode, *args, **kwargs):
    result = _original_compile(source, filename, mode, *args, **kwargs)
    if isinstance(source, str) and len(source) > 10:
        _captured_codes.append(("compile:str", source))
    return result


def run_in_sandbox(code_obj: types.CodeType) -> list[tuple[str, object]]:
    """Chạy code_obj trong sandbox với exec/eval bị patch."""
    log("Đang chạy trong sandbox (exec/eval bị chặn)...")
    builtins.exec = _safe_exec
    builtins.eval = _safe_eval
    builtins.compile = _safe_compile
    try:
        fake_globals = {
            "__name__": "__main__",
            "__builtins__": builtins,
        }
        _original_exec(code_obj, fake_globals)
    except Exception as e:
        log(f"Sandbox exception (bình thường): {type(e).__name__}: {e}")
    finally:
        builtins.exec = _original_exec
        builtins.eval = _original_eval
        builtins.compile = _original_compile
    log(f"Bắt được {len(_captured_codes)} code object / chuỗi bên trong")
    return list(_captured_codes)


# ── Decompiler ────────────────────────────────────────────────────────────────

def try_decompile(co: types.CodeType) -> str | None:
    for pkg in ("decompile", "uncompyle6.main"):
        try:
            if pkg == "decompile":
                import decompile  # type: ignore
                buf = io.StringIO()
                decompile.decompile_code(co, buf)
                return buf.getvalue()
            else:
                import uncompyle6.main as u6  # type: ignore
                buf = io.StringIO()
                u6.decompile_code(sys.version_info[:2], co, buf)
                return buf.getvalue()
        except Exception:
            pass
    return None


# ── Disassemble dạng dễ đọc ───────────────────────────────────────────────────

def disassemble(co: types.CodeType) -> str:
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        dis.dis(co)
    finally:
        sys.stdout = old
    return buf.getvalue()


# ── Thu thập chuỗi ───────────────────────────────────────────────────────────

def collect_strings(co: types.CodeType, results: list, seen: set | None = None):
    if seen is None:
        seen = set()
    if id(co) in seen:
        return
    seen.add(id(co))
    for c in co.co_consts:
        if isinstance(c, str) and len(c) > 2:
            if not all(ord(ch) > 3000 for ch in c[:8] if c):
                results.append(("STR", co.co_name, c))
        elif isinstance(c, bytes) and len(c) > 3:
            decoded = try_decode_bytes(c)
            if decoded:
                results.append(("BYTES", co.co_name, decoded))
        elif hasattr(c, "co_name"):
            collect_strings(c, results, seen)


# ── Ghi output ───────────────────────────────────────────────────────────────

def write_output(path: str, outer_co: types.CodeType, captured: list):
    with open(path, "w", encoding="utf-8") as f:

        # ── PHẦN 1: Chuỗi đọc được từ lớp ngoài ──
        f.write("=" * 70 + "\n")
        f.write("PHẦN 1: CHUỖI GIẢI MÃ TỪ LỚP NGOÀI\n")
        f.write("=" * 70 + "\n\n")
        strings: list = []
        collect_strings(outer_co, strings)
        if strings:
            for kind, fn, val in strings:
                f.write(f"[{kind} | hàm: {fn}]\n  {repr(val)}\n\n")
        else:
            f.write("(không có chuỗi đọc được)\n")

        # ── PHẦN 2: Code bắt được qua sandbox ──
        f.write("\n" + "=" * 70 + "\n")
        f.write("PHẦN 2: CODE BẮT ĐƯỢC KHI CHẠY SANDBOX\n")
        f.write("=" * 70 + "\n\n")

        if not captured:
            f.write("(không bắt được gì — code có thể kiểm tra môi trường trước khi exec)\n")
        else:
            for i, (kind, obj) in enumerate(captured):
                f.write(f"\n--- [{i+1}] Loại: {kind} ---\n")
                if isinstance(obj, str):
                    f.write(obj + "\n")
                elif isinstance(obj, types.CodeType):
                    # Thử decompile trước
                    src = try_decompile(obj)
                    if src:
                        f.write("# ✅ Decompile thành công:\n")
                        f.write(src + "\n")
                    else:
                        f.write("# ℹ️  Bytecode disassembly (decompile3 chưa hỗ trợ Python 3.13):\n")
                        f.write(disassemble(obj) + "\n")

                    # Chuỗi trong code này
                    inner: list = []
                    collect_strings(obj, inner)
                    if inner:
                        f.write("\n# Chuỗi trong code object này:\n")
                        for kind2, fn2, val2 in inner:
                            f.write(f"#   [{kind2}] {repr(val2)}\n")

        # ── PHẦN 3: Bytecode lớp ngoài ──
        f.write("\n" + "=" * 70 + "\n")
        f.write("PHẦN 3: BYTECODE LỚP NGOÀI (tham khảo)\n")
        f.write("=" * 70 + "\n\n")
        src = try_decompile(outer_co)
        if src:
            f.write("# ✅ Decompile thành công:\n")
            f.write(src + "\n")
        else:
            f.write("# ℹ️  Bytecode:\n")
            f.write(disassemble(outer_co) + "\n")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Dùng: python deob.py <input.py> [output.py]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "deobfuscated_output.txt"

    log(f"Đang xử lý: {input_path}")
    outer_co = decode_outer(input_path)
    captured = run_in_sandbox(outer_co)
    write_output(output_path, outer_co, captured)
    log(f"Xong! Kết quả: {output_path}")


if __name__ == "__main__":
    main()
