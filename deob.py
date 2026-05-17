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
import re


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


# ── Thử giải mã bytes constant ───────────────────────────────────────────────

def try_decode_bytes(b: bytes) -> str | None:
    attempts = [
        lambda: zlib.decompress(b).decode("utf-8", errors="replace"),
        lambda: zlib.decompress(b, -15).decode("utf-8", errors="replace"),
        lambda: lzma.decompress(b).decode("utf-8", errors="replace"),
        lambda: zlib.decompress(base64.b85decode(b)).decode("utf-8", errors="replace"),
        lambda: lzma.decompress(base64.b85decode(b)).decode("utf-8", errors="replace"),
        lambda: zlib.decompress(base64.b64decode(b)).decode("utf-8", errors="replace"),
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


# ── Sandbox thông minh ────────────────────────────────────────────────────────

_captured: list[tuple[str, object]] = []
_orig_exec    = builtins.exec
_orig_eval    = builtins.eval
_orig_compile = builtins.compile
_orig_import  = builtins.__import__
_orig_print   = builtins.print
_orig_open    = builtins.open

# Ngưỡng: nếu code/string dài hơn thế này → coi là payload thật
PAYLOAD_MIN_LEN = 500


def _is_payload(obj) -> bool:
    """Kiểm tra obj có phải là payload thật cần chặn không."""
    if isinstance(obj, types.CodeType):
        # Code object có nhiều constant/name → là payload
        if len(obj.co_consts) > 10 or len(obj.co_names) > 5:
            return True
        # Code object có nested code objects → là payload
        if any(hasattr(c, "co_name") for c in obj.co_consts):
            return True
    if isinstance(obj, str) and len(obj) > PAYLOAD_MIN_LEN:
        return True
    return False


def _smart_exec(obj, globs=None, locs=None):
    if _is_payload(obj):
        log(f"  ✅ Bắt được exec payload: {type(obj).__name__}, size={len(obj.co_consts) if isinstance(obj, types.CodeType) else len(obj)}")
        _captured.append(("exec", obj))
        return None  # Không thực thi
    # Cho chạy thật nếu nhỏ/đơn giản
    try:
        return _orig_exec(obj, globs or {}, locs)
    except Exception:
        pass


def _smart_eval(obj, globs=None, locs=None):
    if _is_payload(obj):
        log(f"  ✅ Bắt được eval payload: {type(obj).__name__}")
        _captured.append(("eval", obj))
        return None
    # Cho chạy thật
    try:
        return _orig_eval(obj, globs or {}, locs)
    except Exception:
        return None


def _smart_compile(source, filename, mode, *args, **kwargs):
    result = _orig_compile(source, filename, mode, *args, **kwargs)
    if isinstance(source, str) and len(source) > PAYLOAD_MIN_LEN:
        log(f"  ✅ Bắt được compile: {len(source)} ký tự")
        _captured.append(("compile:str", source))
    return result


def _smart_import(name, *args, **kwargs):
    log(f"  📦 import: {name}")
    # Chặn những module nguy hiểm
    blocked = {"subprocess", "socket", "os", "shutil", "ctypes"}
    if name in blocked:
        log(f"  🚫 Blocked import: {name}")
        raise ImportError(f"Blocked: {name}")
    return _orig_import(name, *args, **kwargs)


_print_log: list[str] = []
def _smart_print(*args, **kwargs):
    line = " ".join(str(a) for a in args)
    _print_log.append(line)
    log(f"  📢 print: {line[:200]}")


def run_sandbox(code_obj: types.CodeType) -> list[tuple[str, object]]:
    log("Đang chạy sandbox thông minh (chỉ chặn payload lớn)...")
    builtins.exec    = _smart_exec
    builtins.eval    = _smart_eval
    builtins.compile = _smart_compile
    builtins.__import__ = _smart_import
    builtins.print   = _smart_print
    try:
        fake_globals = {
            "__name__": "__main__",
            "__builtins__": builtins,
        }
        _orig_exec(code_obj, fake_globals)
    except ZeroDivisionError:
        log("  ⚠️  ZeroDivisionError (bình thường - trick chống debug)")
    except SystemExit:
        log("  ⚠️  SystemExit")
    except Exception as e:
        log(f"  ⚠️  Exception: {type(e).__name__}: {e}")
    finally:
        builtins.exec    = _orig_exec
        builtins.eval    = _orig_eval
        builtins.compile = _orig_compile
        builtins.__import__ = _orig_import
        builtins.print   = _orig_print
    log(f"Kết quả sandbox: {len(_captured)} payload bắt được")
    return list(_captured)


# ── Disassemble & decompile ───────────────────────────────────────────────────

def disassemble(co: types.CodeType) -> str:
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        dis.dis(co)
    finally:
        sys.stdout = old
    return buf.getvalue()


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


# ── Chuỗi có thể đọc được ────────────────────────────────────────────────────

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
            dec = try_decode_bytes(c)
            if dec:
                results.append(("BYTES", co.co_name, dec))
        elif hasattr(c, "co_name"):
            collect_strings(c, results, seen)


# ── Ghi output ───────────────────────────────────────────────────────────────

def write_output(path: str, outer_co: types.CodeType, captured: list):
    with open(path, "w", encoding="utf-8") as f:

        # PHẦN 1: chuỗi lớp ngoài
        f.write("=" * 70 + "\n")
        f.write("PHẦN 1: CHUỖI GIẢI MÃ TỪ LỚP NGOÀI\n")
        f.write("=" * 70 + "\n\n")
        strs: list = []
        collect_strings(outer_co, strs)
        for kind, fn, val in strs:
            f.write(f"[{kind} | {fn}]  {repr(val)}\n")

        # PHẦN 2: print output bắt được
        if _print_log:
            f.write("\n" + "=" * 70 + "\n")
            f.write("PHẦN 2: OUTPUT (print) BẮT ĐƯỢC KHI CHẠY\n")
            f.write("=" * 70 + "\n\n")
            for line in _print_log:
                f.write(line + "\n")

        # PHẦN 3: payload bắt được
        f.write("\n" + "=" * 70 + "\n")
        f.write("PHẦN 3: PAYLOAD BẮT ĐƯỢC\n")
        f.write("=" * 70 + "\n\n")

        if not captured:
            f.write("⚠️  Không bắt được payload.\n")
            f.write("    Code có thể dùng thêm lớp anti-sandbox khác.\n")
            f.write("    Xem Phần 4 để đọc bytecode thủ công.\n")
        else:
            for i, (kind, obj) in enumerate(captured):
                f.write(f"\n--- [{i+1}] {kind} ---\n")
                if isinstance(obj, str):
                    # Thử giải mã nếu trông như encoded
                    decoded = None
                    if len(obj) > 100 and not ' ' in obj[:50]:
                        try:
                            decoded = base64.b64decode(obj).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                    f.write(decoded if decoded else obj)
                    f.write("\n")
                elif isinstance(obj, types.CodeType):
                    src = try_decompile(obj)
                    if src:
                        f.write("# ✅ Decompile thành công:\n")
                        f.write(src + "\n")
                    else:
                        f.write("# Bytecode:\n")
                        f.write(disassemble(obj) + "\n")
                    inner: list = []
                    collect_strings(obj, inner)
                    if inner:
                        f.write("\n# Chuỗi trong payload:\n")
                        for k, fn, v in inner:
                            f.write(f"#   {repr(v)}\n")

        # PHẦN 4: bytecode lớp ngoài
        f.write("\n" + "=" * 70 + "\n")
        f.write("PHẦN 4: BYTECODE LỚP NGOÀI\n")
        f.write("=" * 70 + "\n\n")
        src = try_decompile(outer_co)
        f.write(src if src else disassemble(outer_co))
        f.write("\n")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Dùng: python deob.py <input.py> [output.py]")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output.txt"
    log(f"Đang xử lý: {input_path}")
    outer_co = decode_outer(input_path)
    captured = run_sandbox(outer_co)
    write_output(output_path, outer_co, captured)
    log(f"Xong! → {output_path}")


if __name__ == "__main__":
    main()
