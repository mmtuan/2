"""
obfuscator cho các file Python bị mã hóa theo cấu trúc:
  exec(marshal.loads(lzma.decompress(base64.b85decode(blob[::-1]))))

Cách dùng:
  python deob.py <input_file.py> [output_file.py]
"""

import sys
import re
import base64
import lzma
import marshal
import dis
import io

def decode_file(path: str) -> object:
    with open(path, "rb") as f:
        content = f.read()

    # Tìm blob base85
    idx = content.index(b"b85decode(b'")
    start = idx + len(b"b85decode(b'")
    end = start
    while end < len(content):
        if content[end:end+1] == b"'":
            break
        end += 1

    blob = content[start:end]
    print(f"[*] Blob length: {len(blob):,} bytes", file=sys.stderr)

    # Reverse + base85 decode
    decoded = base64.b85decode(blob[::-1])
    print(f"[*] After base85 decode: {len(decoded):,} bytes", file=sys.stderr)

    # LZMA decompress
    decompressed = lzma.decompress(decoded)
    print(f"[*] After LZMA decompress: {len(decompressed):,} bytes", file=sys.stderr)

    # Marshal load
    code_obj = marshal.loads(decompressed)
    print(f"[*] Marshal loaded: {type(code_obj)}", file=sys.stderr)
    return code_obj


def try_decompile(code_obj) -> str | None:
    """Thử dùng decompile3 hoặc uncompyle6 để ra mã nguồn."""
    # decompile3 (hỗ trợ Python 3.x tốt hơn)
    try:
        import decompile  # type: ignore
        out = io.StringIO()
        decompile.decompile_code(code_obj, out)
        return out.getvalue()
    except Exception as e:
        print(f"[!] decompile3 failed: {e}", file=sys.stderr)

    # uncompyle6
    try:
        import uncompyle6.main as u6  # type: ignore
        out = io.StringIO()
        u6.decompile_code(sys.version_info[:2], code_obj, out)
        return out.getvalue()
    except Exception as e:
        print(f"[!] uncompyle6 failed: {e}", file=sys.stderr)

    return None


def disassemble_to_text(code_obj) -> str:
    """Fallback: dùng dis để dump bytecode dạng đọc được."""
    out = io.StringIO()

    def dump(co, depth=0):
        indent = "  " * depth
        out.write(f"\n{indent}{'='*60}\n")
        out.write(f"{indent}FUNCTION: {co.co_name}  (file: {co.co_filename}, line: {co.co_firstlineno})\n")
        out.write(f"{indent}args: {co.co_varnames[:co.co_argcount]}\n")

        # In hằng số chuỗi có thể đọc được
        readable_consts = []
        for c in co.co_consts:
            if isinstance(c, str) and len(c) > 1 and not all(ord(ch) > 3000 for ch in c[:5] if c):
                readable_consts.append(repr(c))
            elif isinstance(c, bytes):
                try:
                    s = c.decode("utf-8")
                    if s.isprintable() and len(s) > 3:
                        readable_consts.append(f"b{repr(s)}")
                except Exception:
                    pass
        if readable_consts:
            out.write(f"{indent}readable consts: {readable_consts}\n")

        # Bytecode
        old_stdout = sys.stdout
        sys.stdout = out
        try:
            dis.dis(co)
        finally:
            sys.stdout = old_stdout

        # Đệ quy vào hàm con
        for c in co.co_consts:
            if hasattr(c, "co_name"):
                dump(c, depth + 1)

    dump(code_obj)
    return out.getvalue()


def main():
    if len(sys.argv) < 2:
        print("Usage: python deob.py <input.py> [output.py]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "deobfuscated_output.py"

    print(f"[*] Processing: {input_path}", file=sys.stderr)
    code_obj = decode_file(input_path)

    print("[*] Trying decompiler...", file=sys.stderr)
    source = try_decompile(code_obj)

    if source:
        print("[+] Decompiler succeeded! Writing source code.", file=sys.stderr)
        result = source
    else:
        print("[~] Decompiler unavailable, falling back to bytecode disassembly.", file=sys.stderr)
        result = "# *** BYTECODE DISASSEMBLY (decompiler not available for Python 3.13) ***\n"
        result += "# Install: pip install decompile3\n\n"
        result += disassemble_to_text(code_obj)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"[+] Done! Output written to: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
