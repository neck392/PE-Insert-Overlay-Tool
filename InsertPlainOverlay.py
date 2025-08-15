# Overwrite/update the existing helper tool to support a *plain ASCII* overlay mode.
# New commands:
#   hide-plain     -> insert human-readable ASCII payload before the PyInstaller cookie
#   extract-plain  -> extract that ASCII payload by parsing the 'OVP1' marker
tool_code = r'''#!/usr/bin/env python3
"""
pyi_overlay_tool.py  (updated)
- Hide/extract data in the overlay of a PyInstaller --onefile EXE.
- Supports two modes:
    1) hide / extract          : XOR-obfuscated payload (marker 'OVH1')
    2) hide-plain / extract-plain : Plain ASCII payload (marker 'OVP1'), easily visible via hex/strings

Usage examples:
  # Plain ASCII (visible in overlay)
  python pyi_overlay_tool.py hide-plain --in Hello.exe --out Hello_plain.exe --text "VISIBLE_OVERLAY_DEMO"

  # Extract the plain payload
  python pyi_overlay_tool.py extract-plain --in Hello_plain.exe

  # Original XOR mode (still available)
  python pyi_overlay_tool.py hide --in Hello.exe --out Hello_mod.exe --text "SECRET" [--key 0x5A]
  python pyi_overlay_tool.py extract --in Hello_mod.exe
"""
import argparse, struct, sys

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

def u16(b, off): 
    import struct
    return struct.unpack_from("<H", b, off)[0]

def u32(b, off): 
    import struct
    return struct.unpack_from("<I", b, off)[0]

def sha256(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()

def pe_logical_end(buf):
    # returns the "logical end" (end of headers/sections and certificate table if present)
    if buf[:2] != b"MZ":
        raise ValueError("Not an MZ/PE file.")
    e_lfanew = u32(buf, 0x3C)
    if buf[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        raise ValueError("PE signature not found.")
    coff_off = e_lfanew + 4
    num_secs = u16(buf, coff_off + 2)
    size_opt = u16(buf, coff_off + 16)
    opt_off  = coff_off + 20
    size_headers = u32(buf, opt_off + 60)
    sec_off = opt_off + size_opt
    logical_end = size_headers
    for i in range(num_secs):
        off = sec_off + i*40
        size_raw = u32(buf, off+16)
        ptr_raw  = u32(buf, off+20)
        logical_end = max(logical_end, ptr_raw + size_raw)
    # Certificate table (data directory #4) uses file offsets (not RVA)
    magic = u16(buf, opt_off + 0)
    dd_off = opt_off + (112 if magic == 0x20B else 96 if magic == 0x10B else 0)
    if dd_off:
        cert_off = u32(buf, dd_off + 4*8 + 0)
        cert_sz  = u32(buf, dd_off + 4*8 + 4)
        if cert_off and cert_sz:
            logical_end = max(logical_end, cert_off + cert_sz)
    return logical_end

def find_pyinstaller_cookie(buf):
    # Heuristic: search 'MEI' within last 512 bytes
    tail = buf[-512:]
    idx = tail.find(b"MEI")
    if idx == -1:
        return None
    return len(buf) - 512 + idx

def xor_bytes(data, key):
    return bytes((b ^ key) for b in data)

# ---- XOR mode (legacy) ----
def cmd_hide(args):
    buf = read_file(args.infile)
    cookie_off = find_pyinstaller_cookie(buf)
    if cookie_off is None:
        print("[!] PyInstaller cookie not found in last 512 bytes. Refusing to modify.", file=sys.stderr)
        sys.exit(2)
    key = args.key
    raw = args.text.encode("utf-8")
    enc = xor_bytes(raw, key)
    payload = b"OVH1" + struct.pack("<I", len(enc)) + bytes([key]) + enc
    mod = buf[:cookie_off] + payload + buf[cookie_off:]
    write_file(args.outfile, mod)
    print(f"[+] Wrote: {args.outfile}")
    print(f"    Inserted {len(payload)} bytes at offset {cookie_off:,} (before cookie)")
    print(f"    New file size: {len(mod):,} bytes")
    print(f"    SHA-256: {sha256(mod)}")
    new_cookie = find_pyinstaller_cookie(mod)
    print(f"    Cookie in last 512 bytes: {'YES' if new_cookie is not None else 'NO'}")

def cmd_extract(args):
    buf = read_file(args.infile)
    try:
        ovl = pe_logical_end(buf)
    except Exception:
        ovl = 0
    i = buf.find(b"OVH1", ovl)  # search starting at overlay
    if i == -1:
        print("[-] OVH1 marker not found (no XOR payload).")
        return
    L = u32(buf, i+4)
    key = buf[i+8]
    enc = buf[i+9:i+9+L]
    if len(enc) != L:
        print("[!] Truncated payload detected.")
        return
    raw = xor_bytes(enc, key)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    if args.outfile:
        write_file(args.outfile, raw)
        print(f"[+] Extracted {L} bytes to: {args.outfile}")
    else:
        print(text)

# ---- PLAIN ASCII mode ----
def cmd_hide_plain(args):
    buf = read_file(args.infile)
    cookie_off = find_pyinstaller_cookie(buf)
    if cookie_off is None:
        print("[!] PyInstaller cookie not found in last 512 bytes. Refusing to modify.", file=sys.stderr)
        sys.exit(2)
    raw = args.text.encode("utf-8")
    # Marker 'OVP1' + <uint32 length> + plain bytes + newline
    payload = b"OVP1" + struct.pack("<I", len(raw)) + raw + b"\n"
    mod = buf[:cookie_off] + payload + buf[cookie_off:]
    write_file(args.outfile, mod)
    print(f"[+] Wrote: {args.outfile}")
    print(f"    Inserted {len(payload)} bytes at offset {cookie_off:,} (before cookie)")
    print(f"    New file size: {len(mod):,} bytes")
    print(f"    SHA-256: {sha256(mod)}")
    new_cookie = find_pyinstaller_cookie(mod)
    print(f"    Cookie in last 512 bytes: {'YES' if new_cookie is not None else 'NO'}")
    print("    Tip: Visible marker 'OVP1' and your text are now grep/strings-detectable in the overlay.")

def cmd_extract_plain(args):
    buf = read_file(args.infile)
    try:
        ovl = pe_logical_end(buf)
    except Exception:
        ovl = 0
    i = buf.find(b"OVP1", ovl)  # search starting at overlay
    if i == -1:
        print("[-] OVP1 marker not found (no plain payload).")
        return
    L = u32(buf, i+4)
    plain = buf[i+8:i+8+L]
    if len(plain) != L:
        print("[!] Truncated payload detected.")
        return
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        text = plain.decode("utf-8", errors="replace")
    if args.outfile:
        write_file(args.outfile, plain)
        print(f"[+] Extracted {L} bytes to: {args.outfile}")
    else:
        print(text)

def main():
    ap = argparse.ArgumentParser(description="PyInstaller onefile overlay hider/extractor (XOR & PLAIN ASCII).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # XOR mode
    ap_h = sub.add_parser("hide", help="Hide a string in overlay (XOR, marker OVH1).")
    ap_h.add_argument("--in", dest="infile", required=True, help="Input EXE path")
    ap_h.add_argument("--out", dest="outfile", required=True, help="Output EXE path")
    ap_h.add_argument("--text", required=True, help="String to hide")
    ap_h.add_argument("--key", type=lambda x: int(x,0), default=0x5A, help="XOR key (int, e.g., 0x5A)")
    ap_h.set_defaults(func=cmd_hide)

    ap_e = sub.add_parser("extract", help="Extract XOR payload (OVH1).")
    ap_e.add_argument("--in", dest="infile", required=True, help="Input EXE path")
    ap_e.add_argument("--out", dest="outfile", help="Optional output file")
    ap_e.set_defaults(func=cmd_extract)

    # PLAIN mode
    ap_hp = sub.add_parser("hide-plain", help="Hide a PLAIN ASCII string in overlay (marker OVP1).")
    ap_hp.add_argument("--in", dest="infile", required=True, help="Input EXE path")
    ap_hp.add_argument("--out", dest="outfile", required=True, help="Output EXE path")
    ap_hp.add_argument("--text", required=True, help="ASCII/UTF-8 text to embed visibly")
    ap_hp.set_defaults(func=cmd_hide_plain)

    ap_ep = sub.add_parser("extract-plain", help="Extract PLAIN ASCII payload (OVP1).")
    ap_ep.add_argument("--in", dest="infile", required=True, help="Input EXE path")
    ap_ep.add_argument("--out", dest="outfile", help="Optional output file")
    ap_ep.set_defaults(func=cmd_extract_plain)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
'''
tool_path = "/mnt/data/pyi_overlay_tool.py"
with open(tool_path, "w", encoding="utf-8") as f:
    f.write(tool_code)

tool_path
