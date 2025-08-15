# Create a small local tool the user can download and run to hide/extract a string in the overlay
# without needing to download the large EXE. This script works on the user's own Hello.exe locally.
import textwrap, os, hashlib, struct

tool_code = r'''#!/usr/bin/env python3
"""
pyi_overlay_tool.py
- Hide a string inside the overlay of a PyInstaller --onefile EXE (before the EOF cookie so it still runs)
- Extract that hidden string later

Usage:
  python pyi_overlay_tool.py hide --in Hello.exe --out Hello_mod.exe --text "SECRET" [--key 0x5A]
  python pyi_overlay_tool.py extract --in Hello_mod.exe [--out secret.txt]

Notes:
- Inserts payload right BEFORE the PyInstaller cookie (EOF tail "MEI..." bytes), so the cookie stays in the EOF tail.
- Payload format: b"OVH1" + <uint32 length> + <1-byte key> + <XOR(key) data>
"""
import argparse, struct, sys, os, hashlib

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

def u16(b, off): return struct.unpack_from("<H", b, off)[0]
def u32(b, off): return struct.unpack_from("<I", b, off)[0]

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

def sha256(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()

def cmd_hide(args):
    buf = read_file(args.infile)
    cookie_off = find_pyinstaller_cookie(buf)
    if cookie_off is None:
        print("[!] PyInstaller cookie not found in last 512 bytes. Refusing to modify.", file=sys.stderr)
        sys.exit(2)
    # Build payload
    key = args.key
    raw = args.text.encode("utf-8")
    enc = xor_bytes(raw, key)
    payload = b"OVH1" + struct.pack("<I", len(enc)) + bytes([key]) + enc
    # Insert payload before cookie so cookie remains in EOF tail
    mod = buf[:cookie_off] + payload + buf[cookie_off:]
    write_file(args.outfile, mod)
    # Report
    print(f"[+] Wrote: {args.outfile}")
    print(f"    Inserted {len(payload)} bytes at offset {cookie_off:,} (before cookie)")
    print(f"    New file size: {len(mod):,} bytes")
    print(f"    SHA-256: {sha256(mod)}")
    # Sanity: cookie should still be in last 512 bytes
    new_cookie = find_pyinstaller_cookie(mod)
    print(f"    Cookie in last 512 bytes: {'YES' if new_cookie is not None else 'NO'}")

def cmd_extract(args):
    buf = read_file(args.infile)
    # Search within overlay only to reduce false positives
    try:
        ovl = pe_logical_end(buf)
    except Exception:
        ovl = 0
    i = buf.find(b"OVH1", ovl)  # search starting at overlay
    if i == -1:
        print("[-] OVH1 marker not found (no hidden payload).")
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

def main():
    ap = argparse.ArgumentParser(description="PyInstaller onefile overlay hider/extractor (safe & minimal).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_h = sub.add_parser("hide", help="Hide a string in overlay (before cookie).")
    ap_h.add_argument("--in", dest="infile", required=True, help="Input EXE path")
    ap_h.add_argument("--out", dest="outfile", required=True, help="Output EXE path")
    ap_h.add_argument("--text", required=True, help="String to hide")
    ap_h.add_argument("--key", type=lambda x: int(x,0), default=0x5A, help="XOR key (int, e.g., 0x5A)")
    ap_h.set_defaults(func=cmd_hide)

    ap_e = sub.add_parser("extract", help="Extract hidden string (OVH1 payload).")
    ap_e.add_argument("--in", dest="infile", required=True, help="Input EXE path")
    ap_e.add_argument("--out", dest="outfile", help="Optional output file for raw bytes")
    ap_e.set_defaults(func=cmd_extract)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
'''
tool_path = "/mnt/data/pyi_overlay_tool.py"
with open(tool_path, "w", encoding="utf-8") as f:
    f.write(tool_code)

# Provide quick hashes for integrity
import hashlib
h = hashlib.sha256(tool_code.encode("utf-8")).hexdigest()
tool_path, h
