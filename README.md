# PE-Insert-Overlay-Tool
Insert Data into the PE Overlay

## 1) InsertPlainOverlay.py
> Appends the given text or the contents of a file without modification to the end of a PE file (its overlay).

### Usage
Simple usage
```
python InsertPlainOverlay.py hide --in Hello.exe --out Hello_plain.exe --text "VISIBLE_OVERLAY_DEMO"
```

Insert a string into the overlay
```
python InsertPlainOverlay.py -i <input_pe.exe> -s "<text_to_insert>" -o <output_pe.exe>
```

Insert a file's bytes into the overlay
```
python InsertPlainOverlay.py -i <input_pe.exe> -f <data.bin> -o <output_pe.exe>
```

### Options
```
-i, --input : Path to the source PE file (required)
-o, --output: Path to write the modified PE (required)
-s, --string: Text to append to the overlay (mutually exclusive with -f)
-f, --file : Binary file whose bytes to append (mutually exclusive with -s)
```

### More Examples
Example 1: Append a short marker string
```
python InsertPlainOverlay.py -i sample.exe -s "HELLO_BOB" -o sample_plain.exe
```

Example 2: Append raw bytes from data.bin
```
python InsertPlainOverlay.py -i sample.exe -f data.bin -o sample_plain.exe
```

## 2) InsertXorOverlay.py
> XOR-encodes the input (string or file) with a single byte key and appends the result to the overlay.
> XOR with the same key again to recover the original content.

### Usage
Simple usage
```
python InsertXorOverlay.py hide --in Hello.exe --out Hello_mod.exe --text "VISIBLE_OVERLAY_DEMO"
```

Insert a XOR-encoded string
```
python InsertXorOverlay.py -i <input_pe.exe> -s "<text_to_insert>" -k <key> -o <output_pe.exe>
```

Insert a XOR-encoded file
```
python InsertXorOverlay.py -i <input_pe.exe> -f <data.bin> -k <key> -o <output_pe.exe>
```

### Options
```
-i, --input : Path to the source PE file (required)
-o, --output: Path to write the modified PE (required)
-s, --string: Text to encode and append (mutually exclusive with -f)
-f, --file : Binary file to encode and append (mutually exclusive with -s)
-k, --key : XOR key as an integer 0–255. Decimal (e.g., 65) or hex (e.g., 0x41) allowed (required)
```

### More Examples
Example 1: XOR "SECRET" with 0x41 and append
```
python InsertXorOverlay.py -i sample.exe -s "SECRET" -k 0x41 -o sample_xor.exe
```

Example 2: XOR data.bin with 170 (0xAA) and append
```
python InsertXorOverlay.py -i sample.exe -f data.bin -k 170 -o sample_xor.exe
```

## Tips & Notes
* The overlay is not loaded into memory by the Windows PE loader, but some security products may flag unusual or oversized overlays.
* Always write to a new file via -o/--output to preserve the original.
* To verify the overlay:
  * Compare file sizes and hashes before/after.
  * Inspect with a PE viewer (e.g., look for an “Overlay”/“Extra data” section).
  * For research/education only. Do not misuse these scripts.

## Extract
ex)
```
python InsertXorOverlay.py extract --in Hello_mod.exe --out secret.txt
```
