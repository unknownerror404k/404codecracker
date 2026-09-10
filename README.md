# 404 Code Cracker

**Auto-detect and decode encoded/encrypted text — a CTF Swiss Army Knife.**

Paste any encoded text, and the tool automatically detects the encoding, decodes it layer by layer, and gives you the final output — whether that's a flag, a URL, or readable plaintext. Also supports image analysis (QR codes, steganography).

Created by **ERROR 404** — a cybersecurity student, for cybersecurity students.

---

## Installation

### One-Line Install (easiest)

```bash
curl -sSL https://raw.githubusercontent.com/unknownerror404k/404codecracker/main/install.sh | bash
```

### Or with pip

```bash
pip install git+https://github.com/unknownerror404k/404codecracker.git
sudo apt install libzbar0 python3-tk
```

### Manual install

```bash
git clone https://github.com/unknownerror404k/404codecracker.git
cd 404codecracker
sudo apt install libzbar0 python3-tk
pip install .
```

---

## Usage

### GUI mode (default)

```bash
404codecracker
```

Opens the dark hacker-themed GUI with three tabs:
- **DECODE** — paste text, load a file, or load an image
- **BULK SCAN** — select a folder and scan all files at once
- **HOW TO USE** — built-in help

### CLI mode

```bash
404codecracker --cli
404codecracker -t "SGVsbG8gV29ybGQ="
404codecracker -f encoded.txt
404codecracker -i qr.png
404codecracker -d ./ctf_files
```

---

## Features

- **Auto-detection** — you don't need to know the encoding type. Just paste and crack.
- **Recursive decoding** — if the decoded result is ALSO encoded, it keeps peeling layers automatically.
- **25 encodings/ciphers supported:**
  - Base64, Base32, Base85, Base58, Base62
  - Hexadecimal, Binary, Octal
  - ROT13, ROT47, Caesar (all 25 shifts), Atbash, Vigenere (tries common keys)
  - Rail Fence, Bacon Cipher
  - Morse Code, URL Encoding, ASCII Decimal
  - HTML Entities, Unicode Escape, Hex Escape
  - XOR (single byte brute-force — tries all 256 keys)
  - Brainfuck (esoteric language interpreter)
  - JWT (JSON Web Token) decoding
- **Image support:**
  - QR code reading
  - LSB steganography (hidden text in pixel data)
  - EXIF metadata extraction
- **Bulk folder mode** — scan an entire directory of files at once.
- **Flag & URL auto-extraction** — highlights flags and URLs in the output.
- **GUI + CLI** — dark hacker-themed GUI, plus a full command-line interface.

---

## License

MIT License — see [LICENSE](LICENSE) file.

---

## Disclaimer

This tool is for **educational purposes and CTF challenges only**. Only use it on data you own or have explicit permission to test.
