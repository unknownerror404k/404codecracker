"""
404 Code Cracker - Single-file version.
Auto-detect and decode encoded/encrypted text - CTF Swiss Army Knife.

Created by ERROR 404
For educational and CTF use only.
"""

import base64
import binascii
import re
import json
import urllib.parse
import os
import argparse
import sys
import threading

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(s: str) -> str:
    """Strip whitespace and common wrapper artifacts."""
    return s.strip().replace("\r", "").replace("\n", "")


def _is_printable(s: str) -> bool:
    """Return True if string is mostly printable ASCII (0x20-0x7E + whitespace)."""
    if not s:
        return False
    # Count only ASCII printable characters
    printable = sum(1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\n\r\t")
    return printable / len(s) >= 0.90


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

def decode_base64(s: str) -> str | None:
    s = _clean(s)
    # Base64 charset: A-Za-z0-9+/=
    if not re.fullmatch(r'[A-Za-z0-9+/=\s]+', s):
        return None
    s = s.replace(" ", "")
    if len(s) < 4:
        return None
    # Pad if necessary
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    try:
        decoded = base64.b64decode(s, validate=True)
        result = decoded.decode("utf-8", errors="replace")
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Base32
# ---------------------------------------------------------------------------

def decode_base32(s: str) -> str | None:
    s = _clean(s).upper().replace(" ", "")
    # Base32 charset: A-Z2-7=
    if not re.fullmatch(r'[A-Z2-7=]+', s):
        return None
    if len(s) < 8:
        return None
    padding = len(s) % 8
    if padding:
        s += "=" * (8 - padding)
    try:
        decoded = base64.b32decode(s)
        result = decoded.decode("utf-8", errors="replace")
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Base85 / Ascii85
# ---------------------------------------------------------------------------

def decode_base85(s: str) -> str | None:
    s = _clean(s)
    if len(s) < 5:
        return None
    try:
        decoded = base64.b85decode(s)
        result = decoded.decode("utf-8", errors="replace")
        if _is_printable(result):
            return result
        return None
    except Exception:
        pass
    try:
        decoded = base64.a85decode(s, ignorechars=b" \t\n\r\v")
        result = decoded.decode("utf-8", errors="replace")
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Hexadecimal
# ---------------------------------------------------------------------------

def decode_hex(s: str) -> str | None:
    s = _clean(s).lower()
    # Accept with or without 0x prefix, with or without spaces
    s = s.replace("0x", "").replace(" ", "")
    if not re.fullmatch(r'[0-9a-f]+', s):
        return None
    if len(s) % 2 != 0:
        return None
    if len(s) < 2:
        return None
    try:
        decoded = bytes.fromhex(s)
        result = decoded.decode("utf-8", errors="replace")
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Binary
# ---------------------------------------------------------------------------

def decode_binary(s: str) -> str | None:
    s = _clean(s).replace(" ", "")
    # Accept groups of 8 bits separated by spaces or nothing
    if " " in _clean(s):
        parts = _clean(s).split()
    else:
        parts = [s[i:i+8] for i in range(0, len(s), 8)]
    if not parts:
        return None
    if not all(re.fullmatch(r'[01]{8}', p) for p in parts):
        return None
    try:
        chars = [chr(int(p, 2)) for p in parts]
        result = "".join(chars)
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ROT13
# ---------------------------------------------------------------------------

def decode_rot13(s: str) -> str | None:
    s = _clean(s)
    if not s:
        return None
    # Only makes sense if there are letters
    if not any(c.isalpha() for c in s):
        return None
    result = ""
    for c in s:
        if "a" <= c <= "z":
            result += chr((ord(c) - ord("a") + 13) % 26 + ord("a"))
        elif "A" <= c <= "Z":
            result += chr((ord(c) - ord("A") + 13) % 26 + ord("A"))
        else:
            result += c
    if result != s and _is_printable(result):
        return result
    return None


# ---------------------------------------------------------------------------
# Caesar (try all 25 shifts, return best match)
# ---------------------------------------------------------------------------

def decode_caesar(s: str) -> str | None:
    """Try all 25 Caesar shifts. Returns the shift that produces the most
    English-like result, or None."""
    s = _clean(s)
    if not s or not any(c.isalpha() for c in s):
        return None

    common_words = {"the", "and", "for", "are", "but", "not", "you", "all",
                    "can", "her", "was", "one", "our", "out", "has", "flag",
                    "ctf", "key", "secret", "password", "http", "https",
                    "www", "link", "find", "decode", "hidden"}

    best_shift = None
    best_score = 0

    for shift in range(1, 26):
        result = ""
        for c in s:
            if "a" <= c <= "z":
                result += chr((ord(c) - ord("a") + shift) % 26 + ord("a"))
            elif "A" <= c <= "Z":
                result += chr((ord(c) - ord("A") + shift) % 26 + ord("A"))
            else:
                result += c
        # Score based on common word presence
        words = set(result.lower().split())
        score = len(words & common_words)
        # Bonus for readability
        if _is_printable(result):
            score += 0.5
        if score > best_score:
            best_score = score
            best_shift = shift
            best_result = result

    if best_shift is not None and best_score > 0:
        return f"{best_result}  [Caesar shift: -{best_shift}]"
    # If no common words found, return shift 13 (ROT13 equivalent) if printable
    for shift in range(1, 26):
        result = ""
        for c in s:
            if "a" <= c <= "z":
                result += chr((ord(c) - ord("a") + shift) % 26 + ord("a"))
            elif "A" <= c <= "Z":
                result += chr((ord(c) - ord("A") + shift) % 26 + ord("A"))
            else:
                result += c
        if _is_printable(result) and result != s:
            return f"{result}  [Caesar shift: -{shift}]"
    return None


# ---------------------------------------------------------------------------
# Morse Code
# ---------------------------------------------------------------------------

MORSE_DECODE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    ".----.": "'", "-.-.--": "!", "-..-.": "/", "-.--.": "(",
    "-.--.-": ")", ".-...": "&", "---...": ":", "-.-.-.": ";",
    "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@",
}

def decode_morse(s: str) -> str | None:
    s = _clean(s)
    # Morse uses dots, dashes, and spaces (or slashes as separators)
    if not re.fullmatch(r'[.\- /]+', s):
        return None
    if "." not in s and "-" not in s:
        return None
    # Normalise separators: " / " or "  " = word boundary, " " = char boundary
    words = re.split(r'\s{2,}|/', s)
    result_words = []
    for word in words:
        word = word.strip()
        if not word:
            continue
        chars = word.split(" ")
        decoded_word = ""
        for char in chars:
            char = char.strip()
            if char in MORSE_DECODE:
                decoded_word += MORSE_DECODE[char]
            elif char:
                return None  # Invalid morse sequence
        if decoded_word:
            result_words.append(decoded_word)
    if not result_words:
        return None
    result = " ".join(result_words)
    if result and _is_printable(result):
        return result
    return None


# ---------------------------------------------------------------------------
# URL Encoding
# ---------------------------------------------------------------------------

def decode_url(s: str) -> str | None:
    s = _clean(s)
    if "%" not in s:
        return None
    # Skip if input looks like Brainfuck
    bf_chars = set("><+-.,[]")
    stripped_bf = "".join(c for c in s if c in bf_chars)
    if len(stripped_bf) > 10 and len(stripped_bf) / len(s) > 0.3:
        return None
    try:
        decoded = urllib.parse.unquote_plus(s)
        if decoded != s and _is_printable(decoded):
            return decoded
        decoded = urllib.parse.unquote(s)
        if decoded != s and _is_printable(decoded):
            return decoded
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ASCII (decimal values separated by spaces)
# ---------------------------------------------------------------------------

def decode_ascii(s: str) -> str | None:
    s = _clean(s)
    # Accept space or comma separated decimal values
    if not re.fullmatch(r'[0-9 ,]+', s):
        return None
    parts = re.split(r'[ ,]+', s.strip())
    parts = [p for p in parts if p]
    if not parts:
        return None
    try:
        chars = [chr(int(p)) for p in parts]
        result = "".join(chars)
        if _is_printable(result):
            return result
        return None
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Octal
# ---------------------------------------------------------------------------

def decode_octal(s: str) -> str | None:
    s = _clean(s)
    if not re.fullmatch(r'[0-7 ]+', s):
        return None
    parts = s.split()
    if not parts:
        return None
    try:
        chars = [chr(int(p, 8)) for p in parts]
        result = "".join(chars)
        if _is_printable(result):
            return result
        return None
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Atbash Cipher
# ---------------------------------------------------------------------------

def decode_atbash(s: str) -> str | None:
    s = _clean(s)
    if not s or not any(c.isalpha() for c in s):
        return None
    result = ""
    for c in s:
        if "a" <= c <= "z":
            result += chr(ord("z") - (ord(c) - ord("a")))
        elif "A" <= c <= "Z":
            result += chr(ord("Z") - (ord(c) - ord("A")))
        else:
            result += c
    if result != s and _is_printable(result):
        return result
    return None


# ---------------------------------------------------------------------------
# Vigenere (try common keys + prompt user)
# ---------------------------------------------------------------------------

COMMON_VIGENERE_KEYS = [
    "key", "secret", "password", "flag", "ctf", "crypto",
    "hack", "admin", "root", "test", "abc", "default",
]

def _vigenere_decrypt(ciphertext: str, key: str) -> str:
    result = []
    key_idx = 0
    key = key.lower()
    for c in ciphertext:
        if c.isalpha():
            base = ord("a") if c.islower() else ord("A")
            k = ord(key[key_idx % len(key)]) - ord("a")
            result.append(chr((ord(c) - base - k) % 26 + base))
            key_idx += 1
        else:
            result.append(c)
    return "".join(result)

def decode_vigenere(s: str) -> str | None:
    s = _clean(s)
    if not s or not any(c.isalpha() for c in s):
        return None
    common_words = {"the", "and", "for", "are", "flag", "ctf", "key",
                    "secret", "password", "http", "https", "link"}
    for key in COMMON_VIGENERE_KEYS:
        decrypted = _vigenere_decrypt(s, key)
        words = set(decrypted.lower().split())
        if words & common_words:
            return f"{decrypted}  [Vigenere key: '{key}']"
    # Return first key result that's printable
    for key in COMMON_VIGENERE_KEYS:
        decrypted = _vigenere_decrypt(s, key)
        if _is_printable(decrypted) and decrypted != s:
            return f"{decrypted}  [Vigenere key: '{key}']"
    return None


# ---------------------------------------------------------------------------
# JWT (JSON Web Token)
# ---------------------------------------------------------------------------

def decode_jwt(s: str) -> str | None:
    s = _clean(s)
    if not s.startswith("eyJ"):
        return None
    parts = s.split(".")
    if len(parts) < 2:
        return None
    try:
        def _b64decode_jwt(part: str) -> str:
            padding = len(part) % 4
            if padding:
                part += "=" * (4 - padding)
            decoded = base64.urlsafe_b64decode(part)
            return decoded.decode("utf-8", errors="replace")

        header = _b64decode_jwt(parts[0])
        payload = _b64decode_jwt(parts[1])
        result = f"JWT Header:\n{header}\n\nJWT Payload:\n{payload}"
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ROT47 (like ROT13 but for all printable ASCII, not just letters)
# ---------------------------------------------------------------------------

def decode_rot47(s: str) -> str | None:
    s = _clean(s)
    if not s or len(s) < 3:
        return None
    # Skip if input looks like Brainfuck
    bf_chars = set("><+-.,[]")
    bf_count = sum(1 for c in s if c in bf_chars)
    if bf_count > 10 and bf_count / len(s) > 0.3:
        return None
    # ROT47 rotates chars in the range 33-126
    if not any(33 <= ord(c) <= 126 for c in s):
        return None
    result = ""
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            result += chr(33 + (o - 33 + 47) % 94)
        else:
            result += c
    if result != s and _is_printable(result):
        return result
    return None


# ---------------------------------------------------------------------------
# Base58 (Bitcoin-style encoding — no 0, O, I, l)
# ---------------------------------------------------------------------------

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {c: i for i, c in enumerate(BASE58_ALPHABET)}

def decode_base58(s: str) -> str | None:
    s = _clean(s)
    if not s or len(s) < 5:
        return None
    # Must only contain Base58 chars
    if not all(c in BASE58_INDEX for c in s):
        return None
    # Must have at least some non-digit chars (to distinguish from decimal)
    if s.isdigit():
        return None
    try:
        num = 0
        for c in s:
            num = num * 58 + BASE58_INDEX[c]
        # Convert number to bytes
        result_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
        # Handle leading '1' characters (leading zero bytes)
        leading_zeros = 0
        for c in s:
            if c == "1":
                leading_zeros += 1
            else:
                break
        result_bytes = b"\x00" * leading_zeros + result_bytes
        result = result_bytes.decode("utf-8", errors="replace")
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Base62 (alphanumeric — A-Za-z0-9, no + or /)
# ---------------------------------------------------------------------------

BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE62_INDEX = {c: i for i, c in enumerate(BASE62_ALPHABET)}

def decode_base62(s: str) -> str | None:
    s = _clean(s)
    if not s or len(s) < 8:
        return None
    if not all(c in BASE62_INDEX for c in s):
        return None
    # Must have mixed case + digits to look like Base62
    has_lower = any(c.islower() for c in s)
    has_upper = any(c.isupper() for c in s)
    if not (has_lower and has_upper):
        return None
    try:
        num = 0
        for c in s:
            num = num * 62 + BASE62_INDEX[c]
        result_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
        result = result_bytes.decode("utf-8", errors="replace")
        if _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HTML Entity Decoding (& &#65; &#x41; etc.)
# ---------------------------------------------------------------------------

def decode_html_entities(s: str) -> str | None:
    s = _clean(s)
    # Must contain & and ;
    if "&" not in s or ";" not in s:
        return None
    # Check for HTML entity patterns
    if not re.search(r'&#?\w+;', s):
        return None
    try:
        import html
        decoded = html.unescape(s)
        if decoded != s and _is_printable(decoded):
            return decoded
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Reverse Text (sometimes the answer is just reversed)
# ---------------------------------------------------------------------------

def decode_reverse(s: str) -> str | None:
    s = _clean(s)
    if not s or len(s) < 5:
        return None
    # Only reverse if it looks like it could be reversed text
    # (contains letters, not just random symbols)
    if not any(c.isalpha() for c in s):
        return None
    result = s[::-1]
    if result != s and _is_printable(result):
        return result
    return None


# ---------------------------------------------------------------------------
# XOR with single byte (try all 256 possible keys)
# ---------------------------------------------------------------------------

def decode_xor_single_byte(s: str) -> str | None:
    """Try XORing each byte of hex input with all 256 possible single-byte keys."""
    s = _clean(s)
    # Accept hex input
    hex_s = s.replace(" ", "").replace("0x", "").lower()
    if not re.fullmatch(r'[0-9a-f]+', hex_s) or len(hex_s) % 2 != 0:
        return None
    if len(hex_s) < 6:
        return None
    try:
        raw_bytes = bytes.fromhex(hex_s)
    except ValueError:
        return None

    common_words = {"flag", "ctf", "the", "and", "for", "http", "key",
                    "secret", "password", "admin", "user", "login",
                    "hidden", "find", "here", "link", "congratulat"}

    best_result = None
    best_score = 0

    for key in range(256):
        xored = bytes(b ^ key for b in raw_bytes)
        try:
            decoded = xored.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue

        if not _is_printable(decoded):
            continue

        # Score based on common word presence
        words = set(decoded.lower().split())
        score = len(words & common_words)

        # Bonus for having spaces and letters
        alpha_count = sum(1 for c in decoded if c.isalpha())
        space_count = sum(1 for c in decoded if c == " ")
        if alpha_count > 0:
            score += alpha_count / len(decoded)
        if space_count > 0:
            score += 0.5

        if score > best_score:
            best_score = score
            best_result = (decoded, key)

    if best_result and best_score > 1:
        decoded, key = best_result
        return f"{decoded}  [XOR key: 0x{key:02x}]"
    return None


# ---------------------------------------------------------------------------
# Unicode Escape (\u0041 \u0066 etc.)
# ---------------------------------------------------------------------------

def decode_unicode_escape(s: str) -> str | None:
    s = _clean(s)
    # Look for \uXXXX patterns
    if "\\u" not in s:
        return None
    if not re.search(r'\\u[0-9a-fA-F]{4}', s):
        return None
    try:
        decoded = s.encode().decode("unicode_escape")
        if decoded != s and _is_printable(decoded):
            return decoded
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Hex Escape (\x41 \x66 etc.)
# ---------------------------------------------------------------------------

def decode_hex_escape(s: str) -> str | None:
    s = _clean(s)
    # Look for \xNN patterns
    if "\\x" not in s:
        return None
    if not re.search(r'\\x[0-9a-fA-F]{2}', s):
        return None
    try:
        decoded = s.encode().decode("unicode_escape")
        if decoded != s and _is_printable(decoded):
            return decoded
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Brainfuck (esoteric language — very common in CTFs)
# ---------------------------------------------------------------------------

def decode_brainfuck(s: str) -> str | None:
    """Interpret Brainfuck code and return its output."""
    s = _clean(s)
    # Brainfuck uses only these 8 characters
    bf_chars = set("><+-.,[]")
    stripped = "".join(c for c in s if c in bf_chars)
    if len(stripped) < 10:
        return None
    # Check that at least 40% of input is BF code
    if len(stripped) / len(s) < 0.4:
        return None
    # Must have at least one . (output) and balanced []
    if stripped.count(".") == 0:
        return None
    if stripped.count("[") != stripped.count("]"):
        return None

    try:
        tape = [0] * 30000
        ptr = 0
        ip = 0
        output = []
        max_steps = 100000  # Prevent infinite loops
        steps = 0

        # Build jump table for brackets
        jump = {}
        stack = []
        for i, c in enumerate(stripped):
            if c == "[":
                stack.append(i)
            elif c == "]":
                if stack:
                    j = stack.pop()
                    jump[i] = j
                    jump[j] = i

        while ip < len(stripped) and steps < max_steps:
            c = stripped[ip]
            if c == ">":
                ptr = (ptr + 1) % 30000
            elif c == "<":
                ptr = (ptr - 1) % 30000
            elif c == "+":
                tape[ptr] = (tape[ptr] + 1) % 256
            elif c == "-":
                tape[ptr] = (tape[ptr] - 1) % 256
            elif c == ".":
                output.append(chr(tape[ptr]))
            elif c == ",":
                pass  # Input — we ignore
            elif c == "[":
                if tape[ptr] == 0:
                    ip = jump[ip]
            elif c == "]":
                if tape[ptr] != 0:
                    ip = jump[ip]
            ip += 1
            steps += 1

        result = "".join(output)
        if result and _is_printable(result):
            return result
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Bacon Cipher (uses A=00000, B=00001, ... in binary with a/b)
# ---------------------------------------------------------------------------

def decode_bacon(s: str) -> str | None:
    """Decode Bacon cipher where 'a'/'A' = 0, 'b'/'B' = 1."""
    s = _clean(s).lower()
    # Only a's and b's (possibly with spaces)
    if not re.fullmatch(r'[ab ]+', s):
        return None
    s = s.replace(" ", "")
    if len(s) < 5:
        return None
    # Must be a multiple of 5 for full groups
    if len(s) % 5 != 0:
        return None
    bacon_decode = {
        "aaaaa": "a", "aaaab": "b", "aaaba": "c", "aaabb": "d",
        "aabaa": "e", "aabab": "f", "aabba": "g", "aabbb": "h",
        "abaaa": "i", "abaab": "k", "ababa": "l", "ababb": "m",
        "abbaa": "n", "abbab": "o", "abbba": "p", "abbbb": "q",
        "baaaa": "r", "baaab": "s", "baaba": "t", "baabb": "u",
        "babaa": "w", "babab": "x", "babba": "y", "babbb": "z",
    }
    result = ""
    for i in range(0, len(s), 5):
        group = s[i:i+5]
        if group in bacon_decode:
            result += bacon_decode[group]
        else:
            return None
    if result and _is_printable(result):
        return result
    return None


# ---------------------------------------------------------------------------
# Rail Fence Cipher (transposition — tries 2-6 rails)
# ---------------------------------------------------------------------------

def decode_rail_fence(s: str) -> str | None:
    """Try rail fence cipher with 2-6 rails, return best match."""
    s = _clean(s)
    if not s or len(s) < 6:
        return None
    if not any(c.isalpha() for c in s):
        return None

    common_words = {"flag", "ctf", "the", "and", "for", "http", "key",
                    "secret", "password", "hidden", "find", "here", "link"}

    best_result = None
    best_score = 0

    for num_rails in range(2, 7):
        try:
            # Decrypt rail fence
            n = len(s)
            # Build the rail pattern
            pattern = []
            rail = 0
            direction = 1
            for i in range(n):
                pattern.append(rail)
                if rail == 0:
                    direction = 1
                elif rail == num_rails - 1:
                    direction = -1
                rail += direction

            # Figure out how many chars go on each rail
            rail_lengths = [0] * num_rails
            for p in pattern:
                rail_lengths[p] += 1

            # Split the ciphertext into rails
            rails = []
            pos = 0
            for rl in rail_lengths:
                rails.append(s[pos:pos + rl])
                pos += rl

            # Read off in zig-zag order
            rail_indices = [0] * num_rails
            result = ""
            for i in range(n):
                r = pattern[i]
                result += rails[r][rail_indices[r]]
                rail_indices[r] += 1

            # Score this result
            words = set(result.lower().split())
            score = len(words & common_words)
            if _is_printable(result) and result != s:
                if score > best_score:
                    best_score = score
                    best_result = (result, num_rails)
        except Exception:
            continue

    if best_result:
        result, rails = best_result
        if best_score > 0:
            return f"{result}  [Rail Fence: {rails} rails]"
        # If no common words, still return if it looks readable
        if _is_printable(result):
            return f"{result}  [Rail Fence: {rails} rails]"
    return None


# ---------------------------------------------------------------------------
# Decoder Registry
# ---------------------------------------------------------------------------

DECODERS = {
    "Base64": decode_base64,
    "Base32": decode_base32,
    "Base85": decode_base85,
    "Base58": decode_base58,
    "Base62": decode_base62,
    "Hexadecimal": decode_hex,
    "Binary": decode_binary,
    "ROT13": decode_rot13,
    "ROT47": decode_rot47,
    "Caesar": decode_caesar,
    "Morse": decode_morse,
    "URL Encoding": decode_url,
    "ASCII Decimal": decode_ascii,
    "Octal": decode_octal,
    "Atbash": decode_atbash,
    "Vigenere": decode_vigenere,
    "JWT": decode_jwt,
    "HTML Entities": decode_html_entities,
    "Reverse Text": decode_reverse,
    "XOR (single byte)": decode_xor_single_byte,
    "Unicode Escape": decode_unicode_escape,
    "Hex Escape": decode_hex_escape,
    "Brainfuck": decode_brainfuck,
    "Bacon Cipher": decode_bacon,
    "Rail Fence": decode_rail_fence,
}


# Priority: lower number = higher priority (tried first).
# Structural encodings (Base64, Hex, Binary) are tried before
# substitution ciphers (Caesar, Atbash, Vigenere) which match
# almost any alphabetic input.
DECODER_PRIORITY = {
    "JWT": 1,
    "Base64": 2,
    "Base32": 3,
    "Base85": 4,
    "Base58": 5,
    "Base62": 6,
    "Hexadecimal": 7,
    "Binary": 8,
    "URL Encoding": 9,
    "Morse": 10,
    "ASCII Decimal": 11,
    "Octal": 12,
    "HTML Entities": 13,
    "Unicode Escape": 14,
    "Hex Escape": 15,
    "ROT13": 16,
    "ROT47": 17,
    "Caesar": 18,
    "Atbash": 19,
    "Vigenere": 20,
    "Reverse Text": 21,
    "Rail Fence": 22,
    "Bacon Cipher": 23,
    "XOR (single byte)": 24,
    "Brainfuck": 25,
}

# Input pattern signatures — if the input matches one of these,
# the corresponding decoder gets a massive score boost.
# This prevents generic ciphers from intercepting specialized formats.
INPUT_PATTERNS = {
    "JWT": re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "Base64": re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$'),
    "Base32": re.compile(r'^[A-Z2-7=]{16,}$'),
    "Hexadecimal": re.compile(r'^[0-9a-fA-F]{16,}$'),
    "Binary": re.compile(r'^[01]{8}( [01]{8})*$'),
    "Morse": re.compile(r'^[.\- /]{6,}$'),
    "ASCII Decimal": re.compile(r'^[0-9]{2,}( [0-9]{2,})+$'),
    "Octal": re.compile(r'^[0-7]{3}( [0-7]{3})*$'),
    "URL Encoding": re.compile(r'(?:%[0-9a-fA-F]{2}){2,}'),  # needs multiple %xx sequences
    "HTML Entities": re.compile(r'&#?\w+;'),
    "Unicode Escape": re.compile(r'\\u[0-9a-fA-F]{4}'),
    "Hex Escape": re.compile(r'\\x[0-9a-fA-F]{2}'),
    "Bacon Cipher": re.compile(r'^[abAB ]{10,}$'),
    "Brainfuck": re.compile(r'[\[\]]{2,}[><+\-.\[\]]*'),
    "ROT47": re.compile(r'[#$%&\*\(\)=\?\@\^_\{\|}~]{10,}'),  # excludes BF chars
    "XOR (single byte)": re.compile(r'^[0-9a-fA-F]{6,}$'),
}


def detect_and_decode(s: str) -> list[tuple[str, str]]:
    """
    Try every decoder on the input string.

    Returns a list of (encoding_name, decoded_result) tuples, sorted by
    confidence (best first). Only successful decodes are included.
    """
    results = []
    seen = set()

    # Try decoders in priority order
    sorted_decoders = sorted(DECODERS.items(),
                             key=lambda x: DECODER_PRIORITY.get(x[0], 99))

    for name, decoder in sorted_decoders:
        try:
            decoded = decoder(s)
            if decoded is not None and decoded.strip():
                # Deduplicate identical results
                key = decoded.strip()
                if key not in seen:
                    seen.add(key)
                    results.append((name, decoded.strip()))
        except Exception:
            continue

    # Sort: results that look like flags or URLs get priority,
    # then by decoder priority (structural > substitution).
    # Input pattern match gives a huge boost to prevent ciphers
    # from intercepting specialized formats.
    def _score(item):
        name, decoded = item
        dl = decoded.lower()
        score = 0

        # Flags and URLs are the strongest signal
        if "flag{" in dl or "ctf{" in dl:
            score += 1000
        if "http" in dl or "www." in dl:
            score += 500

        # HUGE boost if the decoder's input pattern matches
        # This prevents Caesar/ROT13 from beating specialized decoders
        pattern = INPUT_PATTERNS.get(name)
        if pattern and pattern.search(s):
            score += 200

        # Penalize ciphers that match anything (Caesar, ROT13, Atbash)
        # when the input doesn't look like plain text
        if name in ("Caesar", "ROT13", "Atbash", "Vigenere"):
            # Only give cipher results a decent score if they found common words
            common_words = {"flag", "ctf", "the", "and", "for", "http",
                            "key", "secret", "password", "hidden", "link"}
            words = set(dl.split())
            if not (words & common_words):
                score -= 50  # Penalize random cipher output

        # Prefer results with spaces (readable English)
        if " " in decoded:
            score += 5

        # Prefer shorter (already decoded) results
        score -= len(decoded) * 0.01

        # Tie-breaker: structural encodings rank higher than ciphers
        score += (30 - DECODER_PRIORITY.get(name, 99)) * 2

        return -score  # Negative because sorted ascending

    results.sort(key=_score)
    return results


def best_decode(s: str) -> tuple[str, str] | None:
    """Return the single best (name, decoded) pair, or None."""
    results = detect_and_decode(s)
    return results[0] if results else None


class DecodeStep:
    """One step in the decoding chain."""
    def __init__(self, encoding: str, input_text: str, output_text: str):
        self.encoding = encoding      # e.g. "Base64"
        self.input_text = input_text
        self.output_text = output_text

    def __repr__(self):
        return f"[{self.encoding}] {self.input_text[:40]}... -> {self.output_text[:60]}"


class DecodeResult:
    """Full result of a recursive decode attempt."""
    def __init__(self):
        self.steps: list[DecodeStep] = []
        self.final_output: str = ""
        self.found_flag: str | None = None
        self.found_url: str | None = None
        self.is_final_readable: bool = False
        self.ambiguities: list[tuple[str, str]] = []  # alternative decodes at the last step

    @property
    def depth(self) -> int:
        return len(self.steps)

    def summary(self) -> str:
        lines = []
        if self.steps:
            lines.append(f"Decoded in {self.depth} layer(s):")
            for i, step in enumerate(self.steps, 1):
                lines.append(f"  Layer {i}: [{step.encoding}]")
                lines.append(f"    -> {step.output_text[:100]}")
            lines.append("")
        if self.found_flag:
            lines.append(f"FLAG FOUND: {self.found_flag}")
        if self.found_url:
            lines.append(f"URL FOUND: {self.found_url}")
        if not self.found_flag and not self.found_url:
            lines.append(f"Final output: {self.final_output}")
        if self.ambiguities:
            lines.append("")
            lines.append("Other possible decodes at this level:")
            for name, text in self.ambiguities:
                lines.append(f"  [{name}] -> {text[:80]}")
        return "\n".join(lines)


def recursive_decode(s: str, max_depth: int = 15, _depth: int = 0,
                     _seen: set | None = None) -> DecodeResult:
    """
    Recursively decode an input string, peeling layers until we reach
    readable text, a flag, or a URL — or hit max_depth.

    Args:
        s: The input string to decode.
        max_depth: Maximum number of decoding layers (prevents infinite loops).
        _depth: Current depth (used internally).
        _seen: Set of already-seen strings (prevents infinite loops).

    Returns:
        DecodeResult with the full decoding chain and final output.
    """
    if _seen is None:
        _seen = set()

    result = DecodeResult()

    # Safety: prevent infinite loops
    if s in _seen or _depth >= max_depth:
        result.final_output = s
        result.is_final_readable = is_readable(s)
        result.found_flag = find_flag(s)
        result.found_url = find_url(s)
        return result

    _seen.add(s)

    # Check if current input already contains a flag or URL
    flag = find_flag(s)
    url = find_url(s)

    if flag:
        result.final_output = s
        result.found_flag = flag
        result.found_url = url
        result.is_final_readable = True
        return result

    if url:
        result.final_output = s
        result.found_url = url
        result.is_final_readable = is_readable(s)
        # Don't return yet — the URL might be embedded in more text that
        # is itself encoded. But usually if we found a URL, we're done.
        if is_readable(s):
            return result

    # If input is already readable plaintext and not encoded-looking, stop
    if is_readable(s) and _depth > 0:
        result.final_output = s
        result.is_final_readable = True
        result.found_flag = flag
        result.found_url = url
        return result

    # Try all decoders
    candidates = detect_and_decode(s)

    if not candidates:
        # Can't decode further — this is our final output
        result.final_output = s
        result.is_final_readable = is_readable(s)
        result.found_flag = flag
        result.found_url = url
        return result

    # Try the best candidate first
    best_name, best_decoded = candidates[0]

    # Store ambiguities (other candidates at this level)
    if len(candidates) > 1:
        result.ambiguities = candidates[1:]

    step = DecodeStep(best_name, s, best_decoded)
    result.steps.append(step)

    # Recurse on the decoded output
    sub_result = recursive_decode(best_decoded, max_depth, _depth + 1, _seen)

    # Merge sub-result
    result.steps.extend(sub_result.steps)
    result.final_output = sub_result.final_output
    result.found_flag = sub_result.found_flag or flag
    result.found_url = sub_result.found_url or url
    result.is_final_readable = sub_result.is_final_readable

    return result


def decode_all_paths(s: str, max_depth: int = 10) -> list[DecodeResult]:
    """
    Try ALL decoder paths (not just the best one) and return all results.
    Useful when auto-detection is ambiguous.

    Returns a list of DecodeResult objects, one per decoding path.
    """
    results = []

    # First try the best path
    best = recursive_decode(s, max_depth)
    results.append(best)

    # Also try each decoder individually at the top level
    candidates = detect_and_decode(s)
    if candidates and len(candidates) > 1:
        for name, decoded in candidates[1:]:
            seen = {s}
            sub = recursive_decode(decoded, max_depth, _depth=1, _seen=seen)
            # Prepend the first step manually
            step = DecodeStep(name, s, decoded)
            sub.steps.insert(0, step)
            results.append(sub)

    return results


def read_qr_code(image_path: str) -> str | None:
    """
    Read and decode a QR code from an image file.

    Args:
        image_path: Path to the image file (PNG, JPEG, etc.)

    Returns:
        Decoded text from the QR code, or None if no QR code found.
    """
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image

        img = Image.open(image_path)
        decoded_objects = decode(img)

        if decoded_objects:
            # Return the first decoded QR code
            return decoded_objects[0].data.decode("utf-8", errors="replace")
        return None
    except ImportError:
        return "ERROR: pyzbar library not installed. Run: pip install pyzbar"
    except Exception as e:
        return f"ERROR reading QR code: {e}"


def extract_lsb_steganography(image_path: str) -> str | None:
    """
    Extract hidden text from an image using LSB steganography.

    Reads the least significant bit of each pixel's red channel to
    reconstruct a hidden message. Stops at null terminator or after
    a reasonable limit.

    Args:
        image_path: Path to the image file.

    Returns:
        Hidden text if found, or None.
    """
    try:
        from PIL import Image

        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())

        bits = []
        for pixel in pixels:
            # Extract LSB of red channel
            bits.append(pixel[0] & 1)

        # Convert bits to bytes
        bytes_data = []
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            if byte == 0:  # Null terminator
                break
            bytes_data.append(byte)

        if not bytes_data:
            return None

        # Try to decode as text
        try:
            result = bytes(bytes_data).decode("utf-8", errors="strict")
            if result.isprintable() or " " in result:
                return result
        except UnicodeDecodeError:
            pass

        # Try with errors='replace'
        result = bytes(bytes_data).decode("utf-8", errors="replace")
        # Check if it looks meaningful
        printable = sum(1 for c in result if c.isprintable())
        if result and printable / len(result) > 0.7:
            return result
        return None

    except ImportError:
        return "ERROR: Pillow library not installed. Run: pip install Pillow"
    except Exception as e:
        return f"ERROR extracting steganography: {e}"


def extract_lsb_all_channels(image_path: str) -> str | None:
    """
    Extract hidden text using LSB of ALL RGB channels (R, G, B).

    This catches steganography that hides data in all channels,
    not just red.
    """
    try:
        from PIL import Image

        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())

        bits = []
        for pixel in pixels:
            bits.append(pixel[0] & 1)  # R
            bits.append(pixel[1] & 1)  # G
            bits.append(pixel[2] & 1)  # B

        bytes_data = []
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            if byte == 0:
                break
            bytes_data.append(byte)

        if not bytes_data:
            return None

        try:
            result = bytes(bytes_data).decode("utf-8", errors="strict")
            if result.isprintable() or " " in result:
                return result
        except UnicodeDecodeError:
            pass

        result = bytes(bytes_data).decode("utf-8", errors="replace")
        printable = sum(1 for c in result if c.isprintable())
        if result and printable / len(result) > 0.7:
            return result
        return None

    except Exception as e:
        return f"ERROR: {e}"


def read_image_exif(image_path: str) -> dict | None:
    """
    Extract EXIF metadata from an image (sometimes CTFs hide data here).
    """
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        img = Image.open(image_path)
        exif_data = img._getexif()
        if not exif_data:
            return None

        result = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            result[tag] = str(value)
        return result if result else None

    except Exception:
        return None


def process_image(image_path: str) -> dict:
    """
    Process an image file through all image-based decoding methods.

    Returns a dict with keys: 'qr_code', 'lsb_steganography',
    'lsb_all_channels', 'exif_data'.
    """
    results = {
        "qr_code": read_qr_code(image_path),
        "lsb_steganography": extract_lsb_steganography(image_path),
        "lsb_all_channels": extract_lsb_all_channels(image_path),
        "exif_data": read_image_exif(image_path),
    }
    return results


def is_image_file(filepath: str) -> bool:
    """Check if a file is a supported image type."""
    ext = os.path.splitext(filepath)[1].lower()
    supported = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp"}
    return ext in supported


# Common CTF flag patterns
FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'picoctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'htb\{[^}]+\}', re.IGNORECASE),
    re.compile(r'thm\{[^}]+\}', re.IGNORECASE),
    re.compile(r'pwn\{[^}]+\}', re.IGNORECASE),
    re.compile(r'crypto\{[^}]+\}', re.IGNORECASE),
    re.compile(r'rev\{[^}]+\}', re.IGNORECASE),
    re.compile(r'forensics\{[^}]+\}', re.IGNORECASE),
    re.compile(r'misc\{[^}]+\}', re.IGNORECASE),
    # Note: no generic pattern - would cause false positives on
    # ROT13/Caesar encoded text that happens to look like flag{...}
]

# URL patterns
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+', re.IGNORECASE
)
WWW_PATTERN = re.compile(
    r'www\.[^\s<>"\']+', re.IGNORECASE
)
GENERIC_LINK_PATTERN = re.compile(
    r'[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
    re.IGNORECASE
)


def find_flag(text: str) -> str | None:
    """Find and return the first flag in text, or None."""
    if not text:
        return None
    for pattern in FLAG_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def find_url(text: str) -> str | None:
    """Find and return the first URL in text, or None."""
    if not text:
        return None
    for pattern in [URL_PATTERN, WWW_PATTERN]:
        match = pattern.search(text)
        if match:
            url = match.group(0)
            if not url.startswith("http"):
                url = "https://" + url
            return url
    # Try generic link pattern (e.g., example.com/path)
    match = GENERIC_LINK_PATTERN.search(text)
    if match:
        candidate = match.group(0)
        # Filter out things that aren't really URLs (like file.py)
        if "." in candidate and not candidate.endswith(".py"):
            return "https://" + candidate
    return None


def find_all_flags(text: str) -> list[str]:
    """Find all flags in text."""
    if not text:
        return []
    flags = []
    seen = set()
    for pattern in FLAG_PATTERNS:
        for match in pattern.finditer(text):
            flag = match.group(0)
            if flag not in seen:
                seen.add(flag)
                flags.append(flag)
    return flags


def find_all_urls(text: str) -> list[str]:
    """Find all URLs in text."""
    if not text:
        return []
    urls = []
    seen = set()
    for pattern in [URL_PATTERN, WWW_PATTERN]:
        for match in pattern.finditer(text):
            url = match.group(0)
            if not url.startswith("http"):
                url = "https://" + url
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def is_readable(text: str) -> bool:
    """
    Determine if text looks like readable plaintext (not encoded).

    Heuristics:
    - Contains common English words or readable patterns
    - Has reasonable ratio of letters/punctuation to total characters
    - Not dominated by a single charset (like only hex chars)
    - Does NOT look like Base64/Base32/Hex etc.
    """
    if not text or len(text) < 2:
        return False

    text = text.strip()

    # If it looks like a flag or URL, it's readable
    if find_flag(text) or find_url(text):
        return True

    # --- Reject encoded-looking strings ---
    import re as _re

    # Base64 pattern: 16+ alphanumeric chars (possibly with = padding)
    if re.fullmatch(r'[A-Za-z0-9+/=]{16,}', text) and "=" in text:
        return False
    # Base64 without padding but long
    if re.fullmatch(r'[A-Za-z0-9+/]{20,}', text) and not " " in text:
        return False
    # Base32 pattern: all uppercase A-Z and 2-7
    if re.fullmatch(r'[A-Z2-7=]{16,}', text):
        return False
    # Hex pattern: even-length hex string
    if re.fullmatch(r'[0-9a-fA-F]{16,}', text) and len(text) % 2 == 0:
        return False
    # Binary pattern: only 0s and 1s with spaces
    if re.fullmatch(r'[01 ]{8,}', text):
        return False
    # Morse-like: only dots, dashes, spaces, slashes
    if re.fullmatch(r'[.\- /]{6,}', text):
        return False
    # ASCII decimal pattern: only numbers and spaces/commas
    if re.fullmatch(r'[0-9 ,]{8,}', text):
        return False

    # Ratio of printable characters
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    if printable / len(text) < 0.85:
        return False

    # Ratio of alphabetic characters
    alpha = sum(1 for c in text if c.isalpha())
    if len(text) > 5 and alpha / len(text) < 0.15:
        return False

    # Check for common English words
    common_words = {
        "the", "is", "at", "in", "on", "of", "to", "a", "an", "and",
        "or", "for", "this", "that", "it", "with", "you", "flag",
        "key", "secret", "password", "decode", "find", "here", "link",
        "go", "to", "http", "https", "www", "com", "org", "net",
    }
    words = set(text.lower().split())
    if words & common_words:
        return True

    # If text has spaces and mostly alphabetic, it's readable
    if " " in text:
        word_count = len(text.split())
        if word_count >= 2 and alpha / len(text) > 0.4:
            return True

    # Short strings that are all alphabetic
    if alpha / len(text) > 0.6 and len(text) >= 3 and len(text) <= 15:
        return True

    return False


def looks_encoded(text: str) -> bool:
    """Quick check if text looks like it's encoded (not readable)."""
    return not is_readable(text)


try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False
    tk = None


# ─────────────────────────────────────────────────────────────────────────────
# Color palette — classic hacker terminal
# ─────────────────────────────────────────────────────────────────────────────

BG          = "#050508"   # near-black background
BG_PANEL    = "#0d1117"   # slightly lighter for panels
BG_INPUT    = "#0a0e14"   # input box bg
BG_OUTPUT   = "#0a0e14"   # output box bg
BG_BTN      = "#0d1117"   # button bg
BG_BTN_HOV  = "#161b22"   # button hover
BG_HEADER   = "#0d1117"   # header bar
BG_STATUS   = "#0d1117"   # status bar

# Text colors
GREEN       = "#00ff41"   # matrix green — primary text
GREEN_DIM   = "#008f11"   # dimmer green for secondary
GREEN_BRIGHT= "#39ff14"   # bright green for highlights
AMBER       = "#ffb000"   # amber for warnings/input labels
RED         = "#ff003c"   # red for errors
CYAN        = "#00d4ff"   # cyan for info/URLs
YELLOW      = "#ffff00"   # yellow for flags
WHITE       = "#e0e0e0"   # near-white for decoded text
GRAY        = "#555555"   # gray for dim separators
GRAY_DARK   = "#1a1a1a"   # dark separator
PURPLE      = "#bb86fc"   # purple for notes

# Fonts — monospace throughout for terminal feel
FONT_TITLE    = ("Consolas", 16, "bold")
FONT_SUBTITLE = ("Consolas", 9)
FONT_LABEL    = ("Consolas", 10, "bold")
FONT_BODY     = ("Consolas", 11)
FONT_SMALL    = ("Consolas", 8)
FONT_BTN      = ("Consolas", 10, "bold")
FONT_BTN_BIG  = ("Consolas", 12, "bold")
FONT_OUTPUT   = ("Consolas", 11)
FONT_FLAG     = ("Consolas", 14, "bold")


class Code404CrackerGUI:
    """Main GUI — hacker terminal aesthetic, user-friendly design."""

    def __init__(self, root):
        self.root = root
        self.root.title("404 CODE CRACKER")
        self.root.geometry("1200x750")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)

        self._setup_style()
        self._build_header()
        self._build_notebook()
        self._build_status_bar()

    # ───────────────────────────────────────────────────────────────────────
    # Style
    # ───────────────────────────────────────────────────────────────────────
    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Tabs
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=BG_PANEL,
                        foreground=GRAY,
                        padding=[20, 8],
                        font=FONT_BTN)
        style.map("TNotebook.Tab",
                  background=[("selected", BG_INPUT)],
                  foreground=[("selected", GREEN)])

        style.configure("TFrame", background=BG)

    # ───────────────────────────────────────────────────────────────────────
    # Header bar — ASCII art title
    # ───────────────────────────────────────────────────────────────────────
    def _build_header(self):
        header = tk.Frame(self.root, bg=BG_HEADER, height=70)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        # ASCII art style title
        title = tk.Label(
            header,
            text="▓▒░ 404 CODE CRACKER ░▒▓",
            font=FONT_TITLE,
            bg=BG_HEADER, fg=GREEN
        )
        title.pack(side=tk.LEFT, padx=20, pady=10)

        subtitle = tk.Label(
            header,
            text="// auto-detect → decode → crack",
            font=FONT_SUBTITLE,
            bg=BG_HEADER, fg=GREEN_DIM
        )
        subtitle.pack(side=tk.LEFT, padx=5, pady=10)

        ver = tk.Label(
            header,
            text="v1.0",
            font=FONT_SUBTITLE,
            bg=BG_HEADER, fg=CYAN
        )
        ver.pack(side=tk.RIGHT, padx=20, pady=10)

    # ───────────────────────────────────────────────────────────────────────
    # Notebook with tabs
    # ───────────────────────────────────────────────────────────────────────
    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tab 1: Decode
        self.single_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.single_frame, text="  ▶ DECODE  ")
        self._build_single_tab(self.single_frame)

        # Tab 2: Bulk folder
        self.bulk_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.bulk_frame, text="  ▶ BULK SCAN  ")
        self._build_bulk_tab(self.bulk_frame)

        # Tab 3: Help
        self.help_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.help_frame, text="  ▶ HOW TO USE  ")
        self._build_help_tab(self.help_frame)

    # ───────────────────────────────────────────────────────────────────────
    # DECODE TAB — side by side: input LEFT, output RIGHT
    # ───────────────────────────────────────────────────────────────────────
    def _build_single_tab(self, parent):
        # ── Button bar ──
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        def make_btn(text, bg, fg, command, font=FONT_BTN, padx=15):
            b = tk.Button(btn_bar, text=text, font=font,
                          bg=bg, fg=fg, relief=tk.FLAT,
                          padx=padx, pady=6,
                          activebackground=BG_BTN_HOV,
                          activeforeground=fg,
                          command=command)
            return b

        make_btn("📂 Load File", BG_BTN, CYAN,
                 self._load_text_file, FONT_BTN, 12).pack(side=tk.LEFT, padx=(0, 5))
        make_btn("🖼 Load Image", BG_BTN, CYAN,
                 self._load_image_file, FONT_BTN, 12).pack(side=tk.LEFT, padx=(0, 5))
        make_btn("⚡ CRACK IT", GREEN, "#000000",
                 self._crack_single, FONT_BTN_BIG, 25).pack(side=tk.LEFT, padx=(0, 5))
        make_btn("Clear", BG_BTN, GRAY,
                 self._clear_single, FONT_BTN, 12).pack(side=tk.LEFT)
        make_btn("📋 Copy", BG_BTN, CYAN,
                 self._copy_output, FONT_BTN, 12).pack(side=tk.RIGHT)

        # ── Main content: two panels ──
        content = tk.Frame(parent, bg=BG)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 8))

        # LEFT: Input panel
        left = tk.Frame(content, bg=BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4))

        # Input header bar
        in_bar = tk.Frame(left, bg=BG_PANEL, relief=tk.FLAT)
        in_bar.pack(fill=tk.X, pady=(0, 2))

        tk.Label(in_bar, text=" INPUT ",
                 font=FONT_SMALL, bg=BG_PANEL, fg=GRAY).pack(side=tk.LEFT, padx=2)

        tk.Label(in_bar, text="─" * 50,
                 font=FONT_SMALL, bg=BG_PANEL, fg=GRAY_DARK).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(in_bar, text=" paste here ",
                 font=FONT_SMALL, bg=BG_PANEL, fg=GREEN_DIM).pack(side=tk.RIGHT, padx=4)

        # Input label
        tk.Label(left,
                 text="┌─[ PASTE ENCODED TEXT BELOW ]",
                 font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, pady=(6, 2))

        tk.Label(left,
                 text="│  Base64 • Hex • Binary • Morse • ROT13 • Caesar • and more",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, pady=(0, 4))

        self.input_text = scrolledtext.ScrolledText(
            left,
            font=FONT_BODY,
            bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN,
            relief=tk.FLAT,
            wrap=tk.WORD,
            padx=12, pady=12,
            height=5,
        )
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Input bottom label
        tk.Label(left, text="└─ paste any encoded text ↑",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, pady=(2, 0))

        # RIGHT: Output panel
        right = tk.Frame(content, bg=BG)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4, 0))

        # Output header bar
        out_bar = tk.Frame(right, bg=BG_PANEL, relief=tk.FLAT)
        out_bar.pack(fill=tk.X, pady=(0, 2))

        tk.Label(out_bar, text=" OUTPUT ",
                font=FONT_SMALL, bg=BG_PANEL, fg=GRAY).pack(side=tk.LEFT, padx=2)

        tk.Label(out_bar, text="─" * 50,
                 font=FONT_SMALL, bg=BG_PANEL, fg=GRAY_DARK).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(out_bar, text=" results here ",
                font=FONT_SMALL, bg=BG_PANEL, fg=GREEN_DIM).pack(side=tk.RIGHT, padx=4)

        # Output label
        tk.Label(right,
                 text="┌─[ DECODED RESULT ]",
                 font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, pady=(6, 2))

        tk.Label(right,
                 text="│  each decoding step shown below, then the final answer",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, pady=(0, 4))

        self.output_text = scrolledtext.ScrolledText(
            right,
            font=FONT_OUTPUT,
            bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN,
            relief=tk.FLAT,
            wrap=tk.WORD,
            padx=12, pady=12,
            height=5,
            state=tk.DISABLED,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Output color tags — terminal style
        self.output_text.tag_config("title", foreground=GREEN_BRIGHT,
                                    font=("Consolas", 12, "bold"))
        self.output_text.tag_config("step_num", foreground=CYAN,
                                    font=("Consolas", 11, "bold"))
        self.output_text.tag_config("encoding", foreground=AMBER,
                                    font=("Consolas", 11, "bold"))
        self.output_text.tag_config("arrow", foreground=GREEN_DIM,
                                    font=("Consolas", 11))
        self.output_text.tag_config("decoded", foreground=WHITE,
                                    font=("Consolas", 11))
        self.output_text.tag_config("final_label", foreground=GREEN_BRIGHT,
                                    font=("Consolas", 12, "bold"))
        self.output_text.tag_config("flag", foreground=YELLOW,
                                    font=("Consolas", 14, "bold"))
        self.output_text.tag_config("url", foreground=CYAN,
                                    font=("Consolas", 12, "bold"))
        self.output_text.tag_config("dim", foreground=GRAY,
                                    font=("Consolas", 9))
        self.output_text.tag_config("error", foreground=RED,
                                    font=("Consolas", 10, "bold"))
        self.output_text.tag_config("separator", foreground=GRAY_DARK)
        self.output_text.tag_config("note", foreground=PURPLE,
                                    font=("Consolas", 9, "italic"))
        self.output_text.tag_config("box", foreground=GREEN_DIM,
                                    font=("Consolas", 11))
        self.output_text.tag_config("plain", foreground=WHITE,
                                    font=("Consolas", 11))
        self.output_text.tag_config("prompt", foreground=GREEN_DIM,
                                    font=("Consolas", 10))

        # Output bottom label
        tk.Label(right, text="└─ decoded output ↑",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, pady=(2, 0))

    # ───────────────────────────────────────────────────────────────────────
    # BULK SCAN TAB
    # ───────────────────────────────────────────────────────────────────────
    def _build_bulk_tab(self, parent):
        top = tk.Frame(parent, bg=BG)
        top.pack(fill=tk.X, padx=10, pady=(10, 4))

        tk.Button(top, text="📂 Select Folder",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=15, pady=6, activebackground=BG_BTN_HOV,
                  command=self._select_bulk_folder).pack(side=tk.LEFT, padx=(0, 10))

        self.bulk_path_label = tk.Label(
            top, text="// no folder selected",
            font=FONT_BODY, bg=BG, fg=GRAY
        )
        self.bulk_path_label.pack(side=tk.LEFT)

        tk.Button(top, text="⚡ SCAN ALL FILES",
                  font=FONT_BTN_BIG, bg=GREEN, fg="#000000", relief=tk.FLAT,
                  padx=20, pady=6, activebackground=BG_BTN_HOV,
                  command=self._scan_bulk).pack(side=tk.LEFT, padx=(15, 0))

        # Hint
        tk.Label(parent,
                 text="┌─[ BULK FOLDER SCAN ]",
                 font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(8, 0))

        tk.Label(parent,
                 text="│  select a folder → the tool scans every text and image file inside",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, padx=10, pady=(0, 4))

        self.bulk_output = scrolledtext.ScrolledText(
            parent,
            font=FONT_OUTPUT,
            bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN,
            relief=tk.FLAT,
            wrap=tk.WORD,
            padx=12, pady=12,
        )
        self.bulk_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))

        self.bulk_output.tag_config("flag", foreground=YELLOW,
                                    font=("Consolas", 11, "bold"))
        self.bulk_output.tag_config("url", foreground=CYAN,
                                    font=("Consolas", 10, "bold"))
        self.bulk_output.tag_config("header", foreground=GREEN_BRIGHT,
                                    font=("Consolas", 10, "bold"))
        self.bulk_output.tag_config("dim", foreground=GRAY)
        self.bulk_output.tag_config("error", foreground=RED)
        self.bulk_output.tag_config("step", foreground=CYAN)
        self.bulk_output.tag_config("encoding", foreground=AMBER)
        self.bulk_output.tag_config("separator", foreground=GRAY_DARK)
        self.bulk_output.tag_config("box", foreground=GREEN_DIM)
        self.bulk_output.tag_config("prompt", foreground=GREEN_DIM)

    # ───────────────────────────────────────────────────────────────────────
    # HELP TAB
    # ───────────────────────────────────────────────────────────────────────
    def _build_help_tab(self, parent):
        help_text = scrolledtext.ScrolledText(
            parent,
            font=FONT_BODY,
            bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN,
            relief=tk.FLAT,
            wrap=tk.WORD,
            padx=15, pady=15,
        )
        help_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        help_text.tag_config("h1", foreground=GREEN_BRIGHT,
                             font=("Consolas", 14, "bold"))
        help_text.tag_config("h2", foreground=AMBER,
                             font=("Consolas", 11, "bold"))
        help_text.tag_config("dim", foreground=GRAY)
        help_text.tag_config("green", foreground=GREEN)
        help_text.tag_config("cyan", foreground=CYAN)
        help_text.tag_config("box", foreground=GREEN_DIM)

        content = [
            ("╔═══════════════════════════════════════════╗\n", "box"),
            ("║         404 CODE CRACKER — HOW TO USE      ║\n", "h1"),
            ("╚═══════════════════════════════════════════╝\n", "box"),
            ("\n", "dim"),
            ("WHAT DOES THIS TOOL DO?\n", "h2"),
            ("─────────────────────────\n", "dim"),
            ("You paste any encoded or encrypted text.\n", "dim"),
            ("The tool automatically:\n", "dim"),
            ("  → detects what encoding it is\n", "green"),
            ("  → decodes it\n", "green"),
            ("  → checks if the result is ALSO encoded\n", "green"),
            ("  → decodes again, layer by layer\n", "green"),
            ("  → gives you the final answer (flag, URL, or text)\n", "green"),
            ("\n", "dim"),
            ("SUPPORTED ENCODINGS:\n", "h2"),
            ("─────────────────────\n", "dim"),
            ("  Base64, Base32, Base85, Base58, Base62\n", "dim"),
            ("  Hexadecimal, Binary, Octal\n", "dim"),
            ("  ROT13, ROT47, Caesar, Atbash, Vigenere\n", "dim"),
            ("  Rail Fence, Bacon Cipher\n", "dim"),
            ("  Morse Code, URL Encoding, ASCII Decimal\n", "dim"),
            ("  HTML Entities, Unicode Escape, Hex Escape\n", "dim"),
            ("  XOR (single byte brute-force)\n", "dim"),
            ("  Brainfuck (esoteric language)\n", "dim"),
            ("  JWT (JSON Web Tokens)\n", "dim"),
            ("\n", "dim"),
            ("IMAGE SUPPORT:\n", "h2"),
            ("───────────────\n", "dim"),
            ("  QR Code reading from images\n", "dim"),
            ("  LSB Steganography (hidden text in pixels)\n", "dim"),
            ("  EXIF metadata extraction\n", "dim"),
            ("\n", "dim"),
            ("HOW TO USE — DECODE TAB:\n", "h2"),
            ("────────────────────────\n", "dim"),
            ("  1. Paste your encoded text in the LEFT box\n", "green"),
            ("  2. Click the green CRACK IT button\n", "green"),
            ("  3. Read the result in the RIGHT box\n", "green"),
            ("\n", "dim"),
            ("  The result shows:\n", "dim"),
            ("    • Each decoding step (what encoding → what it decoded to)\n", "cyan"),
            ("    • The final answer at the bottom (boxed)\n", "cyan"),
            ("    • Flags shown in YELLOW\n", "cyan"),
            ("    • URLs shown in CYAN\n", "cyan"),
            ("\n", "dim"),
            ("  You can also:\n", "dim"),
            ("    • Click Load File to read from a .txt file\n", "cyan"),
            ("    • Click Load Image to scan a QR code or find hidden text\n", "cyan"),
            ("\n", "dim"),
            ("HOW TO USE — BULK SCAN TAB:\n", "h2"),
            ("────────────────────────────\n", "dim"),
            ("  1. Click Select Folder and pick a directory\n", "green"),
            ("  2. Click SCAN ALL FILES\n", "green"),
            ("  3. Tool processes every file and shows all flags/URLs found\n", "dim"),
            ("\n", "dim"),
            ("INSTALLATION:\n", "h2"),
            ("─────────────\n", "dim"),
            ("  One line — paste this in your terminal:\n", "dim"),
            ("  curl -sSL https://raw.githubusercontent.com/\n", "cyan"),
            ("    unknownerror404k/404codecracker/main/install.sh | bash\n", "cyan"),
            ("\n", "dim"),
            ("  Or with pip:\n", "dim"),
            ("  pip install git+https://github.com/\n", "cyan"),
            ("    unknownerror404k/404codecracker.git\n", "cyan"),
            ("\n", "dim"),
            ("────────────────────────────────────────────\n", "dim"),
            ("  Created by ERROR 404\n", "dim"),
            ("  For educational and CTF use only.\n", "dim"),
            ("────────────────────────────────────────────\n", "dim"),
        ]

        for text, tag in content:
            help_text.insert(tk.END, text, tag)
        help_text.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # Status bar
    # ───────────────────────────────────────────────────────────────────────
    def _build_status_bar(self):
        self.status_bar = tk.Label(
            self.root,
            text=" [ ready ]  _",
            font=FONT_SMALL,
            bg=BG_STATUS, fg=GREEN_DIM,
            anchor=tk.W,
            relief=tk.FLAT,
            padx=10, pady=4
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _set_status(self, text: str):
        self.status_bar.config(text=f" [ {text} ]  _")
        self.root.update_idletasks()

    # ═══════════════════════════════════════════════════════════════════════
    # OUTPUT WRITING — terminal-style with box drawing
    # ═══════════════════════════════════════════════════════════════════════

    def _enable_output(self):
        self.output_text.configure(state=tk.NORMAL)

    def _disable_output(self):
        self.output_text.configure(state=tk.DISABLED)

    def _write(self, text: str, tag: str = ""):
        self.output_text.insert(tk.END, text, tag if tag else ())
        self.output_text.see(tk.END)

    def _write_line(self, text: str = "", tag: str = ""):
        self._write(text + "\n", tag)

    def _write_separator(self, char="─", width=50):
        """Write a visual separator line using box-drawing chars."""
        self._write_line(char * width, "separator")

    def _write_box_top(self, width=44):
        self._write_line("┌" + "─" * width + "┐", "box")

    def _write_box_mid(self, width=44):
        self._write_line("├" + "─" * width + "┤", "box")

    def _write_box_bottom(self, width=44):
        self._write_line("└" + "─" * width + "┘", "box")

    def _write_box_line(self, text: str, tag: str = "", width=44):
        """Write a line of text inside a box, padded to width."""
        # Calculate display width (rough — doesn't account for wide chars)
        padding = width - len(text)
        if padding < 0:
            padding = 0
        self._write("│ ", "box")
        self._write(text, tag)
        self._write_line(" " * padding + " │", "box")

    # ═══════════════════════════════════════════════════════════════════════
    # ACTIONS: Single input
    # ═══════════════════════════════════════════════════════════════════════

    def _load_text_file(self):
        path = filedialog.askopenfilename(
            title="Select a text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert("1.0", f.read())
                self._set_status(f"loaded: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file:\n{e}")

    def _load_image_file(self):
        path = filedialog.askopenfilename(
            title="Select an image file",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff *.webp"),
                ("All files", "*.*")
            ]
        )
        if path:
            self._process_image(path)

    def _process_image(self, path: str):
        self._set_status(f"scanning image: {os.path.basename(path)}...")
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", f"[image loaded: {os.path.basename(path)}]")
        self._enable_output()
        self.output_text.delete("1.0", tk.END)

        def worker():
            results = process_image(path)
            self.root.after(0, lambda: self._display_image_results(path, results))

        threading.Thread(target=worker, daemon=True).start()

    def _display_image_results(self, path: str, results: dict):
        self._enable_output()
        self.output_text.delete("1.0", tk.END)

        self._write_line("╔" + "═" * 44 + "╗", "box")
        self._write_box_line("IMAGE SCAN RESULTS", "title")
        self._write_box_mid()
        self._write_box_line(f"File: {os.path.basename(path)}", "dim")
        self._write_line("╚" + "═" * 44 + "╝", "box")
        self._write_blank = lambda: self._write_line()
        self._write_line()

        found_something = False

        # QR Code
        qr = results.get("qr_code")
        if qr and not str(qr).startswith("ERROR"):
            found_something = True
            self._write_line("▶ QR CODE FOUND", "step_num")
            self._write_line(f"  Content: {qr}", "decoded")
            self._write_line()

            flag = find_flag(qr)
            url = find_url(qr)
            if flag:
                self._write_box_top()
                self._write_box_line("FLAG FOUND!", "final_label")
                self._write_box_mid()
                self._write_box_line(flag, "flag")
                self._write_box_bottom()
                self._write_line()

            if url:
                self._write_box_top()
                self._write_box_line("URL FOUND!", "final_label")
                self._write_box_mid()
                self._write_box_line(url, "url")
                self._write_box_bottom()
                self._write_line()

            # Recursive decode
            self._write_line("  checking if QR content is also encoded...", "dim")
            result = recursive_decode(qr)
            if result.steps:
                self._write_line()
                self._write_line("  ▶ multiple layers found in QR content:", "note")
                self._write_line()
                self._display_decode_steps(result, indent="  ")
            self._write_line()
        elif qr and str(qr).startswith("ERROR"):
            self._write_line(f"  QR: {qr}", "error")
            self._write_line()
        else:
            self._write_line("▶ QR Code: none found", "dim")
            self._write_line()

        # LSB Steganography
        lsb = results.get("lsb_steganography")
        if lsb and not str(lsb).startswith("ERROR") and lsb:
            found_something = True
            self._write_line("▶ HIDDEN TEXT (Steganography - Red channel)", "step_num")
            self._write_line(f"  Message: {lsb}", "decoded")
            flag = find_flag(lsb)
            if flag:
                self._write_line(f"  FLAG: {flag}", "flag")
            self._write_line()

        lsb_all = results.get("lsb_all_channels")
        if lsb_all and not str(lsb_all).startswith("ERROR") and lsb_all:
            found_something = True
            self._write_line("▶ HIDDEN TEXT (Steganography - RGB channels)", "step_num")
            self._write_line(f"  Message: {lsb_all}", "decoded")
            flag = find_flag(lsb_all)
            if flag:
                self._write_line(f"  FLAG: {flag}", "flag")
            self._write_line()

        # EXIF
        exif = results.get("exif_data")
        if exif:
            found_something = True
            self._write_line("▶ EXIF METADATA", "step_num")
            for k, v in exif.items():
                self._write_line(f"  {k}: {v}", "dim")
            self._write_line()

        if not found_something:
            self._write_line("No hidden data found in this image.", "dim")
            self._write_line("No QR codes, no steganography, no EXIF data.", "dim")

        self._write_separator()
        self._write_line("[ scan complete ]", "title")
        self._disable_output()
        self._set_status("image scan complete.")

    def _crack_single(self):
        raw = self.input_text.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste some encoded text first.")
            return

        self._enable_output()
        self.output_text.delete("1.0", tk.END)

        # Show "decoding..." animation
        self._write("░ decoding", "prompt")
        self._set_status("decoding...")
        self.root.update_idletasks()

        def worker():
            result = recursive_decode(raw)
            self.root.after(0, lambda: self._display_decode_result(result))

        threading.Thread(target=worker, daemon=True).start()

    def _display_decode_steps(self, result, indent=""):
        """Write the step-by-step decoding path in plain English."""
        for i, step in enumerate(result.steps, 1):
            # Step header
            self._write(f"{indent}┌─ Step {i}: ", "step_num")
            self._write(f"{step.encoding}", "encoding")
            self._write_line(" ─┐", "box")

            # Decoded result
            preview = step.output_text
            if len(preview) > 300:
                preview = preview[:300] + "..."
            self._write_line(f"{indent}│  Decoded to: {preview}", "decoded")
            self._write_line(f"{indent}└────────────────────────────────┘", "box")
            self._write_line()

        # Final result
        if result.found_flag:
            self._write_line(f"{indent}╔══════════════════════════════════════════╗", "box")
            self._write_line(f"{indent}║  ✦ FINAL RESULT: FLAG FOUND!             ║", "final_label")
            self._write_line(f"{indent}╠══════════════════════════════════════════╣", "box")
            flag_text = result.found_flag
            padded = flag_text + " " * (42 - len(flag_text)) if len(flag_text) < 42 else flag_text
            self._write_line(f"{indent}║  {padded}  ║", "flag")
            self._write_line(f"{indent}╚══════════════════════════════════════════╝", "box")

        if result.found_url:
            self._write_line(f"{indent}╔══════════════════════════════════════════╗", "box")
            self._write_line(f"{indent}║  ➜ FINAL RESULT: URL FOUND!              ║", "final_label")
            self._write_line(f"{indent}╠══════════════════════════════════════════╣", "box")
            url_text = result.found_url
            padded = url_text + " " * (42 - len(url_text)) if len(url_text) < 42 else url_text
            self._write_line(f"{indent}║  {padded}  ║", "url")
            self._write_line(f"{indent}╚══════════════════════════════════════════╝", "box")

        if not result.found_flag and not result.found_url:
            self._write_line(f"{indent}╔══════════════════════════════════════════╗", "box")
            self._write_line(f"{indent}║  FINAL RESULT:                           ║", "final_label")
            self._write_line(f"{indent}╠══════════════════════════════════════════╣", "box")
            output = result.final_output
            if len(output) > 42:
                # Wrap long text
                while output:
                    chunk = output[:42]
                    output = output[42:]
                    padded = chunk + " " * (42 - len(chunk))
                    self._write_line(f"{indent}║  {padded}  ║", "plain")
            else:
                padded = output + " " * (42 - len(output))
                self._write_line(f"{indent}║  {padded}  ║", "plain")
            self._write_line(f"{indent}╚══════════════════════════════════════════╝", "box")

        # Other possible decodes
        if result.ambiguities:
            self._write_line()
            self._write_line(f"{indent}┌─ Other possible decodes (layer 1) ───────┐", "box")
            for name, text in result.ambiguities[:3]:
                preview = text[:38]
                self._write_line(f"{indent}│  {name}: {preview}", "note")
            self._write_line(f"{indent}└─────────────────────────────────────────┘", "box")

    def _display_decode_result(self, result):
        self._enable_output()
        self.output_text.delete("1.0", tk.END)

        if result.steps:
            # Header
            self._write_line("╔══════════════════════════════════════════╗", "box")
            self._write_line("║  ✦ DECODING PROCESS                      ║", "title")
            self._write_line("╚══════════════════════════════════════════╝", "box")
            self._write_line()
            self._write_line(f"Found {result.depth} layer(s) of encoding.", "dim")
            self._write_line("Decoding one by one:", "dim")
            self._write_separator()
            self._write_line()

            # Steps
            self._display_decode_steps(result)

        else:
            # No encoding detected
            self._write_line("╔══════════════════════════════════════════╗", "box")
            self._write_line("║  RESULT                                  ║", "title")
            self._write_line("╚══════════════════════════════════════════╝", "box")
            self._write_line()
            self._write_line("No encoding was detected.", "dim")
            self._write_line()
            self._write_line("This could mean:", "dim")
            self._write_line("  • The text is already readable plaintext", "dim")
            self._write_line("  • The encoding is not supported", "dim")
            self._write_line("  • It might be encrypted (AES/RSA) — needs a key", "dim")
            self._write_line()

            flag = find_flag(result.final_output)
            url = find_url(result.final_output)
            if flag:
                self._write_line(f"FLAG: {flag}", "flag")
            if url:
                self._write_line(f"URL: {url}", "url")

            self._write_line(f"Your text: {result.final_output}", "plain")

        self._write_line()
        self._write_separator()
        self._write_line("[ done ]", "prompt")
        self._set_status(f"done — {result.depth} layer(s) decoded")
        self._disable_output()

    # ═══════════════════════════════════════════════════════════════════════
    # ACTIONS: Bulk folder
    # ═══════════════════════════════════════════════════════════════════════

    def _select_bulk_folder(self):
        path = filedialog.askdirectory(title="Select a folder to scan")
        if path:
            self.bulk_folder = path
            self.bulk_path_label.config(text=f"// {path}", fg=GREEN_DIM)
            self._set_status(f"folder selected: {path}")

    def _scan_bulk(self):
        folder = getattr(self, "bulk_folder", None)
        if not folder:
            messagebox.showwarning("No folder", "Please select a folder first.")
            return

        self.bulk_output.delete("1.0", tk.END)
        self._set_status("scanning...")

        def worker():
            self._bulk_scan_worker(folder)

        threading.Thread(target=worker, daemon=True).start()

    def _bulk_scan_worker(self, folder: str):
        files = []
        for root_dir, _, filenames in os.walk(folder):
            for fname in filenames:
                fpath = os.path.join(root_dir, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext in {".txt", ".csv", ".json", ".xml", ".log",
                           ".md", ".py", ".js", ".html", ".htm", ""} or \
                   is_image_file(fpath):
                    files.append(fpath)

        self.root.after(0, lambda: self._bulk_write(
            f"╔══════════════════════════════════════════╗\n", "box"))
        self.root.after(0, lambda: self._bulk_write(
            f"║  BULK SCAN — {len(files)} file(s)                ║\n", "header"))
        self.root.after(0, lambda: self._bulk_write(
            f"╚══════════════════════════════════════════╝\n", "box"))
        self.root.after(0, lambda: self._bulk_write(
            f"{folder}\n\n", "dim"))

        flags_found = []
        urls_found = []

        for i, fpath in enumerate(files):
            fname = os.path.basename(fpath)
            self.root.after(0, lambda fn=fname, n=i+1, t=len(files):
                self._bulk_write(f"┌─ [{n}/{t}] {fn}\n", "box"))

            try:
                if is_image_file(fpath):
                    img_results = process_image(fpath)
                    qr = img_results.get("qr_code")
                    if qr and not str(qr).startswith("ERROR"):
                        self.root.after(0, lambda q=qr:
                            self._bulk_write(f"│  QR: {q}\n",
                                "flag" if find_flag(q) else "url"
                                if find_url(q) else "step"))
                        flag = find_flag(qr)
                        url = find_url(qr)
                        if flag: flags_found.append((fname, flag))
                        if url: urls_found.append((fname, url))
                        result = recursive_decode(qr)
                        if result.steps:
                            for s in result.steps:
                                self.root.after(0, lambda st=s:
                                    self._bulk_write(
                                        f"│    → {st.encoding}: {st.output_text[:50]}\n",
                                        "encoding"))
                            if result.found_flag:
                                flags_found.append((fname, result.found_flag))

                    lsb = img_results.get("lsb_steganography")
                    if lsb and not str(lsb).startswith("ERROR"):
                        self.root.after(0, lambda l=lsb:
                            self._bulk_write(f"│  Hidden: {l[:60]}\n",
                                "flag" if find_flag(l) else "step"))
                        flag = find_flag(lsb)
                        if flag: flags_found.append((fname, flag))
                else:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read().strip()
                    if not content:
                        self.root.after(0, lambda:
                            self._bulk_write("│  (empty)\n", "dim"))
                        continue

                    result = recursive_decode(content)
                    if result.steps:
                        for s in result.steps:
                            self.root.after(0, lambda st=s:
                                self._bulk_write(
                                    f"│  → {st.encoding}: {st.output_text[:55]}\n",
                                    "encoding"))

                    if result.found_flag:
                        self.root.after(0, lambda r=result:
                            self._bulk_write(f"│  ★ FLAG: {r.found_flag}\n", "flag"))
                        flags_found.append((fname, result.found_flag))
                    if result.found_url:
                        self.root.after(0, lambda r=result:
                            self._bulk_write(f"│  ➜ URL: {r.found_url}\n", "url"))
                        urls_found.append((fname, result.found_url))
                    if not result.found_flag and not result.found_url and result.steps:
                        self.root.after(0, lambda r=result:
                            self._bulk_write(f"│  Result: {r.final_output[:55]}\n", "dim"))

            except Exception as e:
                self.root.after(0, lambda err=e:
                    self._bulk_write(f"│  ✗ ERROR: {err}\n", "error"))

            self.root.after(0, lambda: self._bulk_write("└──────────────────────\n", "box"))

        # Summary
        self.root.after(0, lambda: self._bulk_write(
            f"\n{'─' * 44}\n", "separator"))
        self.root.after(0, lambda: self._bulk_write(
            "╔══════════════════════════════════════════╗\n", "box"))
        self.root.after(0, lambda: self._bulk_write(
            "║  SCAN COMPLETE                           ║\n", "header"))
        self.root.after(0, lambda: self._bulk_write(
            "╚══════════════════════════════════════════╝\n", "box"))

        if flags_found:
            self.root.after(0, lambda: self._bulk_write(
                f"\n★ FLAGS FOUND ({len(flags_found)}):\n", "header"))
            for fname, flag in flags_found:
                self.root.after(0, lambda fn=fname, fl=flag:
                    self._bulk_write(f"  {fn}: {fl}\n", "flag"))

        if urls_found:
            self.root.after(0, lambda: self._bulk_write(
                f"\n➜ URLS FOUND ({len(urls_found)}):\n", "header"))
            for fname, url in urls_found:
                self.root.after(0, lambda fn=fname, u=url:
                    self._bulk_write(f"  {fn}: {u}\n", "url"))

        if not flags_found and not urls_found:
            self.root.after(0, lambda: self._bulk_write(
                "\nNo flags or URLs found.\n", "dim"))

        self.root.after(0, lambda: self._set_status(
            f"done — {len(flags_found)} flag(s), {len(urls_found)} url(s)"))

    def _bulk_write(self, text: str, tag: str = ""):
        self.bulk_output.insert(tk.END, text, tag if tag else ())
        self.bulk_output.see(tk.END)
        self.root.update_idletasks()

    # ═══════════════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════════════

    def _clear_single(self):
        self.input_text.delete("1.0", tk.END)
        self._enable_output()
        self.output_text.delete("1.0", tk.END)
        self._disable_output()
        self._set_status("ready — paste text and click CRACK IT")

    def _copy_output(self):
        content = self.output_text.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("copied to clipboard")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────



BANNER = r"""
  ╔══════════════════════════════════════════════╗
  ║  404 CODE CRACKER v1.1                       ║
  ║  Auto-detect | Decode | Crack               ║
  ║  Created by ERROR 404                        ║
  ╚══════════════════════════════════════════════╝
"""

def print_banner():
    print(BANNER)


def print_result(result):
    """Print a DecodeResult in hacker-terminal style with clear steps."""
    if result.steps:
        print()
        print("  ╔══════════════════════════════════════════╗")
        print("  ║  ✦ DECODING PROCESS                      ║")
        print("  ╚══════════════════════════════════════════╝")
        print()
        print(f"  Found {result.depth} layer(s) of encoding.")
        print(f"  Decoding one by one:")
        print("  " + "─" * 50)
        for i, step in enumerate(result.steps, 1):
            print(f"\n  ┌─ Step {i}: {step.encoding} ─┐")
            preview = step.output_text[:200]
            if len(step.output_text) > 200:
                preview += "..."
            print(f"  │  Decoded to: {preview}")
            print(f"  └────────────────────────────────┘")
        print("\n  " + "─" * 50)
    else:
        print()
        print("  ╔══════════════════════════════════════════╗")
        print("  ║  RESULT                                  ║")
        print("  ╚══════════════════════════════════════════╝")
        print()
        print("  No encoding was detected.")
        print()
        print("  This could mean:")
        print("    • The text is already plain readable text")
        print("    • The encoding is not supported by this tool")
        print("    • It might be encrypted (AES/RSA) which needs a key")
        print()

    if result.found_flag:
        print()
        print("  ╔══════════════════════════════════════════╗")
        print("  ║  ✦ FINAL RESULT: FLAG FOUND!             ║")
        print("  ╠══════════════════════════════════════════╣")
        print(f"  ║  {result.found_flag}")
        print("  ╚══════════════════════════════════════════╝")

    if result.found_url:
        print()
        print("  ╔══════════════════════════════════════════╗")
        print("  ║  ➜ FINAL RESULT: URL FOUND!              ║")
        print("  ╠══════════════════════════════════════════╣")
        print(f"  ║  {result.found_url}")
        print("  ╚══════════════════════════════════════════╝")

    if not result.found_flag and not result.found_url:
        print(f"\n  FINAL RESULT:")
        print(f"  {result.final_output}")

    if result.ambiguities:
        print(f"\n  ┌─ Other possible decodes (layer 1) ───────┐")
        for name, text in result.ambiguities[:5]:
            preview = text[:38]
            print(f"  │  {name}: {preview}")
        print(f"  └─────────────────────────────────────────┘")

    print("\n  " + "─" * 50)
    print("  [ done ]")


def handle_text(text: str):
    """Decode a text string."""
    if not text.strip():
        print("  [-] Empty input.")
        return
    result = recursive_decode(text.strip())
    print_result(result)


def handle_file(filepath: str):
    """Decode contents of a text file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
        if not content:
            print("  [-] File is empty.")
            return
        print(f"\n  [*] File: {os.path.basename(filepath)}")
        handle_text(content)
    except FileNotFoundError:
        print(f"  [-] File not found: {filepath}")
    except Exception as e:
        print(f"  [-] Error reading file: {e}")


def handle_image(filepath: str):
    """Process an image file (QR code + steganography)."""
    print(f"\n  [*] Image: {os.path.basename(filepath)}")
    print("  " + "=" * 55)

    results = process_image(filepath)

    # QR Code
    qr = results.get("qr_code")
    if qr and not str(qr).startswith("ERROR"):
        print(f"\n  [QR CODE FOUND]")
        print(f"    {qr}")
        flag = find_flag(qr)
        url = find_url(qr)
        if flag:
            print(f"\n  >>> FLAG: {flag}")
        if url:
            print(f"\n  >>> URL: {url}")
        # Try recursive decode
        if qr:
            print(f"\n  [*] Attempting recursive decode on QR content...")
            result = recursive_decode(qr)
            if result.steps:
                print_result(result)
    elif qr and str(qr).startswith("ERROR"):
        print(f"\n  [-] QR: {qr}")
    else:
        print("\n  [QR CODE] None found.")

    # LSB Steganography
    lsb = results.get("lsb_steganography")
    if lsb and not str(lsb).startswith("ERROR"):
        print(f"\n  [LSB STEGANOGRAPHY (R channel)]")
        print(f"    {lsb[:200]}")
        flag = find_flag(lsb)
        if flag:
            print(f"\n  >>> FLAG: {flag}")

    lsb_all = results.get("lsb_all_channels")
    if lsb_all and not str(lsb_all).startswith("ERROR"):
        print(f"\n  [LSB STEGANOGRAPHY (RGB channels)]")
        print(f"    {lsb_all[:200]}")
        flag = find_flag(lsb_all)
        if flag:
            print(f"\n  >>> FLAG: {flag}")

    # EXIF
    exif = results.get("exif_data")
    if exif:
        print(f"\n  [EXIF METADATA]")
        for k, v in exif.items():
            print(f"    {k}: {v}")

    print("\n  " + "=" * 55)
    print("  Image analysis complete.")


def handle_directory(dirpath: str):
    """Bulk scan a directory."""
    print(f"\n  [*] Scanning directory: {dirpath}")
    print("  " + "=" * 55)

    files = []
    for root_dir, _, filenames in os.walk(dirpath):
        for fname in filenames:
            fpath = os.path.join(root_dir, fname)
            ext = os.path.splitext(fname)[1].lower()
            if ext in {".txt", ".csv", ".json", ".xml", ".log", ".md",
                       ".py", ".js", ".html", ".htm", ""} or \
               is_image_file(fpath):
                files.append(fpath)

    print(f"\n  Found {len(files)} file(s) to process.\n")

    flags_found = []
    urls_found = []

    for i, fpath in enumerate(files):
        fname = os.path.basename(fpath)
        print(f"  [{i+1}/{len(files)}] {fname}")

        try:
            if is_image_file(fpath):
                img_results = process_image(fpath)
                qr = img_results.get("qr_code")
                if qr and not str(qr).startswith("ERROR"):
                    print(f"    QR: {qr[:100]}")
                    flag = find_flag(qr)
                    url = find_url(qr)
                    if flag:
                        flags_found.append((fname, flag))
                    if url:
                        urls_found.append((fname, url))

                lsb = img_results.get("lsb_steganography")
                if lsb and not str(lsb).startswith("ERROR"):
                    print(f"    LSB: {lsb[:100]}")
                    flag = find_flag(lsb)
                    if flag:
                        flags_found.append((fname, flag))
            else:
                with open(fpath, "r", encoding="utf-8",
                          errors="replace") as f:
                    content = f.read().strip()
                if not content:
                    print("    (empty)")
                    continue

                result = recursive_decode(content)
                if result.found_flag:
                    print(f"    FLAG: {result.found_flag}")
                    flags_found.append((fname, result.found_flag))
                if result.found_url:
                    print(f"    URL: {result.found_url}")
                    urls_found.append((fname, result.found_url))

                if result.steps and not result.found_flag:
                    print(f"    Decoded {result.depth} layer(s) -> "
                          f"{result.final_output[:80]}")
        except Exception as e:
            print(f"    ERROR: {e}")

    print("\n  " + "=" * 55)
    print(f"\n  SCAN COMPLETE")

    if flags_found:
        print(f"\n  FLAGS FOUND ({len(flags_found)}):")
        for fname, flag in flags_found:
            print(f"    {fname}: {flag}")

    if urls_found:
        print(f"\n  URLS FOUND ({len(urls_found)}):")
        for fname, url in urls_found:
            print(f"    {fname}: {url}")

    if not flags_found and not urls_found:
        print("\n  No flags or URLs found.")

    print()


def interactive_mode():
    """Interactive CLI loop — paste text and get results."""
    print_banner()
    print("  Interactive mode. Paste encoded text and press Enter.")
    print("  Commands: 'exit' to quit, 'file <path>' to read a file,")
    print("            'image <path>' to scan an image.")
    print("  " + "=" * 55)

    while True:
        try:
            print()
            user_input = input("  404> ").strip()

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                print("\n  Goodbye!\n")
                break
            if user_input.lower().startswith("file "):
                filepath = user_input[5:].strip()
                handle_file(filepath)
                continue
            if user_input.lower().startswith("image "):
                filepath = user_input[6:].strip()
                handle_image(filepath)
                continue

            handle_text(user_input)

        except KeyboardInterrupt:
            print("\n\n  Goodbye!\n")
            break
        except EOFError:
            print("\n  Goodbye!\n")
            break



def main():
    """Main entry point - parses args and routes to the right handler."""
    # Import is done at the top of the file
    parser = argparse.ArgumentParser(
        prog="404codecracker",
        description="404 Code Cracker - Auto-detect and decode encoded text (CTF tool)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  404codecracker                  Launch GUI (default)
  404codecracker --cli            Interactive CLI mode
  404codecracker -t "SGVsbG8="   Decode a single string
  404codecracker -f encoded.txt   Decode a text file
  404codecracker -i qr.png        Scan an image (QR/steganography)
  404codecracker -d ./ctf_files   Bulk scan a directory
        """
    )

    parser.add_argument("--cli", action="store_true",
                        help="Run in interactive CLI mode instead of GUI")
    parser.add_argument("-t", "--text", type=str, default=None,
                        help="Text string to decode")
    parser.add_argument("-f", "--file", type=str, default=None,
                        help="Text file to decode")
    parser.add_argument("-i", "--image", type=str, default=None,
                        help="Image file to scan (QR code / steganography)")
    parser.add_argument("-d", "--dir", type=str, default=None,
                        help="Directory to bulk scan")
    parser.add_argument("--no-banner", action="store_true",
                        help="Skip the banner")

    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    if args.text:
        handle_text(args.text)
    elif args.file:
        handle_file(args.file)
    elif args.image:
        handle_image(args.image)
    elif args.dir:
        handle_directory(args.dir)
    elif args.cli:
        interactive_mode()
    else:
        # Default: launch GUI
        try:
            run_gui()
        except Exception as e:
            print(f"  [-] Could not launch GUI: {e}")
            print("  [-] Run with --cli for terminal mode instead.")
            interactive_mode()


def run_gui():
    """Launch the GUI application."""
    import tkinter as tk
    from tkinter import ttk
    root = tk.Tk()
    app = Code404CrackerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
