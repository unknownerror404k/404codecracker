"""
404 Code Cracker - Single-file version.
Auto-detect and decode encoded/encrypted text - CTF Swiss Army Knife.

Created by ERROR 404
For educational and CTF use only.
"""

import base64
import binascii
import re
import re as _re
import json
import urllib.parse
import os
import argparse
import sys
import threading
import math

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
# Rail Fence Multi-Rail (v3.0 addition)
# ---------------------------------------------------------------------------
def decode_rail_fence_multi(s, num_rails=3):
    """Decode rail fence cipher with a specific number of rails."""
    s = ''.join(c for c in s if c.isalpha() or c.isdigit())
    if not s or len(s) < 4:
        raise ValueError("Rail Fence needs at least 4 characters")
    if num_rails < 2 or num_rails > 10:
        raise ValueError("Rails must be between 2 and 10")
    n = len(s)
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
    rail_lengths = [0] * num_rails
    for r in pattern:
        rail_lengths[r] += 1
    rail_texts = []
    pos = 0
    for r in range(num_rails):
        rail_texts.append(s[pos:pos + rail_lengths[r]])
        pos += rail_lengths[r]
    result = []
    indices = [0] * num_rails
    for r in pattern:
        result.append(rail_texts[r][indices[r]])
        indices[r] += 1
    return ''.join(result)

def encode_rail_fence_multi(s, num_rails=3):
    """Encode rail fence cipher with a specific number of rails."""
    s = ''.join(c for c in s if c.isalpha() or c.isdigit())
    if not s or len(s) < 4:
        raise ValueError("Rail Fence needs at least 4 characters")
    if num_rails < 2 or num_rails > 10:
        raise ValueError("Rails must be between 2 and 10")
    n = len(s)
    rails = [[] for _ in range(num_rails)]
    rail = 0
    direction = 1
    for i in range(n):
        rails[rail].append(s[i])
        if rail == 0:
            direction = 1
        elif rail == num_rails - 1:
            direction = -1
        rail += direction
    return ''.join(''.join(r) for r in rails)

def rail_fence_all_rails(s):
    """Try rail fence with 2-7 rails, return all results."""
    s_clean = ''.join(c for c in s if c.isalpha() or c.isdigit())
    if not s_clean or len(s_clean) < 4:
        raise ValueError("Rail Fence needs at least 4 characters")
    results = []
    for num_rails in range(2, 8):
        try:
            decoded = decode_rail_fence_multi(s_clean, num_rails)
            results.append((num_rails, decoded))
        except Exception:
            continue
    return results


# ---------------------------------------------------------------------------
# File Carving — extract embedded files (v3.0 addition)
# ---------------------------------------------------------------------------
FILE_SIGNATURES_CARVE = [
    (b'\x89PNG\r\n\x1a\n', 'PNG Image', '.png'),
    (b'\xff\xd8\xff', 'JPEG Image', '.jpg'),
    (b'GIF87a', 'GIF Image (87a)', '.gif'),
    (b'GIF89a', 'GIF Image (89a)', '.gif'),
    (b'PK\x03\x04', 'ZIP Archive', '.zip'),
    (b'Rar!\x1a\x07', 'RAR Archive', '.rar'),
    (b'\x1f\x8b', 'GZIP Archive', '.gz'),
    (b'BZh', 'BZIP2 Archive', '.bz2'),
    (b'%PDF', 'PDF Document', '.pdf'),
    (b'\x7fELF', 'ELF Binary', '.elf'),
    (b'MZ', 'Windows Executable', '.exe'),
    (b'RIFF', 'RIFF Container (WAV/AVI)', '.wav'),
    (b'SQLite format 3', 'SQLite Database', '.sqlite'),
    (b'\x49\x49\x2a\x00', 'TIFF Image', '.tiff'),
    (b'\x00\x00\x01\x00', 'ICO Icon', '.ico'),
    (b'ftyp', 'MP4 Video', '.mp4'),
    (b'\x1a\x45\xdf\xa3', 'Matroska (MKV/WebM)', '.mkv'),
    (b'ID3', 'MP3 Audio', '.mp3'),
    (b'\xff\xfb', 'MP3 Audio', '.mp3'),
    (b'OGG', 'OGG Audio', '.ogg'),
    (b'\x66\x4c\x61\x43', 'FLAC Audio', '.flac'),
    (b'\xd0\xcf\x11\xe0', 'OLE Document (DOC/XLS)', '.doc'),
]

def carve_files(filepath, output_dir='/tmp/404_carved'):
    """Extract embedded files from inside another file."""
    import os
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        return f"Error reading file: {e}"
    findings = []
    carved = 0
    os.makedirs(output_dir, exist_ok=True)
    for sig, name, ext in FILE_SIGNATURES_CARVE:
        pos = 0
        while True:
            pos = data.find(sig, pos)
            if pos == -1:
                break
            # Find the next signature or end of file to determine the carved file's size
            next_pos = len(data)
            for next_sig, _, _ in FILE_SIGNATURES_CARVE:
                if next_sig == sig:
                    continue
                next_find = data.find(next_sig, pos + len(sig))
                if next_find != -1 and next_find < next_pos:
                    next_pos = next_find
            carved_data = data[pos:next_pos]
            if len(carved_data) > len(sig):
                # Check for proper end markers
                if name.startswith('PNG'):
                    end_pos = carved_data.find(b'IEND\xaeB`\x82')
                    if end_pos != -1:
                        carved_data = carved_data[:end_pos + 8]
                elif name.startswith('JPEG'):
                    end_pos = carved_data.find(b'\xff\xd9')
                    if end_pos != -1:
                        carved_data = carved_data[:end_pos + 2]
                elif name.startswith('GIF'):
                    end_pos = carved_data.find(b'\x00\x3b')
                    if end_pos != -1:
                        carved_data = carved_data[:end_pos + 2]
                elif name.startswith('ZIP') or name.startswith('GZIP') or name.startswith('BZIP2'):
                    pass  # Archives don't have simple end markers
                elif name.startswith('PDF'):
                    end_pos = carved_data.find(b'%%EOF')
                    if end_pos != -1:
                        carved_data = carved_data[:end_pos + 5]
                fname = f"{output_dir}/carved_{carved:03d}_{name.replace(' ', '_').replace('/', '_')}{ext}"
                try:
                    with open(fname, 'wb') as f:
                        f.write(carved_data)
                    findings.append(f"  Offset 0x{pos:08x}: {name} → {fname} ({len(carved_data)} bytes)")
                    carved += 1
                except Exception:
                    pass
            pos += len(sig)
    if not findings:
        return "No embedded files found to carve."
    header = f"Carved {carved} file(s) from {len(data)} bytes of data:\n"
    return header + '\n'.join(findings)


# ---------------------------------------------------------------------------
# Decoder Registry
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Base64 Image Detection
# ---------------------------------------------------------------------------

IMAGE_SIGNATURES = {
    b"\x89PNG": ".png",
    b"\xff\xd8\xff": ".jpg",
    b"GIF8": ".gif",
    b"BM": ".bmp",
    b"RIFF": ".webp",
}

def decode_base64_image(s: str) -> str | None:
    """Check if Base64 decodes to an image. If yes, save and open it."""
    s = _clean(s)
    if not re.fullmatch(r'[A-Za-z0-9+/=\s]+', s):
        return None
    s = s.replace(" ", "")
    if len(s) < 40:
        return None
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    try:
        decoded_bytes = base64.b64decode(s, validate=True)
    except Exception:
        return None

    image_ext = None
    for sig, ext in IMAGE_SIGNATURES.items():
        if decoded_bytes.startswith(sig):
            image_ext = ext
            break

    if image_ext is None:
        return None

    import tempfile, subprocess, platform
    if platform.system() == "Linux":
        save_path = f"/tmp/404codecracker_image{image_ext}"
    else:
        save_path = os.path.join(os.path.expanduser("~"), f"404codecracker_image{image_ext}")

    with open(save_path, "wb") as f:
        f.write(decoded_bytes)

    try:
        if platform.system() == "Linux":
            subprocess.Popen(["xdg-open", save_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif platform.system() == "Windows":
            os.startfile(save_path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", save_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    return f"IMAGE DETECTED! Saved to: {save_path} - Image opened! Check it!"


# ===========================================================================
# NEW ENCODING DECODERS (v3.0)
# ===========================================================================


# --- Base91 ---
_B91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~'
_B91_DECODE = {c: i for i, c in enumerate(_B91_ALPHABET)}

def decode_base91(s):
    s = s.strip()
    if not s:
        raise ValueError("Empty input")
    cleaned = ''.join(c for c in s if c in _B91_DECODE)
    if not cleaned or len(cleaned) < 2:
        raise ValueError("Not valid Base91")
    if len(cleaned) < len(s.replace('\n','').replace('\r','').replace('\t','').replace(' ','')) * 0.5:
        raise ValueError("Too many invalid characters for Base91")
    b = 0
    n = 0
    v = -1
    result = bytearray()
    for c in cleaned:
        if v < 0:
            v = _B91_DECODE[c]
        else:
            v += _B91_DECODE[c] * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                result.append(b & 0xff)
                b >>= 8
                n -= 8
            v = -1
    if v >= 0:
        b |= v << n
        result.append(b & 0xff)
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        return result.decode('latin-1')

def encode_base91(s):
    data = s.encode('utf-8')
    result = []
    b = 0
    n = 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 0x1fff
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 0x3fff
                b >>= 14
                n -= 14
            result.append(_B91_ALPHABET[v % 91])
            result.append(_B91_ALPHABET[v // 91])
    if n > 0:
        result.append(_B91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            result.append(_B91_ALPHABET[b // 91])
    return ''.join(result)

# --- Base45 ---
_B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

def decode_base45(s):
    s = s.strip()
    dtab = {c: i for i, c in enumerate(_B45_ALPHABET)}
    if any(c not in dtab for c in s):
        raise ValueError("Not valid Base45")
    chunks = [s[i:i+3] for i in range(0, len(s), 3)]
    result = bytearray()
    for chunk in chunks:
        if len(chunk) == 3:
            c, d, e = (dtab[x] for x in chunk)
            n = c + d * 45 + e * 45 * 45
            if n > 0xFFFF:
                raise ValueError("Invalid Base45 value")
            result.append(n >> 8)
            result.append(n & 0xff)
        elif len(chunk) == 2:
            c, d = (dtab[x] for x in chunk)
            n = c + d * 45
            if n > 255:
                raise ValueError("Invalid Base45 value")
            result.append(n)
        else:
            raise ValueError("Invalid Base45 chunk length")
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        return result.decode('latin-1')

def encode_base45(s):
    data = s.encode('utf-8')
    result = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            n = data[i] * 256 + data[i + 1]
            result.append(_B45_ALPHABET[n % 45])
            result.append(_B45_ALPHABET[(n // 45) % 45])
            result.append(_B45_ALPHABET[(n // 2025) % 45])
        else:
            n = data[i]
            result.append(_B45_ALPHABET[n % 45])
            result.append(_B45_ALPHABET[n // 45])
    return ''.join(result)

# --- UUencode ---
def decode_uuencode(s):
    s = s.strip()
    lines = s.split('\n')
    # Filter out begin/end header lines
    body_lines = []
    for line in lines:
        line = line.strip()
        if not line or line.lower() == 'end':
            continue
        if line.lower().startswith('begin '):
            continue
        body_lines.append(line)
    body = '\n'.join(body_lines)
    if not body:
        raise ValueError("Not valid UUencode (no body found)")
    try:
        result = binascii.a2b_uu(body)
        return result.decode('utf-8', errors='replace')
    except Exception:
        # Try line by line as fallback
        result = bytearray()
        for line in body_lines:
            try:
                line_bytes = line.encode('ascii')
                length = (line_bytes[0] - 32) & 0x3F
                for i in range(1, len(line_bytes), 4):
                    if i + 3 > len(line_bytes):
                        break
                    c1, c2, c3, c4 = [(b - 32) & 0x3F for b in line_bytes[i:i+4]]
                    result.append((c1 << 2) | (c2 >> 4))
                    if len(result) < length:
                        result.append(((c2 & 0xF) << 4) | (c3 >> 2))
                    if len(result) < length:
                        result.append(((c3 & 0x3) << 6) | c4)
            except Exception:
                continue
        if not result:
            raise ValueError("Not valid UUencode")
        try:
            return result.decode('utf-8')
        except UnicodeDecodeError:
            return result.decode('latin-1')

def encode_uuencode(s):
    import binascii
    data = s.encode('utf-8')
    return "begin 644 data\n" + binascii.b2a_uu(data).decode('ascii') + "end\n"

# --- A1Z26 ---
def decode_a1z26(s):
    s = s.strip()
    parts = _re.split(r'[\s,\-]+', s)
    result = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p.isdigit():
            num = int(p)
            if 1 <= num <= 26:
                result.append(chr(num + 64))
            else:
                result.append(p)
        else:
            result.append(p)
    if not result:
        raise ValueError("No valid numbers found for A1Z26")
    return ''.join(result)

def encode_a1z26(s):
    result = []
    for c in s.upper():
        if 'A' <= c <= 'Z':
            result.append(str(ord(c) - 64))
        else:
            result.append(c)
    return ' '.join(result)

# --- Tap Code ---
_TAP_GRID = [
    ['A','B','C','D','E'],
    ['F','G','H','I','J'],
    ['L','M','N','O','P'],
    ['Q','R','S','T','U'],
    ['V','W','X','Y','Z'],
]

def decode_tap_code(s):
    s = s.strip()
    pairs = _re.findall(r'(\d)[\s,]+(\d)', s)
    if len(pairs) < 2:
        raise ValueError("Not valid tap code")
    result = []
    for r_str, c_str in pairs:
        r, c = int(r_str), int(c_str)
        if 1 <= r <= 5 and 1 <= c <= 5:
            result.append(_TAP_GRID[r-1][c-1])
        else:
            result.append('?')
    return ''.join(result)

def encode_tap_code(s):
    result = []
    for c in s.upper():
        if c == 'K':
            c = 'C'
        found = False
        for r in range(5):
            for c_idx in range(5):
                if _TAP_GRID[r][c_idx] == c:
                    result.append(f"{r+1},{c_idx+1}")
                    found = True
                    break
            if found:
                break
    return ' '.join(result)

# --- Punycode ---
def decode_punycode(s):
    s = s.strip()
    if s.lower().startswith('xn--'):
        s = s[4:]
    try:
        return s.encode('ascii').decode('punycode')
    except Exception:
        raise ValueError("Not valid Punycode")

def encode_punycode(s):
    try:
        return 'xn--' + s.encode('punycode').decode('ascii')
    except Exception:
        raise ValueError("Cannot encode to Punycode")

# --- BCD (Binary Coded Decimal) ---
def decode_bcd(s):
    s = s.strip().replace(' ', '')
    if not s or not _re.match(r'^[01]+$', s):
        raise ValueError("Not valid BCD (binary digits only)")
    if len(s) % 4 != 0:
        raise ValueError("BCD length must be multiple of 4")
    result = []
    for i in range(0, len(s), 4):
        nibble = s[i:i+4]
        val = int(nibble, 2)
        if val > 9:
            result.append('?')
        else:
            result.append(str(val))
    return ''.join(result)

def encode_bcd(s):
    result = []
    for c in s:
        if c.isdigit():
            result.append(format(int(c), '04b'))
    return ' '.join(result)

# --- ROT8000 ---
def decode_rot8000(s):
    result = []
    for c in s:
        cp = ord(c)
        if 0x4E00 <= cp <= 0x9FFF:
            result.append(chr(cp + 0x8000) if cp + 0x8000 <= 0x9FFF + 0x8000 else chr(cp - 0x8000))
        elif 0x10000 <= cp <= 0x1FFFF:
            result.append(chr(cp - 0x8000))
        else:
            result.append(c)
    return ''.join(result)

def encode_rot8000(s):
    return decode_rot8000(s)

# --- ROT-n (try all shifts for auto-detect) ---
def decode_rot_n(s, shift=13):
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


# ===========================================================================
# NEW CIPHER DECODERS (v3.0)
# ===========================================================================

# --- Affine Cipher ---
_AFFINE_A_INV = {1:1, 3:9, 5:21, 7:15, 9:3, 11:19, 15:7, 17:23, 19:11, 21:5, 23:17, 25:25}

def decode_affine(s, a=5, b=8):
    if a not in _AFFINE_A_INV:
        raise ValueError(f"Invalid 'a' value: {a}. Must be coprime with 26.")
    a_inv = _AFFINE_A_INV[a]
    result = []
    for c in s:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            x = (a_inv * ((ord(c) - base) - b)) % 26
            result.append(chr(x + base))
        else:
            result.append(c)
    return ''.join(result)

def encode_affine(s, a=5, b=8):
    if a not in _AFFINE_A_INV:
        raise ValueError(f"Invalid 'a' value: {a}. Must be coprime with 26.")
    result = []
    for c in s:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            x = (a * (ord(c) - base) + b) % 26
            result.append(chr(x + base))
        else:
            result.append(c)
    return ''.join(result)

# --- Playfair Cipher ---
def _playfair_grid(key):
    key = key.upper().replace('J', 'I')
    seen = set()
    grid = []
    for c in key:
        if c.isalpha() and c not in seen:
            seen.add(c)
            grid.append(c)
    for c in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.add(c)
            grid.append(c)
    return [grid[i:i+5] for i in range(0, 25, 5)]

def decode_playfair(s, key='PLAYFAIREXAMPLE'):
    s = s.upper().replace('J', 'I')
    s = ''.join(c for c in s if c.isalpha())
    if len(s) < 2:
        raise ValueError("Playfair needs at least 2 letters")
    grid = _playfair_grid(key)
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[grid[r][c]] = (r, c)
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else 'X'
        if a == b:
            b = 'X'
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    result = []
    for a, b in pairs:
        if a not in pos or b not in pos:
            result.append(a)
            result.append(b)
            continue
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            result.append(grid[ra][(ca-1) % 5])
            result.append(grid[rb][(cb-1) % 5])
        elif ca == cb:
            result.append(grid[(ra-1) % 5][ca])
            result.append(grid[(rb-1) % 5][cb])
        else:
            result.append(grid[ra][cb])
            result.append(grid[rb][ca])
    return ''.join(result)

def encode_playfair(s, key='PLAYFAIREXAMPLE'):
    s = s.upper().replace('J', 'I')
    s = ''.join(c for c in s if c.isalpha())
    if len(s) < 2:
        raise ValueError("Playfair needs at least 2 letters")
    grid = _playfair_grid(key)
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[grid[r][c]] = (r, c)
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else 'X'
        if a == b:
            b = 'X'
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    result = []
    for a, b in pairs:
        if a not in pos or b not in pos:
            result.append(a)
            result.append(b)
            continue
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            result.append(grid[ra][(ca+1) % 5])
            result.append(grid[rb][(cb+1) % 5])
        elif ca == cb:
            result.append(grid[(ra+1) % 5][ca])
            result.append(grid[(rb+1) % 5][cb])
        else:
            result.append(grid[ra][cb])
            result.append(grid[rb][ca])
    return ''.join(result)

# --- Columnar Transposition ---
def decode_columnar_transposition(s, key='ZEBRA'):
    s = ''.join(c for c in s.upper() if c.isalpha())
    if not s:
        raise ValueError("No alphabetic characters for transposition")
    key = key.upper()
    num_cols = len(key)
    num_rows = -(-len(s) // num_cols)
    num_full_cols = len(s) % num_cols if len(s) % num_cols != 0 else num_cols
    key_order = sorted(range(num_cols), key=lambda i: (key[i], i))
    grid = [[''] * num_cols for _ in range(num_rows)]
    idx = 0
    for col_idx, col in enumerate(key_order):
        col_height = num_rows if col < num_full_cols else num_rows - 1
        for row in range(col_height):
            if idx < len(s):
                grid[row][col] = s[idx]
                idx += 1
    result = []
    for row in range(num_rows):
        for col in range(num_cols):
            if grid[row][col]:
                result.append(grid[row][col])
    return ''.join(result)

def encode_columnar_transposition(s, key='ZEBRA'):
    s = ''.join(c for c in s.upper() if c.isalpha())
    if not s:
        raise ValueError("No alphabetic characters for transposition")
    key = key.upper()
    num_cols = len(key)
    num_rows = -(-len(s) // num_cols)
    grid = [[''] * num_cols for _ in range(num_rows)]
    idx = 0
    for row in range(num_rows):
        for col in range(num_cols):
            if idx < len(s):
                grid[row][col] = s[idx]
                idx += 1
    key_order = sorted(range(num_cols), key=lambda i: (key[i], i))
    result = []
    for col in key_order:
        for row in range(num_rows):
            if grid[row][col]:
                result.append(grid[row][col])
    return ''.join(result)

# --- Polybius Square ---
_POLYBIUS_GRID = [
    ['A','B','C','D','E'],
    ['F','G','H','I','K'],
    ['L','M','N','O','P'],
    ['Q','R','S','T','U'],
    ['V','W','X','Y','Z'],
]

def decode_polybius(s):
    s = _re.sub(r'[^0-9]', '', s)
    if len(s) < 2 or len(s) % 2 != 0:
        raise ValueError("Polybius needs pairs of digits")
    result = []
    for i in range(0, len(s), 2):
        r = int(s[i])
        c = int(s[i+1])
        if 1 <= r <= 5 and 1 <= c <= 5:
            result.append(_POLYBIUS_GRID[r-1][c-1])
        else:
            result.append('?')
    return ''.join(result)

def encode_polybius(s):
    result = []
    for c in s.upper():
        if c == 'J':
            c = 'I'
        found = False
        for r in range(5):
            for c_idx in range(5):
                if _POLYBIUS_GRID[r][c_idx] == c:
                    result.append(f"{r+1}{c_idx+1}")
                    found = True
                    break
            if found:
                break
    return ' '.join(result)

# --- Bifid Cipher ---
def decode_bifid(s, key='CRYPTO'):
    s = ''.join(c for c in s.upper() if c.isalpha())
    if not s:
        raise ValueError("No alphabetic characters for Bifid")
    grid = _playfair_grid(key)
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[grid[r][c]] = (r, c)
    nums = []
    for c in s:
        if c in pos:
            r, c_idx = pos[c]
            nums.extend([r, c_idx])
    half = len(nums) // 2
    row_nums = nums[:half]
    col_nums = nums[half:]
    result = []
    for i in range(half):
        r = row_nums[i]
        c = col_nums[i]
        result.append(grid[r][c])
    return ''.join(result)

def encode_bifid(s, key='CRYPTO'):
    s = ''.join(c for c in s.upper() if c.isalpha())
    if not s:
        raise ValueError("No alphabetic characters for Bifid")
    grid = _playfair_grid(key)
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[grid[r][c]] = (r, c)
    row_nums = []
    col_nums = []
    for c in s:
        if c in pos:
            r, c_idx = pos[c]
            row_nums.append(r)
            col_nums.append(c_idx)
    combined = []
    for i in range(len(row_nums)):
        combined.append(row_nums[i])
    for i in range(len(col_nums)):
        combined.append(col_nums[i])
    result = []
    for i in range(0, len(combined), 2):
        if i+1 < len(combined):
            r = combined[i]
            c = combined[i+1]
            result.append(grid[r][c])
    return ''.join(result)

# --- Beaufort Cipher ---
def decode_beaufort(s, key='KEYWORD'):
    s = s.upper()
    key = key.upper()
    result = []
    ki = 0
    for c in s:
        if c.isalpha():
            k = key[ki % len(key)]
            result.append(chr((ord(k) - ord(c)) % 26 + ord('A')))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def encode_beaufort(s, key='KEYWORD'):
    return decode_beaufort(s, key)

# --- ADFGVX Cipher ---
_ADFGVX_COLS = 'ADFGVX'
_ADFGVX_GRID = [
    list('NA1C3H'),
    list('TBPGM4'),
    list('REOF6'),
    list('IK7L9'),
    list('D8QS0'),
    list('UVWXYZ'),
]

def decode_adfgvx(s, key='GERMAN'):
    s = s.upper().strip()
    s = ''.join(c for c in s if c in 'ADFGVX')
    if len(s) < 2 or len(s) % 2 != 0:
        raise ValueError("ADFGVX needs pairs of ADFGVX characters")
    if len(s) < 4:
        raise ValueError("ADFGVX needs at least 4 characters")
    key = key.upper()
    num_cols = len(key)
    num_rows = -(-len(s) // num_cols)
    key_order = sorted(range(num_cols), key=lambda i: (key[i], i))
    grid = [[''] * num_cols for _ in range(num_rows)]
    idx = 0
    for col in key_order:
        for row in range(num_rows):
            if idx < len(s):
                grid[row][col] = s[idx]
                idx += 1
    pairs = []
    for row in range(num_rows):
        for col in range(num_cols):
            if grid[row][col]:
                pairs.append(grid[row][col])
    result = []
    for i in range(0, len(pairs), 2):
        if i+1 < len(pairs):
            r = _ADFGVX_COLS.index(pairs[i])
            c = _ADFGVX_COLS.index(pairs[i+1])
            result.append(_ADFGVX_GRID[r][c])
    return ''.join(result)

def encode_adfgvx(s, key='GERMAN'):
    s = s.upper()
    key = key.upper()
    pairs = []
    for c in s:
        found = False
        for r in range(6):
            for c_idx in range(6):
                if _ADFGVX_GRID[r][c_idx] == c:
                    pairs.append(_ADFGVX_COLS[r] + _ADFGVX_COLS[c_idx])
                    found = True
                    break
            if found:
                break
        if not found:
            pairs.append(c + c)
    combined = ''.join(pairs)
    num_cols = len(key)
    num_rows = -(-len(combined) // num_cols)
    grid = [[''] * num_cols for _ in range(num_rows)]
    idx = 0
    for row in range(num_rows):
        for col in range(num_cols):
            if idx < len(combined):
                grid[row][col] = combined[idx]
                idx += 1
    key_order = sorted(range(num_cols), key=lambda i: (key[i], i))
    result = []
    for col in key_order:
        for row in range(num_rows):
            if grid[row][col]:
                result.append(grid[row][col])
    return ''.join(result)


# ===========================================================================
# ESOTERIC LANGUAGES (v3.0)
# ===========================================================================

# --- Ook! ---
def decode_ook(s):
    s = s.strip()
    if 'Ook' not in s and 'ook' not in s:
        raise ValueError("Not Ook! (no 'Ook' found)")
    tokens = _re.findall(r'[Oo]ok[.!?]', s)
    if len(tokens) % 2 != 0:
        raise ValueError("Ook! tokens must come in pairs")
    bf_map = {
        ('Ook.', 'Ook.'): '.', ('Ook!', 'Ook!'): '!', ('Ook?', 'Ook?'): '?',
        ('Ook.', 'Ook!'): '>', ('Ook!', 'Ook.'): '<',
        ('Ook.', 'Ook?'): '+', ('Ook?', 'Ook.'): '-',
        ('Ook!', 'Ook?'): ',', ('Ook?', 'Ook!'): '.',
        ('Ook!', 'Ook.'): '<', ('Ook?', 'Ook.'): '-',
    }
    bf_code = []
    for i in range(0, len(tokens), 2):
        pair = (tokens[i], tokens[i+1])
        if pair in bf_map:
            bf_code.append(bf_map[pair])
    return decode_brainfuck(''.join(bf_code))

# --- Whitespace ---
def decode_whitespace(s):
    ws = ''.join(c for c in s if c in ' \t\n')
    if len(ws) < 2:
        raise ValueError("No whitespace program found")
    stack = []
    heap = {}
    output = []
    labels = {}
    pc = 0
    instructions = []
    while pc < len(ws):
        if ws[pc] == ' ':
            pc += 1
            if pc >= len(ws):
                break
            if ws[pc] == ' ':
                pc += 1
                num = ''
                if pc < len(ws) and ws[pc] == '\t':
                    num = '1'
                    pc += 1
                elif pc < len(ws) and ws[pc] == ' ':
                    num = '0'
                    pc += 1
                else:
                    break
                while pc < len(ws) and ws[pc] in ' \t':
                    num += '1' if ws[pc] == '\t' else '0'
                    pc += 1
                if pc < len(ws) and ws[pc] == '\n':
                    pc += 1
                if num:
                    val = int(num[1:], 2) if len(num) > 1 else 0
                    if num[0] == '1':
                        val = -val
                    instructions.append(('push', val))
                else:
                    instructions.append(('push', 0))
            elif ws[pc] == '\t':
                pc += 1
                if pc < len(ws) and ws[pc] == ' ':
                    pc += 1
                    instructions.append(('dup',))
                elif pc < len(ws) and ws[pc] == '\n':
                    pc += 1
                    if pc < len(ws):
                        if ws[pc] == ' ':
                            instructions.append(('swap',))
                        elif ws[pc] == '\t':
                            instructions.append(('drop',))
                        pc += 1
            elif ws[pc] == '\n':
                pc += 1
                if pc < len(ws):
                    if ws[pc] == ' ':
                        instructions.append(('dup',))
                    pc += 1
        elif ws[pc] == '\t':
            pc += 1
            if pc >= len(ws):
                break
            if ws[pc] == ' ':
                pc += 1
                if pc >= len(ws):
                    break
                if ws[pc] == ' ':
                    pc += 1
                    op = ''
                    while pc < len(ws) and ws[pc] in ' \t':
                        op += 't' if ws[pc] == '\t' else 's'
                        pc += 1
                    if pc < len(ws) and ws[pc] == '\n':
                        pc += 1
                    if op == 'ss':
                        instructions.append(('add',))
                    elif op == 'st':
                        instructions.append(('sub',))
                    elif op == 'ts':
                        instructions.append(('mul',))
                    elif op == 'tt':
                        instructions.append(('div',))
                    elif op == 'stt' or op == 'tst':
                        instructions.append(('mod',))
                elif ws[pc] == '\t':
                    pc += 1
                    op = ''
                    while pc < len(ws) and ws[pc] in ' \t':
                        op += 't' if ws[pc] == '\t' else 's'
                        pc += 1
                    if pc < len(ws) and ws[pc] == '\n':
                        pc += 1
                    if op == 'ss':
                        instructions.append(('store',))
                    elif op == 'st':
                        instructions.append(('retrieve',))
            elif ws[pc] == '\n':
                pc += 1
                if pc < len(ws):
                    if ws[pc] == ' ':
                        pc += 1
                        instructions.append(('output_char',))
                    elif ws[pc] == '\t':
                        pc += 1
                        instructions.append(('output_num',))
                    else:
                        pc += 1
            else:
                pc += 1
        elif ws[pc] == '\n':
            pc += 1
            if pc < len(ws) and ws[pc] == '\n':
                pc += 1
                if pc < len(ws) and ws[pc] == '\n':
                    instructions.append(('end',))
                    pc += 1
                else:
                    pass
            else:
                pc += 1
        else:
            pc += 1
    for label, instr in enumerate(instructions):
        if instr[0] == 'label':
            labels[instr[1]] = label
    pc = 0
    while pc < len(instructions) and pc >= 0:
        instr = instructions[pc]
        op = instr[0]
        try:
            if op == 'push':
                stack.append(instr[1])
            elif op == 'dup':
                stack.append(stack[-1] if stack else 0)
            elif op == 'swap':
                if len(stack) >= 2:
                    stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op == 'drop':
                if stack:
                    stack.pop()
            elif op == 'add':
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a + b)
            elif op == 'sub':
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a - b)
            elif op == 'mul':
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a * b)
            elif op == 'div':
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a // b if b != 0 else 0)
            elif op == 'mod':
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append(a % b if b != 0 else 0)
            elif op == 'store':
                if len(stack) >= 2:
                    addr = stack.pop()
                    val = stack.pop()
                    heap[addr] = val
            elif op == 'retrieve':
                if stack:
                    addr = stack.pop()
                    stack.append(heap.get(addr, 0))
            elif op == 'output_char':
                if stack:
                    output.append(chr(stack.pop() & 0xFF))
            elif op == 'output_num':
                if stack:
                    output.append(str(stack.pop()))
            elif op == 'end':
                break
        except Exception:
            pass
        pc += 1
    return ''.join(output) if output else "Whitespace program executed (no output)"

# --- JSFuck ---
def decode_jsfuck(s):
    s = s.strip()
    if not all(c in '[]()!+' for c in s):
        raise ValueError("Not valid JSFuck (only []()!+ allowed)")
    if len(s) < 10:
        raise ValueError("JSFuck too short")
    try:
        import subprocess
        result = subprocess.run(['node', '-e', 'try{console.log(eval(process.argv[1]))}catch(e){console.log("Error:"+e.message)}', s],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return "JSFuck detected. Copy this code and run it in a browser console (F12) or with: node -e 'console.log(CODE)'"

# --- Deadfish ---
def decode_deadfish(s):
    s = s.strip().lower()
    if not s or not all(c in 'idso x\n\r\t' for c in s):
        raise ValueError("Not valid Deadfish (only i,d,s,o allowed)")
    result = []
    val = 0
    for c in s:
        if c == 'i':
            val += 1
        elif c == 'd':
            val -= 1
        elif c == 's':
            val *= val
        elif c == 'o':
            result.append(chr(val & 0xFF) if 0 <= val <= 255 else str(val))
        if val == -1 or val == 256:
            val = 0
    return ''.join(result) if result else "Deadfish executed (no output)"

def encode_deadfish(s):
    result = []
    for c in s:
        target = ord(c)
        ops = []
        v = 0
        while v < target:
            if v * v <= target and v * v > v + 1 and v > 1:
                v *= v
                ops.append('s')
            else:
                v += 1
                ops.append('i')
        while v > target:
            v -= 1
            ops.append('d')
        ops.append('o')
        result.append(''.join(ops))
    return ' '.join(result)

# --- Malbolge ---
def decode_malbolge(s):
    s = s.strip()
    if not s:
        raise ValueError("Empty Malbolge program")
    if not all(33 <= ord(c) <= 126 for c in s):
        raise ValueError("Malbolge uses only printable ASCII")
    mem = [0] * 59049
    for i, c in enumerate(s):
        mem[i] = ord(c) - 33
    a, c_reg, d = 0, 0, 0
    output = []
    for _ in range(100000):
        if c_reg >= 59049:
            break
        op = (mem[c_reg] + c_reg) % 94
        if op == 4:
            d = mem[d]
        elif op == 5:
            out_val = (a % 256 + 33)
            if 33 <= out_val <= 126:
                output.append(chr(out_val))
        elif op == 23:
            pass
        elif op == 39:
            a = mem[d] // (3 ** 0) % 3
        elif op == 40:
            d = mem[d]
        elif op == 62:
            pass
        elif op == 68:
            pass
        elif op == 81:
            break
        x = mem[c_reg] % 3
        y = (mem[d] // 1) % 3
        if x == 0:
            new_val = [1, 2, 0][y]
        elif x == 1:
            new_val = [2, 2, 1][y]
        else:
            new_val = y
        mem[d] = (mem[d] // 3) * 3 + new_val
        if mem[c_reg] < 33:
            mem[c_reg] += 33
        if mem[d] < 33:
            mem[d] += 33
        if mem[c_reg] > 126:
            mem[c_reg] = mem[c_reg] % 94 + 33
        if mem[d] > 126:
            mem[d] = mem[d] % 94 + 33
        c_reg = (c_reg + 1) % 59049
        d = (d + 1) % 59049
    return ''.join(output) if output else "Malbolge program executed (no output or too complex)"


# ===========================================================================
# HASH IDENTIFIER (v3.0)
# ===========================================================================

def identify_hash(s):
    s = s.strip()
    length = len(s)
    charset = 'hex' if all(c in '0123456789abcdefABCDEF' for c in s) else 'mixed'
    results = []
    if charset == 'hex':
        if length == 32:
            results.append("MD5 (128-bit, 32 hex chars)")
            results.append("MD4 (128-bit, 32 hex chars)")
            results.append("NTLM (128-bit, 32 hex chars)")
            results.append("LM (128-bit, 32 hex chars)")
            results.append("RIPEMD-128 (128-bit, 32 hex chars)")
            results.append("Haval-128 (128-bit, 32 hex chars)")
            results.append("Tiger-128 (128-bit, 32 hex chars)")
        elif length == 40:
            results.append("SHA-1 (160-bit, 40 hex chars)")
            results.append("RIPEMD-160 (160-bit, 40 hex chars)")
            results.append("Haval-160 (160-bit, 40 hex chars)")
            results.append("Tiger-160 (160-bit, 40 hex chars)")
            results.append("MySQL5 (160-bit, 40 hex chars)")
        elif length == 56:
            results.append("SHA-224 (224-bit, 56 hex chars)")
            results.append("Haval-224 (224-bit, 56 hex chars)")
        elif length == 64:
            results.append("SHA-256 (256-bit, 64 hex chars)")
            results.append("RIPEMD-256 (256-bit, 64 hex chars)")
            results.append("GOST (256-bit, 64 hex chars)")
            results.append("Haval-256 (256-bit, 64 hex chars)")
        elif length == 96:
            results.append("SHA-384 (384-bit, 96 hex chars)")
            results.append("RIPEMD-320 (320-bit, 96 hex chars)")
            results.append("Tiger-320 (320-bit, 96 hex chars)")
        elif length == 128:
            results.append("SHA-512 (512-bit, 128 hex chars)")
            results.append("Whirlpool (512-bit, 128 hex chars)")
    else:
        if length == 13:
            results.append("DES (Unix) - 13 chars")
        elif length == 16:
            results.append("MySQL323 - 16 chars")
        elif length == 20:
            results.append("MySQL SHA1 - 20 chars")
        elif length == 24:
            results.append("Base64 encoded hash?")
        elif length == 32:
            results.append("Base64 encoded MD5?")
        elif length == 28:
            results.append("Base64 encoded SHA-1?")
        elif length == 44:
            results.append("Base64 encoded SHA-256?")
        elif length == 88:
            results.append("Base64 encoded SHA-512?")
    if not results:
        results.append(f"Unknown hash type (length: {length}, charset: {charset})")
    return '\n'.join(results)


# ===========================================================================
# XOR WITH CUSTOM KEY (v3.0)
# ===========================================================================

def xor_custom_key(data_hex, key):
    try:
        data = bytes.fromhex(data_hex.replace(' ', ''))
    except ValueError:
        try:
            data = data_hex.encode('utf-8')
        except Exception:
            raise ValueError("Input must be hex string or text")
    if isinstance(key, str):
        key = key.encode('utf-8')
    if not key:
        raise ValueError("Key cannot be empty")
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        return result.hex()


# ===========================================================================
# RC4 DECRYPT (v3.0)
# ===========================================================================

def rc4_crypt(data, key):
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data.replace(' ', ''))
        except ValueError:
            data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        return result.hex()


# ===========================================================================
# AES DECRYPT (v3.0)
# ===========================================================================

def aes_decrypt(data_hex, key_hex, iv_hex=''):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        return "AES decryption requires pycryptodome: pip install pycryptodome"
    try:
        data = bytes.fromhex(data_hex.replace(' ', ''))
        key = bytes.fromhex(key_hex.replace(' ', ''))
        iv = bytes.fromhex(iv_hex.replace(' ', '')) if iv_hex else b'\x00' * 16
        if len(key) not in (16, 24, 32):
            return "Key must be 16, 24, or 32 bytes (32, 48, or 64 hex chars)"
        if len(iv) != 16:
            return "IV must be 16 bytes (32 hex chars)"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted.decode('utf-8', errors='replace')
    except Exception as e:
        return f"AES decryption error: {e}"


# ===========================================================================
# FILE TYPE DETECTION (v3.0)
# ===========================================================================

MAGIC_BYTES = {
    b'\x89PNG': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'GIF87a': 'GIF Image (87a)',
    b'GIF89a': 'GIF Image (89a)',
    b'BM': 'BMP Image',
    b'PK\x03\x04': 'ZIP Archive',
    b'PK\x05\x06': 'Empty ZIP Archive',
    b'Rar!\x1a\x07': 'RAR Archive',
    b'\x1f\x8b': 'GZIP Archive',
    b'BZh': 'BZIP2 Archive',
    b'\x7fELF': 'ELF Binary (Linux executable)',
    b'MZ': 'Windows Executable (EXE/DLL)',
    b'\xca\xfe\xba\xbe': 'Java CLASS File',
    b'%PDF': 'PDF Document',
    b'\x25\x50\x44\x46': 'PDF Document',
    b'RIFF': 'RIFF Container (WAV/AVI)',
    b'\x00\x00\x01\x00': 'ICO Icon',
    b'\x00\x00\x02\x00': 'CUR Cursor',
    b'\x49\x49\x2a\x00': 'TIFF Image (little-endian)',
    b'\x4d\x4d\x00\x2a': 'TIFF Image (big-endian)',
    b'\x50\x4b\x03\x04': 'ZIP/DOCX/XLSX/JAR',
    b'\xd0\xcf\x11\xe0': 'OLE2 Document (DOC/XLS/PPT)',
    b'\x7b\x5c\x72\x74\x66': 'RTF Document',
    b'SQLite format 3': 'SQLite Database',
    b'\x42\x5a\x68': 'BZIP2 Archive',
    b'OGG': 'OGG Audio',
    b'ID3': 'MP3 Audio (ID3)',
    b'\xff\xfb': 'MP3 Audio',
    b'\x66\x4c\x61\x43': 'FLAC Audio',
    b'\x52\x49\x46\x46': 'WAV/AVI (RIFF)',
    b'\x1a\x45\xdf\xa3': 'MKV/WebM (Matroska)',
    b'\x00\x00\x00\x1cftyp': 'MP4 Video',
    b'\x00\x00\x00\x18ftyp': 'MP4 Video',
    b'\x00\x00\x00\x20ftyp': 'MP4 Video',
    b'ftyp': 'MP4/MOV Video',
    b'\x49\x44\x33': 'MP3 (ID3v2)',
    b'\x00asm': 'WebAssembly Module',
    b'\x7fCGC': 'CGC Executable',
}

def detect_file_type(hex_or_data):
    if isinstance(hex_or_data, str):
        clean = hex_or_data.strip().replace(' ', '').replace('\n', '')
        try:
            data = bytes.fromhex(clean)
        except ValueError:
            data = hex_or_data.encode('latin-1')
    else:
        data = hex_or_data
    if not data:
        return "Empty data"
    for magic, ftype in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            return ftype
    if data[:2] == b'\x42\x5a':
        return "BZIP2 Archive"
    if data[:4] == b'\x25\x50\x44\x46':
        return "PDF Document"
    first_byte = data[0]
    if first_byte == 0x00:
        return "Unknown (starts with null byte - possibly binary/data)"
    if 0x20 <= first_byte <= 0x7E:
        return "Unknown (starts with printable ASCII - possibly text)"
    return f"Unknown file type (first bytes: {data[:8].hex()})"


# ===========================================================================
# STRINGS EXTRACTION (v3.0)
# ===========================================================================

def extract_strings(hex_or_data, min_length=4):
    if isinstance(hex_or_data, str):
        clean = hex_or_data.strip().replace(' ', '').replace('\n', '')
        try:
            data = bytes.fromhex(clean)
        except ValueError:
            data = hex_or_data.encode('latin-1')
    else:
        data = hex_or_data
    if not data:
        return "No data to scan"
    result = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                result.append(''.join(current))
            current = []
    if len(current) >= min_length:
        result.append(''.join(current))
    if not result:
        return "No printable strings found (min length: {})".format(min_length)
    return '\n'.join(result)


# ===========================================================================
# HEX DUMP VIEWER (v3.0)
# ===========================================================================

def hex_dump(hex_or_data, bytes_per_line=16):
    if isinstance(hex_or_data, str):
        clean = hex_or_data.strip().replace(' ', '').replace('\n', '')
        try:
            data = bytes.fromhex(clean)
        except ValueError:
            data = hex_or_data.encode('latin-1')
    else:
        data = hex_or_data
    if not data:
        return "No data to display"
    result = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset+bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f'{offset:08x}  {hex_part}  |{ascii_part}|')
    return '\n'.join(result)


# ===========================================================================
# FILE CARVING / SIGNATURE SCAN (v3.0)
# ===========================================================================

FILE_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 'PNG Image', '.png'),
    (b'\xff\xd8\xff', 'JPEG Image', '.jpg'),
    (b'GIF87a', 'GIF Image (87a)', '.gif'),
    (b'GIF89a', 'GIF Image (89a)', '.gif'),
    (b'PK\x03\x04', 'ZIP Archive', '.zip'),
    (b'Rar!\x1a\x07', 'RAR Archive', '.rar'),
    (b'\x1f\x8b', 'GZIP Archive', '.gz'),
    (b'BZh', 'BZIP2 Archive', '.bz2'),
    (b'%PDF', 'PDF Document', '.pdf'),
    (b'\x7fELF', 'ELF Binary', '.elf'),
    (b'MZ', 'Windows Executable', '.exe'),
    (b'RIFF', 'RIFF Container (WAV/AVI)', '.wav'),
    (b'SQLite format 3', 'SQLite Database', '.sqlite'),
    (b'\x49\x49\x2a\x00', 'TIFF Image', '.tiff'),
    (b'\x00\x00\x01\x00', 'ICO Icon', '.ico'),
    (b'ftyp', 'MP4 Video', '.mp4'),
    (b'\x1a\x45\xdf\xa3', 'Matroska (MKV/WebM)', '.mkv'),
    (b'ID3', 'MP3 Audio', '.mp3'),
    (b'\xff\xfb', 'MP3 Audio', '.mp3'),
    (b'OGG', 'OGG Audio', '.ogg'),
    (b'\x66\x4c\x61\x43', 'FLAC Audio', '.flac'),
    (b'\x50\x4b\x05\x06', 'Empty ZIP', '.zip'),
    (b'\xd0\xcf\x11\xe0', 'OLE Document (DOC/XLS)', '.doc'),
]

def scan_file_signatures(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        return f"Error reading file: {e}"
    findings = []
    for sig, name, ext in FILE_SIGNATURES:
        pos = 0
        while True:
            pos = data.find(sig, pos)
            if pos == -1:
                break
            findings.append(f"  Offset 0x{pos:08x}: {name} ({len(sig)} bytes signature)")
            pos += len(sig)
    if not findings:
        return "No embedded file signatures found."
    header = f"Found {len(findings)} signature(s) in {len(data)} bytes:\n"
    return header + '\n'.join(findings)


# ===========================================================================
# HIDDEN DATA AFTER EOF (v3.0)
# ===========================================================================

def find_hidden_data(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        return f"Error reading file: {e}"
    eof_markers = [
        (b'\xff\xd9', 'JPEG end marker (FF D9)'),
        (b'IEND\xaeB`\x82', 'PNG end chunk (IEND)'),
        (b'%%EOF', 'PDF end marker'),
        (b'PK\x05\x06', 'ZIP End of Central Directory'),
    ]
    results = []
    for marker, name in eof_markers:
        pos = data.find(marker)
        if pos != -1:
            after = data[pos + len(marker):]
            if after and len(after) > 0:
                printable = after[:500]
                try:
                    text = printable.decode('utf-8', errors='replace')
                except Exception:
                    text = printable.hex()
                results.append(f"Found {name} at offset 0x{pos:08x}")
                results.append(f"  {len(after)} bytes of hidden data after EOF!")
                results.append(f"  Preview: {text[:200]}")
    if not results:
        return "No hidden data found after EOF markers."
    return '\n'.join(results)


# ===========================================================================
# PNG CHUNK ANALYSIS (v3.0)
# ===========================================================================

def analyze_png_chunks(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        return f"Error reading file: {e}"
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return "Not a valid PNG file (missing PNG signature)"
    results = ["PNG Signature: Valid"]
    pos = 8
    total_size = len(data)
    while pos < total_size:
        if pos + 8 > total_size:
            break
        length = int.from_bytes(data[pos:pos+4], 'big')
        chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
        results.append(f"  Chunk: {chunk_type} | Length: {length} bytes | Offset: 0x{pos:08x}")
        if chunk_type == 'tEXt' or chunk_type == 'zTXt':
            try:
                text_data = data[pos+8:pos+8+min(length, 200)]
                results.append(f"    Text: {text_data.decode('latin-1', errors='replace')[:100]}")
            except Exception:
                pass
        elif chunk_type == 'IEND':
            after = data[pos + 12:]
            if after:
                results.append(f"  WARNING: {len(after)} bytes after IEND chunk!")
            break
        pos += 12 + length
    return '\n'.join(results)


# ===========================================================================
# IMAGE DIMENSIONS CHECK (v3.0)
# ===========================================================================

def check_image_dimensions(filepath):
    try:
        from PIL import Image
        img = Image.open(filepath)
        w, h = img.size
        results = [f"Image: {filepath}", f"Size: {w} x {h} pixels",
                   f"Mode: {img.mode}", f"Format: {img.format}"]
        if w > 10000 or h > 10000:
            results.append("WARNING: Unusually large dimensions!")
        if w == 1 or h == 1:
            results.append("NOTE: 1-pixel dimension - possible hidden data in row/column")
        if w * h < 100:
            results.append("NOTE: Very small image - possible stego carrier")
        ratio = w / h if h > 0 else 0
        if ratio > 10 or ratio < 0.1:
            results.append("NOTE: Unusual aspect ratio")
        try:
            exif = img._getexif()
            if exif:
                results.append(f"EXIF data found: {len(exif)} entries")
        except Exception:
            pass
        return '\n'.join(results)
    except ImportError:
        return "PIL (Pillow) required: pip install Pillow"
    except Exception as e:
        return f"Error: {e}"


# ===========================================================================
# STEGANOGRAPHY DETECTION (v3.0)
# ===========================================================================

def detect_steganography(filepath):
    try:
        from PIL import Image
        import math
        img = Image.open(filepath).convert('RGB')
        w, h = img.size
        pixels = list(img.getdata())
        sample_size = min(len(pixels), 10000)
        ones = [0, 0, 0]
        total = [0, 0, 0]
        for i in range(sample_size):
            r, g, b = pixels[i]
            ones[0] += r & 1
            ones[1] += g & 1
            ones[2] += b & 1
            total[0] += 1
            total[1] += 1
            total[2] += 1
        results = [f"Steganography Analysis:", f"Image: {w}x{h}", f"Sampled: {sample_size} pixels", ""]
        suspicious = False
        for ch, name in enumerate(['Red', 'Green', 'Blue']):
            ratio = ones[ch] / total[ch] if total[ch] > 0 else 0
            deviation = abs(ratio - 0.5)
            status = "NORMAL" if deviation < 0.05 else "SUSPICIOUS"
            if deviation >= 0.05:
                suspicious = True
            results.append(f"  {name} channel LSB: {ratio:.4f} (deviation: {deviation:.4f}) [{status}]")
        results.append("")
        if suspicious:
            results.append("RESULT: LSB distribution is uneven - possible hidden data!")
        else:
            results.append("RESULT: LSB distribution looks normal - no obvious stego detected")
        return '\n'.join(results)
    except ImportError:
        return "PIL (Pillow) required: pip install Pillow"
    except Exception as e:
        return f"Error: {e}"


# ===========================================================================
# BIT PLANE VISUALIZATION (v3.0)
# ===========================================================================

def extract_bit_planes(filepath, output_dir='/tmp/404_bitplanes'):
    try:
        from PIL import Image
        import os
        img = Image.open(filepath).convert('RGB')
        w, h = img.size
        os.makedirs(output_dir, exist_ok=True)
        saved = []
        for channel_idx, ch_name in enumerate(['R', 'G', 'B']):
            for bit in range(8):
                plane = Image.new('L', (w, h))
                plane_pixels = plane.load()
                for x in range(w):
                    for y in range(h):
                        r, g, b = img.getpixel((x, y))
                        val = [r, g, b][channel_idx]
                        plane_pixels[x, y] = 255 if (val >> bit) & 1 else 0
                fname = f"{output_dir}/{ch_name}_bit{bit}.png"
                plane.save(fname)
                saved.append(fname)
        return f"Extracted 24 bit planes to {output_dir}\nFiles: {', '.join(os.path.basename(f) for f in saved)}"
    except ImportError:
        return "PIL (Pillow) required: pip install Pillow"
    except Exception as e:
        return f"Error: {e}"


# ===========================================================================
# COLOR CHANNEL SEPARATION (v3.0)
# ===========================================================================

def separate_color_channels(filepath, output_dir='/tmp/404_channels'):
    try:
        from PIL import Image
        import os
        img = Image.open(filepath).convert('RGB')
        w, h = img.size
        os.makedirs(output_dir, exist_ok=True)
        saved = []
        for idx, name in enumerate(['Red', 'Green', 'Blue']):
            channel = Image.new('L', (w, h))
            channel_pixels = channel.load()
            for x in range(w):
                for y in range(h):
                    r, g, b = img.getpixel((x, y))
                    channel_pixels[x, y] = [r, g, b][idx]
            fname = f"{output_dir}/channel_{name}.png"
            channel.save(fname)
            saved.append(fname)
        return f"Separated R, G, B channels to {output_dir}\nFiles: {', '.join(os.path.basename(f) for f in saved)}"
    except ImportError:
        return "PIL (Pillow) required: pip install Pillow"
    except Exception as e:
        return f"Error: {e}"


# ===========================================================================
# IMAGE DIFF COMPARISON (v3.0)
# ===========================================================================

def compare_images(filepath1, filepath2, output_path='/tmp/404_diff.png'):
    try:
        from PIL import Image
        import os
        img1 = Image.open(filepath1).convert('RGB')
        img2 = Image.open(filepath2).convert('RGB')
        if img1.size != img2.size:
            img2 = img2.resize(img1.size)
        w, h = img1.size
        diff_img = Image.new('RGB', (w, h))
        diff_pixels = diff_img.load()
        diff_count = 0
        for x in range(w):
            for y in range(h):
                r1, g1, b1 = img1.getpixel((x, y))
                r2, g2, b2 = img2.getpixel((x, y))
                dr = abs(r1 - r2)
                dg = abs(g1 - g2)
                db = abs(b1 - b2)
                if dr > 0 or dg > 0 or db > 0:
                    diff_count += 1
                diff_pixels[x, y] = (dr, dg, db)
        diff_img.save(output_path)
        pct = (diff_count / (w * h)) * 100 if w * h > 0 else 0
        result = f"Image comparison complete!\n"
        result += f"Different pixels: {diff_count} / {w*h} ({pct:.2f}%)\n"
        result += f"Diff image saved to: {output_path}"
        if diff_count > 0:
            result += "\n\nThe diff image highlights differences in bright colors.\nCheck for hidden messages!"
        return result
    except ImportError:
        return "PIL (Pillow) required: pip install Pillow"
    except Exception as e:
        return f"Error: {e}"


# ===========================================================================
# HTTP HEADER DECODER (v3.0)
# ===========================================================================

def decode_http_headers(s):
    s = s.strip()
    lines = s.split('\n')
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            results.append(f"  {key}: {value}")
            if key.lower() in ('authorization', 'cookie', 'set-cookie'):
                if value.lower().startswith('basic '):
                    try:
                        import base64
                        decoded = base64.b64decode(value[6:]).decode('utf-8', errors='replace')
                        results.append(f"    -> Decoded: {decoded}")
                    except Exception:
                        pass
                elif value.lower().startswith('bearer '):
                    results.append(f"    -> Bearer token (JWT?)")
                    if '.' in value[7:]:
                        parts = value[7:].split('.')
                        if len(parts) >= 2:
                            try:
                                import base64
                                payload = parts[1]
                                payload += '=' * (4 - len(payload) % 4)
                                decoded = base64.urlsafe_b64decode(payload)
                                results.append(f"    -> JWT payload: {decoded.decode('utf-8', errors='replace')}")
                            except Exception:
                                pass
            if key.lower() in ('location', 'referer'):
                results.append(f"    -> URL: {value}")
        elif line.startswith('HTTP/'):
            results.append(f"  Status: {line}")
        else:
            results.append(f"  {line}")
    return '\n'.join(results) if results else "No valid HTTP headers found"


# ===========================================================================
# COOKIE DECODER (v3.0)
# ===========================================================================

def decode_cookies(s):
    s = s.strip()
    cookies = s.split(';')
    results = []
    for cookie in cookies:
        cookie = cookie.strip()
        if not cookie:
            continue
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            name = name.strip()
            value = value.strip()
            results.append(f"  {name} = {value}")
            if _re.match(r'^[A-Za-z0-9+/=]+$', value) and len(value) >= 4:
                try:
                    import base64
                    decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                    if decoded.isprintable():
                        results.append(f"    -> Base64 decoded: {decoded}")
                except Exception:
                    pass
            if '%' in value:
                try:
                    import urllib.parse
                    decoded = urllib.parse.unquote(value)
                    if decoded != value:
                        results.append(f"    -> URL decoded: {decoded}")
                except Exception:
                    pass
            if value.startswith('{') or value.startswith('['):
                results.append(f"    -> Looks like JSON")
        else:
            results.append(f"  {cookie}")
    return '\n'.join(results) if results else "No cookies found"


# ===========================================================================
# IP ADDRESS CONVERSION (v3.0)
# ===========================================================================

def convert_ip(s):
    s = s.strip()
    results = []
    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
        parts = s.split('.')
        decimal = sum(int(parts[i]) << (8 * (3 - i)) for i in range(4))
        hex_val = format(decimal, '08x')
        binary = ' '.join(format(int(p), '08b') for p in parts)
        octal = ' '.join(oct(int(p))[2:] for p in parts)
        results.append(f"  IP: {s}")
        results.append(f"  Decimal: {decimal}")
        results.append(f"  Hex: 0x{hex_val}")
        results.append(f"  Binary: {binary}")
        results.append(f"  Octal: {octal}")
        results.append(f"  Reverse DNS: {'.'.join(reversed(parts))}.in-addr.arpa")
        results.append(f"  Integer: {decimal}")
    elif s.isdigit():
        decimal = int(s)
        parts = [(decimal >> (8 * i)) & 0xFF for i in range(3, -1, -1)]
        ip = '.'.join(str(p) for p in parts)
        hex_val = format(decimal, '08x')
        binary = ' '.join(format(p, '08b') for p in parts)
        results.append(f"  Decimal: {decimal}")
        results.append(f"  IP: {ip}")
        results.append(f"  Hex: 0x{hex_val}")
        results.append(f"  Binary: {binary}")
    elif s.lower().startswith('0x'):
        decimal = int(s, 16)
        parts = [(decimal >> (8 * i)) & 0xFF for i in range(3, -1, -1)]
        ip = '.'.join(str(p) for p in parts)
        results.append(f"  Hex: {s}")
        results.append(f"  Decimal: {decimal}")
        results.append(f"  IP: {ip}")
    else:
        return "Not a valid IP address or decimal number"
    return '\n'.join(results)


# ===========================================================================
# DNS LOOKUP (v3.0)
# ===========================================================================

def dns_lookup(domain):
    import socket
    domain = domain.strip()
    if not domain:
        return "No domain provided"
    results = []
    try:
        ip = socket.gethostbyname(domain)
        results.append(f"  A record: {ip}")
    except socket.gaierror:
        return f"Could not resolve domain: {domain}"
    except Exception as e:
        return f"Error: {e}"
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
        ipv6 = [info[4][0] for info in infos]
        if ipv6:
            results.append(f"  AAAA record: {ipv6[0]}")
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(domain, None)
        all_ips = set(info[4][0] for info in infos)
        if len(all_ips) > 1:
            results.append(f"  All addresses: {', '.join(sorted(all_ips))}")
    except Exception:
        pass
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        if hostname != domain:
            results.append(f"  PTR record: {hostname}")
        if aliases:
            results.append(f"  Aliases: {', '.join(aliases)}")
    except Exception:
        pass
    try:
        import subprocess
        result = subprocess.run(['dig', '+short', 'TXT', domain],
                                capture_output=True, text=True, timeout=5)
        if result.stdout.strip():
            results.append(f"  TXT record: {result.stdout.strip()}")
    except Exception:
        pass
    try:
        import subprocess
        result = subprocess.run(['dig', '+short', 'MX', domain],
                                capture_output=True, text=True, timeout=5)
        if result.stdout.strip():
            results.append(f"  MX record: {result.stdout.strip()}")
    except Exception:
        pass
    return '\n'.join(results) if results else f"No DNS records found for {domain}"


# ===========================================================================
# QR CODE GENERATOR (v3.0)
# ===========================================================================

def generate_qr_code(text, output_path='/tmp/404_qrcode.png'):
    try:
        import qrcode
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        img.save(output_path)
        return f"QR code generated and saved to: {output_path}"
    except ImportError:
        return "QR code generation requires: pip install qrcode[pil]"
    except Exception as e:
        return f"Error: {e}"


# ===========================================================================
# MORSE CODE AUDIO PLAYER (v3.0)
# ===========================================================================

def play_morse_audio(morse_code):
    import os, sys, struct, wave
    morse_code = morse_code.strip()
    if not morse_code:
        return "No morse code to play"
    morse_map = {'.': 60, '-': 180, ' ': 0, '/': 0}
    wav_path = '/tmp/404_morse.wav'
    try:
        sample_rate = 8000
        freq = 800
        dot_duration = 0.1
        elements = []
        for c in morse_code:
            if c == '.':
                elements.append(('tone', dot_duration))
                elements.append(('silence', dot_duration))
            elif c == '-':
                elements.append(('tone', dot_duration * 3))
                elements.append(('silence', dot_duration))
            elif c == ' ':
                elements.append(('silence', dot_duration * 2))
            elif c == '/':
                elements.append(('silence', dot_duration * 6))
        total_samples = int(sum(d for _, d in elements) * sample_rate) + sample_rate
        samples = []
        for elem_type, duration in elements:
            num_samples = int(duration * sample_rate)
            if elem_type == 'tone':
                for i in range(num_samples):
                    t = i / sample_rate
                    val = int(32767 * 0.5 * math.sin(2 * 3.14159 * freq * t))
                    samples.append(struct.pack('<h', val))
            else:
                for i in range(num_samples):
                    samples.append(struct.pack('<h', 0))
        with wave.open(wav_path, 'w') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(sample_rate)
            wav_file.writeframes(b''.join(samples))
        try:
            if sys.platform == 'darwin':
                os.system(f'afplay "{wav_path}" &')
            elif sys.platform == 'win32':
                os.system(f'start /b powershell -c "(New-Object Media.SoundPlayer \'{wav_path}\').PlaySync()"')
            else:
                os.system(f'aplay "{wav_path}" 2>/dev/null &')
            return f"Morse audio generated and playing! WAV saved to: {wav_path}"
        except Exception:
            return f"Morse audio saved to: {wav_path} (install aplay/afplay to hear it)"
    except Exception as e:
        return f"Error generating audio: {e}"


# ===========================================================================
# BARCODE GENERATOR (v3.0)
# ===========================================================================

def generate_barcode(text, output_path='/tmp/404_barcode.png'):
    try:
        import barcode
        from barcode.writer import ImageWriter
        code = barcode.get('code128', text, writer=ImageWriter())
        code.save(output_path.replace('.png', ''))
        return f"Barcode generated and saved to: {output_path}"
    except ImportError:
        return "Barcode generation requires: pip install python-barcode"
    except Exception as e:
        return f"Error: {e}"


# ===========================================================================
# VIGENERE WITH CUSTOM KEY (v3.0)
# ===========================================================================

def decode_vigenere_custom(s, key):
    s = s.upper()
    key = key.upper()
    result = []
    ki = 0
    for c in s:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(c) - ord('A') - k) % 26 + ord('A')))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def encode_vigenere_custom(s, key):
    s = s.upper()
    key = key.upper()
    result = []
    ki = 0
    for c in s:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(c) - ord('A') + k) % 26 + ord('A')))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)



DECODERS = {
    "Base64": decode_base64,
    "Base64 Image": decode_base64_image,
    "Base32": decode_base32,
    "Base85": decode_base85,
    "Base58": decode_base58,
    "Base62": decode_base62,
    "Base91": decode_base91,
    "Base45": decode_base45,
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
    # --- v3.0 additions ---
    "A1Z26": decode_a1z26,
    "Tap Code": decode_tap_code,
    "BCD": decode_bcd,
    "Punycode": decode_punycode,
    "UUencode": decode_uuencode,
    "Affine Cipher": decode_affine,
    "Polybius Square": decode_polybius,
    "Beaufort Cipher": decode_beaufort,
    "Ook!": decode_ook,
    "Whitespace": decode_whitespace,
    "Deadfish": decode_deadfish,
    "Malbolge": decode_malbolge,
    "ROT8000": decode_rot8000,
    "JSFuck": decode_jsfuck,
}


# Priority: lower number = higher priority (tried first).
DECODER_PRIORITY = {
    "JWT": 1,
    "Base64": 2,
    "Base64 Image": 2,
    "Base32": 3,
    "Base85": 4,
    "Base58": 5,
    "Base62": 6,
    "Base91": 7,
    "Base45": 8,
    "Hexadecimal": 9,
    "Binary": 10,
    "URL Encoding": 11,
    "Morse": 12,
    "ASCII Decimal": 13,
    "Octal": 14,
    "HTML Entities": 15,
    "Unicode Escape": 16,
    "Hex Escape": 17,
    "UUencode": 18,
    "Punycode": 19,
    "BCD": 20,
    "ROT13": 21,
    "ROT47": 22,
    "Caesar": 23,
    "Atbash": 24,
    "Affine Cipher": 25,
    "Vigenere": 26,
    "Beaufort Cipher": 27,
    "Reverse Text": 28,
    "Rail Fence": 29,
    "Bacon Cipher": 30,
    "A1Z26": 31,
    "Tap Code": 32,
    "Polybius Square": 33,
    "XOR (single byte)": 34,
    "ROT8000": 35,
    "JSFuck": 36,
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
    from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
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
        self._setup_drag_drop()

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

        # Tab 2: Encode
        self.encode_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encode_frame, text="  ▶ ENCODE  ")
        self._build_encode_tab(self.encode_frame)

        # Tab 3: Hash
        self.hash_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.hash_frame, text="  ▶ HASH  ")
        self._build_hash_tab(self.hash_frame)

        # Tab 4: Tools
        self.tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tools_frame, text="  ▶ TOOLS  ")
        self._build_tools_tab(self.tools_frame)

        # Tab 5: Ciphers
        self.ciphers_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ciphers_frame, text="  ▶ CIPHERS  ")
        self._build_ciphers_tab(self.ciphers_frame)

        # Tab 6: Forensics
        self.forensics_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.forensics_frame, text="  ▶ FORENSICS  ")
        self._build_forensics_tab(self.forensics_frame)

        # Tab 7: Image Lab
        self.imagelab_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.imagelab_frame, text="  ▶ IMAGE LAB  ")
        self._build_imagelab_tab(self.imagelab_frame)

        # Tab 8: Web Tools
        self.webtools_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.webtools_frame, text="  ▶ WEB TOOLS  ")
        self._build_webtools_tab(self.webtools_frame)

        # Tab 9: Generate
        self.generate_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.generate_frame, text="  ▶ GENERATE  ")
        self._build_generate_tab(self.generate_frame)

        # Tab 10: Bulk folder
        self.bulk_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.bulk_frame, text="  ▶ BULK SCAN  ")
        self._build_bulk_tab(self.bulk_frame)

        # Tab 11: Help
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
        make_btn("💾 Save", BG_BTN, AMBER,
                 self._save_output, FONT_BTN, 12).pack(side=tk.RIGHT, padx=(0, 5))

        # Auto-detect on paste
        self.input_text.bind("<<Paste>>", lambda e: self.root.after(100, self._on_input_change))
        self.input_text.bind("<KeyRelease>", lambda e: self.root.after(200, self._on_input_change))
        # Right-click menu for input
        self._add_right_click_menu(self.input_text)
        # Right-click menu for output
        self._add_right_click_menu(self.output_text)

        # ── Hint: drag the divider to resize ──
        tk.Label(parent,
                 text="  ↔ drag the divider between panels to resize",
                 font=FONT_SMALL, bg=BG, fg=GRAY_DARK).pack(anchor=tk.W, padx=10, pady=(2, 0))

        # ── Resizable split: input LEFT | output RIGHT ──
        paned = tk.PanedWindow(parent, orient=tk.HORIZONTAL,
                               bg=BG_PANEL, sashwidth=4, sashrelief=tk.RAISED,
                               sashpad=0, handlesize=10)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 8))

        # LEFT: Input panel
        left = tk.Frame(paned, bg=BG)

        tk.Label(left,
                 text="┌─[ INPUT ] paste encoded text here",
                 font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=8, pady=(4, 2))

        tk.Label(left,
                 text="│  Base64 • Hex • Binary • Morse • ROT13 • Caesar • +20 more",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, padx=8, pady=(0, 4))

        self.input_text = scrolledtext.ScrolledText(
            left,
            font=FONT_BODY,
            bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN,
            relief=tk.FLAT,
            wrap=tk.WORD,
            padx=12, pady=12,
        )
        self.input_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 2))

        tk.Label(left, text="└─ paste any encoded text above ↑",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, padx=8, pady=(2, 4))

        paned.add(left, minsize=250)

        # RIGHT: Output panel
        right = tk.Frame(paned, bg=BG)

        tk.Label(right,
                 text="┌─[ OUTPUT ] decoded result appears here",
                 font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=8, pady=(4, 2))

        tk.Label(right,
                 text="│  each decoding step shown with encoding type, then final answer",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, padx=8, pady=(0, 4))

        self.output_text = scrolledtext.ScrolledText(
            right,
            font=FONT_OUTPUT,
            bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN,
            relief=tk.FLAT,
            wrap=tk.WORD,
            padx=12, pady=12,
            state=tk.DISABLED,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 2))

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
        self.output_text.tag_config("input_text_tag", foreground=GREEN_DIM,
                                    font=("Consolas", 10))
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
        self.output_text.tag_config("separator", foreground=GREEN_DIM)
        self.output_text.tag_config("note", foreground=PURPLE,
                                    font=("Consolas", 9, "italic"))
        self.output_text.tag_config("box", foreground=GREEN_DIM,
                                    font=("Consolas", 11))
        self.output_text.tag_config("plain", foreground=WHITE,
                                    font=("Consolas", 11))
        self.output_text.tag_config("prompt", foreground=GREEN_DIM,
                                    font=("Consolas", 10))

        tk.Label(right, text="└─ decoded output above ↑",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(anchor=tk.W, padx=8, pady=(2, 4))

        paned.add(right, minsize=250)

        # Set initial split (50/50)
        paned.sashpos(0, 580)

    # ───────────────────────────────────────────────────────────────────────
    # ENCODE TAB
    # ───────────────────────────────────────────────────────────────────────
    def _build_encode_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(btn_bar, text="Encode mode — convert text to encoded format",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_bar, text="⚡ ENCODE ALL",
                  font=FONT_BTN_BIG, bg=GREEN, fg="#000000", relief=tk.FLAT,
                  padx=20, pady=6, activebackground=BG_BTN_HOV,
                  command=self._do_encode).pack(side=tk.RIGHT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_encode_output).pack(side=tk.RIGHT, padx=(0, 5))

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_encode).pack(side=tk.RIGHT, padx=(0, 5))

        # Input
        tk.Label(parent, text="┌─[ INPUT ] type text to encode here",
                font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.encode_input = scrolledtext.ScrolledText(
            parent, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, height=4)
        self.encode_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 4))
        self.encode_input.bind("<Control-a>", lambda e: e.widget.tag_add(tk.SEL, "1.0", tk.END))
        # Right-click menu
        self._add_right_click_menu(self.encode_input)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] all encodings appear here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.encode_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.encode_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.encode_output.tag_config("enc_name", foreground=CYAN,
                                      font=("Consolas", 10, "bold"))
        self.encode_output.tag_config("enc_val", foreground=WHITE,
                                      font=("Consolas", 11))
        self.encode_output.tag_config("enc_sep", foreground=GREEN_DIM)

    def _do_encode(self):
        raw = self.encode_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please type some text first.")
            return
        self.encode_output.configure(state=tk.NORMAL)
        self.encode_output.delete("1.0", tk.END)
        self._set_status("encoding...")
        for name, encoder in ENCODERS.items():
            try:
                result = encoder(raw)
                self.encode_output.insert(tk.END, f"  {name}:\n", "enc_name")
                self.encode_output.insert(tk.END, f"    {result}\n\n", "enc_val")
            except Exception as e:
                self.encode_output.insert(tk.END, f"  {name}: ERROR: {e}\n\n", "enc_name")
        self.encode_output.insert(tk.END, "─" * 50 + "\n", "enc_sep")
        self.encode_output.insert(tk.END, "[ done ]\n", "enc_name")
        self.encode_output.configure(state=tk.DISABLED)
        self._set_status("encoding complete")

    def _copy_encode_output(self):
        content = self.encode_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("copied to clipboard")

    def _clear_encode(self):
        self.encode_input.delete("1.0", tk.END)
        self.encode_output.configure(state=tk.NORMAL)
        self.encode_output.delete("1.0", tk.END)
        self.encode_output.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # HASH TAB
    # ───────────────────────────────────────────────────────────────────────
    def _build_hash_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(btn_bar, text="Hash generator — paste text, get MD5/SHA1/SHA256/etc.",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_bar, text="⚡ GENERATE HASHES",
                  font=FONT_BTN_BIG, bg=GREEN, fg="#000000", relief=tk.FLAT,
                  padx=20, pady=6, activebackground=BG_BTN_HOV,
                  command=self._do_hash).pack(side=tk.RIGHT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_hash_output).pack(side=tk.RIGHT, padx=(0, 5))

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_hash).pack(side=tk.RIGHT, padx=(0, 5))

        # Input
        tk.Label(parent, text="┌─[ INPUT ] paste text to hash here",
                font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.hash_input = scrolledtext.ScrolledText(
            parent, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, height=4)
        self.hash_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 4))
        self._add_right_click_menu(self.hash_input)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] hashes appear here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.hash_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.hash_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.hash_output.tag_config("hash_name", foreground=CYAN,
                                    font=("Consolas", 10, "bold"))
        self.hash_output.tag_config("hash_val", foreground=YELLOW,
                                    font=("Consolas", 11))
        self.hash_output.tag_config("hash_sep", foreground=GREEN_DIM)

    def _do_hash(self):
        raw = self.hash_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please type some text first.")
            return
        self.hash_output.configure(state=tk.NORMAL)
        self.hash_output.delete("1.0", tk.END)
        self._set_status("generating hashes...")
        hashes = generate_hashes(raw)
        for name, value in hashes.items():
            self.hash_output.insert(tk.END, f"  {name}:\n", "hash_name")
            self.hash_output.insert(tk.END, f"    {value}\n\n", "hash_val")
        self.hash_output.insert(tk.END, "─" * 50 + "\n", "hash_sep")
        self.hash_output.insert(tk.END, "[ done ]\n", "hash_name")
        self.hash_output.configure(state=tk.DISABLED)
        self._set_status("hashes generated")

    def _copy_hash_output(self):
        content = self.hash_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("copied to clipboard")

    def _clear_hash(self):
        self.hash_input.delete("1.0", tk.END)
        self.hash_output.configure(state=tk.NORMAL)
        self.hash_output.delete("1.0", tk.END)
        self.hash_output.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # TOOLS TAB — Caesar all shifts + Frequency analysis
    # ───────────────────────────────────────────────────────────────────────
    def _build_tools_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Button(btn_bar, text="CAESAR — ALL 25 SHIFTS",
                  font=FONT_BTN, bg=BG_BTN, fg=AMBER, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._do_caesar_shifts).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(btn_bar, text="FREQUENCY ANALYSIS",
                  font=FONT_BTN, bg=BG_BTN, fg=AMBER, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._do_freq_analysis).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_tools).pack(side=tk.LEFT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_tools_output).pack(side=tk.RIGHT)

        # Input
        tk.Label(parent, text="┌─[ INPUT ] paste text for analysis here",
                font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.tools_input = scrolledtext.ScrolledText(
            parent, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, height=4)
        self.tools_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 4))
        self._add_right_click_menu(self.tools_input)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] analysis appears here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.tools_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.tools_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.tools_output.tag_config("t_title", foreground=GREEN_BRIGHT,
                                     font=("Consolas", 12, "bold"))
        self.tools_output.tag_config("t_shift", foreground=CYAN,
                                     font=("Consolas", 10, "bold"))
        self.tools_output.tag_config("t_result", foreground=WHITE,
                                     font=("Consolas", 11))
        self.tools_output.tag_config("t_freq_letter", foreground=AMBER,
                                     font=("Consolas", 10, "bold"))
        self.tools_output.tag_config("t_freq_bar", foreground=GREEN,
                                     font=("Consolas", 10))
        self.tools_output.tag_config("t_freq_pct", foreground=CYAN,
                                     font=("Consolas", 10))
        self.tools_output.tag_config("t_sep", foreground=GREEN_DIM)
        self.tools_output.tag_config("t_note", foreground=PURPLE,
                                    font=("Consolas", 9, "italic"))

    def _do_caesar_shifts(self):
        raw = self.tools_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please type some text first.")
            return
        self.tools_output.configure(state=tk.NORMAL)
        self.tools_output.delete("1.0", tk.END)
        self._set_status("generating Caesar shifts...")
        self.tools_output.insert(tk.END, "╔══════════════════════════════════════════════╗\n", "t_sep")
        self.tools_output.insert(tk.END, "║  CAESAR CIPHER — ALL 25 SHIFTS               ║\n", "t_title")
        self.tools_output.insert(tk.END, "╚══════════════════════════════════════════════╝\n\n", "t_sep")
        shifts = caesar_all_shifts(raw)
        for shift, result in shifts:
            self.tools_output.insert(tk.END, f"  Shift {shift:2d}:  ", "t_shift")
            preview = result[:60]
            if len(result) > 60:
                preview += "..."
            self.tools_output.insert(tk.END, f"{preview}\n", "t_result")
        self.tools_output.insert(tk.END, "\n")
        self.tools_output.insert(tk.END, "─" * 50 + "\n", "t_sep")
        self.tools_output.insert(tk.END, "Tip: Look for the shift that produces readable English.\n", "t_note")
        self.tools_output.insert(tk.END, "The most common letter in English is E (shift to match).\n", "t_note")
        self.tools_output.configure(state=tk.DISABLED)
        self._set_status("Caesar shifts generated")

    def _do_freq_analysis(self):
        raw = self.tools_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please type some text first.")
            return
        self.tools_output.configure(state=tk.NORMAL)
        self.tools_output.delete("1.0", tk.END)
        self._set_status("analyzing frequency...")
        freq = frequency_analysis(raw)
        if not freq:
            self.tools_output.insert(tk.END, "No letters found in input.\n", "t_note")
            self.tools_output.configure(state=tk.DISABLED)
            return
        self.tools_output.insert(tk.END, "╔══════════════════════════════════════════════╗\n", "t_sep")
        self.tools_output.insert(tk.END, "║  FREQUENCY ANALYSIS                          ║\n", "t_title")
        self.tools_output.insert(tk.END, "╚══════════════════════════════════════════════╝\n\n", "t_sep")
        self.tools_output.insert(tk.END, "  Letter | Count |  %   | Bar\n", "t_shift")
        self.tools_output.insert(tk.END, "  " + "─" * 46 + "\n", "t_sep")
        max_count = max(v[0] for v in freq.values()) or 1
        for letter, (count, pct) in freq.items():
            if count == 0:
                continue
            bar_len = int(count / max_count * 30)
            bar = "█" * bar_len
            self.tools_output.insert(tk.END, f"  ", "t_result")
            self.tools_output.insert(tk.END, f"  {letter}    ", "t_freq_letter")
            self.tools_output.insert(tk.END, f"| {count:5d} | {pct:5.1f}% | ", "t_result")
            self.tools_output.insert(tk.END, f"{bar}\n", "t_freq_bar")
        self.tools_output.insert(tk.END, "\n")
        self.tools_output.insert(tk.END, "─" * 50 + "\n", "t_sep")
        self.tools_output.insert(tk.END, "Tip: English letter frequency order: ETAOINSHRDLCUMWFGYPBVKJXQZ\n", "t_note")
        self.tools_output.insert(tk.END, "Match the most frequent letter in ciphertext to E.\n", "t_note")
        self.tools_output.configure(state=tk.DISABLED)
        self._set_status("frequency analysis done")

    def _copy_tools_output(self):
        content = self.tools_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("copied to clipboard")

    def _clear_tools(self):
        self.tools_input.delete("1.0", tk.END)
        self.tools_output.configure(state=tk.NORMAL)
        self.tools_output.delete("1.0", tk.END)
        self.tools_output.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # RIGHT-CLICK CONTEXT MENU HELPER
    # ───────────────────────────────────────────────────────────────────────
    def _add_right_click_menu(self, widget):
        """Add copy/paste/cut/select all right-click menu to a text widget."""
        menu = tk.Menu(widget, tearoff=0, bg=BG_PANEL, fg=GREEN,
                       activebackground=BG_BTN_HOV, activeforeground=GREEN_BRIGHT)
        menu.add_command(label="Copy  (Ctrl+C)", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste  (Ctrl+V)", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_command(label="Cut  (Ctrl+X)", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_separator()
        menu.add_command(label="Select All  (Ctrl+A)", command=lambda: widget.tag_add(tk.SEL, "1.0", tk.END))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)

    # ───────────────────────────────────────────────────────────────────────
    # SAVE RESULTS TO FILE
    # ───────────────────────────────────────────────────────────────────────
    def _save_output(self):
        """Save current output to a text file."""
        # Try to get content from the active tab's output widget
        content = None
        try:
            content = self.output_text.get("1.0", tk.END)
        except Exception:
            pass
        if not content or not content.strip():
            messagebox.showwarning("Empty", "No output to save.")
            return
        path = filedialog.asksaveasfilename(
            title="Save results to file",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                self._set_status(f"saved to: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file:\n{e}")

    # ───────────────────────────────────────────────────────────────────────
    # AUTO-DETECT ON PASTE
    # ───────────────────────────────────────────────────────────────────────
    def _on_input_change(self, event=None):
        """Live-detect encoding type as user pastes/types."""
        try:
            raw = self.input_text.get("1.0", tk.END).strip()
        except Exception:
            return
        if not raw or len(raw) < 4:
            self._set_status("ready — paste encoded text and click CRACK IT")
            return
        # Quick detection
        results = detect_and_decode(raw)
        if results:
            name, decoded = results[0]
            self._set_status(f"detected: {name} — click CRACK IT to decode")
        else:
            self._set_status("no encoding detected yet — try clicking CRACK IT")

    # ───────────────────────────────────────────────────────────────────────
    # DRAG AND DROP SUPPORT (basic file drop via Tkinter DnD or manual)
    # ───────────────────────────────────────────────────────────────────────
    def _setup_drag_drop(self):
        """Try to enable drag-and-drop if tkinterdnd2 is available."""
        try:
            import tkinterdnd2
            # If available, register drop handler
            self.input_text.drop_target_register(tkinterdnd2.DND_FILES)
            self.input_text.dnd_bind("<<Drop>>", self._on_file_drop)
        except ImportError:
            # tkinterdnd2 not installed — drag-drop won't work but everything else is fine
            pass

    def _on_file_drop(self, event):
        """Handle a file dropped onto the input box."""
        filepath = event.data.strip().strip("{}").strip()
        if filepath:
            try:
                if is_image_file(filepath):
                    self._process_image(filepath)
                else:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        self.input_text.delete("1.0", tk.END)
                        self.input_text.insert("1.0", f.read())
                    self._set_status(f"loaded: {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not load file:\n{e}")

    # ───────────────────────────────────────────────────────────────────────
    # CIPHERS TAB — Playfair, Columnar, Bifid, ADFGVX, Vigenere custom key
    # ───────────────────────────────────────────────────────────────────────
    def _build_ciphers_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(btn_bar, text="Classic ciphers — paste text, pick a cipher, enter key, click button",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_ciphers).pack(side=tk.RIGHT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_ciphers_output).pack(side=tk.RIGHT, padx=(0, 5))

        # Key entry
        key_frame = tk.Frame(parent, bg=BG)
        key_frame.pack(fill=tk.X, padx=10, pady=(4, 2))
        tk.Label(key_frame, text="Key:", font=FONT_SMALL, bg=BG, fg=AMBER).pack(side=tk.LEFT, padx=(0, 5))
        self.cipher_key_entry = tk.Entry(key_frame, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
                                         insertbackground=GREEN, relief=tk.FLAT, width=30)
        self.cipher_key_entry.insert(0, "KEY")
        self.cipher_key_entry.pack(side=tk.LEFT, padx=5)
        tk.Label(key_frame, text="(for Playfair, Bifid, Vigenere, Columnar, ADFGVX, Beaufort)",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=10)

        # Cipher buttons
        cipher_btns = tk.Frame(parent, bg=BG)
        cipher_btns.pack(fill=tk.X, padx=10, pady=(4, 4))

        cipher_list = [
            ("DECODE Playfair", lambda: self._run_cipher("decode_playfair")),
            ("DECODE Columnar", lambda: self._run_cipher("decode_columnar_transposition")),
            ("DECODE Bifid", lambda: self._run_cipher("decode_bifid")),
            ("DECODE ADFGVX", lambda: self._run_cipher("decode_adfgvx")),
            ("DECODE Vigenere", lambda: self._run_cipher("decode_vigenere_custom")),
            ("DECODE Beaufort", lambda: self._run_cipher("decode_beaufort")),
            ("DECODE Affine", lambda: self._run_cipher("decode_affine")),
            ("Rail Fence ALL", lambda: self._run_rail_fence_all()),
            ("DECODE ROT8000", lambda: self._run_cipher("decode_rot8000")),
        ]
        for text, cmd in cipher_list:
            tk.Button(cipher_btns, text=text, font=FONT_BTN, bg=BG_BTN, fg=AMBER,
                      relief=tk.FLAT, padx=8, pady=4, activebackground=BG_BTN_HOV,
                      command=cmd).pack(side=tk.LEFT, padx=2)

        # Input
        tk.Label(parent, text="┌─[ INPUT ] paste ciphertext here",
                font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.ciphers_input = scrolledtext.ScrolledText(
            parent, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, height=5)
        self.ciphers_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 4))
        self._add_right_click_menu(self.ciphers_input)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] plaintext appears here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.ciphers_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.ciphers_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.ciphers_output.tag_config("c_name", foreground=CYAN, font=("Consolas", 10, "bold"))
        self.ciphers_output.tag_config("c_val", foreground=WHITE, font=("Consolas", 11))
        self.ciphers_output.tag_config("c_err", foreground="#ff4444", font=("Consolas", 10, "italic"))

    def _run_cipher(self, func_name):
        raw = self.ciphers_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste some ciphertext first.")
            return
        key = self.cipher_key_entry.get().strip() or "KEY"
        func = globals().get(func_name)
        if not func:
            messagebox.showerror("Error", f"Function {func_name} not found.")
            return
        self.ciphers_output.configure(state=tk.NORMAL)
        self.ciphers_output.delete("1.0", tk.END)
        self._set_status(f"running {func_name}...")
        try:
            import inspect
            sig = inspect.signature(func)
            if len(sig.parameters) >= 2:
                result = func(raw, key)
            else:
                result = func(raw)
            self.ciphers_output.insert(tk.END, f"  Result:\n", "c_name")
            self.ciphers_output.insert(tk.END, f"    {result}\n", "c_val")
        except Exception as e:
            self.ciphers_output.insert(tk.END, f"  Error: {e}\n", "c_err")
        self.ciphers_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _run_rail_fence_all(self):
        raw = self.ciphers_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste some ciphertext first.")
            return
        self.ciphers_output.configure(state=tk.NORMAL)
        self.ciphers_output.delete("1.0", tk.END)
        self._set_status("trying rail fence 2-7 rails...")
        try:
            results = rail_fence_all_rails(raw)
            self.ciphers_output.insert(tk.END, "  Rail Fence — All Rails:\n\n", "c_name")
            for rails, decoded in results:
                self.ciphers_output.insert(tk.END, f"    {rails} rails: {decoded[:60]}\n", "c_val")
        except Exception as e:
            self.ciphers_output.insert(tk.END, f"  Error: {e}\n", "c_err")
        self.ciphers_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _copy_ciphers_output(self):
        content = self.ciphers_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _clear_ciphers(self):
        self.ciphers_input.delete("1.0", tk.END)
        self.ciphers_output.configure(state=tk.NORMAL)
        self.ciphers_output.delete("1.0", tk.END)
        self.ciphers_output.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # FORENSICS TAB — file type detection, strings, hex dump, file carving
    # ───────────────────────────────────────────────────────────────────────
    def _build_forensics_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(btn_bar, text="Forensics tools — paste hex/data or load a file",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_forensics).pack(side=tk.RIGHT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_forensics_output).pack(side=tk.RIGHT, padx=(0, 5))

        # Forensics buttons
        forensics_btns = tk.Frame(parent, bg=BG)
        forensics_btns.pack(fill=tk.X, padx=10, pady=(4, 4))

        tools = [
            ("File Type Detect", lambda: self._run_forensics("detect_file_type")),
            ("Extract Strings", lambda: self._run_forensics("extract_strings")),
            ("Hex Dump", lambda: self._run_forensics("hex_dump")),
            ("Hash Identifier", lambda: self._run_forensics("identify_hash")),
            ("XOR (key=AB)", lambda: self._run_forensics_xor()),
            ("Scan File Sigs", lambda: self._run_forensics_file("scan_file_signatures")),
            ("Find Hidden EOF", lambda: self._run_forensics_file("find_hidden_data")),
            ("PNG Chunks", lambda: self._run_forensics_file("analyze_png_chunks")),
            ("Carve Files", lambda: self._run_forensics_file("carve_files")),
            ("AES Decrypt", lambda: self._run_aes_decrypt()),
            ("DECODE JSFuck", lambda: self._run_forensics("decode_jsfuck")),
        ]
        for text, cmd in tools:
            tk.Button(forensics_btns, text=text, font=FONT_BTN, bg=BG_BTN, fg=AMBER,
                      relief=tk.FLAT, padx=8, pady=4, activebackground=BG_BTN_HOV,
                      command=cmd).pack(side=tk.LEFT, padx=2)

        # Input
        tk.Label(parent, text="┌─[ INPUT ] paste hex data here (or use buttons above to load a file)",
                font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.forensics_input = scrolledtext.ScrolledText(
            parent, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, height=5)
        self.forensics_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 4))
        self._add_right_click_menu(self.forensics_input)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] results appear here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.forensics_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.forensics_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.forensics_output.tag_config("f_name", foreground=CYAN, font=("Consolas", 10, "bold"))
        self.forensics_output.tag_config("f_val", foreground=WHITE, font=("Consolas", 10))
        self.forensics_output.tag_config("f_err", foreground="#ff4444", font=("Consolas", 10, "italic"))
        self.forensics_output.tag_config("f_warn", foreground=YELLOW, font=("Consolas", 10, "bold"))

    def _run_forensics(self, func_name):
        raw = self.forensics_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste some data first.")
            return
        func = globals().get(func_name)
        if not func:
            messagebox.showerror("Error", f"Function {func_name} not found.")
            return
        self.forensics_output.configure(state=tk.NORMAL)
        self.forensics_output.delete("1.0", tk.END)
        self._set_status(f"running {func_name}...")
        try:
            result = func(raw)
            self.forensics_output.insert(tk.END, f"{result}\n", "f_val")
        except Exception as e:
            self.forensics_output.insert(tk.END, f"Error: {e}\n", "f_err")
        self.forensics_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _run_forensics_xor(self):
        raw = self.forensics_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste hex data first.")
            return
        self.forensics_output.configure(state=tk.NORMAL)
        self.forensics_output.delete("1.0", tk.END)
        self._set_status("running XOR with key AB...")
        try:
            result = xor_custom_key(raw, "AB")
            self.forensics_output.insert(tk.END, f"XOR result:\n{result}\n", "f_val")
        except Exception as e:
            self.forensics_output.insert(tk.END, f"Error: {e}\n", "f_err")
        self.forensics_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _run_aes_decrypt(self):
        """AES decrypt — ask for key, then decrypt input data."""
        raw = self.forensics_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste hex-encoded ciphertext first.")
            return
        key_hex = simpledialog.askstring("AES Key", "Enter AES key (hex):\n(e.g. 00112233445566778899aabbccddeeff\nfor 128-bit key)",
                                          parent=self.root)
        if not key_hex:
            return
        iv_hex = simpledialog.askstring("AES IV", "Enter IV (hex), or leave empty for zeros:",
                                         parent=self.root) or ""
        self.forensics_output.configure(state=tk.NORMAL)
        self.forensics_output.delete("1.0", tk.END)
        self._set_status("decrypting AES...")
        try:
            result = aes_decrypt(raw, key_hex.strip(), iv_hex.strip())
            self.forensics_output.insert(tk.END, f"AES Decryption:\n{result}\n", "f_val")
        except Exception as e:
            self.forensics_output.insert(tk.END, f"Error: {e}\n", "f_err")
        self.forensics_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _run_forensics_file(self, func_name):
        filepath = filedialog.askopenfilename(title=f"Select file for {func_name}")
        if not filepath:
            return
        func = globals().get(func_name)
        if not func:
            messagebox.showerror("Error", f"Function {func_name} not found.")
            return
        self.forensics_output.configure(state=tk.NORMAL)
        self.forensics_output.delete("1.0", tk.END)
        self._set_status(f"running {func_name} on {os.path.basename(filepath)}...")
        try:
            result = func(filepath)
            self.forensics_output.insert(tk.END, f"{result}\n", "f_val")
        except Exception as e:
            self.forensics_output.insert(tk.END, f"Error: {e}\n", "f_err")
        self.forensics_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _copy_forensics_output(self):
        content = self.forensics_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _clear_forensics(self):
        self.forensics_input.delete("1.0", tk.END)
        self.forensics_output.configure(state=tk.NORMAL)
        self.forensics_output.delete("1.0", tk.END)
        self.forensics_output.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # IMAGE LAB TAB — bit planes, channels, diff, stego detection
    # ───────────────────────────────────────────────────────────────────────
    def _build_imagelab_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(btn_bar, text="Image forensics lab — load an image and run analysis",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_imagelab).pack(side=tk.RIGHT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_imagelab_output).pack(side=tk.RIGHT, padx=(0, 5))

        # Image lab buttons
        lab_btns = tk.Frame(parent, bg=BG)
        lab_btns.pack(fill=tk.X, padx=10, pady=(4, 4))

        tools = [
            ("Check Dimensions", lambda: self._run_imagelab("check_image_dimensions")),
            ("Stego Detection", lambda: self._run_imagelab("detect_steganography")),
            ("Bit Planes", lambda: self._run_imagelab("extract_bit_planes")),
            ("Separate RGB", lambda: self._run_imagelab("separate_color_channels")),
            ("PNG Chunk Analysis", lambda: self._run_imagelab("analyze_png_chunks")),
            ("Find Hidden Data", lambda: self._run_imagelab("find_hidden_data")),
            ("Compare 2 Images", lambda: self._run_imagelab_compare()),
        ]
        for text, cmd in tools:
            tk.Button(lab_btns, text=text, font=FONT_BTN, bg=BG_BTN, fg=AMBER,
                      relief=tk.FLAT, padx=8, pady=4, activebackground=BG_BTN_HOV,
                      command=cmd).pack(side=tk.LEFT, padx=2)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] image analysis results appear here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.imagelab_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.imagelab_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.imagelab_output.tag_config("il_name", foreground=CYAN, font=("Consolas", 10, "bold"))
        self.imagelab_output.tag_config("il_val", foreground=WHITE, font=("Consolas", 10))
        self.imagelab_output.tag_config("il_err", foreground="#ff4444", font=("Consolas", 10, "italic"))
        self.imagelab_output.tag_config("il_warn", foreground=YELLOW, font=("Consolas", 10, "bold"))

    def _run_imagelab(self, func_name):
        filepath = filedialog.askopenfilename(title="Select an image file",
                                               filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tiff"), ("All files", "*.*")])
        if not filepath:
            return
        func = globals().get(func_name)
        if not func:
            messagebox.showerror("Error", f"Function {func_name} not found.")
            return
        self.imagelab_output.configure(state=tk.NORMAL)
        self.imagelab_output.delete("1.0", tk.END)
        self._set_status(f"running {func_name}...")
        try:
            result = func(filepath)
            self.imagelab_output.insert(tk.END, f"{result}\n", "il_val")
        except Exception as e:
            self.imagelab_output.insert(tk.END, f"Error: {e}\n", "il_err")
        self.imagelab_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _run_imagelab_compare(self):
        file1 = filedialog.askopenfilename(title="Select FIRST image",
                                           filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tiff"), ("All files", "*.*")])
        if not file1:
            return
        file2 = filedialog.askopenfilename(title="Select SECOND image",
                                           filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tiff"), ("All files", "*.*")])
        if not file2:
            return
        self.imagelab_output.configure(state=tk.NORMAL)
        self.imagelab_output.delete("1.0", tk.END)
        self._set_status("comparing images...")
        try:
            result = compare_images(file1, file2)
            self.imagelab_output.insert(tk.END, f"{result}\n", "il_val")
        except Exception as e:
            self.imagelab_output.insert(tk.END, f"Error: {e}\n", "il_err")
        self.imagelab_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _copy_imagelab_output(self):
        content = self.imagelab_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _clear_imagelab(self):
        self.imagelab_output.configure(state=tk.NORMAL)
        self.imagelab_output.delete("1.0", tk.END)
        self.imagelab_output.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # WEB TOOLS TAB — HTTP headers, cookies, IP conversion, DNS lookup
    # ───────────────────────────────────────────────────────────────────────
    def _build_webtools_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(btn_bar, text="Web & network tools — decode headers, cookies, IPs, DNS",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_webtools).pack(side=tk.RIGHT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_webtools_output).pack(side=tk.RIGHT, padx=(0, 5))

        # Web tool buttons
        web_btns = tk.Frame(parent, bg=BG)
        web_btns.pack(fill=tk.X, padx=10, pady=(4, 4))

        tools = [
            ("Decode HTTP Headers", lambda: self._run_webtools("decode_http_headers")),
            ("Decode Cookies", lambda: self._run_webtools("decode_cookies")),
            ("IP Convert", lambda: self._run_webtools("convert_ip")),
            ("DNS Lookup", lambda: self._run_webtools("dns_lookup")),
        ]
        for text, cmd in tools:
            tk.Button(web_btns, text=text, font=FONT_BTN, bg=BG_BTN, fg=AMBER,
                      relief=tk.FLAT, padx=8, pady=4, activebackground=BG_BTN_HOV,
                      command=cmd).pack(side=tk.LEFT, padx=2)

        # Input
        tk.Label(parent, text="┌─[ INPUT ] paste HTTP headers / cookies / IP / domain here",
                font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.webtools_input = scrolledtext.ScrolledText(
            parent, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, height=5)
        self.webtools_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 4))
        self._add_right_click_menu(self.webtools_input)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] results appear here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.webtools_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.webtools_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.webtools_output.tag_config("w_name", foreground=CYAN, font=("Consolas", 10, "bold"))
        self.webtools_output.tag_config("w_val", foreground=WHITE, font=("Consolas", 10))
        self.webtools_output.tag_config("w_err", foreground="#ff4444", font=("Consolas", 10, "italic"))

    def _run_webtools(self, func_name):
        raw = self.webtools_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please paste some data first.")
            return
        func = globals().get(func_name)
        if not func:
            messagebox.showerror("Error", f"Function {func_name} not found.")
            return
        self.webtools_output.configure(state=tk.NORMAL)
        self.webtools_output.delete("1.0", tk.END)
        self._set_status(f"running {func_name}...")
        try:
            result = func(raw)
            self.webtools_output.insert(tk.END, f"{result}\n", "w_val")
        except Exception as e:
            self.webtools_output.insert(tk.END, f"Error: {e}\n", "w_err")
        self.webtools_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _copy_webtools_output(self):
        content = self.webtools_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _clear_webtools(self):
        self.webtools_input.delete("1.0", tk.END)
        self.webtools_output.configure(state=tk.NORMAL)
        self.webtools_output.delete("1.0", tk.END)
        self.webtools_output.configure(state=tk.DISABLED)

    # ───────────────────────────────────────────────────────────────────────
    # GENERATE TAB — QR codes, barcodes, morse audio, ROT-n
    # ───────────────────────────────────────────────────────────────────────
    def _build_generate_tab(self, parent):
        btn_bar = tk.Frame(parent, bg=BG)
        btn_bar.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(btn_bar, text="Generation tools — create QR codes, barcodes, morse audio, ROT-n",
                 font=FONT_SMALL, bg=BG, fg=GRAY).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_bar, text="Clear",
                  font=FONT_BTN, bg=BG_BTN, fg=GRAY, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._clear_generate).pack(side=tk.RIGHT)

        tk.Button(btn_bar, text="📋 Copy",
                  font=FONT_BTN, bg=BG_BTN, fg=CYAN, relief=tk.FLAT,
                  padx=12, pady=6, activebackground=BG_BTN_HOV,
                  command=self._copy_generate_output).pack(side=tk.RIGHT, padx=(0, 5))

        # Generate buttons
        gen_btns = tk.Frame(parent, bg=BG)
        gen_btns.pack(fill=tk.X, padx=10, pady=(4, 4))

        tools = [
            ("Generate QR Code", lambda: self._run_generate("generate_qr_code")),
            ("Generate Barcode", lambda: self._run_generate("generate_barcode")),
            ("Play Morse Audio", lambda: self._run_generate("play_morse_audio")),
            ("ROT-n (try all)", lambda: self._run_generate_rotn()),
        ]
        for text, cmd in tools:
            tk.Button(gen_btns, text=text, font=FONT_BTN, bg=BG_BTN, fg=AMBER,
                      relief=tk.FLAT, padx=8, pady=4, activebackground=BG_BTN_HOV,
                      command=cmd).pack(side=tk.LEFT, padx=2)

        # Input
        tk.Label(parent, text="┌─[ INPUT ] type text to generate from here",
                font=FONT_LABEL, bg=BG, fg=AMBER).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.generate_input = scrolledtext.ScrolledText(
            parent, font=FONT_BODY, bg=BG_INPUT, fg=GREEN,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, height=5)
        self.generate_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 4))
        self._add_right_click_menu(self.generate_input)

        # Output
        tk.Label(parent, text="┌─[ OUTPUT ] results appear here",
                font=FONT_LABEL, bg=BG, fg=GREEN).pack(anchor=tk.W, padx=10, pady=(4, 2))
        self.generate_output = scrolledtext.ScrolledText(
            parent, font=FONT_OUTPUT, bg=BG_OUTPUT, fg=WHITE,
            insertbackground=GREEN, relief=tk.FLAT, wrap=tk.WORD,
            padx=12, pady=12, state=tk.DISABLED)
        self.generate_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.generate_output.tag_config("g_name", foreground=CYAN, font=("Consolas", 10, "bold"))
        self.generate_output.tag_config("g_val", foreground=WHITE, font=("Consolas", 10))
        self.generate_output.tag_config("g_err", foreground="#ff4444", font=("Consolas", 10, "italic"))

    def _run_generate(self, func_name):
        raw = self.generate_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please type some text first.")
            return
        func = globals().get(func_name)
        if not func:
            messagebox.showerror("Error", f"Function {func_name} not found.")
            return
        self.generate_output.configure(state=tk.NORMAL)
        self.generate_output.delete("1.0", tk.END)
        self._set_status(f"running {func_name}...")
        try:
            result = func(raw)
            self.generate_output.insert(tk.END, f"{result}\n", "g_val")
        except Exception as e:
            self.generate_output.insert(tk.END, f"Error: {e}\n", "g_err")
        self.generate_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _run_generate_rotn(self):
        raw = self.generate_input.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Empty", "Please type some text first.")
            return
        self.generate_output.configure(state=tk.NORMAL)
        self.generate_output.delete("1.0", tk.END)
        self._set_status("generating ROT-n table...")
        for shift in range(1, 26):
            result = decode_rot_n(raw, shift)
            self.generate_output.insert(tk.END, f"  ROT-{shift:2d}: {result[:60]}\n", "g_val")
        self.generate_output.configure(state=tk.DISABLED)
        self._set_status("done")

    def _copy_generate_output(self):
        content = self.generate_output.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _clear_generate(self):
        self.generate_input.delete("1.0", tk.END)
        self.generate_output.configure(state=tk.NORMAL)
        self.generate_output.delete("1.0", tk.END)
        self.generate_output.configure(state=tk.DISABLED)

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
            ("SUPPORTED ENCODINGS (DECODE + ENCODE):\n", "h2"),
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
            ("    • Right-click any text box for Copy/Paste/Cut menu\n", "cyan"),
            ("    • Drag the divider between panels to resize\n", "cyan"),
            ("    • Click Save to save results to a file\n", "cyan"),
            ("\n", "dim"),
            ("HOW TO USE — ENCODE TAB:\n", "h2"),
            ("─────────────────────────\n", "dim"),
            ("  1. Type or paste plain text in the input box\n", "green"),
            ("  2. Click ENCODE ALL\n", "green"),
            ("  3. See your text encoded in 18 different formats at once\n", "green"),
            ("\n", "dim"),
            ("HOW TO USE — HASH TAB:\n", "h2"),
            ("──────────────────────\n", "dim"),
            ("  1. Paste text in the input box\n", "green"),
            ("  2. Click GENERATE HASHES\n", "green"),
            ("  3. Get MD5, SHA1, SHA256, SHA512, SHA224, SHA384 hashes\n", "green"),
            ("\n", "dim"),
            ("HOW TO USE — TOOLS TAB:\n", "h2"),
            ("───────────────────────\n", "dim"),
            ("  Caesar All Shifts:\n", "green"),
            ("    Paste text → see all 25 Caesar shifts at once\n", "dim"),
            ("  Frequency Analysis:\n", "green"),
            ("    Paste text → see letter frequency bar chart\n", "dim"),
            ("    Compare to English: ETAOINSHRDLCUMWFGYPBVKJXQZ\n", "dim"),
            ("\n", "dim"),
            ("HOW TO USE — CIPHERS TAB:\n", "h2"),
            ("──────────────────────────\n", "dim"),
            ("  1. Paste ciphertext in the input box\n", "green"),
            ("  2. Enter a key in the Key field\n", "green"),
            ("  3. Click the cipher button (Playfair, Columnar, Bifid, etc.)\n", "green"),
            ("\n", "dim"),
            ("HOW TO USE — FORENSICS TAB:\n", "h2"),
            ("────────────────────────────\n", "dim"),
            ("  Paste hex data and click a button:\n", "green"),
            ("    File Type Detect — identify file from magic bytes\n", "dim"),
            ("    Extract Strings — find readable text in binary data\n", "dim"),
            ("    Hex Dump — view data in hex + ASCII format\n", "dim"),
            ("    Hash Identifier — identify hash type (MD5, SHA256, etc.)\n", "dim"),
            ("  Or load a file for: file signature scan, hidden EOF data, PNG chunks\n", "dim"),
            ("\n", "dim"),
            ("HOW TO USE — IMAGE LAB TAB:\n", "h2"),
            ("────────────────────────────\n", "dim"),
            ("  Click a button and select an image file:\n", "green"),
            ("    Check Dimensions, Stego Detection, Bit Planes, RGB Split\n", "dim"),
            ("    PNG Chunk Analysis, Find Hidden Data, Compare 2 Images\n", "dim"),
            ("\n", "dim"),
            ("HOW TO USE — WEB TOOLS TAB:\n", "h2"),
            ("───────────────────────────\n", "dim"),
            ("  Paste data and click a button:\n", "green"),
            ("    Decode HTTP Headers, Decode Cookies, IP Convert, DNS Lookup\n", "dim"),
            ("\n", "dim"),
            ("HOW TO USE — GENERATE TAB:\n", "h2"),
            ("──────────────────────────\n", "dim"),
            ("  Type text and click a button:\n", "green"),
            ("    Generate QR Code, Generate Barcode, Play Morse Audio, ROT-n table\n", "dim"),
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
        """Write the step-by-step decoding path clearly."""
        for i, step in enumerate(result.steps, 1):
            # Step header - box drawing
            self._write_line(f"{indent}┌──────────────────────────────────────────────┐", "box")
            self._write(f"{indent}│  Step {i}  ", "step_num")
            self._write(f"Encoding: {step.encoding}", "encoding")
            self._write_line(f"{' ' * max(0, 30 - len(step.encoding) - len(str(i)) - 10)}│", "box")

            # Input that was decoded
            input_preview = step.input_text[:60]
            if len(step.input_text) > 60:
                input_preview += "..."
            self._write_line(f"{indent}│  Input:  {input_preview:<38}│", "input_text_tag")

            # Decoded result
            preview = step.output_text
            if len(preview) > 300:
                preview = preview[:300] + "..."
            self._write_line(f"{indent}│  Output: {preview[:38]:<38}│", "decoded")
            self._write_line(f"{indent}└──────────────────────────────────────────────┘", "box")
            self._write_line()

        # Final result
        if result.found_flag:
            self._write_line(f"{indent}╔══════════════════════════════════════════════╗", "box")
            self._write_line(f"{indent}║  ✦ FINAL RESULT: FLAG FOUND!                 ║", "final_label")
            self._write_line(f"{indent}╠══════════════════════════════════════════════╣", "box")
            flag_text = result.found_flag
            if len(flag_text) <= 42:
                padded = flag_text + " " * (42 - len(flag_text))
                self._write_line(f"{indent}║  {padded}  ║", "flag")
            else:
                # Wrap long flags
                while flag_text:
                    chunk = flag_text[:42]
                    flag_text = flag_text[42:]
                    padded = chunk + " " * (42 - len(chunk))
                    self._write_line(f"{indent}║  {padded}  ║", "flag")
            self._write_line(f"{indent}╚══════════════════════════════════════════════╝", "box")

        if result.found_url:
            self._write_line(f"{indent}╔══════════════════════════════════════════════╗", "box")
            self._write_line(f"{indent}║  ➜ FINAL RESULT: URL FOUND!                  ║", "final_label")
            self._write_line(f"{indent}╠══════════════════════════════════════════════╣", "box")
            url_text = result.found_url
            if len(url_text) <= 42:
                padded = url_text + " " * (42 - len(url_text))
                self._write_line(f"{indent}║  {padded}  ║", "url")
            else:
                while url_text:
                    chunk = url_text[:42]
                    url_text = url_text[42:]
                    padded = chunk + " " * (42 - len(chunk))
                    self._write_line(f"{indent}║  {padded}  ║", "url")
            self._write_line(f"{indent}╚══════════════════════════════════════════════╝", "box")

        if not result.found_flag and not result.found_url:
            self._write_line(f"{indent}╔══════════════════════════════════════════════╗", "box")
            self._write_line(f"{indent}║  FINAL RESULT:                               ║", "final_label")
            self._write_line(f"{indent}╠══════════════════════════════════════════════╣", "box")
            output = result.final_output
            if len(output) > 42:
                while output:
                    chunk = output[:42]
                    output = output[42:]
                    padded = chunk + " " * (42 - len(chunk))
                    self._write_line(f"{indent}║  {padded}  ║", "plain")
            else:
                padded = output + " " * (42 - len(output))
                self._write_line(f"{indent}║  {padded}  ║", "plain")
            self._write_line(f"{indent}╚══════════════════════════════════════════════╝", "box")

        # Other possible decodes
        if result.ambiguities:
            self._write_line()
            self._write_line(f"{indent}┌─ Other possible decodes (layer 1) ──────────┐", "box")
            for name, text in result.ambiguities[:3]:
                preview = text[:36]
                self._write_line(f"{indent}│  {name}: {preview:<32}│", "note")
            self._write_line(f"{indent}└──────────────────────────────────────────────┘", "box")

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




# ===========================================================================
# ENCODERS — reverse of decoders (for encode mode)
# ===========================================================================

def encode_base64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def encode_base32(s: str) -> str:
    return base64.b32encode(s.encode()).decode()

def encode_base85(s: str) -> str:
    return base64.b85encode(s.encode()).decode()

def encode_hex(s: str) -> str:
    return s.encode().hex()

def encode_binary(s: str) -> str:
    return " ".join(format(ord(c), "08b") for c in s)

def encode_rot13(s: str) -> str:
    result = ""
    for c in s:
        if "a" <= c <= "z":
            result += chr((ord(c) - ord("a") + 13) % 26 + ord("a"))
        elif "A" <= c <= "Z":
            result += chr((ord(c) - ord("A") + 13) % 26 + ord("A"))
        else:
            result += c
    return result

def encode_rot47(s: str) -> str:
    result = ""
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            result += chr(33 + (o - 33 + 47) % 94)
        else:
            result += c
    return result

def encode_caesar(s: str, shift: int = 3) -> str:
    result = ""
    for c in s:
        if "a" <= c <= "z":
            result += chr((ord(c) - ord("a") + shift) % 26 + ord("a"))
        elif "A" <= c <= "Z":
            result += chr((ord(c) - ord("A") + shift) % 26 + ord("A"))
        else:
            result += c
    return result

def encode_atbash(s: str) -> str:
    result = ""
    for c in s:
        if "a" <= c <= "z":
            result += chr(ord("z") - (ord(c) - ord("a")))
        elif "A" <= c <= "Z":
            result += chr(ord("Z") - (ord(c) - ord("A")))
        else:
            result += c
    return result

def encode_morse(s: str) -> str:
    MORSE_ENCODE = {v: k for k, v in MORSE_DECODE.items()}
    result = []
    for word in s.split():
        chars = []
        for c in word.upper():
            if c in MORSE_ENCODE:
                chars.append(MORSE_ENCODE[c])
        result.append(" ".join(chars))
    return " / ".join(result)

def encode_url(s: str) -> str:
    return urllib.parse.quote_plus(s)

def encode_ascii(s: str) -> str:
    return " ".join(str(ord(c)) for c in s)

def encode_octal(s: str) -> str:
    return " ".join(oct(ord(c))[2:] for c in s)

def encode_reverse(s: str) -> str:
    return s[::-1]

def encode_unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in s)

def encode_hex_escape(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in s)

def encode_html_entities(s: str) -> str:
    import html
    return html.escape(s)

def encode_vigenere(s: str, key: str = "key") -> str:
    result = []
    key_idx = 0
    key = key.lower()
    for c in s:
        if c.isalpha():
            base = ord("a") if c.islower() else ord("A")
            k = ord(key[key_idx % len(key)]) - ord("a")
            result.append(chr((ord(c) - base + k) % 26 + base))
            key_idx += 1
        else:
            result.append(c)
    return "".join(result)

ENCODERS = {
    "Base64": encode_base64,
    "Base32": encode_base32,
    "Base85": encode_base85,
    "Base91": encode_base91,
    "Base45": encode_base45,
    "Hexadecimal": encode_hex,
    "Binary": encode_binary,
    "ROT13": encode_rot13,
    "ROT47": encode_rot47,
    "Caesar (shift 3)": encode_caesar,
    "Atbash": encode_atbash,
    "Affine Cipher": encode_affine,
    "Morse Code": encode_morse,
    "URL Encoding": encode_url,
    "ASCII Decimal": encode_ascii,
    "Octal": encode_octal,
    "Reverse Text": encode_reverse,
    "Unicode Escape": encode_unicode_escape,
    "Hex Escape": encode_hex_escape,
    "HTML Entities": encode_html_entities,
    "Vigenere (key='key')": encode_vigenere,
    "A1Z26": encode_a1z26,
    "Tap Code": encode_tap_code,
    "BCD": encode_bcd,
    "Punycode": encode_punycode,
    "UUencode": encode_uuencode,
    "Polybius Square": encode_polybius,
    "Beaufort Cipher": encode_beaufort,
    "Deadfish": encode_deadfish,
}


# ===========================================================================
# HASH GENERATOR
# ===========================================================================

def generate_hashes(text: str) -> dict:
    """Generate all common hashes for given text."""
    import hashlib
    data = text.encode("utf-8")
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "SHA512": hashlib.sha512(data).hexdigest(),
        "SHA224": hashlib.sha224(data).hexdigest(),
        "SHA384": hashlib.sha384(data).hexdigest(),
    }


# ===========================================================================
# CAESAR ALL 25 SHIFTS TABLE
# ===========================================================================

def caesar_all_shifts(s: str) -> list[tuple[int, str]]:
    """Return all 25 Caesar shifts of the input string."""
    results = []
    for shift in range(1, 26):
        result = ""
        for c in s:
            if "a" <= c <= "z":
                result += chr((ord(c) - ord("a") + shift) % 26 + ord("a"))
            elif "A" <= c <= "Z":
                result += chr((ord(c) - ord("A") + shift) % 26 + ord("A"))
            else:
                result += c
        results.append((shift, result))
    return results


# ===========================================================================
# FREQUENCY ANALYSIS
# ===========================================================================

def frequency_analysis(s: str) -> dict:
    """Return letter frequency analysis of text."""
    s = s.upper()
    total_letters = sum(1 for c in s if c.isalpha())
    if total_letters == 0:
        return {}
    freq = {}
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        count = s.count(c)
        freq[c] = (count, count / total_letters * 100)
    # Sort by frequency descending
    freq = dict(sorted(freq.items(), key=lambda x: x[1][0], reverse=True))
    return freq




BANNER = r"""
  ╔══════════════════════════════════════════════╗
  ║  404 CODE CRACKER v3.0                       ║
  ║  Auto-detect | Decode | Encode | Crack       ║
  ║  70+ Tools | 11 Tabs | Created by ERROR 404  ║
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
