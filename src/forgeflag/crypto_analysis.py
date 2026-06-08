from __future__ import annotations

import math
import random
import re

from forgeflag.flags import extract_flags


RSA_PARAM_PATTERN = re.compile(r"(?im)^\s*((?:n|e|c|p|q|d|phi)\d*)\s*[:=]\s*(0x[0-9a-f]+|\d+)\s*$")
PUBLIC_KEY_MARKERS = ("-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----")
PRIVATE_KEY_MARKERS = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")
PY_RANDOM_RANDINT_PATTERN = re.compile(r"random\.randint\(\s*([0-9*+\-\s]+)\s*,\s*([0-9*+\-\s]+)\s*\)")
PY_RANDOM_BITS_PATTERN = re.compile(r"random\.getrandbits\(\s*(\d{1,5})\s*\)")
LARGE_DECIMAL_PATTERN = re.compile(r"\b\d{8,}\b")
HEX_CIPHERTEXT_PATTERN = re.compile(
    r"(?im)^\s*(?:ciphertext|cipher|ct|enc|encrypted|single byte xor ciphertext)\s*[:=]\s*([0-9a-f]{8,})\s*$"
)
KEY_PATTERN = re.compile(r"(?im)^\s*(?:key|xor_key|vigenere key)\s*[:=]\s*['\"]?([A-Za-z0-9_{}-]{1,64})['\"]?\s*$")
VIGENERE_PATTERN = re.compile(r"(?im)^\s*(?:vigenere\s+)?(?:ciphertext|cipher|ct)\s*[:=]\s*([A-Za-z{}_-]{8,})\s*$")


def rsa_summary_from_text(text: str) -> dict[str, object]:
    parameters = {
        name.lower(): value
        for name, value in RSA_PARAM_PATTERN.findall(text)
    }
    has_public_key = any(marker in text for marker in PUBLIC_KEY_MARKERS)
    has_private_key = any(marker in text for marker in PRIVATE_KEY_MARKERS)
    hints = _rsa_hints(parameters, has_public_key, has_private_key)
    recommended_tools = []
    if parameters or has_public_key or has_private_key:
        recommended_tools.append("RsaCtfTool")
    if (
        {"n", "e", "c"}.issubset(parameters)
        or {"n", "e1", "e2", "c1", "c2"}.issubset(parameters)
        or {"n1", "n2", "e", "c1"}.issubset(parameters)
        or {"n1", "n2", "n3", "e", "c1", "c2", "c3"}.issubset(parameters)
    ):
        recommended_tools.append("SageMath")
    if "low_exponent" in hints:
        recommended_tools.append("Z3")

    return {
        "parameters": parameters,
        "has_public_key": has_public_key,
        "has_private_key": has_private_key,
        "hints": hints,
        "recommended_tools": list(dict.fromkeys(recommended_tools)),
    }


def recover_rsa_flags_from_text(text: str) -> dict[str, object]:
    summary = rsa_summary_from_text(text)
    parameters = {
        name: _parse_int(value)
        for name, value in dict(summary["parameters"]).items()
    }
    if {"n", "e1", "e2", "c1", "c2"}.issubset(parameters):
        plaintext = _rsa_common_modulus_recover(
            parameters["n"],
            parameters["e1"],
            parameters["e2"],
            parameters["c1"],
            parameters["c2"],
        )
        preview = plaintext.decode("utf-8", errors="replace") if plaintext else ""
        return {
            "method": "common_modulus",
            "flags": list(extract_flags(preview)),
            "plaintext_preview": preview[:500],
            "parameters": {name: str(value) for name, value in parameters.items()},
        }

    if {"n1", "n2", "n3", "e", "c1", "c2", "c3"}.issubset(parameters):
        plaintext = _rsa_broadcast_recover(
            (parameters["n1"], parameters["n2"], parameters["n3"]),
            (parameters["c1"], parameters["c2"], parameters["c3"]),
            parameters["e"],
        )
        preview = plaintext.decode("utf-8", errors="replace") if plaintext else ""
        return {
            "method": "broadcast",
            "flags": list(extract_flags(preview)),
            "plaintext_preview": preview[:500],
            "parameters": {name: str(value) for name, value in parameters.items()},
        }

    if {"n1", "n2", "e", "c1"}.issubset(parameters):
        plaintext, factor = _rsa_shared_prime_recover(
            parameters["n1"],
            parameters["n2"],
            parameters["e"],
            parameters["c1"],
        )
        preview = plaintext.decode("utf-8", errors="replace") if plaintext else ""
        replay_parameters = {name: str(value) for name, value in parameters.items()}
        if factor:
            replay_parameters["p"] = str(factor)
        return {
            "method": "shared_prime",
            "flags": list(extract_flags(preview)),
            "plaintext_preview": preview[:500],
            "parameters": replay_parameters,
        }

    required = {"n", "e", "c"}
    if not required.issubset(parameters):
        return {"method": None, "flags": [], "plaintext_preview": ""}

    method = None
    plaintext = b""
    n = parameters["n"]
    e = parameters["e"]
    c = parameters["c"]
    if {"p", "q"}.issubset(parameters):
        method = "known_factors"
        plaintext = _rsa_decrypt_with_factors(n, e, c, parameters["p"], parameters["q"])
    elif e in {3, 5, 17}:
        method = "low_exponent_root"
        root = _integer_nth_root(c, e)
        if root is not None:
            plaintext = _int_to_bytes(root)
    if not plaintext and _is_probable_prime(n):
        method = "prime_modulus"
        plaintext = _rsa_decrypt_with_prime_modulus(n, e, c)
    if not plaintext:
        factors = _fermat_factor(n)
        if factors is not None:
            p, q = factors
            method = "fermat_factors"
            plaintext = _rsa_decrypt_with_factors(n, e, c, p, q)
            parameters["p"] = p
            parameters["q"] = q

    preview = plaintext.decode("utf-8", errors="replace") if plaintext else ""
    return {
        "method": method,
        "flags": list(extract_flags(preview)),
        "plaintext_preview": preview[:500],
        "parameters": {name: str(value) for name, value in parameters.items()},
    }


def recover_python_random_xor_flags_from_text(text: str) -> dict[str, object]:
    if "random.seed" not in text or "random.getrandbits" not in text or "^" not in text:
        return {"method": None, "flags": [], "seed": None, "key_bits": None, "plaintext_preview": ""}

    seed_bounds = _python_random_seed_bounds(text)
    key_bits = _python_random_key_bits(text)
    enc_values = _large_decimal_values(text)
    if not seed_bounds or not key_bits or not enc_values:
        return {"method": None, "flags": [], "seed": None, "key_bits": key_bits, "plaintext_preview": ""}

    start, stop = seed_bounds
    if stop < start or stop - start > 1_000_000:
        return {"method": "python_random_xor", "flags": [], "seed": None, "key_bits": key_bits, "plaintext_preview": ""}

    for enc in enc_values:
        for seed in range(start, stop + 1):
            random.seed(seed)
            key = random.getrandbits(key_bits)
            plaintext = _int_to_bytes(enc ^ key)
            preview = plaintext.decode("utf-8", errors="replace")
            flags = list(extract_flags(preview))
            if flags:
                return {
                    "method": "python_random_xor",
                    "flags": flags,
                    "seed": seed,
                    "key_bits": key_bits,
                    "enc": str(enc),
                    "plaintext_preview": preview[:500],
                }

    return {"method": "python_random_xor", "flags": [], "seed": None, "key_bits": key_bits, "plaintext_preview": ""}


def recover_single_byte_xor_flags_from_text(text: str) -> dict[str, object]:
    if "xor" not in text.lower():
        return {"method": "single_byte_xor", "flags": [], "key": None, "plaintext_preview": ""}
    best: dict[str, object] = {"method": "single_byte_xor", "flags": [], "key": None, "plaintext_preview": ""}
    for ciphertext in _hex_ciphertexts(text):
        data = bytes.fromhex(ciphertext)
        for key in range(256):
            plaintext = bytes(byte ^ key for byte in data)
            preview = plaintext.decode("utf-8", errors="ignore")
            flags = list(extract_flags(preview))
            if flags:
                return {
                    "method": "single_byte_xor",
                    "flags": flags,
                    "key": f"0x{key:02x}",
                    "ciphertext": ciphertext,
                    "plaintext_preview": preview[:500],
                }
            score = _englishish_score(preview)
            if score > int(best.get("score", 0)):
                best = {
                    "method": "single_byte_xor",
                    "flags": [],
                    "key": f"0x{key:02x}",
                    "ciphertext": ciphertext,
                    "plaintext_preview": preview[:500],
                    "score": score,
                }
    best.pop("score", None)
    return best


def recover_repeating_key_xor_flags_from_text(text: str) -> dict[str, object]:
    keys = _declared_keys(text)
    if not keys:
        return {"method": "repeating_key_xor", "flags": [], "key": None, "plaintext_preview": ""}
    for ciphertext in _hex_ciphertexts(text):
        data = bytes.fromhex(ciphertext)
        for key_text in keys:
            key = key_text.encode("utf-8")
            if not key:
                continue
            plaintext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))
            preview = plaintext.decode("utf-8", errors="ignore")
            flags = list(extract_flags(preview))
            if flags:
                return {
                    "method": "repeating_key_xor",
                    "flags": flags,
                    "key": key_text,
                    "ciphertext": ciphertext,
                    "plaintext_preview": preview[:500],
                }
    return {"method": "repeating_key_xor", "flags": [], "key": keys[0], "plaintext_preview": ""}


def recover_vigenere_flags_from_text(text: str) -> dict[str, object]:
    keys = _declared_keys(text)
    if not keys:
        return {"method": "vigenere", "flags": [], "key": None, "plaintext_preview": ""}
    ciphertexts = [match.group(1).strip() for match in VIGENERE_PATTERN.finditer(text)]
    for ciphertext in ciphertexts:
        for key in keys:
            plaintext = _vigenere_decrypt(ciphertext, key)
            flags = list(extract_flags(plaintext))
            if flags:
                return {
                    "method": "vigenere",
                    "flags": flags,
                    "key": key,
                    "ciphertext": ciphertext,
                    "plaintext_preview": plaintext[:500],
                }
    return {"method": "vigenere", "flags": [], "key": keys[0], "plaintext_preview": ""}


def _rsa_hints(parameters: dict[str, str], has_public_key: bool, has_private_key: bool) -> list[str]:
    hints: list[str] = []
    if {"n", "e", "c"}.issubset(parameters):
        hints.append("rsa_n_e_c")
    if {"n", "e1", "e2", "c1", "c2"}.issubset(parameters):
        hints.append("common_modulus")
    if {"n1", "n2", "e", "c1"}.issubset(parameters):
        hints.append("shared_prime")
    if {"n1", "n2", "n3", "e", "c1", "c2", "c3"}.issubset(parameters):
        hints.append("broadcast")
    if parameters.get("e") in {"3", "5", "17"}:
        hints.append("low_exponent")
    if "n" in parameters and _looks_prime_decimal(parameters["n"]):
        hints.append("prime_modulus")
    if "n" in parameters:
        hints.append("fermat_check")
    if {"p", "q"}.issubset(parameters):
        hints.append("known_factors")
    if has_public_key:
        hints.append("public_key")
    if has_private_key:
        hints.append("private_key")
    return hints


def _parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def _rsa_decrypt_with_factors(n: int, e: int, c: int, p: int, q: int) -> bytes:
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return b""
    d = pow(e, -1, phi)
    return _int_to_bytes(pow(c, d, n))


def _rsa_decrypt_with_prime_modulus(n: int, e: int, c: int) -> bytes:
    phi = n - 1
    if math.gcd(e, phi) != 1:
        return b""
    d = pow(e, -1, phi)
    return _int_to_bytes(pow(c, d, n))


def _fermat_factor(n: int, max_iterations: int = 100_000) -> tuple[int, int] | None:
    if n <= 0 or n % 2 == 0:
        return None
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iterations + 1):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p > 1 and q > 1 and p * q == n:
                return (p, q) if p <= q else (q, p)
        a += 1
    return None


def _rsa_common_modulus_recover(n: int, e1: int, e2: int, c1: int, c2: int) -> bytes:
    gcd, a, b = _extended_gcd(e1, e2)
    if gcd != 1:
        return b""
    m = (_pow_with_signed_exponent(c1, a, n) * _pow_with_signed_exponent(c2, b, n)) % n
    return _int_to_bytes(m)


def _rsa_shared_prime_recover(n1: int, n2: int, e: int, c1: int) -> tuple[bytes, int]:
    factor = math.gcd(n1, n2)
    if factor <= 1 or factor >= n1 or n1 % factor != 0:
        return b"", 0
    q1 = n1 // factor
    plaintext = _rsa_decrypt_with_factors(n1, e, c1, factor, q1)
    return plaintext, factor


def _rsa_broadcast_recover(moduli: tuple[int, int, int], ciphertexts: tuple[int, int, int], exponent: int) -> bytes:
    if exponent != len(moduli):
        return b""
    combined = _crt_combine(ciphertexts, moduli)
    root = _integer_nth_root(combined, exponent)
    if root is None:
        return b""
    return _int_to_bytes(root)


def _crt_combine(residues: tuple[int, ...], moduli: tuple[int, ...]) -> int:
    modulus_product = math.prod(moduli)
    total = 0
    for residue, modulus in zip(residues, moduli, strict=True):
        partial = modulus_product // modulus
        total += residue * partial * pow(partial, -1, modulus)
    return total % modulus_product


def _looks_prime_decimal(value: str) -> bool:
    try:
        return _is_probable_prime(_parse_int(value))
    except ValueError:
        return False


def _is_probable_prime(value: int) -> bool:
    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small_primes:
        return True
    if any(value % prime == 0 for prime in small_primes):
        return False
    d = value - 1
    shifts = 0
    while d % 2 == 0:
        shifts += 1
        d //= 2
    for base in (2, 3, 5, 7, 11, 13, 17):
        if base >= value:
            continue
        candidate = pow(base, d, value)
        if candidate in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            candidate = pow(candidate, 2, value)
            if candidate == value - 1:
                break
        else:
            return False
    return True


def _pow_with_signed_exponent(base: int, exponent: int, modulus: int) -> int:
    if exponent >= 0:
        return pow(base, exponent, modulus)
    if math.gcd(base, modulus) != 1:
        return 0
    return pow(pow(base, -1, modulus), -exponent, modulus)


def _extended_gcd(left: int, right: int) -> tuple[int, int, int]:
    old_r, r = left, right
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def _integer_nth_root(value: int, degree: int) -> int | None:
    low = 0
    high = 1 << ((value.bit_length() + degree - 1) // degree)
    while low <= high:
        mid = (low + high) // 2
        powered = mid**degree
        if powered == value:
            return mid
        if powered < value:
            low = mid + 1
        else:
            high = mid - 1
    return None


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big").lstrip(b"\x00")


def _python_random_seed_bounds(text: str) -> tuple[int, int] | None:
    match = PY_RANDOM_RANDINT_PATTERN.search(text)
    if not match:
        return None
    start = _safe_int_expr(match.group(1))
    stop = _safe_int_expr(match.group(2))
    if start is None or stop is None:
        return None
    return start, stop


def _python_random_key_bits(text: str) -> int | None:
    match = PY_RANDOM_BITS_PATTERN.search(text)
    if not match:
        return None
    bits = int(match.group(1))
    if bits <= 0 or bits > 16384:
        return None
    return bits


def _large_decimal_values(text: str) -> list[int]:
    values: list[int] = []
    for match in LARGE_DECIMAL_PATTERN.finditer(text):
        value = int(match.group(0))
        if value not in values:
            values.append(value)
    return values[:20]


def _hex_ciphertexts(text: str) -> list[str]:
    values: list[str] = []
    for match in HEX_CIPHERTEXT_PATTERN.finditer(text):
        value = match.group(1).strip().lower()
        if len(value) % 2 == 0 and value not in values:
            values.append(value)
    return values[:20]


def _declared_keys(text: str) -> list[str]:
    keys: list[str] = []
    for match in KEY_PATTERN.finditer(text):
        key = match.group(1).strip()
        if key and key.lower() not in {"none", "unknown"} and key not in keys:
            keys.append(key)
    return keys[:10]


def _vigenere_decrypt(ciphertext: str, key: str) -> str:
    if not key:
        return ciphertext
    key_offsets = [ord(char.lower()) - ord("a") for char in key if char.isalpha()]
    if not key_offsets:
        return ciphertext
    plaintext: list[str] = []
    key_index = 0
    for char in ciphertext:
        if "a" <= char <= "z":
            shift = key_offsets[key_index % len(key_offsets)]
            plaintext.append(chr((ord(char) - ord("a") - shift) % 26 + ord("a")))
            key_index += 1
        elif "A" <= char <= "Z":
            shift = key_offsets[key_index % len(key_offsets)]
            plaintext.append(chr((ord(char) - ord("A") - shift) % 26 + ord("A")))
            key_index += 1
        else:
            plaintext.append(char)
    return "".join(plaintext)


def _englishish_score(text: str) -> int:
    if not text:
        return 0
    common = " etaoinshrdluflag{}_-"
    printable = sum(1 for char in text if char.isprintable() or char.isspace())
    common_chars = sum(1 for char in text.lower() if char in common)
    return printable + common_chars


def _safe_int_expr(value: str) -> int | None:
    cleaned = value.replace(" ", "")
    if not re.fullmatch(r"\d+(?:\*\*\d+)?", cleaned):
        return None
    if "**" in cleaned:
        base_text, exponent_text = cleaned.split("**", 1)
        base = int(base_text)
        exponent = int(exponent_text)
        if base > 10 or exponent > 30:
            return None
        return base**exponent
    return int(cleaned)
