from __future__ import annotations

import ast
import hashlib
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
    modular_root_hint = _rsa_modular_low_exponent_root_hint(text)
    if "e" not in parameters and modular_root_hint is not None:
        parameters["e"] = modular_root_hint[0]
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
    elif modular_root_hint is not None:
        method = "modular_low_exponent_root"
        root, multiplier, limit = _rsa_modular_low_exponent_root(n, c, e, modular_root_hint[1])
        if root is not None:
            plaintext = _int_to_bytes(root)
            parameters["root_multiplier"] = multiplier
            parameters["root_search_limit"] = limit
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


def recover_lfsr_bm_flags_from_text(text: str) -> dict[str, object]:
    normalized = re.sub(r"\s+", "", text)
    if "classlfsr" not in normalized or "sha256(hex(KEY)[2:].rstrip('L'))" not in normalized:
        return {"method": None, "flags": [], "plaintext_preview": ""}
    if "self.init&self.mask" not in normalized or "output^=(i&1)" not in normalized:
        return {"method": None, "flags": [], "plaintext_preview": ""}

    length_match = re.search(r"(?m)^\s*LENGTH\s*=\s*(\d{1,5})\s*$", text)
    length = int(length_match.group(1)) if length_match else 256
    if length <= 0 or length > 512:
        return {"method": "lfsr_berlekamp_massey", "flags": [], "plaintext_preview": ""}

    prefix_match = re.search(r"FLAG\[\s*\d+\s*:\s*\d+\s*\]\s*==\s*['\"]([0-9a-fA-F]{1,16})['\"]", text)
    digest_prefix = prefix_match.group(1).lower() if prefix_match else ""
    for sequence_text in _binary_comment_sequences(text):
        sequence = [1 if char == "1" else 0 for char in sequence_text]
        if len(sequence) < length + 1:
            continue
        recovered = _recover_lfsr_bm_key(sequence, length, digest_prefix)
        if recovered is None:
            continue
        key, mask, free_variables = recovered
        digest = hashlib.sha256(hex(key)[2:].rstrip("L").encode()).hexdigest()
        flag = f"de1ctf{{{digest}}}"
        return {
            "method": "lfsr_berlekamp_massey",
            "flags": [flag],
            "plaintext_preview": flag,
            "key": str(key),
            "mask": str(mask),
            "linear_complexity": length,
            "free_variables": free_variables,
            "sequence_bits": len(sequence),
            "key_sha256_prefix": digest_prefix,
        }

    return {
        "method": "lfsr_berlekamp_massey",
        "flags": [],
        "plaintext_preview": "",
        "key_sha256_prefix": digest_prefix,
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


def recover_python_random_prime_offset_flags_from_text(text: str) -> dict[str, object]:
    if "random.seed(bytes_to_long(seed))" not in re.sub(r"\s+", "", text):
        return {"method": None, "flags": [], "seed_text": None, "plaintext_preview": ""}
    if "next_prime(random.randint" not in re.sub(r"\s+", "", text) or "bytes_to_long(flag)+t-r" not in re.sub(r"\s+", "", text):
        return {"method": None, "flags": [], "seed_text": None, "plaintext_preview": ""}

    key = _assigned_bytes_literal(text, "key")
    gift = _printed_gift_bytes(text)
    randint_bounds = _python_random_randint_bounds(text)
    enc_values = _large_decimal_values(text)
    if key is None or gift is None or len(key) != len(gift) or len(randint_bounds) < 2 or not enc_values:
        return {"method": "python_random_prime_offset", "flags": [], "seed_text": None, "plaintext_preview": ""}

    seed = bytes(left ^ right for left, right in zip(key, gift))
    seed_int = int.from_bytes(seed, "big")
    first_start, first_stop = randint_bounds[0]
    second_start, second_stop = randint_bounds[1]
    if first_stop < first_start or second_stop < second_start:
        return {"method": "python_random_prime_offset", "flags": [], "seed_text": _safe_decode(seed), "plaintext_preview": ""}

    rng = random.Random(seed_int)
    t = _next_prime(rng.randint(first_start, first_stop))
    r = _next_prime(rng.randint(second_start, second_stop))
    for enc in enc_values:
        plaintext = _int_to_bytes(enc - t + r)
        preview = plaintext.decode("utf-8", errors="replace")
        flags = list(extract_flags(preview))
        if flags:
            return {
                "method": "python_random_prime_offset",
                "flags": flags,
                "seed_text": _safe_decode(seed),
                "seed_hex": seed.hex(),
                "seed_int": str(seed_int),
                "key": _safe_decode(key),
                "gift_hex": gift.hex(),
                "t": t,
                "r": r,
                "enc": str(enc),
                "plaintext_preview": preview[:500],
                "randint_bounds": [
                    [first_start, first_stop],
                    [second_start, second_stop],
                ],
            }

    return {
        "method": "python_random_prime_offset",
        "flags": [],
        "seed_text": _safe_decode(seed),
        "seed_hex": seed.hex(),
        "t": t,
        "r": r,
        "plaintext_preview": "",
    }


def recover_prng_stream_flags_from_text(text: str) -> dict[str, object]:
    for recovery in (
        _recover_lcg_flags_from_text,
        _recover_simple_lfsr_flags_from_text,
        _recover_mt19937_624_clone_flags_from_text,
    ):
        result = recovery(text)
        if result["flags"]:
            return result
    return {"method": None, "flags": [], "plaintext_preview": ""}


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


def _rsa_modular_low_exponent_root_hint(text: str) -> tuple[int, int] | None:
    expression_pattern = re.compile(
        r"iroot\(\s*c\s*\+\s*n\s*\*\s*i\s*,\s*(\d{1,3})\s*\)|"
        r"iroot\(\s*c\s*\+\s*i\s*\*\s*n\s*,\s*(\d{1,3})\s*\)"
    )
    expression = expression_pattern.search(text)
    if not expression:
        return None
    exponent = int(next(group for group in expression.groups() if group))
    if exponent < 2 or exponent > 32:
        return None
    limit_match = re.search(r"range\(\s*(\d{1,7})\s*\)", text)
    limit = int(limit_match.group(1)) if limit_match else 100_000
    return exponent, min(limit, 1_000_000)


def _rsa_modular_low_exponent_root(n: int, c: int, e: int, search_limit: int) -> tuple[int | None, int, int]:
    if n <= 0 or e < 2 or search_limit <= 0:
        return None, 0, search_limit
    for multiplier in range(search_limit):
        candidate = c + n * multiplier
        if candidate < 0:
            continue
        root = _integer_nth_root(candidate, e)
        if root is not None:
            return root, multiplier, search_limit
    return None, 0, search_limit


def _binary_comment_sequences(text: str) -> list[str]:
    sequences: list[str] = []
    for match in re.finditer(r"(?m)#\s*\w+\s*=\s*['\"]([01]{64,})['\"]", text):
        value = match.group(1)
        if value not in sequences:
            sequences.append(value)
    for match in re.finditer(r"['\"]([01]{128,})['\"]", text):
        value = match.group(1)
        if value not in sequences:
            sequences.append(value)
    return sequences[:8]


def _recover_lfsr_bm_key(sequence: list[int], length: int, digest_prefix: str) -> tuple[int, int, int] | None:
    rows: list[int] = []
    rhs: list[int] = []
    for index in range(length, len(sequence)):
        row = 0
        for bit_index in range(length):
            if sequence[index - 1 - bit_index]:
                row ^= 1 << bit_index
        rows.append(row)
        rhs.append(sequence[index])
    rows.append(1 << (length - 1))
    rhs.append(1)

    solved = _gf2_affine_solution_space(rows, rhs, length)
    if solved is None:
        return None
    base, basis, free_variables = solved
    if len(basis) > 16:
        return None
    for selector in range(1 << len(basis)):
        mask = base
        for index, vector in enumerate(basis):
            if (selector >> index) & 1:
                mask ^= vector
        if mask.bit_length() != length:
            continue
        key = _lfsr_recover_initial_state(sequence, mask, length)
        if key.bit_length() != length:
            continue
        if _lfsr_generate_bits(key, mask, length, len(sequence)) != sequence:
            continue
        digest = hashlib.sha256(hex(key)[2:].rstrip("L").encode()).hexdigest()
        if digest_prefix and not digest.startswith(digest_prefix):
            continue
        return key, mask, free_variables
    return None


def _gf2_affine_solution_space(rows: list[int], rhs: list[int], variables: int) -> tuple[int, list[int], int] | None:
    rows = list(rows)
    rhs = list(rhs)
    pivot_columns: list[int] = []
    row_index = 0
    for column in range(variables):
        pivot = None
        for candidate in range(row_index, len(rows)):
            if (rows[candidate] >> column) & 1:
                pivot = candidate
                break
        if pivot is None:
            continue
        rows[row_index], rows[pivot] = rows[pivot], rows[row_index]
        rhs[row_index], rhs[pivot] = rhs[pivot], rhs[row_index]
        for candidate in range(len(rows)):
            if candidate != row_index and ((rows[candidate] >> column) & 1):
                rows[candidate] ^= rows[row_index]
                rhs[candidate] ^= rhs[row_index]
        pivot_columns.append(column)
        row_index += 1

    for row, value in zip(rows, rhs, strict=True):
        if row == 0 and value:
            return None

    pivot_set = set(pivot_columns)
    free_columns = [column for column in range(variables) if column not in pivot_set]
    base = 0
    for index, column in enumerate(pivot_columns):
        if rhs[index]:
            base |= 1 << column

    basis: list[int] = []
    for free_column in free_columns:
        vector = 1 << free_column
        for index, column in enumerate(pivot_columns):
            if (rows[index] >> free_column) & 1:
                vector |= 1 << column
        basis.append(vector)
    return base, basis, len(free_columns)


def _lfsr_recover_initial_state(sequence: list[int], mask: int, length: int) -> int:
    mask_bits = [(mask >> bit_index) & 1 for bit_index in range(length)]
    key_bits = [0] * length
    for output_index in range(length - 1, -1, -1):
        accumulator = 0
        for bit_index in range(output_index):
            accumulator ^= mask_bits[bit_index] & sequence[output_index - 1 - bit_index]
        for bit_index in range(output_index, length - 1):
            accumulator ^= mask_bits[bit_index] & key_bits[bit_index - output_index]
        key_bits[length - 1 - output_index] = sequence[output_index] ^ accumulator
    return sum(bit << index for index, bit in enumerate(key_bits))


def _lfsr_generate_bits(key: int, mask: int, length: int, count: int) -> list[int]:
    state = key
    length_mask = 2 ** (length + 1) - 1
    output_bits: list[int] = []
    for _ in range(count):
        next_state = (state << 1) & length_mask
        value = state & mask & length_mask
        output = 0
        while value:
            output ^= value & 1
            value >>= 1
        state = next_state ^ output
        output_bits.append(output)
    return output_bits


def _recover_lcg_flags_from_text(text: str) -> dict[str, object]:
    normalized = re.sub(r"\s+", "", text).lower()
    if "seed=(a*seed+b)%n" not in normalized:
        return {"method": None, "flags": [], "plaintext_preview": ""}

    parameters = _named_decimal_assignments(text)
    decimals = _large_decimal_values(text)
    try:
        if {"a", "b", "n", "c", "seed"}.issubset(parameters) and "^plaintext" in normalized:
            state = parameters["seed"]
            for _ in range(10):
                state = (parameters["a"] * state + parameters["b"]) % parameters["n"]
            return _flag_result_from_int(
                state ^ parameters["c"],
                "lcg_known_parameters_xor",
                {"rounds": 10, "n": str(parameters["n"])},
            )

        if {"a", "b", "n", "c"}.issubset(parameters) and "seed=plaintext" in normalized:
            state = parameters["c"]
            inverse = pow(parameters["a"], -1, parameters["n"])
            for _ in range(10):
                state = (state - parameters["b"]) * inverse % parameters["n"]
            return _flag_result_from_int(
                state,
                "lcg_known_parameters_inverse",
                {"rounds": 10, "n": str(parameters["n"])},
            )

        if {"a", "n", "output1", "output2"}.issubset(parameters) and "b=plaintext" in normalized:
            plaintext = (parameters["output2"] - parameters["a"] * parameters["output1"]) % parameters["n"]
            return _flag_result_from_int(
                plaintext,
                "lcg_increment_from_two_outputs",
                {"n": str(parameters["n"])},
            )

        if "n" in parameters and len(decimals) >= 3 and "print(seed)" in normalized:
            modulus = parameters["n"]
            outputs = [value for value in decimals if value != modulus and value.bit_length() > 128][:3]
            if len(outputs) >= 3:
                result = _recover_lcg_from_consecutive_outputs(outputs, modulus, first_output_round=11)
                if result["flags"]:
                    return result

        if len(decimals) >= 6:
            modulus = _recover_lcg_modulus(decimals[:6])
            if modulus and modulus.bit_length() > 64:
                result = _recover_lcg_from_consecutive_outputs(decimals[:6], modulus, first_output_round=1)
                if result["flags"]:
                    return result
    except (ValueError, ZeroDivisionError):
        return {"method": "lcg_consecutive_outputs", "flags": [], "plaintext_preview": ""}

    return {"method": "lcg", "flags": [], "plaintext_preview": ""}


def _recover_lcg_from_consecutive_outputs(outputs: list[int], modulus: int, first_output_round: int) -> dict[str, object]:
    if len(outputs) < 3 or modulus <= 0:
        return {"method": "lcg_consecutive_outputs", "flags": [], "plaintext_preview": ""}
    multiplier = (outputs[2] - outputs[1]) * pow((outputs[1] - outputs[0]) % modulus, -1, modulus) % modulus
    increment = (outputs[1] - multiplier * outputs[0]) % modulus
    inverse = pow(multiplier, -1, modulus)
    state = outputs[0]
    for _ in range(first_output_round):
        state = (state - increment) * inverse % modulus
    lifted = _lift_flag_residue(state, modulus)
    if lifted is None:
        return _flag_result_from_int(
            state,
            "lcg_consecutive_outputs",
            {"n": str(modulus), "a": str(multiplier), "b": str(increment), "lift_multiplier": 0},
        )
    plaintext, lift_multiplier = lifted
    return _flag_result_from_int(
        plaintext,
        "lcg_consecutive_outputs",
        {"n": str(modulus), "a": str(multiplier), "b": str(increment), "lift_multiplier": lift_multiplier},
    )


def _recover_simple_lfsr_flags_from_text(text: str) -> dict[str, object]:
    normalized = re.sub(r"\s+", "", text).lower()
    if "classlfsr" not in normalized or "self.state=[feedback]+self.state[:-1]" not in normalized:
        return {"method": None, "flags": [], "plaintext_preview": ""}
    taps_match = re.search(r"taps\s*=\s*\[([0-9,\s]+)\]", text)
    if not taps_match:
        return {"method": "lfsr_known_taps", "flags": [], "plaintext_preview": ""}
    taps = [int(value) for value in re.findall(r"\d+", taps_match.group(1))]
    values = _large_decimal_values(text)
    if len(values) < 2:
        return {"method": "lfsr_known_taps", "flags": [], "plaintext_preview": ""}

    if "assertkey1==key2" in normalized:
        key, enc = values[-2], values[-1]
        return _flag_result_from_int(enc ^ key, "lfsr_repeated_keystream_xor", {"key": str(key), "enc": str(enc)})

    if "seed>>8" in normalized:
        seed_high, enc = values[-2], values[-1]
        for low_bits in range(256):
            seed = (seed_high << 8) + low_bits
            key = _simple_lfsr_keystream_int(seed, taps, enc.bit_length())
            plaintext = enc ^ key
            preview = _int_to_bytes(plaintext).decode("utf-8", errors="replace")
            flags = list(extract_flags(preview))
            if flags:
                return {
                    "method": "lfsr_seed_high_bits",
                    "flags": flags,
                    "seed": str(seed),
                    "seed_low_bits": low_bits,
                    "enc": str(enc),
                    "plaintext_preview": preview[:500],
                }
        return {"method": "lfsr_seed_high_bits", "flags": [], "plaintext_preview": ""}

    seed, enc = values[-2], values[-1]
    key = _simple_lfsr_keystream_int(seed, taps, enc.bit_length())
    return _flag_result_from_int(enc ^ key, "lfsr_known_seed", {"seed": str(seed), "enc": str(enc)})


def _recover_mt19937_624_clone_flags_from_text(text: str) -> dict[str, object]:
    if "getrandbits(32)" not in text and "numbers" not in text and "numbers =" not in text:
        return {"method": None, "flags": [], "plaintext_preview": ""}
    numbers = _first_int_list_with_length(text, minimum=624)
    ciphertext = _last_bytes_literal(text)
    if numbers is None or len(numbers) < 624 or ciphertext is None:
        return {"method": "mt19937_624_clone", "flags": [], "plaintext_preview": ""}
    clone = _MT19937Clone(numbers[:624])
    next_value = clone.getrandbits32()
    key = hashlib.md5(str(next_value).encode()).hexdigest().encode()
    plaintext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(ciphertext))
    preview = plaintext.decode("utf-8", errors="replace")
    return {
        "method": "mt19937_624_clone",
        "flags": list(extract_flags(preview)),
        "next_value": next_value,
        "plaintext_preview": preview[:500],
    }


def _flag_result_from_int(value: int, method: str, evidence: dict[str, object]) -> dict[str, object]:
    plaintext = _int_to_bytes(value)
    preview = plaintext.decode("utf-8", errors="replace")
    result: dict[str, object] = {
        "method": method,
        "flags": list(extract_flags(preview)),
        "plaintext_preview": preview[:500],
    }
    result.update(evidence)
    return result


def _named_decimal_assignments(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for name, value in re.findall(r"(?m)^\s*#?\s*(a|b|n|c|seed|output1|output2)\s*=\s*(\d{2,})\s*$", text):
        values[name] = int(value)
    return values


def _recover_lcg_modulus(outputs: list[int]) -> int:
    if len(outputs) < 4:
        return 0
    differences = [outputs[index + 1] - outputs[index] for index in range(len(outputs) - 1)]
    modulus = 0
    for index in range(len(differences) - 2):
        value = abs(differences[index + 2] * differences[index] - differences[index + 1] ** 2)
        modulus = math.gcd(modulus, value)
    return modulus


def _lift_flag_residue(residue: int, modulus: int, max_multiplier: int = 32) -> tuple[int, int] | None:
    for multiplier in range(max_multiplier + 1):
        candidate = residue + multiplier * modulus
        preview = _int_to_bytes(candidate).decode("utf-8", errors="ignore")
        if extract_flags(preview):
            return candidate, multiplier
    return None


def _simple_lfsr_keystream_int(seed: int, taps: list[int], steps: int) -> int:
    state = [int(bit) for bit in f"{seed:b}"]
    output_bits: list[str] = []
    for _ in range(steps):
        feedback = 0
        for tap in taps:
            if tap >= len(state):
                return 0
            feedback ^= state[tap]
        output_bits.append(str(state[-1]))
        state = [feedback] + state[:-1]
    return int("".join(output_bits), 2) if output_bits else 0


def _first_int_list_with_length(text: str, minimum: int) -> list[int] | None:
    for match in re.finditer(r"\[[0-9,\s]{1000,}\]", text):
        try:
            value = ast.literal_eval(match.group(0))
        except (SyntaxError, ValueError):
            continue
        if isinstance(value, list) and len(value) >= minimum and all(isinstance(item, int) for item in value):
            return value
    return None


def _last_bytes_literal(text: str) -> bytes | None:
    selected: bytes | None = None
    for match in re.finditer(r"b(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')", text):
        value = _bytes_literal(match.group(0))
        if value and not _looks_like_placeholder_bytes(value):
            selected = value
    return selected


class _MT19937Clone:
    def __init__(self, outputs: list[int]) -> None:
        self.state = [_mt19937_untemper(value) for value in outputs[:624]]
        self.index = 624

    def getrandbits32(self) -> int:
        if self.index >= 624:
            self._twist()
        value = self.state[self.index]
        value ^= value >> 11
        value ^= (value << 7) & 0x9D2C5680
        value ^= (value << 15) & 0xEFC60000
        value ^= value >> 18
        self.index += 1
        return value & 0xFFFFFFFF

    def _twist(self) -> None:
        for index in range(624):
            value = (self.state[index] & 0x80000000) + (self.state[(index + 1) % 624] & 0x7FFFFFFF)
            self.state[index] = self.state[(index + 397) % 624] ^ (value >> 1)
            if value & 1:
                self.state[index] ^= 0x9908B0DF
            self.state[index] &= 0xFFFFFFFF
        self.index = 0


def _mt19937_untemper(value: int) -> int:
    result = value
    for _ in range(5):
        result = value ^ (result >> 18)
    value = result
    for _ in range(5):
        result = value ^ ((result << 15) & 0xEFC60000)
    value = result
    for _ in range(5):
        result = value ^ ((result << 7) & 0x9D2C5680)
    value = result
    for _ in range(5):
        result = value ^ (result >> 11)
    return result & 0xFFFFFFFF


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


def _python_random_randint_bounds(text: str) -> list[tuple[int, int]]:
    bounds: list[tuple[int, int]] = []
    for match in PY_RANDOM_RANDINT_PATTERN.finditer(text):
        start = _safe_int_expr(match.group(1))
        stop = _safe_int_expr(match.group(2))
        if start is None or stop is None:
            continue
        bounds.append((start, stop))
    return bounds[:8]


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


def _assigned_bytes_literal(text: str, name: str) -> bytes | None:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*(b(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'))", text)
    if not match:
        return None
    return _bytes_literal(match.group(1))


def _printed_gift_bytes(text: str) -> bytes | None:
    match = re.search(r"(?m)^\s*#\s*(b(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'))", text)
    while match:
        value = _bytes_literal(match.group(1))
        if value and not _looks_like_placeholder_bytes(value):
            return value
        match = re.search(r"(?m)^\s*#\s*(b(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'))", text[match.end() :])
    return None


def _bytes_literal(value: str) -> bytes | None:
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return None
    return parsed if isinstance(parsed, bytes) else None


def _looks_like_placeholder_bytes(value: bytes) -> bool:
    return set(value) <= {ord("x"), ord("*")} or not value


def _next_prime(value: int) -> int:
    if value <= 2:
        return 2
    candidate = value if value % 2 else value + 1
    while not _is_probable_prime(candidate):
        candidate += 2
    return candidate


def _safe_decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")
