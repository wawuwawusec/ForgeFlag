from __future__ import annotations

import math
import re

from forgeflag.flags import extract_flags


RSA_PARAM_PATTERN = re.compile(r"(?im)^\s*(n|e|c|p|q|d|phi)\s*[:=]\s*(0x[0-9a-f]+|\d+)\s*$")
PUBLIC_KEY_MARKERS = ("-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----")
PRIVATE_KEY_MARKERS = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")


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
    if {"n", "e", "c"}.issubset(parameters):
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

    preview = plaintext.decode("utf-8", errors="replace") if plaintext else ""
    return {
        "method": method,
        "flags": list(extract_flags(preview)),
        "plaintext_preview": preview[:500],
    }


def _rsa_hints(parameters: dict[str, str], has_public_key: bool, has_private_key: bool) -> list[str]:
    hints: list[str] = []
    if {"n", "e", "c"}.issubset(parameters):
        hints.append("rsa_n_e_c")
    if parameters.get("e") in {"3", "5", "17"}:
        hints.append("low_exponent")
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
