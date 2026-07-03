from __future__ import annotations

import unittest

from forgeflag.crypto_analysis import (
    recover_lfsr_bm_flags_from_text,
    recover_python_random_prime_offset_flags_from_text,
    recover_python_random_xor_flags_from_text,
    recover_prng_stream_flags_from_text,
    recover_repeating_key_xor_flags_from_text,
    recover_rsa_flags_from_text,
    recover_single_byte_xor_flags_from_text,
    recover_vigenere_flags_from_text,
    rsa_summary_from_text,
)


class CryptoAnalysisTest(unittest.TestCase):
    def test_rsa_summary_extracts_common_parameters_and_hints(self) -> None:
        summary = rsa_summary_from_text("n = 3233\ne = 3\nc = 2790\n")

        self.assertEqual(summary["parameters"]["n"], "3233")
        self.assertEqual(summary["parameters"]["e"], "3")
        self.assertEqual(summary["parameters"]["c"], "2790")
        self.assertIn("low_exponent", summary["hints"])
        self.assertIn("RsaCtfTool", summary["recommended_tools"])

    def test_rsa_summary_detects_pem_public_key(self) -> None:
        summary = rsa_summary_from_text("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----")

        self.assertTrue(summary["has_public_key"])
        self.assertIn("RsaCtfTool", summary["recommended_tools"])

    def test_recover_rsa_flags_from_known_factors(self) -> None:
        message = int.from_bytes(b"flag{rsa_known_factors}", "big")
        p = 2**127 - 1
        q = 2**89 - 1
        n = p * q
        e = 65537
        c = pow(message, e, n)

        result = recover_rsa_flags_from_text(f"n = {n}\ne = {e}\nc = {c}\np = {p}\nq = {q}\n")

        self.assertEqual(result["flags"], ["flag{rsa_known_factors}"])
        self.assertEqual(result["method"], "known_factors")
        self.assertEqual(result["parameters"]["n"], str(n))
        self.assertEqual(result["parameters"]["e"], str(e))
        self.assertEqual(result["parameters"]["c"], str(c))
        self.assertEqual(result["parameters"]["p"], str(p))
        self.assertEqual(result["parameters"]["q"], str(q))

    def test_recover_rsa_flags_from_low_exponent_plaintext_root(self) -> None:
        message = int.from_bytes(b"flag{rsa_low_exponent}", "big")
        e = 3
        n = 2**521 - 1
        c = message**e

        result = recover_rsa_flags_from_text(f"n = {n}\ne = {e}\nc = {c}\n")

        self.assertEqual(result["flags"], ["flag{rsa_low_exponent}"])
        self.assertEqual(result["method"], "low_exponent_root")
        self.assertEqual(result["parameters"]["n"], str(n))
        self.assertEqual(result["parameters"]["e"], str(e))
        self.assertEqual(result["parameters"]["c"], str(c))

    def test_recover_rsa_flags_from_source_loop_modular_low_exponent_root(self) -> None:
        message = int.from_bytes(b"flag{rsa_modular_low_exp}", "big")
        e = 7
        n = 2**521 - 1
        k = 11
        c = message**e - n * k
        script = f"""
from gmpy2 import iroot
n={n}
c={c}
for i in range(10000):
    if iroot(c+n*i,7)[1] == True:
        print(i)
        print(long_to_bytes(iroot(c+n*i,7)[0]))
"""

        result = recover_rsa_flags_from_text(script)

        self.assertEqual(result["flags"], ["flag{rsa_modular_low_exp}"])
        self.assertEqual(result["method"], "modular_low_exponent_root")
        self.assertEqual(result["parameters"]["e"], str(e))
        self.assertEqual(result["parameters"]["root_multiplier"], str(k))
        self.assertEqual(result["parameters"]["root_search_limit"], "10000")

    def test_recover_lfsr_bm_flag_from_de1ctf_source(self) -> None:
        script = r"""
import hashlib
from secret import KEY,FLAG,MASK
assert(FLAG=="de1ctf{"+hashlib.sha256(hex(KEY)[2:].rstrip('L')).hexdigest()+"}")
assert(FLAG[7:11]=='1224')
LENGTH = 256
assert(KEY.bit_length()==LENGTH)
assert(MASK.bit_length()==LENGTH)
class lfsr():
    def next(self):
        nextdata = (self.init << 1) & self.lengthmask
        i = self.init & self.mask & self.lengthmask
        output = 0
        while i != 0:
            output ^= (i & 1)
            i = i >> 1
        nextdata ^= output
        self.init = nextdata
        return output
# key = '001010010111101000001101101111010000001111011001101111011000100001100011111000010001100101110110011000001100111010111110000000111011000110111110001110111000010100110010011111100011010111101101101001110000010111011110010110010011101101010010100101011111011001111010000000001011000011000100000101111010001100000011010011010111001010010101101000110011001110111010000011010101111011110100011110011010000001100100101000010110100100100011001000101010001100000010000100111001110110101000000101011100000001100010'
"""

        result = recover_lfsr_bm_flags_from_text(script)

        self.assertEqual(
            result["flags"],
            ["de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}"],
        )
        self.assertEqual(result["method"], "lfsr_berlekamp_massey")
        self.assertEqual(result["linear_complexity"], 256)
        self.assertEqual(result["free_variables"], 7)
        self.assertEqual(result["key_sha256_prefix"], "1224")

    def test_recover_lcg_flag_with_residue_lifting(self) -> None:
        script = """
from Crypto.Util.number import *
flag = b'flag{1111122222333344440000}'
seed = bytes_to_long(flag)
a = getPrime(length)
b = getPrime(length)
n = getPrime(length)
assert seed < n
for i in range(10):
    seed = (a*seed+b)%n
for i in range(3):
    seed = (a * seed + b) % n
    print(seed)
'''
1931431799049777676669577354064129950051581433022223703848456038114
1747549989944521471205309829691725031663707005936040583622213014238
1805530798038026397584823848781741965222297750650259934550864515641
n =  7538579824168138312234334836011836666836054247296632942094455781627
'''
"""

        result = recover_prng_stream_flags_from_text(script)

        self.assertEqual(result["flags"], ["flag{1111122222333344440000}"])
        self.assertEqual(result["method"], "lcg_consecutive_outputs")
        self.assertEqual(result["lift_multiplier"], 1)

    def test_recover_lfsr_flag_from_leaked_seed_high_bits(self) -> None:
        script = """
flag = b'xxx'
class LFSR:
    def __init__(self, seed, taps):
        self.state = seed
        self.taps = taps
    def step(self):
        feedback = 0
        for tap in self.taps:
            feedback ^= self.state[tap]
        output = self.state[-1]
        self.state = [feedback] + self.state[:-1]
        return output
taps = [0,2,7,9]
print(seed>>8)
print(enc)
'''
440358935580716225897652527798714954
128630106471527198983348796142845381608
'''
"""

        result = recover_prng_stream_flags_from_text(script)

        self.assertEqual(result["flags"], ["flag{easy_lfsr2}"])
        self.assertEqual(result["method"], "lfsr_seed_high_bits")
        self.assertEqual(result["seed_low_bits"], 176)

    def test_recover_lcg_flag_and_modulus_from_six_outputs(self) -> None:
        script = """
for i in range(6):
    seed = (a*seed+b)%n
    print(seed)
'''
4635999258132653079461892773553210543207941749635079204865158951
2783184169268667111333925413098102662330190636193653362762891596
24339632049772515398253787739258552922789383066237320110250050386
27564356346354076192833659490414228931762093252326470944597617182
20376660764525038406901369475010187010730483488095540460596713947
21991137834682652251817374004044769098798886231365284644481445604
'''
"""

        result = recover_prng_stream_flags_from_text(script)

        self.assertEqual(result["flags"], ["flag{just_a_simple_problem}"])
        self.assertEqual(result["method"], "lcg_consecutive_outputs")
        self.assertEqual(result["n"], "43302892913731123561110592263537580528838671299456522545099511041")

    def test_recover_mt19937_flag_from_624_outputs(self) -> None:
        # Small synthetic clone case: the 624 observed values are enough to predict the
        # next 32-bit value used as an MD5-derived XOR key.
        import random
        from hashlib import md5

        rng = random.Random(1337)
        numbers = [rng.getrandbits(32) for _ in range(624)]
        key = md5(str(rng.getrandbits(32)).encode()).hexdigest().encode()
        flag = b"flag{mt_clone_test}"
        cipher = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(flag))
        script = f"numbers = {numbers!r}\n# {cipher!r}\n"

        result = recover_prng_stream_flags_from_text(script)

        self.assertEqual(result["flags"], ["flag{mt_clone_test}"])
        self.assertEqual(result["method"], "mt19937_624_clone")

    def test_recover_rsa_flags_from_common_modulus_pair(self) -> None:
        message = int.from_bytes(b"flag{rsa_common_modulus}", "big")
        n = 2**521 - 1
        e1 = 17
        e2 = 65537
        c1 = pow(message, e1, n)
        c2 = pow(message, e2, n)

        result = recover_rsa_flags_from_text(f"n = {n}\ne1 = {e1}\ne2 = {e2}\nc1 = {c1}\nc2 = {c2}\n")

        self.assertEqual(result["flags"], ["flag{rsa_common_modulus}"])
        self.assertEqual(result["method"], "common_modulus")
        self.assertEqual(result["parameters"]["e1"], str(e1))
        self.assertEqual(result["parameters"]["e2"], str(e2))
        self.assertEqual(result["parameters"]["c1"], str(c1))
        self.assertEqual(result["parameters"]["c2"], str(c2))

    def test_recover_rsa_flags_from_shared_prime_moduli(self) -> None:
        p = 2**127 - 1
        q1 = 2**89 - 1
        q2 = 2**107 - 1
        n1 = p * q1
        n2 = p * q2
        e = 65537
        message = int.from_bytes(b"flag{rsa_shared_prime}", "big")
        c1 = pow(message, e, n1)

        result = recover_rsa_flags_from_text(f"n1 = {n1}\nn2 = {n2}\ne = {e}\nc1 = {c1}\n")

        self.assertEqual(result["flags"], ["flag{rsa_shared_prime}"])
        self.assertEqual(result["method"], "shared_prime")
        self.assertEqual(result["parameters"]["n1"], str(n1))
        self.assertEqual(result["parameters"]["n2"], str(n2))
        self.assertEqual(result["parameters"]["c1"], str(c1))
        self.assertEqual(result["parameters"]["p"], str(p))

    def test_recover_rsa_flags_from_broadcast_attack(self) -> None:
        message = int.from_bytes(b"flag{rsa_broadcast}", "big")
        e = 3
        n1 = 2**521 - 1
        n2 = 2**607 - 1
        n3 = 2**431 - 1
        c1 = pow(message, e, n1)
        c2 = pow(message, e, n2)
        c3 = pow(message, e, n3)

        result = recover_rsa_flags_from_text(f"n1 = {n1}\nn2 = {n2}\nn3 = {n3}\ne = {e}\nc1 = {c1}\nc2 = {c2}\nc3 = {c3}\n")

        self.assertEqual(result["flags"], ["flag{rsa_broadcast}"])
        self.assertEqual(result["method"], "broadcast")
        self.assertEqual(result["parameters"]["n1"], str(n1))
        self.assertEqual(result["parameters"]["n2"], str(n2))
        self.assertEqual(result["parameters"]["n3"], str(n3))
        self.assertEqual(result["parameters"]["c3"], str(c3))

    def test_recover_rsa_flags_from_prime_modulus(self) -> None:
        n = 2**521 - 1
        e = 65537
        message = int.from_bytes(b"flag{rsa_prime_modulus}", "big")
        c = pow(message, e, n)

        result = recover_rsa_flags_from_text(f"n = {n}\ne = {e}\nc = {c}\n")

        self.assertEqual(result["flags"], ["flag{rsa_prime_modulus}"])
        self.assertEqual(result["method"], "prime_modulus")
        self.assertEqual(result["parameters"]["n"], str(n))
        self.assertEqual(result["parameters"]["e"], str(e))
        self.assertEqual(result["parameters"]["c"], str(c))

    def test_recover_rsa_flags_from_fermat_close_primes(self) -> None:
        p = 170141183460469231731687303715884105727
        q = 170141183460469231731687303715884105757
        n = p * q
        e = 65537
        message = int.from_bytes(b"flag{rsa_fermat}", "big")
        c = pow(message, e, n)

        result = recover_rsa_flags_from_text(f"n = {n}\ne = {e}\nc = {c}\n")

        self.assertEqual(result["flags"], ["flag{rsa_fermat}"])
        self.assertEqual(result["method"], "fermat_factors")
        self.assertEqual(result["parameters"]["p"], str(p))
        self.assertEqual(result["parameters"]["q"], str(q))

    def test_recover_python_random_xor_flags_from_small_seed_script(self) -> None:
        script = """
import random
from Crypto.Util.number import *

# flag{
flag = b'xxx'
m = bytes_to_long(flag)
seed = random.randint(1,2**12)
random.seed(seed)
key = random.getrandbits(150)
enc = key ^ m
print(enc)
# 1027275529278332342097876075445098700759415489
"""

        result = recover_python_random_xor_flags_from_text(script)

        self.assertEqual(result["flags"], ["flag{just_a_seed}"])
        self.assertEqual(result["seed"], 3277)
        self.assertEqual(result["key_bits"], 150)

    def test_recover_python_random_prime_offset_from_xored_seed_script(self) -> None:
        script = r"""
from Crypto.Util.number import *
from gmpy2 import *
import random

seed = b'xxxx'
flag = b'*****'
key = b'fake_seed'
gift = bytes(l)
print(gift)
# b'\x12\x13\x1e\x00\x00\x1f\n\x13\x01'

random.seed(bytes_to_long(seed))
t = next_prime(random.randint(2**20,2**21))
r = next_prime(random.randint(1000,10000))
print(bytes_to_long(flag)+t-r)
# 567785900217270586430439246129051365510368280197
"""

        result = recover_python_random_prime_offset_flags_from_text(script)

        self.assertEqual(result["flags"], ["ctf{true_0r_false??}"])
        self.assertEqual(result["seed_text"], "true_love")
        self.assertEqual(result["t"], 1713221)
        self.assertEqual(result["r"], 9533)

    def test_recover_single_byte_xor_flag_from_hex_ciphertext(self) -> None:
        plaintext = b"flag{single_byte_xor}"
        ciphertext = bytes(byte ^ 0x37 for byte in plaintext).hex()

        result = recover_single_byte_xor_flags_from_text(f"single byte xor ciphertext = {ciphertext}\n")

        self.assertEqual(result["flags"], ["flag{single_byte_xor}"])
        self.assertEqual(result["key"], "0x37")
        self.assertEqual(result["method"], "single_byte_xor")

    def test_recover_repeating_key_xor_flag_when_key_is_given(self) -> None:
        plaintext = b"flag{repeating_xor}"
        key = b"ice"
        ciphertext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(plaintext)).hex()

        result = recover_repeating_key_xor_flags_from_text(f"key = ice\nct = {ciphertext}\n")

        self.assertEqual(result["flags"], ["flag{repeating_xor}"])
        self.assertEqual(result["key"], "ice")
        self.assertEqual(result["method"], "repeating_key_xor")

    def test_recover_vigenere_flag_when_key_is_given(self) -> None:
        result = recover_vigenere_flags_from_text("key = lemon\nciphertext = qpmu{itkqbrci}\n")

        self.assertEqual(result["flags"], ["flag{vigenere}"])
        self.assertEqual(result["key"], "lemon")
        self.assertEqual(result["method"], "vigenere")


if __name__ == "__main__":
    unittest.main()
