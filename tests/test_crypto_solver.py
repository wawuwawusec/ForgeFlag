from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from forgeflag.domain import Challenge, ChallengeCategory, RunConfig
from forgeflag.manager import Manager
from forgeflag.notebook import SQLiteNotebook


class CryptoSolverTest(unittest.TestCase):
    def test_crypto_solver_decodes_flag_from_description(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-transform",
                    category=ChallengeCategory.CRYPTO,
                    description="ciphertext: 666c61677b6379626572636865667d",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-transform")
            finding = next(f for f in notebook.findings_for("crypto-transform") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{cyberchef}"])
        self.assertEqual(finding.finding, "Decoded crypto transform candidates")
        self.assertEqual(finding.evidence["ctf_scope"]["category"], "crypto")
        self.assertEqual(finding.evidence["ctf_scope"]["research_context"], "local_or_authorized_ctf_lab")
        self.assertIn("hex_decode", finding.evidence["transform_candidates"][0]["recipe"])

    def test_crypto_solver_prioritizes_base32_transform_over_classical_shift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "crypto-base32.txt"
            attachment.write_text("MZWGCZ33MNXXE4DVONPWG4TZOB2G67I\n", encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-base32",
                    category=ChallengeCategory.CRYPTO,
                    title="Corpus Crypto Base32",
                    description="Base32/encoding warmup pattern.",
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-base32")
            finding = next(f for f in notebook.findings_for("crypto-base32") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{corpus_crypto}"])
        self.assertEqual(finding.finding, "Decoded crypto transform candidates")
        self.assertIn("base32_decode", finding.evidence["transform_candidates"][0]["recipe"])

    def test_crypto_solver_recovers_trithemius_wrapped_htb_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "output.txt"
            attachment.write_text(
                "Make sure you wrap the decrypted text with the HTB flag format :-]\n"
                "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-trithemius",
                    category=ChallengeCategory.CRYPTO,
                    title="HTB Cyber Apocalypse 2024 - Dynastic",
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-trithemius")
            finding = next(f for f in notebook.findings_for("crypto-trithemius") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(
            summary["accepted_flags"],
            ["HTB{DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!_IT_IS_SIMILAR_TO_CAESAR_CIPHER}"],
        )
        self.assertEqual(finding.finding, "Recovered classical crypto flag candidates")
        self.assertIn("trithemius_shift", finding.evidence)

    def test_crypto_solver_recovers_shufflebox_permutation_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output_censored.txt"
            output.write_text(
                "aaaabbbbccccdddd -> ccaccdabdbdbbada\n"
                "abcdabcdabcdabcd -> bcaadbdcdbcdacab\n"
                "???????????????? -> owuwspdgrtejiiud\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-shufflebox",
                    category=ChallengeCategory.CRYPTO,
                    title="DUCTF 2024 - shufflebox",
                    description="Find the text censored with question marks in output_censored.txt and surround it with DUCTF{}.",
                    attachment_paths=(str(output),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-shufflebox")
            finding = next(f for f in notebook.findings_for("crypto-shufflebox") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["DUCTF{udiditgjwowsuper}"])
        self.assertEqual(finding.finding, "Recovered classical crypto flag candidates")
        self.assertIn("shufflebox", finding.evidence)

    def test_crypto_solver_records_rsa_parameter_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa",
                    category=ChallengeCategory.CRYPTO,
                    description="RSA task:\nn = 3233\ne = 3\nc = 2790\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa")
            finding = next(f for f in notebook.findings_for("crypto-rsa") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed RSA challenge parameters")
        self.assertEqual(finding.evidence["rsa"]["parameters"]["e"], "3")
        self.assertIn("RsaCtfTool", finding.evidence["rsa"]["recommended_tools"])

    def test_crypto_solver_recovers_rsa_flag_from_known_factors(self) -> None:
        p = 2**127 - 1
        q = 2**89 - 1
        n = p * q
        e = 65537
        message = int.from_bytes(b"flag{rsa_known_factors}", "big")
        c = pow(message, e, n)
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-known-factors",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n = {n}\ne = {e}\nc = {c}\np = {p}\nq = {q}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-known-factors")
            finding = next(f for f in notebook.findings_for("crypto-rsa-known-factors") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_known_factors}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "known_factors")

    def test_crypto_solver_recovers_rsa_low_exponent_plaintext_root(self) -> None:
        e = 3
        n = 2**521 - 1
        message = int.from_bytes(b"flag{rsa_low_exponent}", "big")
        c = message**e
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-low-exponent",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n = {n}\ne = {e}\nc = {c}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-low-exponent")
            finding = next(f for f in notebook.findings_for("crypto-rsa-low-exponent") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_low_exponent}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "low_exponent_root")

    def test_crypto_solver_recovers_rsa_common_modulus_pair(self) -> None:
        n = 2**521 - 1
        message = int.from_bytes(b"flag{rsa_common_modulus}", "big")
        e1 = 17
        e2 = 65537
        c1 = pow(message, e1, n)
        c2 = pow(message, e2, n)
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-common-modulus",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n = {n}\ne1 = {e1}\ne2 = {e2}\nc1 = {c1}\nc2 = {c2}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-common-modulus")
            finding = next(f for f in notebook.findings_for("crypto-rsa-common-modulus") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_common_modulus}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "common_modulus")

    def test_crypto_solver_recovers_rsa_shared_prime_moduli(self) -> None:
        p = 2**127 - 1
        q1 = 2**89 - 1
        q2 = 2**107 - 1
        n1 = p * q1
        n2 = p * q2
        e = 65537
        message = int.from_bytes(b"flag{rsa_shared_prime}", "big")
        c1 = pow(message, e, n1)
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-shared-prime",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n1 = {n1}\nn2 = {n2}\ne = {e}\nc1 = {c1}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-shared-prime")
            finding = next(f for f in notebook.findings_for("crypto-rsa-shared-prime") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_shared_prime}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "shared_prime")

    def test_crypto_solver_recovers_rsa_broadcast_attack(self) -> None:
        message = int.from_bytes(b"flag{rsa_broadcast}", "big")
        e = 3
        n1 = 2**521 - 1
        n2 = 2**607 - 1
        n3 = 2**431 - 1
        c1 = pow(message, e, n1)
        c2 = pow(message, e, n2)
        c3 = pow(message, e, n3)
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-broadcast",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n1 = {n1}\nn2 = {n2}\nn3 = {n3}\ne = {e}\nc1 = {c1}\nc2 = {c2}\nc3 = {c3}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-broadcast")
            finding = next(f for f in notebook.findings_for("crypto-rsa-broadcast") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_broadcast}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "broadcast")

    def test_crypto_solver_recovers_rsa_prime_modulus(self) -> None:
        n = 2**521 - 1
        e = 65537
        message = int.from_bytes(b"flag{rsa_prime_modulus}", "big")
        c = pow(message, e, n)
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-prime-modulus",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n = {n}\ne = {e}\nc = {c}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-prime-modulus")
            finding = next(f for f in notebook.findings_for("crypto-rsa-prime-modulus") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_prime_modulus}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "prime_modulus")

    def test_crypto_solver_recovers_rsa_fermat_close_primes(self) -> None:
        p = 170141183460469231731687303715884105727
        q = 170141183460469231731687303715884105757
        n = p * q
        e = 65537
        message = int.from_bytes(b"flag{rsa_fermat}", "big")
        c = pow(message, e, n)
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-rsa-fermat",
                    category=ChallengeCategory.CRYPTO,
                    description=f"n = {n}\ne = {e}\nc = {c}\n",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-rsa-fermat")
            finding = next(f for f in notebook.findings_for("crypto-rsa-fermat") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{rsa_fermat}"])
        self.assertEqual(finding.finding, "Recovered RSA flag candidates")
        self.assertEqual(finding.evidence["rsa_recovery"]["method"], "fermat_factors")

    def test_crypto_solver_recovers_python_random_xor_flag_from_attachment(self) -> None:
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "easy_seed.py"
            attachment.write_text(script, encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-random-xor",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-random-xor")
            finding = next(f for f in notebook.findings_for("crypto-random-xor") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{just_a_seed}"])
        self.assertEqual(finding.finding, "Recovered Python random XOR flag candidates")
        self.assertEqual(finding.evidence["python_random_xor"]["seed"], 3277)

    def test_crypto_solver_recovers_python_random_prime_offset_from_xored_seed(self) -> None:
        script = r"""
from Crypto.Util.number import *
from gmpy2 import *
import random

seed = b'xxxx'
flag = b'*****'
key = b'fake_seed'
# c = a^b a = b^c
l = [
for i in range(len(key)):
    l.append(key[i]^seed[i])
gift = bytes(l)
print(gift)
# b'\x12\x13\x1e\x00\x00\x1f\n\x13\x01'

random.seed(bytes_to_long(seed))
t = next_prime(random.randint(2**20,2**21))
r = next_prime(random.randint(1000,10000))

print(bytes_to_long(flag)+t-r)
# 567785900217270586430439246129051365510368280197
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "easy_random.py"
            attachment.write_text(script, encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-random-prime-offset",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-random-prime-offset")
            finding = next(f for f in notebook.findings_for("crypto-random-prime-offset") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["ctf{true_0r_false??}"])
        self.assertEqual(finding.finding, "Recovered Python random prime-offset flag candidates")
        self.assertEqual(finding.evidence["python_random_prime_offset"]["seed_text"], "true_love")
        self.assertEqual(finding.evidence["python_random_prime_offset"]["t"], 1713221)
        self.assertEqual(finding.evidence["python_random_prime_offset"]["r"], 9533)

    def test_crypto_solver_recovers_lfsr_bm_flag_before_transform_templates(self) -> None:
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "BM.py"
            attachment.write_text(script, encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-lfsr-bm",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-lfsr-bm")
            finding = next(f for f in notebook.findings_for("crypto-lfsr-bm") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(
            summary["accepted_flags"],
            ["de1ctf{1224473d5e349dbf2946353444d727d8fa91da3275ed3ac0dedeb7e6a9ad8619}"],
        )
        self.assertEqual(finding.finding, "Recovered LFSR Berlekamp-Massey flag candidates")
        self.assertEqual(finding.evidence["lfsr_bm"]["method"], "lfsr_berlekamp_massey")

    def test_crypto_solver_recovers_prng_stream_lcg_lift_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "lcg4.py"
            attachment.write_text(
                """
from Crypto.Util.number import *
flag = b'flag{1111122222333344440000}'
seed = bytes_to_long(flag)
length = seed.bit_length()
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
""",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-prng-lcg-lift",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-prng-lcg-lift")
            finding = next(f for f in notebook.findings_for("crypto-prng-lcg-lift") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{1111122222333344440000}"])
        self.assertEqual(finding.finding, "Recovered PRNG/stream cipher flag candidates")
        self.assertEqual(finding.evidence["prng_stream"]["method"], "lcg_consecutive_outputs")

    def test_crypto_solver_recovers_linear_xorshift_script_flag(self) -> None:
        plaintext = b"flag{linear_xorshift_inverse}"
        random.seed(0)
        ciphertext_int = int(plaintext.hex(), 16)
        for _ in range(100):
            ciphertext_int ^= ciphertext_int >> random.randint(1, 32)
        ciphertext = bytes.fromhex(hex(ciphertext_int)[2:])
        script = f"""
import random
flag = input().encode()
assert len(flag)=={len(plaintext)}

def enc(pt):
    random.seed(0)
    ct = int(pt.hex(),16)
    for _ in range(100):
        ct ^= ct>>random.randint(1,32)
    return bytes.fromhex(hex(ct)[2:])

assert enc(flag)=={ciphertext!r}
print(f"{{flag = }}")
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "chal.py"
            attachment.write_text(script, encoding="utf-8")
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-linear-xorshift",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-linear-xorshift")
            finding = next(f for f in notebook.findings_for("crypto-linear-xorshift") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["flag{linear_xorshift_inverse}"])
        self.assertEqual(finding.finding, "Recovered linear xorshift flag candidates")
        self.assertEqual(finding.evidence["linear_xorshift"]["rounds"], 100)

    def test_crypto_solver_recovers_common_xor_and_vigenere_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plaintext = b"flag{solver_single_xor}"
            single_byte_ct = bytes(byte ^ 0x42 for byte in plaintext).hex()
            repeating_plaintext = b"flag{solver_repeating_xor}"
            repeating_key = b"ice"
            repeating_ct = bytes(
                byte ^ repeating_key[index % len(repeating_key)]
                for index, byte in enumerate(repeating_plaintext)
            ).hex()
            attachment = root / "xor-vigenere.txt"
            attachment.write_text(
                f"single byte xor ciphertext = {single_byte_ct}\n"
                f"key = ice\nct = {repeating_ct}\n"
                "vigenere key = lemon\nvigenere ciphertext = qpmu{itkqbrci}\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-xor-vigenere",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-xor-vigenere")
            finding = next(f for f in notebook.findings_for("crypto-xor-vigenere") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertIn("flag{solver_single_xor}", summary["accepted_flags"])
        self.assertIn("flag{solver_repeating_xor}", summary["accepted_flags"])
        self.assertIn("flag{vigenere}", summary["accepted_flags"])
        self.assertEqual(finding.finding, "Recovered classical crypto flag candidates")
        self.assertIn("single_byte_xor", finding.evidence)
        self.assertIn("repeating_key_xor", finding.evidence)
        self.assertIn("vigenere", finding.evidence)

    def test_crypto_solver_recovers_self_sync_low_nibble_xor_real_challenge(self) -> None:
        root = Path(__file__).resolve().parents[1]
        challenge_root = root / ".forgeflag" / "heldout-cache" / "ductf2024" / "crypto" / "three-line-crypto" / "publish"
        if not challenge_root.exists():
            self.skipTest("DUCTF three-line-crypto held-out artifact cache is not available")
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-three-line-real",
                    category=ChallengeCategory.CRYPTO,
                    title="three line crypto",
                    description="Platform: DownUnderCTF 2024\nNOTE: passage.txt is English text.",
                    attachment_paths=(str(challenge_root / "encrypt.py"), str(challenge_root / "passage.enc.txt")),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-three-line-real")
            finding = next(f for f in notebook.findings_for("crypto-three-line-real") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "flag_found")
        self.assertEqual(summary["accepted_flags"], ["DUCTF{when_in_doubt_xort_it_out}"])
        self.assertEqual(finding.finding, "Recovered self-synchronizing XOR flag candidates")
        self.assertEqual(finding.evidence["self_sync_xor"]["method"], "previous_plaintext_low_nibble_key_slot")

    def test_crypto_solver_records_hash_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-hash",
                    category=ChallengeCategory.CRYPTO,
                    description="crack this: 5d41402abc4b2a76b9719d911017c592",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-hash")
            finding = next(f for f in notebook.findings_for("crypto-hash") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Analyzed hash candidates")
        self.assertEqual(finding.evidence["hashes"]["candidates"][0]["type"], "md5_or_ntlm")
        self.assertIn("hashcat", finding.evidence["hashes"]["recommended_tools"])

    def test_crypto_solver_identifies_aes_ctr_nonce_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachment = root / "ctr.py"
            attachment.write_text(
                "cipher = AES.new(key, AES.MODE_CTR, nonce=b'fixed')\n"
                "Two ciphertexts reuse the same nonce, so recover the keystream with XOR cribbing.\n",
                encoding="utf-8",
            )
            notebook = SQLiteNotebook(root / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-ctr-reuse",
                    category=ChallengeCategory.CRYPTO,
                    attachment_paths=(str(attachment),),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-ctr-reuse")
            finding = next(f for f in notebook.findings_for("crypto-ctr-reuse") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Identified crypto primitive misuse pattern")
        self.assertEqual(finding.evidence["pattern"], "aes_ctr_nonce_reuse")
        self.assertIn("nonce", finding.next_action.lower())
        self.assertIn("keystream", finding.next_action.lower())

    def test_crypto_solver_identifies_poly1305_one_time_key_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-poly1305-reuse",
                    category=ChallengeCategory.CRYPTO,
                    description="Poly1305 one-time MAC key was reused; solve algebra equations over message/tag pairs.",
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-poly1305-reuse")
            finding = next(f for f in notebook.findings_for("crypto-poly1305-reuse") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.evidence["pattern"], "poly1305_one_time_key_reuse")
        self.assertIn("algebra", finding.next_action.lower())

    def test_crypto_solver_identifies_aes_gcm_nonce_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notebook = SQLiteNotebook(Path(tmp) / "notebook.sqlite")
            notebook.add_challenge(
                Challenge(
                    challenge_id="crypto-gcm-reuse",
                    category=ChallengeCategory.CRYPTO,
                    description=(
                        "AES-GCM nonce was reused for two ciphertext/tag pairs. "
                        "Recover GHASH authentication subkey with forbidden attack style algebra.\n"
                        "c1 = 0011223344556677, tag1 = 8899aabbccddeeff0011223344556677\n"
                        "c2 = 1021324354657687, tag2 = 9988ffeeddccbbaa7766554433221100\n"
                    ),
                )
            )

            summary = Manager(notebook, RunConfig()).run_challenge("crypto-gcm-reuse")
            finding = next(f for f in notebook.findings_for("crypto-gcm-reuse") if f.solver == "CryptoSolver")

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(finding.finding, "Identified crypto primitive misuse pattern")
        self.assertEqual(finding.evidence["pattern"], "aes_gcm_nonce_reuse")
        self.assertIn("tag", finding.next_action.lower())
        self.assertIn("ghash", finding.next_action.lower())


if __name__ == "__main__":
    unittest.main()
