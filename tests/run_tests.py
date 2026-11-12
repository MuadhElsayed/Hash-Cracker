"""
Self-test suite for HashCrypt. Run:  python3 tests/run_tests.py
Exercises all 4 phases: identification, engines, storage, plus the MD4 fallback.
"""

import hashlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hashcrypt import cracker, identifier, storage

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def t_identifier():
    print("- Phase 1: identification")
    cases = [
        ("8621ffdbc5698829397d97767ac13db3", "MD5", 32),
        ("af8978b1797b72acfff9595a5a2a373ec3d9106d", "SHA-1", 40),
        ("a9c43be948c5cabd56ef2bacffb77cdaa5eec49dd5eb0cc4129cf3eda5f0e74c", "SHA-256", 64),
        ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
         "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA-512", 128),
        ("$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234", "bcrypt", 0),
        ("$6$rounds=4096$salt$hAbH8F5N2mBgVx3K", "SHA-512 crypt (Unix $6$)", 0),
        ("$NT$" + "0" * 32, "NTLM (hashcat $NT$ form)", 0),
    ]
    for h, expected, elen in cases:
        a = identifier.analyze_hash(h)
        check(f"{expected} recognized", a.best == expected, f"got {a.best}")
        if elen:
            check(f"{expected} length", a.length == elen)


def t_engines():
    print("- Phase 2: cracking engines")
    for algo, word in (("md5", "dragon"), ("sha256", "letmein"), ("ntlm", "shadow"),
                       ("sha1", "football"), ("sha512", "monkey")):
        target = cracker.compute_digest(word, algo)
        words = ["zzz", "wrong", word, "pass"]
        res = cracker.crack_dictionary(target, algo, words, workers=4)
        check(f"{algo} dictionary", res["found"] and res["plaintext"] == word)

    # brute force, threaded
    target = cracker.compute_digest("xyz", "sha256")
    res = cracker.crack_bruteforce(target, "sha256", "abcxyz", 3, 3, workers=4)
    check("sha256 brute (threading)", res["found"] and res["plaintext"] == "xyz")

    # brute force, multiprocessing
    target = cracker.compute_digest("cat", "md5")
    res = cracker.crack_bruteforce(target, "md5", "act", 3, 3, workers=2, use_processes=True)
    check("md5 brute (multiprocessing)", res["found"] and res["plaintext"] == "cat")

    # dictionary via multiprocessing
    target = cracker.compute_digest("welcome", "ntlm")
    res = cracker.crack_dictionary(target, "ntlm", ["welcome", "xx"], workers=2,
                                   use_processes=True)
    check("ntlm dict (multiprocessing)", res["found"] and res["plaintext"] == "welcome")

    # salts
    target = hashlib.md5(b"2024dragon").hexdigest()
    res = cracker.crack_dictionary(target, "md5", ["dragon"], salt="2024",
                                   position="prepend")
    check("salt prepend", res["found"])
    target = hashlib.sha256(b"dragon2024").hexdigest()
    res = cracker.crack_dictionary(target, "sha256", ["dragon"], salt="2024",
                                   position="append")
    check("salt append", res["found"])

    # no-match reports failure but correct attempt count
    res = cracker.crack_dictionary(cracker.compute_digest("nope", "md5"), "md5",
                                   ["a", "b", "c"])
    check("no-match counted", not res["found"] and res["attempts"] == 3)

    # unified crack() with auto-identification + fallback chain
    res = cracker.universal_crack(cracker.compute_digest("hello123", "ntlm"),
                                  ["wrong", "hello123"])
    check("auto md5->ntlm fallback", res and res["plaintext"] == "hello123")


def t_md4_fallback():
    print("- Phase 2b: pure-python MD4 fallback")
    check("MD4('')", cracker._pure_md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0")
    check("MD4('a')", cracker._pure_md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24")
    check("MD4('abc')", cracker._pure_md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d")
    ntlm = cracker._pure_md4("password".encode("utf-16-le")).hex()
    check("NTLM('password')", ntlm == "8846f7eaee8fb117ad06bdd830b7586c")
    # multi-block messages (> 64 bytes)
    long_msg = (b"0123456789abcdef" * 9)              # 144 bytes = 2+ blocks
    ref = hashlib.new("md4", long_msg).hexdigest()
    check("MD4 multi-block", cracker._pure_md4(long_msg).hex() == ref,
          f"pure={cracker._pure_md4(long_msg).hex()} ref={ref}")


def t_storage():
    print("- Phase 4: audit storage")
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "audit.db")
        db = storage.AuditDB(db_path)
        sid = db.log_session(storage.AuditRecord(
            algorithm="md5", target_hash="a" * 32, method="dictionary", found=True,
            plaintext="hunter2", attempts=9999, total_candidates=10000,
            elapsed_sec=1.5, rate_hps=6666.0, workers=8, engine="threading",
            wordlist="test.txt"))
        check("log_session returns id", sid == 1)
        hist = db.history(only_found=True)
        check("history only-found", len(hist) == 1 and hist[0]["plaintext"] == "hunter2")
        s = db.stats()
        check("stats aggregates", s["sessions"] == 1 and s["cracked"] == 1)
        db.log_wordlist("test.txt", 100)
        check("wordlist tracked", db.stats()["wordlists_tracked"] == 1)
        db.close()


if __name__ == "__main__":
    print("HashCrypt self-tests")
    t_identifier()
    t_engines()
    t_md4_fallback()
    t_storage()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)
