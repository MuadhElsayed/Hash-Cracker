"""
Phase 1: Hash Identification & Structure Analysis Module.

Inspects an unknown hash string's length, character composition and structural
markers, then reports the most likely cryptographic algorithm(s) that could
have produced it.

NOTE: Length/charset alone cannot *prove* an algorithm — collisions exist at
every length (e.g. MD5 and NTLM are both 32 hex characters; BLAKE2b-256 and
SHA-256 are both 64 hex characters). This module therefore returns a ranked
list of candidates with a confidence score, and gives extra weight to
algorithm-specific structural markers (GPG / bcrypt / sha512crypt etc.).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Signature table
# ---------------------------------------------------------------------------
# Each entry: (name, exact_length, confidence_base, notes)
# confidence_base expresses how *unique* this (length, charset) fingerprint is.
HEX = "hex"
BASE64 = "base64"

HASH_TABLE: list[dict] = [
    # --- Hex-digest hashes, identified by digest length ---------------------
    {"name": "CRC32",    "length": 8,   "confidence": 0.60, "charset": HEX, "algorithm": "crc32"},
    {"name": "MD5",      "length": 32,  "confidence": 0.50, "charset": HEX, "algorithm": "md5"},
    {"name": "NTLM",     "length": 32,  "confidence": 0.45, "charset": HEX, "algorithm": "ntlm"},
    {"name": "MD4",      "length": 32,  "confidence": 0.30, "charset": HEX, "algorithm": "md4"},
    {"name": "MD2",      "length": 32,  "confidence": 0.20, "charset": HEX, "algorithm": None},
    {"name": "RIPEMD128","length": 32,  "confidence": 0.20, "charset": HEX, "algorithm": None},
    {"name": "SHA-1",    "length": 40,  "confidence": 0.90, "charset": HEX, "algorithm": "sha1"},
    {"name": "RIPEMD160","length": 40,  "confidence": 0.50, "charset": HEX, "algorithm": "ripemd160"},
    {"name": "BLAKE2b64","length": 64,  "confidence": 0.10, "charset": HEX, "algorithm": None},
    {"name": "SHA-224",  "length": 56,  "confidence": 0.95, "charset": HEX, "algorithm": "sha224"},
    {"name": "SHA3-224", "length": 56,  "confidence": 0.60, "charset": HEX, "algorithm": "sha3_224"},
    {"name": "SHA-256",  "length": 64,  "confidence": 0.92, "charset": HEX, "algorithm": "sha256"},
    {"name": "SHA3-256", "length": 64,  "confidence": 0.70, "charset": HEX, "algorithm": "sha3_256"},
    {"name": "BLAKE2s-256", "length": 64, "confidence": 0.65, "charset": HEX, "algorithm": "blake2s"},
    {"name": "SHA-384",  "length": 96,  "confidence": 0.90, "charset": HEX, "algorithm": "sha384"},
    {"name": "SHA3-384", "length": 96,  "confidence": 0.65, "charset": HEX, "algorithm": "sha3_384"},
    {"name": "SHA-512",  "length": 128, "confidence": 0.92, "charset": HEX, "algorithm": "sha512"},
    {"name": "SHA3-512", "length": 128, "confidence": 0.70, "charset": HEX, "algorithm": "sha3_512"},
    {"name": "WHIRLPOOL","length": 128, "confidence": 0.60, "charset": HEX, "algorithm": "whirlpool"},
    {"name": "BLAKE2b-512", "length": 128, "confidence": 0.65, "charset": HEX, "algorithm": "blake2b"},
]

# --- Structural markers that *provingly* identify a format -----------------
# (regex pattern, algorithm name, confidence)
STRUCTURAL_MARKERS: list[tuple[str, str, float]] = [
    (r"^\$1\$[^$]+\$[\w./]+$",        "MD5 crypt (md5crypt, Unix $1$)",          0.99),
    (r"^\$5\$rounds=\d+\$[^$]+\$[\w./]+$", "SHA-256 crypt (Unix $5$)",           0.99),
    (r"^\$5\$[^$]+\$[\w./]+$",        "SHA-256 crypt (Unix $5$)",                0.98),
    (r"^\$6\$rounds=\d+\$[^$]+\$[\w./]+$", "SHA-512 crypt (Unix $6$)",           0.99),
    (r"^\$6\$[^$]+\$[\w./]+$",        "SHA-512 crypt (Unix $6$)",                0.98),
    (r"^\$2[aby]\$\d{2}\$[\w./]{53}$","bcrypt",                                  0.99),
    (r"^\$apr1\$[^$]+\$[\w./]+$",     "MD5 crypt (APR1, Apache)",                0.99),
    (r"^\$argon2(id|i|d)\$",          "Argon2 (id|i|d)",                         0.99),
    (r"^\$pbkdf2(-sha\d+)?\$",        "PBKDF2",                                  0.99),
    (r"^\$scram\$",                   "SCRAM",                                   0.95),
    (r"^\$NT\$[0-9a-f]{32}$",         "NTLM (hashcat $NT$ form)",                0.99),
    (r"^\$lm\$[0-9a-f]{32}$",         "LAN Manager (LM)",                        0.99),
    (r"^[0-9a-f]{32}:[0-9a-f]{32}$",  "NTLM pair (NtHash:DcHash / DCC2)",        0.95),
    (r"^\$mysql[0-9a-z]*\$",          "MySQL hash",                              0.99),
    (r"^\$blowfish\$",                "Blowfish/Eggdrop",                        0.99),
]

_MYSQL_OLD_RE = re.compile(r"^[0-9a-fA-F]{16}$")


def _charset_label(s: str) -> str:
    """Describe the character composition of the candidate hash."""
    if re.fullmatch(r"[0-9a-f]+", s):
        return "lowercase hex"
    if re.fullmatch(r"[0-9A-F]+", s):
        return "UPPERCASE hex"
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        return "mixed-case hex"
    if re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return "base64-like"
    if re.fullmatch(r"[\x20-\x7e]+", s):
        return "printable ascii"
    return "binary / non-printable"


@dataclass
class HashAnalysis:
    """Structured result of analyzing one hash string."""
    raw: str
    length: int
    charset: str
    candidates: list[tuple[str, float]] = field(default_factory=list)
    best: str | None = None
    crackable: str | None = None   # engine name usable by cracker.py (or None)

    def __str__(self) -> str:
        lines = [
            f"Input           : {self.raw if len(self.raw) <= 64 else self.raw[:61] + '...'}",
            f"Length          : {self.length}",
            f"Character set   : {self.charset}",
            f"Best guess      : {self.best or 'unknown'}",
            "Candidates      :",
        ]
        if not self.candidates:
            lines.append("    (no known signature matched)")
        for name, conf in self.candidates:
            bar = "#" * int(round(conf * 20))
            lines.append(f"    {name:<28} {conf:>5.0%}  |{bar:<20}|")
        if self.crackable:
            lines.append(f"Crackable via    : `{self.crackable}`")
        else:
            lines.append("Crackable via    : not supported by the built-in engine "
                         "(try hashcat identification modes instead)")
        return "\n".join(lines)


def analyze_hash(value: str) -> HashAnalysis:
    """
    Analyze an unknown hash string and identify likely algorithms.

    Strategy:
      1. Try high-confidence structural markers (bcrypt/sha512crypt/...).
      2. Otherwise score every signature whose digest length matches.
    """
    s = value.strip()
    scores: dict[str, float] = {}

    # 1. Structural markers --------------------------------------------------
    for pattern, name, conf in STRUCTURAL_MARKERS:
        if re.match(pattern, s, re.IGNORECASE):
            scores[name] = max(scores.get(name, 0.0), conf)
            best = max(scores.items(), key=lambda kv: kv[1])
            analysis = HashAnalysis(s, len(s), _charset_label(s),
                                    candidates=sorted(scores.items(), key=lambda kv: -kv[1]))
            analysis.best = best[0]
            analysis.crackable = None  # salted formats aren't in the demo engine
            return analysis

    # 2. Length + charset fingerprints ---------------------------------------
    charset = _charset_label(s)
    lower_hex = charset.endswith("hex")
    for entry in HASH_TABLE:
        if entry["length"] != len(s):
            continue
        conf = entry["confidence"]
        if entry["charset"] == HEX and not lower_hex:
            conf *= 0.3          # correct length but not hex — unlikely digest
        # Uppercase hex slightly penalizes (most tools emit lowercase)
        if charset == "UPPERCASE hex":
            conf *= 0.8
        scores[entry["name"]] = conf

    ordered = sorted(scores.items(), key=lambda kv: -kv[1])
    best_name = ordered[0][0] if ordered else None

    # choose engine algorithm for the best candidate
    crackable = None
    if best_name and len(s) in (32, 40, 56, 64, 96, 128):
        for entry in HASH_TABLE:
            if entry["name"] == best_name and entry["algorithm"]:
                _algo, engine = _pick_engine(entry["algorithm"], s)
                if engine:
                    crackable = engine
                break

    return HashAnalysis(s, len(s), charset, candidates=ordered, best=best_name,
                        crackable=crackable)


def _pick_engine(algorithm: str, s: str) -> tuple[str, str | None]:
    """Return (canonical name, engine name) for algorithms the cracker supports."""
    # NTLM vs MD5 ambiguity: both 32 hex. We hand both back; caller decides.
    if algorithm == "ntlm" and s:
        return algorithm, "ntlm"
    if algorithm == "md5":
        return algorithm, "md5"
    if algorithm == "md4":
        return algorithm, "ntlm"      # MD4 hex == NTLM implementation-wise
    if algorithm in {"sha1", "sha224", "sha256", "sha384", "sha512",
                     "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                     "blake2b", "blake2s"}:
        return algorithm, algorithm
    return algorithm, None


def identify(value: str) -> HashAnalysis:
    """Convenience alias used by the CLI."""
    return analyze_hash(value)


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:]:
        print(analyze_hash(arg))
        print("-" * 70)
