"""
Phase 2: Multi-threaded / multi-process cracking engine.

Two search strategies:

  * Dictionary attack  — streams a wordlist, chunks it evenly across worker
                         threads (or processes) and hashes every candidate.
  * Brute-force attack — walks a keyspace with radix indexing; the keyspace is
                         mathematically partitioned by word index so every
                         worker scans a disjoint slice, never duplicating work.

Both strategies share one compare-and-report loop (`_probe_block`) and report
live progress through a thread/process-safe counter. Cooperative abort: pass a
`threading.Event` as `stop` (Ctrl+C handling, web-app stop button) and workers
exit between work units.

Supported algorithms (plug directly into hashlib):
    md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384,
    sha3_512, blake2b, blake2s  +  ntlm (MD4 of UTF-16LE, pure-python fallback)

Offensive-security tooling — the operator assumes full responsibility for use.
"""

from __future__ import annotations

import hashlib
import concurrent.futures
import os
import struct
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field


class SearchAborted(Exception):
    """Raised inside workers when the caller requested a stop."""


# Cooperative-stop plumbing. `_STOP_HIT` is swapped for a real checker by the
# engine (thread mode checks the caller's event; process mode checks an
# mp.Event shared through the worker initializer).
_STOP_HIT = lambda: False          # noqa: E731

# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------

HASHLIB_ALGOS: dict[str, str] = {
    "md5": "md5",
    "md4": "md4",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha3_224": "sha3_224",
    "sha3_256": "sha3_256",
    "sha3_384": "sha3_384",
    "sha3_512": "sha3_512",
    "blake2b": "blake2b",
    "blake2s": "blake2s",
}

FRIENDLY_NAMES: dict[str, str] = {
    "md5": "MD5",
    "md4": "MD4",
    "ntlm": "NTLM",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_224": "SHA3-224",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b-512",
    "blake2s": "BLAKE2s-256",
    "crc32": "CRC32",
}


def supported_algorithms() -> list[str]:
    return sorted(set(HASHLIB_ALGOS) | {"ntlm"})


def resolve_algorithm(name: str) -> str:
    """Accept friendly names (SHA-256, NTLM, sha512...) and normalize them."""
    key = name.lower().replace("-", "_").replace(" ", "").replace("/", "_")
    if key == "sha512crypt":
        raise ValueError("salted sha512crypt is not supported by the demo engine")
    if key in ("sha3_256", "sha3256"):
        key = "sha3_256"
    if key not in HASHLIB_ALGOS and key != "ntlm":
        raise ValueError(f"unsupported algorithm: {name!r}. "
                         f"Supported: {', '.join(supported_algorithms())}")
    return key


# ---------------------------------------------------------------------------
# NTLM (MD4) support — OpenSSL 3 usually removed MD4, so we carry a compact
# pure-python MD4 implementation as a fallback.
# ---------------------------------------------------------------------------

def _pure_md4(message: bytes) -> bytes:
    """Pure-python MD4 (RFC 1320/6149) for OpenSSL builds without MD4."""
    def lrot(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def F(x, y, z):  return (x & y) | (~x & z)          # noqa: E731
    def G(x, y, z):  return (x & y) | (x & z) | (y & z)  # noqa: E731
    def H(x, y, z):  return x ^ y ^ z                   # noqa: E731

    ml = len(message) * 8
    msg = bytearray(message)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)

    K1, K2 = 0x5A827999, 0x6ED9EBA1

    def round1(a, b, c, d, X):
        a = lrot((a + F(b, c, d) + X[0]) & 0xFFFFFFFF, 3)
        d = lrot((d + F(a, b, c) + X[1]) & 0xFFFFFFFF, 7)
        c = lrot((c + F(d, a, b) + X[2]) & 0xFFFFFFFF, 11)
        b = lrot((b + F(c, d, a) + X[3]) & 0xFFFFFFFF, 19)
        a = lrot((a + F(b, c, d) + X[4]) & 0xFFFFFFFF, 3)
        d = lrot((d + F(a, b, c) + X[5]) & 0xFFFFFFFF, 7)
        c = lrot((c + F(d, a, b) + X[6]) & 0xFFFFFFFF, 11)
        b = lrot((b + F(c, d, a) + X[7]) & 0xFFFFFFFF, 19)
        a = lrot((a + F(b, c, d) + X[8]) & 0xFFFFFFFF, 3)
        d = lrot((d + F(a, b, c) + X[9]) & 0xFFFFFFFF, 7)
        c = lrot((c + F(d, a, b) + X[10]) & 0xFFFFFFFF, 11)
        b = lrot((b + F(c, d, a) + X[11]) & 0xFFFFFFFF, 19)
        a = lrot((a + F(b, c, d) + X[12]) & 0xFFFFFFFF, 3)
        d = lrot((d + F(a, b, c) + X[13]) & 0xFFFFFFFF, 7)
        c = lrot((c + F(d, a, b) + X[14]) & 0xFFFFFFFF, 11)
        b = lrot((b + F(c, d, a) + X[15]) & 0xFFFFFFFF, 19)
        return a, b, c, d

    def round2(a, b, c, d, X):
        a = lrot((a + G(b, c, d) + X[0] + K1) & 0xFFFFFFFF, 3)
        d = lrot((d + G(a, b, c) + X[4] + K1) & 0xFFFFFFFF, 5)
        c = lrot((c + G(d, a, b) + X[8] + K1) & 0xFFFFFFFF, 9)
        b = lrot((b + G(c, d, a) + X[12] + K1) & 0xFFFFFFFF, 13)
        a = lrot((a + G(b, c, d) + X[1] + K1) & 0xFFFFFFFF, 3)
        d = lrot((d + G(a, b, c) + X[5] + K1) & 0xFFFFFFFF, 5)
        c = lrot((c + G(d, a, b) + X[9] + K1) & 0xFFFFFFFF, 9)
        b = lrot((b + G(c, d, a) + X[13] + K1) & 0xFFFFFFFF, 13)
        a = lrot((a + G(b, c, d) + X[2] + K1) & 0xFFFFFFFF, 3)
        d = lrot((d + G(a, b, c) + X[6] + K1) & 0xFFFFFFFF, 5)
        c = lrot((c + G(d, a, b) + X[10] + K1) & 0xFFFFFFFF, 9)
        b = lrot((b + G(c, d, a) + X[14] + K1) & 0xFFFFFFFF, 13)
        a = lrot((a + G(b, c, d) + X[3] + K1) & 0xFFFFFFFF, 3)
        d = lrot((d + G(a, b, c) + X[7] + K1) & 0xFFFFFFFF, 5)
        c = lrot((c + G(d, a, b) + X[11] + K1) & 0xFFFFFFFF, 9)
        b = lrot((b + G(c, d, a) + X[15] + K1) & 0xFFFFFFFF, 13)
        return a, b, c, d

    def round3(a, b, c, d, X):
        a = lrot((a + H(b, c, d) + X[0] + K2) & 0xFFFFFFFF, 3)
        d = lrot((d + H(a, b, c) + X[8] + K2) & 0xFFFFFFFF, 9)
        c = lrot((c + H(d, a, b) + X[4] + K2) & 0xFFFFFFFF, 11)
        b = lrot((b + H(c, d, a) + X[12] + K2) & 0xFFFFFFFF, 15)
        a = lrot((a + H(b, c, d) + X[2] + K2) & 0xFFFFFFFF, 3)
        d = lrot((d + H(a, b, c) + X[10] + K2) & 0xFFFFFFFF, 9)
        c = lrot((c + H(d, a, b) + X[6] + K2) & 0xFFFFFFFF, 11)
        b = lrot((b + H(c, d, a) + X[14] + K2) & 0xFFFFFFFF, 15)
        a = lrot((a + H(b, c, d) + X[1] + K2) & 0xFFFFFFFF, 3)
        d = lrot((d + H(a, b, c) + X[9] + K2) & 0xFFFFFFFF, 9)
        c = lrot((c + H(d, a, b) + X[5] + K2) & 0xFFFFFFFF, 11)
        b = lrot((b + H(c, d, a) + X[13] + K2) & 0xFFFFFFFF, 15)
        a = lrot((a + H(b, c, d) + X[3] + K2) & 0xFFFFFFFF, 3)
        d = lrot((d + H(a, b, c) + X[11] + K2) & 0xFFFFFFFF, 9)
        c = lrot((c + H(d, a, b) + X[7] + K2) & 0xFFFFFFFF, 11)
        b = lrot((b + H(c, d, a) + X[15] + K2) & 0xFFFFFFFF, 15)
        return a, b, c, d

    h0, h1, h2, h3 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", bytes(msg[off:off + 64]))
        a, b, c, d = h0, h1, h2, h3
        a, b, c, d = round1(a, b, c, d, X)
        a, b, c, d = round2(a, b, c, d, X)
        a, b, c, d = round3(a, b, c, d, X)
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
    return struct.pack("<4I", h0, h1, h2, h3)


def _md4(data: bytes) -> bytes:
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, TypeError, AttributeError):
        return _pure_md4(data)


def compute_digest(word: str, algorithm: str) -> str:
    """Hash one plaintext candidate with the requested algorithm -> hex digest."""
    data = word.encode("utf-8", "surrogatepass")
    if algorithm == "ntlm":
        return _md4(data.decode("utf-8", "replace").encode("utf-16-le")).hex()
    return hashlib.new(HASHLIB_ALGOS[algorithm], data).hexdigest()


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------

class _ThreadProgress:
    """Thread-safe attempt counter for the threaded engine."""

    def __init__(self, total: int | None, callback=None, every: int = 20000):
        self._count = 0
        self._lock = threading.Lock()
        self._total = total
        self._callback = callback
        self._every = every
        self._since_cb = 0

    def bump(self, n: int = 1) -> None:
        with self._lock:
            self._count += n
            self._since_cb += n
        if self._callback and self._since_cb >= self._every:
            with self._lock:
                self._since_cb = 0
            self._callback(self._count, self._total)

    @property
    def count(self) -> int:
        with self._lock:
            return self._count


# multiprocessing mode shares an mp.Value via worker initializers
_MP: dict = {}

try:
    import multiprocessing as _mp
    _MP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MP_AVAILABLE = False


def _mp_init(counter, lock, target_hash, algorithm, salt, position, stop_event) -> None:
    _MP["counter"] = counter
    _MP["lock"] = lock
    _MP["target"] = target_hash
    _MP["algorithm"] = algorithm
    _MP["salt"] = salt
    _MP["position"] = position
    _MP["stop"] = stop_event
    # each worker process gets its own module copy after fork-server/spawn
    globals()["_STOP_HIT"] = lambda: _MP["stop"].is_set()


def _mp_bump(n: int) -> None:
    c, l = _MP["counter"], _MP["lock"]
    l.acquire()
    try:
        c.value += n
    finally:
        l.release()


# ---------------------------------------------------------------------------
# Shared candidate-*-compare loop (used by both engines)
# ---------------------------------------------------------------------------

def _salted(word: str, salt: str, position: str) -> str:
    if not salt:
        return word
    return salt + word if position == "prepend" else word + salt


def _probe_block(words, target_hash: str, algorithm: str,
                 salt: str, position: str, progress) -> str | None:
    """Hash a block of candidates; return the plaintext on first match."""
    digest = compute_digest     # local binding for speed
    new_hash = hashlib.new
    bump_every = 4096
    since = 0

    for word in words:
        candidate = _salted(word, salt, position)
        if algorithm == "ntlm":
            computed = _md4(candidate.encode("utf-16-le", "replace")).hex()
        else:
            computed = new_hash(HASHLIB_ALGOS[algorithm],
                                candidate.encode("utf-8", "surrogatepass")).hexdigest()
        if computed == target_hash:
            progress.bump(since + 1)
            return candidate
        since += 1
        if since >= bump_every:
            progress.bump(since)
            since = 0
            if _STOP_HIT():
                raise SearchAborted()
    if since:
        progress.bump(since)
    return None


# ---------------------------------------------------------------------------
# Dictionary engine
# ---------------------------------------------------------------------------

def load_wordlist(path: str) -> list[str]:
    """Read a wordlist into memory (stripped, de-duplicated via set)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"wordlist not found: {path}")
    words: list[str] = []
    seen: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            w = line.rstrip("\r\n")
            if w and w not in seen:
                seen.add(w)
                words.append(w)
    return words


def _chunkify(seq: list, n_chunks: int) -> list[list]:
    """Split a list into ~ n_chunks contiguous slices."""
    n_chunks = max(1, min(n_chunks, len(seq)))
    size = (len(seq) + n_chunks - 1) // n_chunks
    return [seq[i:i + size] for i in range(0, len(seq), size)]


def _index_slices(size: int, n_chunks: int) -> list[tuple[int, int]]:
    """Arithmetically split 0..size into ≤ n_chunks contiguous [start, end) ranges."""
    n_chunks = max(1, min(n_chunks, size))
    span = (size + n_chunks - 1) // n_chunks
    return [(i, min(i + span, size)) for i in range(0, size, span)]


def _watch_stop(stop, mp_stop) -> None:
    """Parent-side bridge: user (thread) event -> shared mp.Event for workers."""
    while not mp_stop.is_set():
        if stop.is_set():
            mp_stop.set()
            return
        time.sleep(0.1)


def crack_dictionary(target_hash: str, algorithm: str, words: list[str],
                     workers: int = 4, use_processes: bool = False,
                     salt: str = "", position: str = "append",
                     progress_callback=None, stop: threading.Event | None = None) -> dict:
    """
    Crack `target_hash` (hex, lowercase) using the given candidate words.

    Returns a result dict:
        {found, plaintext, attempts, elapsed, rate, workers, engine,
         total_candidates, aborted}
    Set `stop` (threading.Event) to abort cooperatively.
    """
    started = time.perf_counter()
    target_hash = target_hash.strip().lower()
    total = len(words)
    aborted = False

    if workers <= 1 or total <= 1 or (not use_processes):
        globals()["_STOP_HIT"] = (stop.is_set if stop is not None else _STOP_HIT)
        progress = _ThreadProgress(total, progress_callback)
        found = None
        try:
            for block in _chunkify(words, workers * 4):
                found = _probe_block(block, target_hash, algorithm, salt, position, progress)
                if found:
                    break
        except SearchAborted:
            aborted = True
        globals()["_STOP_HIT"] = _STOP_HIT  # restore
        attempts = progress.count
        engine = "threading"
        worker_count = max(1, workers)
    elif use_processes:
        if not _MP_AVAILABLE:
            raise RuntimeError("multiprocessing unavailable on this platform")
        counter = _mp.Value("L", 0)
        lock = _mp.Lock()
        mp_stop = _mp.Event()
        if stop is not None and stop.is_set():
            mp_stop.set()
        if stop is not None:
            threading.Thread(target=_watch_stop, args=(stop, mp_stop), daemon=True).start()
        progress = _MultiprocessProgress(counter, lock, total, workers, progress_callback)
        tasks = _chunkify(words, workers)
        with ProcessPoolExecutor(
                max_workers=workers,
                initializer=_mp_init,
                initargs=(counter, lock, target_hash, algorithm, salt, position,
                          mp_stop)) as pool:
            futures = [pool.submit(_mp_probe_wordlist_block, block) for block in tasks]
            found = None
            pending = set(futures)
            try:
                while pending:
                    done, pending = concurrent.futures.wait(
                        pending, timeout=0.25,
                        return_when=concurrent.futures.FIRST_COMPLETED)
                    progress.sample()           # live progress from shared Value
                    for fut in done:
                        hit = fut.result()
                        if hit and not found:
                            found = hit[1]
            except SearchAborted:
                aborted = True
                for f in futures:
                    f.cancel()
            attempts = counter.value
        engine = "multiprocessing"
        worker_count = workers
    else:
        return {}

    elapsed = max(time.perf_counter() - started, 1e-9)
    return {
        "found": found is not None,
        "plaintext": found,
        "attempts": attempts,
        "elapsed": elapsed,
        "rate": attempts / elapsed,
        "workers": worker_count,
        "engine": engine,
        "total_candidates": total,
        "aborted": aborted,
    }


class _MultiprocessProgress:
    """Drives the live callback by sampling a shared mp.Value."""

    def __init__(self, counter, lock, total, workers, callback):
        self.counter = counter
        self.lock = lock
        self.total = total
        self.workers = workers
        self.callback = callback

    def bump(self, n):
        pass  # workers hold the mp.Value themselves

    @property
    def count(self):
        with self.lock:
            return self.counter.value

    def sample(self):
        with self.lock:
            n = self.counter.value
        if self.callback:
            self.callback(n, self.total)


def _mp_probe_wordlist_block(block):
    """Worker entrypoint for ProcessPoolExecutor dictionary mode."""
    counter, lock = _MP["counter"], _MP["lock"]
    progress = _MpCounter(counter, lock)
    hit = _probe_block(block, _MP["target"], _MP["algorithm"],
                       _MP["salt"], _MP["position"], progress)
    if hit:
        return (block.index(hit), hit)
    return None


class _MpCounter:
    def __init__(self, counter, lock):
        self.counter = counter
        self.lock = lock

    def bump(self, n):
        with self.lock:
            self.counter.value += n

    @property
    def count(self):
        with self.lock:
            return self.counter.value


# ---------------------------------------------------------------------------
# Brute-force engine (radix-indexed keyspace, mathematically partitioned)
# ---------------------------------------------------------------------------

def _keyspace_size(charset_len: int, min_len: int, max_len: int) -> int:
    return sum(charset_len ** n for n in range(min_len, max_len + 1))


def _word_at_index(index: int, charset: str, length: int) -> str:
    """Map a linear keyspace index to its candidate string (no iteration)."""
    base = len(charset)
    chars = []
    for _ in range(length):
        index, r = divmod(index, base)
        chars.append(charset[r])
    return "".join(reversed(chars))


def crack_bruteforce(target_hash: str, algorithm: str, charset: str,
                     min_len: int, max_len: int, workers: int = 4,
                     use_processes: bool = False, salt: str = "",
                     position: str = "append", progress_callback=None,
                     stop: threading.Event | None = None) -> dict:
    """Brute-force `target_hash` over every permutation of `charset`."""
    target_hash = target_hash.strip().lower()
    base = len(charset)
    if base < 1:
        raise ValueError("charset is empty")
    total = _keyspace_size(base, min_len, max_len)

    # Build (length, start_index, end_index) work slices — arithmetic only,
    # so enormous keyspaces never get materialized in RAM.
    slices = []
    for n in range(min_len, max_len + 1):
        size_n = base ** n
        for start, end in _index_slices(size_n, workers):
            slices.append((n, start, end))

    started = time.perf_counter()
    found = None
    aborted = False

    if use_processes and _MP_AVAILABLE and workers > 1:
        counter = _mp.Value("L", 0)
        lock = _mp.Lock()
        mp_stop = _mp.Event()
        if stop is not None and stop.is_set():
            mp_stop.set()
        if stop is not None:
            threading.Thread(target=_watch_stop, args=(stop, mp_stop), daemon=True).start()
        self_prog = _MultiprocessProgress(counter, lock, total, workers, progress_callback)
        with ProcessPoolExecutor(
                max_workers=workers,
                initializer=_mp_init,
                initargs=(counter, lock, target_hash, algorithm, salt, position,
                          mp_stop)) as pool:
            futures = [pool.submit(_mp_probe_brute_slice, n, a, b, charset)
                       for n, a, b in slices]
            try:
                for fut in futures:
                    hit = fut.result()
                    if hit and not found:
                        found = hit
                    self_prog.sample()
            except SearchAborted:
                aborted = True
                for f in futures:
                    f.cancel()
        attempts = counter.value
        engine = "multiprocessing"
    else:
        globals()["_STOP_HIT"] = (stop.is_set if stop is not None else _STOP_HIT)
        progress = _ThreadProgress(total, progress_callback)
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = [
                pool.submit(_probe_brute_slice, n, a, b, charset,
                            target_hash, algorithm, salt, position, progress)
                for n, a, b in slices
            ]
            try:
                for fut in futures:
                    hit = fut.result()
                    if hit and not found:
                        found = hit
            except SearchAborted:
                aborted = True
                for f in futures:
                    f.cancel()
        globals()["_STOP_HIT"] = _STOP_HIT
        attempts = progress.count
        engine = "threading"

    elapsed = max(time.perf_counter() - started, 1e-9)
    return {
        "found": found is not None,
        "plaintext": found,
        "attempts": attempts,
        "elapsed": elapsed,
        "rate": attempts / elapsed,
        "workers": workers,
        "engine": engine,
        "total_candidates": total,
        "keyspace": total,
        "aborted": aborted,
    }


def _probe_brute_slice(n, start, end, charset, target_hash, algorithm,
                       salt, position, progress):
    digest = compute_digest
    new_hash = hashlib.new
    salted = _salted
    bump_every = 4096
    since = 0
    for idx in range(start, end):
        word = _word_at_index(idx, charset, n)
        candidate = salted(word, salt, position)
        if algorithm == "ntlm":
            computed = _md4(candidate.encode("utf-16-le", "replace")).hex()
        else:
            computed = new_hash(HASHLIB_ALGOS[algorithm],
                                candidate.encode("utf-8", "surrogatepass")).hexdigest()
        if computed == target_hash:
            progress.bump(since + 1)
            return candidate
        since += 1
        if since >= bump_every:
            progress.bump(since)
            since = 0
            if _STOP_HIT():
                raise SearchAborted()
    if since:
        progress.bump(since)
    return None


def _mp_probe_brute_slice(n, start, end, charset):
    counter, lock = _MP["counter"], _MP["lock"]
    progress = _MpCounter(counter, lock)
    return _probe_brute_slice(n, start, end, charset, _MP["target"],
                              _MP["algorithm"], _MP["salt"], _MP["position"],
                              progress)


# ---------------------------------------------------------------------------
# One-call convenience for the CLI and web dashboard
# ---------------------------------------------------------------------------

def crack(target_hash: str, algorithm: str | None = None, words: list[str] | None = None,
          wordlist_path: str | None = None, brute_charset: str | None = None,
          brute_lengths: tuple[int, int] = (1, 6), workers: int = 4,
          use_processes: bool = False, salt: str = "", position: str = "append",
          progress_callback=None, stop: threading.Event | None = None) -> dict:
    """
    Unified entry point. Tries dictionary first (if words given), then
    brute force (if a charset is given). Returns the winning metadata dict,
    enriched with `algorithm` and `target`.
    """
    algo = resolve_algorithm(algorithm) if algorithm else None
    if algo is None:
        from .identifier import analyze_hash
        analysis = analyze_hash(target_hash)
        if analysis.crackable is None:
            raise ValueError("could not identify a crackable algorithm for this hash")
        algo = analysis.crackable

    if words is None and wordlist_path:
        words = load_wordlist(wordlist_path)

    results: list[dict] = []
    if words:
        res = crack_dictionary(target_hash, algo, words, workers, use_processes,
                               salt, position, progress_callback, stop=stop)
        res["method"] = "dictionary"
        res["algorithm"] = algo
        res["target"] = target_hash
        results.append(res)
        if res["found"] or res.get("aborted"):
            return res

    if brute_charset:
        res = crack_bruteforce(target_hash, algo, brute_charset,
                               brute_lengths[0], brute_lengths[1], workers,
                               use_processes, salt, position, progress_callback,
                               stop=stop)
        res["method"] = "bruteforce"
        res["algorithm"] = algo
        res["target"] = target_hash
        results.append(res)
        if res["found"] or res.get("aborted"):
            return res

    if results:
        return results[-1] if not results[0]["found"] else results[0]
    raise ValueError("no attack mode provided: supply a wordlist and/or brute charset")


def universal_crack(target_hash: str, words: list[str], workers: int = 4,
                    use_processes: bool = False) -> dict | None:
    """
    'Auto mode': the wordlist is replayed against every algorithm compatible
    with the hash's length. Used when the user can't be sure which algorithm
    produced the hash (e.g. MD5 vs NTLM, both 32 hex chars).
    """
    from .identifier import analyze_hash
    analysis = analyze_hash(target_hash)
    engine_name = analysis.crackable
    if engine_name is None:
        return None
    aliases = {"md5": ["md5"], "ntlm": ["ntlm"], "md4": ["ntlm"]}
    candidates = aliases.get(engine_name, [engine_name])
    if len(target_hash) == 32:
        candidates = ["md5", "ntlm"]          # ambiguous: try both
    for algo in candidates:
        res = crack_dictionary(target_hash, algo, words, workers, use_processes)
        if res["found"]:
            res["algorithm"] = algo
            res["target"] = target_hash
            res["method"] = "dictionary"
            return res
    last = crack_dictionary(target_hash, candidates[0], words, workers, use_processes)
    last["algorithm"] = candidates[0]
    last["target"] = target_hash
    last["method"] = "dictionary"
    return last


if __name__ == "__main__":
    # quick self-test
    t = hashlib.sha256(b"abc").hexdigest()
    print(crack_bruteforce(t, "sha256", "abcxyz", 3, 3, workers=4))
