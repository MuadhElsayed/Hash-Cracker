#!/usr/bin/env python3
"""
HashCrypt — credential auditing console (Phase 3 interface).

    hashcrypt identify <hash>          identify a hash's algorithm
    hashcrypt crack <hash> -w W ...    dictionary / brute-force attack
    hashcrypt history                  review saved audit records
    hashcrypt stats                    aggregate audit statistics
    hashcrypt web [--port N]           launch the Flask live dashboard

Run `hashcrypt --help` or `hashcrypt crack --help` for full option lists.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sqlite3
import sys
import threading
import time

# allow `python hashcrypt/cli.py` from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hashcrypt import __version__, cracker, identifier, storage  # noqa: E402

# ---------------------------------------------------------------------------
# Color management
# ---------------------------------------------------------------------------

GREEN, RED, YELLOW, CYAN, BLUE, MAGENTA, DIM, BOLD = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[94m",
    "\033[95m", "\033[2m", "\033[1m")
RESET = "\033[0m"

_USE_COLOR = sys.stdout.isatty()      # never emit codes into pipes/logs

# ---------------------------------------------------------------------------
# Banner — a programmatically-rendered pixel-art logotype (no trailing
# whitespace, guaranteed alignment) + framed info panel. DANGER palette.
# ---------------------------------------------------------------------------

_PIXEL_FONT: dict[str, list[str]] = {
    "H": ["#   #", "#   #", "#   #", "#####",
          "#   #", "#   #", "#   #"],
    "A": [" ### ", "#   #", "#   #", "#####",
          "#   #", "#   #", "#   #"],
    "S": [" ####", "#    ", "#    ", " ### ",
          "    #", "    #", "#### "],
    "C": [" ### ", "#   #", "#    ", "#    ",
          "#    ", "#   #", " ### "],
    "R": ["#### ", "#   #", "#   #", "#### ",
          "# #  ", "#  # ", "#   #"],
    "Y": ["#   #", "#   #", " # # ", "  #  ",
          "  #  ", "  #  ", "  #  "],
    "P": ["#### ", "#   #", "#   #", "#### ",
          "#    ", "#    ", "#    "],
    "T": ["#####", "  #  ", "  #  ", "  #  ",
          "  #  ", "  #  ", "  #  "],
}
# 256-color red gradient (bright → deep)
_R1 = "\033[38;5;196m"
_R2 = "\033[38;5;160m"
_R3 = "\033[38;5;124m"
_DECK_DOWN = [_R1, _R1, _R2, _R2, _R2, _R3, _R3]
_DECK_UP = list(reversed(_DECK_DOWN))

W = 78                                  # banner design width (fits 80-col TTYs)


def _logo_rows(word: str) -> list[str]:
    """Render a word at ×2 scale: every pixel column becomes two display cols."""
    letters: list[list[str]] = []
    for ch in word.upper():
        if ch in _PIXEL_FONT:
            letters.append(["".join("██" if c == "#" else "  " for c in row)
                            for row in _PIXEL_FONT[ch]])
    return [" ".join(letter[r] for letter in letters) for r in range(7)]


def _vlen(s: str) -> int:
    """Visible length of a possibly-ANSI-colored string."""
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def _center(text: str, width: int, fill: str = " ") -> str:
    pad = max(0, width - _vlen(text))
    left = pad // 2
    return fill * left + text + fill * (pad - left)


def _hexrain(width: int) -> str:
    """Decorative fake-hash strip — fresh bytes on every launch."""
    chunks: list[str] = []
    while True:
        chunk = os.urandom(4).hex()
        if chunks and len(" ".join(chunks + [chunk])) > width:
            break
        chunks.append(chunk)
    return " ".join(chunks)


def c_rail(s: str) -> str:
    """Bright rail color for the info lines."""
    return s if not _USE_COLOR else f"{BOLD}{_R1}{s}{RESET}"


def c_lab(s: str) -> str:
    """Deep label color for the info lines."""
    return s if not _USE_COLOR else f"{_R2}{s}{RESET}"


def _rail(label: str, value: str) -> str:
    """One info row with glowing side rails, padded to the design width."""
    lab = f"{label:<9}"
    pad = max(0, W - 13 - _vlen(value))
    return c_rail("▐") + " " + c_lab(lab) + value + " " * pad + c_rail("▐")


def _banner() -> str:
    """Compose the v3 DANGER banner honoring the current color mode."""
    c = (lambda s, col: s if not _USE_COLOR else f"{col}{s}{RESET}")

    sid = "0x" + os.urandom(4).hex().upper()
    nproc = os.cpu_count() or 1

    lines: list[str] = []
    # hex-rain canopies (fresh bytes every launch)
    rain = _center("▒▒ " + _hexrain(W - 14) + " ▒▒", W, "·")
    lines.append(c(rain, _R3))
    lines.append("")
    # chunky double-width logotype in two decks (bright → deep gradient)
    for i, row in enumerate(_logo_rows("HASH")):
        lines.append(c("  " + row, _DECK_DOWN[i]))
    for i, row in enumerate(_logo_rows("CRYPT")):
        lines.append(c("  " + row, _DECK_UP[i]))
    lines.append("")
    # glow divider
    lines.append(c(_center("☠ ─────  D A N G E R   Z O N E  ───── ☠", W, "─"), _R1))
    lines.append("")
    # command chips
    chips = "  ".join(c("[ " + m + " ]", _R2)
                      for m in ("identify", "crack", "history", "stats", "web"))
    lines.append(_center(chips, W))
    lines.append("")
    # info rails
    lines.append(_rail("engine", "hashlib · threads · processes · abort-safe"))
    lines.append(_rail("wordlist", "wordlists/ · /usr/share/wordlists/*"))
    lines.append(_rail("session", sid + " · pid " + str(os.getpid())
                       + " · " + str(nproc) + " cores"))
    lines.append("")
    # DANGER ribbon + bottom canopy
    ribbon = "☠ DANGER MODE ACTIVE · v" + __version__ + " · destructive capability ☠"
    lines.append(c(_center(ribbon, W, "─"), BOLD + _R1))
    lines.append(c(_center("▒▒ " + _hexrain(W - 14) + " ▒▒", W, "·"), _R3))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Live progress renderer (single-line, redrawn ~6×/s from a daemon thread)
# ---------------------------------------------------------------------------

def _fmt(n: float) -> str:
    """Compact number formatting: 1.2k / 3.4M / 2.1G."""
    for unit, div in (("G", 1e9), ("M", 1e6), ("k", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.1f}{unit}"
    return f"{n:,.0f}"


class LiveProgress:
    def __init__(self, total: int | None, algorithm: str, label: str):
        self.total = total
        self.algorithm = algorithm
        self.label = label
        self.count = 0
        self.started = time.perf_counter()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._is_tty = sys.stdout.isatty()
        if self._is_tty:                              # live line renderer
            threading.Thread(target=self._spin, daemon=True).start()

    def __call__(self, count: int, total: int | None):
        with self._lock:
            self.count = count
            if total:
                self.total = total

    def _render(self) -> str:
        now = time.perf_counter()
        rate = self.count / max(now - self.started, 1e-9)
        base = f"[{self.label}]"
        if self.total:
            pct = min(self.count / self.total * 100, 100.0)
            filled = int(pct / 100 * 26)
            bar = ("█" * filled).ljust(26, "░")
            eta = (self.total - self.count) / rate if rate > 0 else 0
            return (f"{c_dim(base)} {c_Y(f'|{bar}|')}  "
                    f"{pct:5.1f}%  {_fmt(self.count)} / {_fmt(self.total)}  "
                    f"{c_C(f'{_fmt(rate)} h/s')}  "
                    f"ETA {time.strftime('%H:%M:%S', time.gmtime(eta))}  "
                    f"· {self.algorithm}")
        return (f"{c_dim(base)} {_fmt(self.count)} tried  "
                f"{c_C(f'{_fmt(rate)} h/s')}  · {self.algorithm}")

    def _spin(self):
        while not self._stop.wait(0.15):
            sys.stdout.write("\r\033[K" + self._render())
            sys.stdout.flush()

    def finish(self, found: bool, plaintext: str | None, aborted: bool = False):
        self._stop.set()
        if self._is_tty:
            sys.stdout.write("\r\033[K" + self._render() + "\n")
            sys.stdout.flush()
        if aborted:
            sys.stdout.write(f"{YELLOW}[⏹] aborted{RESET} — partial scan, "
                             "no session logged.\n")
        elif found:
            sys.stdout.write(f"{GREEN}[✓] CRACKED{RESET} → {BOLD}{plaintext}{RESET}\n")
        else:
            sys.stdout.write(f"{RED}[✗] exhausted{RESET} — no match in this "
                             "candidate set.\n")


def c_dim(s: str) -> str:
    return s if not _USE_COLOR else f"{DIM}{s}{RESET}"


def c_Y(s: str) -> str:
    """Danger-palette bar color."""
    return s if not _USE_COLOR else f"{RED}{s}{RESET}"


def c_C(s: str) -> str:
    """Danger-palette accent (was cyan)."""
    return s if not _USE_COLOR else f"{RED}{s}{RESET}"


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_identify(args) -> int:
    analysis = identifier.analyze_hash(args.hash)
    print(analysis)
    return 0


def cmd_gen(args) -> int:
    """Utility: generate reference hashes for testing."""
    for algo in args.algorithms:
        try:
            algo_n = cracker.resolve_algorithm(algo)
        except ValueError as e:
            print(f"{RED}{e}{RESET}")
            return 2
        if algo_n == "ntlm":
            digest = cracker._md4(args.word.encode("utf-16-le")).hex()
        else:
            digest = hashlib.new(cracker.HASHLIB_ALGOS[algo_n],
                                 args.word.encode()).hexdigest()
        print(f"{cracker.FRIENDLY_NAMES[algo_n]:<14} {digest}   (plaintext: {args.word!r})")
    return 0


def cmd_crack(args) -> int:
    """Run a full cracking session: identify → attack → report → audit-log."""
    target = args.hash.strip().lower()
    analysis = identifier.analyze_hash(target)

    print(f"{c_C('[*] Target')}     : {target}")
    print(f"    best guess : {BOLD}{analysis.best or 'unknown'}{RESET}"
          if _USE_COLOR else f"    best guess : {analysis.best or 'unknown'}")

    # ---- decide algorithm(s) -------------------------------------------------
    try:
        if args.algo:
            algos = [cracker.resolve_algorithm(args.algo)]
        elif analysis.crackable and len(target) == 32:
            algos = None        # MD5/NTLM ambiguous — try both
        elif analysis.crackable:
            algos = [analysis.crackable]
        else:
            print(f"{RED}[!] Could not map this hash to a crackable algorithm.{RESET}")
            cm = input("    Force an algorithm anyway (md5/ntlm/sha1/sha256/sha512)? "
                       "[blank=abort]: ")
            algos = [cracker.resolve_algorithm(cm)] if cm else None
            if not algos:
                return 2
    except ValueError as e:
        print(f"{RED}[!] {e}{RESET}")
        return 2

    # ---- gather candidates ---------------------------------------------------
    words: list[str] | None = None
    if args.wordlist:
        try:
            words = cracker.load_wordlist(args.wordlist)
            print(f"{c_C('[*] Wordlist')}   : {args.wordlist} "
                  f"({len(words):,} unique entries)")
        except FileNotFoundError as e:
            print(f"{RED}[!] {e}{RESET}")
            return 2

    if not words and not args.brute:
        print(f"{RED}[!] Nothing to do — provide -w WORDLIST and/or -b CHARSET.{RESET}")
        return 2

    stop = threading.Event()
    db = None
    if not args.no_log:
        try:
            db = storage.AuditDB(args.db)
        except sqlite3.Error as e:
            print(f"{YELLOW}[!] Could not open audit DB ({e}); continuing without "
                  "logging.{RESET}")

    total_result = None
    ret = 1
    try:
        # ---- dictionary passes ------------------------------------------------
        passes = []
        if words:
            passes = ["md5", "ntlm"] if algos is None else [algos[0]]

        all_found = None
        for algo in passes:
            label = f"dict/{cracker.FRIENDLY_NAMES[algo]}"
            lp = LiveProgress(len(words), cracker.FRIENDLY_NAMES[algo], label)
            res = cracker.crack_dictionary(
                target, algo, words, workers=args.threads,
                use_processes=args.processes,
                salt=args.salt or "", position=args.salt_pos,
                progress_callback=lp, stop=stop)
            total_result = res
            res["algorithm"], res["method"], res["target"] = algo, "dictionary", target
            lp.finish(res["found"], res["plaintext"], res.get("aborted", False))
            if res.get("aborted"):
                return 130
            if res["found"]:
                all_found = res
                break

        # ---- brute-force pass -------------------------------------------------
        if not all_found and args.brute:
            algo = algos[0] if algos else analysis.crackable or "md5"
            keyspace = cracker._keyspace_size(len(args.brute), *args.lengths)
            label = f"brute/{cracker.FRIENDLY_NAMES[algo]}"
            print(f"{c_C('[*] Brute-force keyspace')}  : {keyspace:,} candidates "
                  f"({len(args.brute)}^len {args.lengths[0]}..{args.lengths[1]})")
            lp = LiveProgress(keyspace, cracker.FRIENDLY_NAMES[algo], label)
            res = cracker.crack_bruteforce(
                target, algo, args.brute, *args.lengths, workers=args.threads,
                use_processes=args.processes, salt=args.salt or "",
                position=args.salt_pos, progress_callback=lp, stop=stop)
            total_result = res
            res["algorithm"], res["method"], res["target"] = algo, "bruteforce", target
            lp.finish(res["found"], res["plaintext"], res.get("aborted", False))
            if res.get("aborted"):
                return 130
            if res["found"]:
                all_found = res

        # ---- report -----------------------------------------------------------
        if all_found:
            res = all_found
            print(f"{GREEN}{'═' * 74}{RESET}")
            print(f"  {GREEN}PASSWORD{RESET}  {BOLD}{res['plaintext']}{RESET}")
            print(f"  {c_C('ALGORITHM')}  {res['algorithm']}   "
                  f"{c_C('HASH')}  {res['target']}")
            print(f"  {c_C('ATTEMPTS')}   {res['attempts']:,} / "
                  f"{res['total_candidates']:,}")
            print(f"  {c_C('TIME')}      {res['elapsed']:.3f}s  @  "
                  f"{res['rate']:,.0f} h/s")
            print(f"  {c_C('ENGINE')}    {res['engine']} × {res['workers']} "
                  f"worker(s) — {res['method']}")
            print(f"{GREEN}{'═' * 74}{RESET}")
        else:
            print(f"{RED}[!] No match recovered in "
                  f"{total_result['attempts']:,} attempts "
                  f"over {total_result['elapsed']:.2f}s.{RESET}")
            print(f"{DIM}    hints: bigger wordlist? --salt? "
                  f"--algo ntlm? brute-force charset?{RESET}")
        ret = 0 if all_found else 1

        # ---- audit log ---------------------------------------------------------
        if db is not None:
            if words:
                db.log_wordlist(args.wordlist, len(words))
            db.log_session(storage.AuditRecord(
                algorithm=(all_found or total_result)["algorithm"],
                target_hash=target,
                method=(all_found or total_result)["method"],
                found=bool(all_found),
                plaintext=all_found["plaintext"] if all_found else None,
                attempts=total_result["attempts"],
                total_candidates=total_result["total_candidates"],
                elapsed_sec=total_result["elapsed"],
                rate_hps=total_result["rate"],
                workers=total_result["workers"],
                engine=total_result["engine"],
                wordlist=args.wordlist,
                salt_used=args.salt,
                user_note=args.note,
            ))
            if all_found:
                print(f"{DIM}[i] Session saved to {args.db}{RESET}")
        return ret
    except KeyboardInterrupt:
        stop.set()
        time.sleep(0.4)
        raise
    finally:
        if db is not None:
            db.close()


def cmd_history(args) -> int:
    if not os.path.exists(args.db):
        print(f"{YELLOW}No audit database yet at {args.db}{RESET}")
        return 0
    storage.print_history(args.db, args.limit, args.found_only, args.algo)
    return 0


def cmd_stats(args) -> int:
    """Aggregate audit statistics for reporting / policy review."""
    if not os.path.exists(args.db):
        print(f"{YELLOW}No audit database yet at {args.db}{RESET}")
        return 0
    db = storage.AuditDB(args.db)
    try:
        rows = db.history(limit=10_000)
        if not rows:
            print("No sessions recorded yet.")
            return 0
        sessions = len(rows)
        cracked = sum(r["found"] for r in rows)
        attempts = sum(r["attempts"] for r in rows)
        elapsed_sum = sum(r["elapsed_sec"] for r in rows)
        best = max(rows, key=lambda r: r["rate_hps"])
        by_algo: dict[str, int] = {}
        by_method: dict[str, int] = {}
        for r in rows:
            by_algo[r["hash_algo"]] = by_algo.get(r["hash_algo"], 0) + 1
            by_method[r["method"]] = by_method.get(r["method"], 0) + r["found"]

        print(f"{BOLD}HashCrypt session statistics{RESET}  ({args.db})")
        print(f"{'═' * 74}")
        print(f"  sessions        : {sessions:>10,}")
        print(f"  cracked         : {cracked:>10,}  "
              f"({cracked / sessions * 100:.1f}% success rate)")
        print(f"  failed          : {sessions - cracked:>10,}")
        print(f"  total attempts  : {attempts:>10,}")
        print(f"  cpu time spent  : {elapsed_sum:>10,.1f}s "
              f"(≈ {time.strftime('%H:%M:%S', time.gmtime(elapsed_sum))})")
        print(f"  best rate       : {best['rate_hps']:>10,.0f} h/s   "
              f"[{best['hash_algo']} · {best['engine']} × {best['workers']}]")
        print(f"  ----------------")
        print(f"  by algorithm    : "
              + ", ".join(f"{k} × {v}" for k, v in
                          sorted(by_algo.items(), key=lambda kv: -kv[1])))
        print(f"  cracked by method: "
              + ", ".join(f"{k} × {v}" for k, v in
                          sorted(by_method.items(), key=lambda kv: -kv[1])))
        print(f"  last session    : {rows[0]['ts_utc']} "
              f"— {'CRACKED' if rows[0]['found'] else 'no match'}"
              f" ({rows[0]['plaintext'] or '-'})")
        print(f"{'═' * 74}")
        print(f"{DIM}  wordlists tracked : {db.stats()['wordlists_tracked']}{RESET}")
        return 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="hashcrypt",
        description="Multi-threaded hash cracker with auto identification, "
                    "dictionary & brute-force engines, and SQLite audit logging.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version=f"HashCrypt v{__version__}")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colors")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("identify", help="identify a hash's algorithm")
    p_id.add_argument("hash")

    p_gen = sub.add_parser("gen", help="generate hashes of a word (for testing)")
    p_gen.add_argument("word")
    p_gen.add_argument("--algorithms", nargs="+",
                       default=["md5", "ntlm", "sha1", "sha256", "sha512"])

    p_crack = sub.add_parser("crack", help="run a cracking session")
    p_crack.add_argument("hash")
    p_crack.add_argument("-w", "--wordlist", help="path to a dictionary wordlist")
    p_crack.add_argument("-a", "--algo",
                         help="force algorithm (md5, ntlm, sha1, sha256, sha512, ...)")
    p_crack.add_argument("-b", "--brute",
                         help="brute-force charset, e.g. '0123456789'")
    p_crack.add_argument("-l", "--lengths", nargs=2, type=int, metavar=("MIN", "MAX"),
                         default=[1, 6], help="brute-force length range")
    p_crack.add_argument("-t", "--threads", type=int, default=4,
                         help="worker threads/processes")
    p_crack.add_argument("-p", "--processes", action="store_true",
                         help="use the multiprocess engine instead of threads")
    p_crack.add_argument("--salt", help="salt string appended/prepended to candidates")
    p_crack.add_argument("--salt-pos", choices=["append", "prepend"], default="append")
    p_crack.add_argument("--db", default=storage.DEFAULT_DB, help="audit database path")
    p_crack.add_argument("--no-log", action="store_true",
                         help="skip writing to the audit database")
    p_crack.add_argument("--note", help="free-text note stored with the audit record")

    p_hist = sub.add_parser("history", help="review saved audit records")
    p_hist.add_argument("--found-only", action="store_true")
    p_hist.add_argument("--algo")
    p_hist.add_argument("--limit", type=int, default=25)
    p_hist.add_argument("--db", default=storage.DEFAULT_DB, help="audit database path")

    p_stats = sub.add_parser("stats", help="aggregate session statistics")
    p_stats.add_argument("--db", default=storage.DEFAULT_DB, help="audit database path")

    p_web = sub.add_parser("web", help="launch the Flask live dashboard")
    p_web.add_argument("--host", default="127.0.0.1")
    p_web.add_argument("--port", type=int, default=5000)

    # accept `--no-color` either before or after the sub-command
    for _p in (p_id, p_gen, p_crack, p_hist, p_stats, p_web):
        _p.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)

    args = parser.parse_args(argv)
    no_color = getattr(args, "no_color", False)
    if no_color or not _USE_COLOR:
        globals().update({k: "" for k in
                          ("GREEN", "RED", "YELLOW", "CYAN", "BLUE", "MAGENTA",
                           "DIM", "BOLD", "RESET")})

    print(_banner())

    try:
        if args.cmd == "identify":
            return cmd_identify(args)
        if args.cmd == "gen":
            return cmd_gen(args)
        if args.cmd == "history":
            return cmd_history(args)
        if args.cmd == "stats":
            return cmd_stats(args)
        if args.cmd == "web":
            from hashcrypt import webapp
            webapp.run(args.host, args.port)
            return 0
        if args.cmd == "crack":
            return cmd_crack(args)
        return 1
    except KeyboardInterrupt:
        # engines already got the stopEvent via KeyboardInterrupt handling
        print(f"\n{YELLOW}[⏹] interrupted by user (Ctrl+C){RESET}")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
