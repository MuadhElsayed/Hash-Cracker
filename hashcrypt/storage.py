"""
Phase 4: Result Storage & Audit Logging.

Persists every cracking session into a local SQLite database so that recovered
plaintexts, timings and attempt counts can be reviewed later for credential
policy/security reporting.

Tables
------
crack_sessions : one row per crack attempt (success OR failure) — the audit log
wordlist_stats : cached statistics about the wordlists used
"""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "data", "audit_log.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS crack_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc        TEXT    NOT NULL,
    hash_algo     TEXT    NOT NULL,
    target_hash   TEXT    NOT NULL,
    method        TEXT    NOT NULL,
    found         INTEGER NOT NULL,
    plaintext     TEXT,
    attempts      INTEGER NOT NULL,
    total_candidates INTEGER NOT NULL,
    elapsed_sec   REAL    NOT NULL,
    rate_hps      REAL    NOT NULL,
    workers       INTEGER NOT NULL,
    engine        TEXT    NOT NULL,
    wordlist      TEXT,
    salt_used     TEXT,
    user_note     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_target ON crack_sessions(target_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_ts     ON crack_sessions(ts_utc);

CREATE TABLE IF NOT EXISTS wordlist_stats (
    path        TEXT PRIMARY KEY,
    entries     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    last_used   TEXT    NOT NULL
);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class AuditRecord:
    """One row for crack_sessions."""
    algorithm: str
    target_hash: str
    method: str                  # 'dictionary' | 'bruteforce'
    found: bool
    plaintext: str | None
    attempts: int
    total_candidates: int
    elapsed_sec: float
    rate_hps: float
    workers: int
    engine: str                  # 'threading' | 'multiprocessing'
    wordlist: str | None = None
    salt_used: str | None = None
    user_note: str | None = None


class AuditDB:
    """Thin SQLite wrapper. Databases live in ./data by default."""

    def __init__(self, path: str = DEFAULT_DB):
        self.path = path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- write ---------------------------------------------------------------
    def log_session(self, rec: AuditRecord) -> int:
        cur = self._conn.execute(
            """INSERT INTO crack_sessions
               (ts_utc, hash_algo, target_hash, method, found, plaintext,
                attempts, total_candidates, elapsed_sec, rate_hps, workers,
                engine, wordlist, salt_used, user_note)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (utc_now_iso(), rec.algorithm, rec.target_hash, rec.method,
             int(rec.found), rec.plaintext, rec.attempts, rec.total_candidates,
             rec.elapsed_sec, rec.rate_hps, rec.workers, rec.engine,
             rec.wordlist, rec.salt_used, rec.user_note))
        self._conn.commit()
        return cur.lastrowid

    def log_wordlist(self, path: str, entries: int) -> None:
        try:
            nbytes = os.path.getsize(path)
        except OSError:
            nbytes = -1
        self._conn.execute(
            """INSERT INTO wordlist_stats (path, entries, bytes, last_used)
               VALUES (?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET
                   entries=excluded.entries, bytes=excluded.bytes,
                   last_used=excluded.last_used""",
            (path, entries, nbytes, utc_now_iso()))
        self._conn.commit()

    # -- read ----------------------------------------------------------------
    def history(self, limit: int = 25, only_found: bool = False,
                algo: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM crack_sessions"
        clauses, params = [], []
        if only_found:
            clauses.append("found = 1")
        if algo:
            clauses.append("hash_algo = ?")
            params.append(algo)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return self._conn.execute(sql, params).fetchall()

    def stats(self) -> dict:
        cur = self._conn.execute(
            """SELECT COUNT(*) AS sessions,
                      SUM(found) AS cracked,
                      SUM(attempts) AS total_attempts,
                      AVG(elapsed_sec) AS avg_elapsed,
                      MAX(rate_hps) AS best_rate
               FROM crack_sessions""").fetchone()
        wl = self._conn.execute("SELECT COUNT(*) AS lists FROM wordlist_stats").fetchone()
        return dict(cur) | {"wordlists_tracked": wl["lists"]}

    def close(self):
        self._conn.close()


def fmt_session_row(row: sqlite3.Row) -> str:
    status = "CRACKED" if row["found"] else "failed "
    plain = row["plaintext"] if row["found"] else "-"
    wordlist = (row["wordlist"] or "-")
    short_wl = os.path.basename(str(wordlist)) if wordlist != "-" else "-"
    return (f"[{row['id']:>4}] {status} | {row['ts_utc']} | "
            f"{row['hash_algo']:<9} | {row['target_hash'][:16]:<16}… "
            f"-> {plain:<24} | {row['attempts']:>10,} attempts | "
            f"{row['elapsed_sec']:>7.2f}s | {row['rate_hps']:>10,.0f} h/s | "
            f"{row['workers']}w/{row['engine']:<14} | {row['method']:<10} | {short_wl}")


def print_history(path: str = DEFAULT_DB, limit: int = 25,
                  only_found: bool = False, algo: str | None = None) -> None:
    if not os.path.exists(path):
        print(f"No audit database yet at {path}")
        return
    db = AuditDB(path)
    try:
        rows = db.history(limit=limit, only_found=only_found, algo=algo)
        if not rows:
            print("No sessions recorded yet.")
            return
        print(f"{'=' * 118}\nCracking audit history  ({path})\n{'=' * 118}")
        for r in rows:
            print(fmt_session_row(r))
        s = db.stats()
        print('-' * 118)
        print(f"Sessions: {s['sessions']} | Cracked: {s['cracked'] or 0} | "
              f"Total attempts: {s['total_attempts'] or 0:,} | "
              f"Avg time: {s['avg_elapsed'] or 0:.2f}s | "
              f"Best rate: {s['best_rate'] or 0:,.0f} h/s | "
              f"Wordlists tracked: {s['wordlists_tracked']}")
    finally:
        db.close()


if __name__ == "__main__":
    _argv = sys.argv[1:]
    _path = _argv[0] if _argv else DEFAULT_DB
    _limit = int(_argv[1]) if len(_argv) > 1 else 25
    print_history(_path, _limit)
