# ☠ HashCrypt — Danger Console

**Hash identification & credential-cracking console** — a Python-based offensive
security tool that identifies hash algorithms automatically, runs multi-threaded /
multi-process dictionary and brute-force attacks, tracks live progress in a CLI or
web dashboard, and logs every session to a local SQLite audit database.

> ⚠️ **DANGER MODE** — dual-use tooling. The operator assumes full responsibility
> for its use and for compliance with applicable laws.

---

## Screenshots

**Web dashboard** (`hashcrypt web`) — target config, live session cards, copy button,
audit history with CRACKED/FAILED badges:

![HashCrypt web dashboard](docs/dashboard.png)

**CLI console** — the DANGER banner printed on every launch (rendered bright
red in a real terminal):

```text
·····▒▒ f3859734 927b2270 7660708b 3e3edeff 90f62d1c 9b033f1e b15df634 ▒▒·····

  ██      ██   ██████     ████████ ██      ██
  ██      ██ ██      ██ ██         ██      ██
  ██      ██ ██      ██ ██         ██      ██
  ██████████ ██████████   ██████   ██████████
  ██      ██ ██      ██         ██ ██      ██
  ██      ██ ██      ██         ██ ██      ██
  ██      ██ ██      ██ ████████   ██      ██
    ██████   ████████   ██      ██ ████████   ██████████
  ██      ██ ██      ██ ██      ██ ██      ██     ██    
  ██         ██      ██   ██  ██   ██      ██     ██    
  ██         ████████       ██     ████████       ██    
  ██         ██  ██         ██     ██             ██    
  ██      ██ ██    ██       ██     ██             ██    
    ██████   ██      ██     ██     ██             ██    

───────────────────☠ ─────  D A N G E R   Z O N E  ───── ☠────────────────────

           [ identify ]  [ crack ]  [ history ]  [ stats ]  [ web ]           

▐ engine   hashlib · threads · processes · abort-safe                       ▐
▐ wordlist wordlists/ · /usr/share/wordlists/*                              ▐
▐ session  0x144924FE · pid 129664 · 2 cores                                ▐

───────────☠ DANGER MODE ACTIVE · v2.1.0 · destructive capability ☠───────────
·····▒▒ 9f21867c 7ea62e5c ab5586fe 3236caed 49c3d948 c3756593 d45903c5 ▒▒·····
```

---

## Features

| Phase | Module | What it does |
|---|---|---|
| 1 — Identification | `hashcrypt/identifier.py` | Length + charset + **structural markers** (`$6$…`, bcrypt, `$NT$…`, `$apr1$`, Argon2, PBKDF2) → ranked candidate list with confidence bars |
| 2 — Cracking core | `hashcrypt/cracker.py` | Dictionary & **radix-partitioned brute-force** engines, threading and multiprocessing, salting, cooperative abort (Ctrl+C / web stop button), live h/s + ETA |
| 3 — Interfaces | `hashcrypt/cli.py`, `hashcrypt/webapp.py` | argparse CLI with live animated progress; Flask dashboard with identification preview, stop button, and history console |
| 4 — Audit trail | `hashcrypt/storage.py` | Every session (success **or** failure) persisted to SQLite: plaintext, attempts, timings, engine, workers, wordlist, salt, notes — plus aggregate `stats` |

**Supported attack algorithms:** MD5, MD4, NTLM*(pure-python MD4 fallback)*, SHA-1,
SHA-224/256/384/512, SHA3-224/256/384/512, BLAKE2b, BLAKE2s — salted variants supported
as libraries, format detection identifies their structures (marked "not crackable by
the built-in engine").

---

## Install (from GitHub)

```bash
# 1) plain git clone — zero dependencies, Python ≥ 3.9
git clone https://github.com/YOUR-GITHUB-USERNAME/hashcrypt.git
cd hashcrypt
python3 -m hashcrypt --version

# 2) editable install with console entrypoint + dashboard extra
#    (Kali/Debian PEP-668 note: use a venv, pipx, or --break-system-packages)
pip install -e ".[web]"
hashcrypt --version        # ← native shell command
```

- **No dependencies** are required for the CLI (Python standard library only).
- `pip install -e ".[web]"` adds Flask for the dashboard.
- Works on **any machine with Python ≥ 3.9** — designed and tested on **Kali Linux**.

---

## Quickstart

### 1. Identify an unknown hash

```bash
hashcrypt identify 8621ffdbc5698829397d97767ac13db3
```
```text
Input           : 8621ffdbc5698829397d97767ac13db3
Length          : 32
Character set   : lowercase hex
Best guess      : MD5
Candidates      :  MD5 50% |##########|  NTLM 45% |#########|  MD4 30% |######| …
Crackable via   : `md5`
```

### 2. Dictionary attack (the core workflow)

```bash
hashcrypt crack 8621ffdbc5698829397d97767ac13db3 -w /usr/share/wordlists/rockyou.txt -t 8
```
Live progress: `[dict/MD5] ██████░░░░░ 42.0%  8.4k / 20k  54.8k h/s  ETA 00:00:21`.
Press **Ctrl+C** any time — workers exit cooperatively and nothing is half-logged.

### 3. Ambiguity handling (auto-detect)

MD5 and NTLM are both 32 hex chars. When `-a` is not forced, HashCrypt tries **both**:

```bash
hashcrypt crack f7eb9c06fafaa23c4bcf22ba6781c1e2 -w wordlists/common_passwords.txt
# [dict/MD5]  …  exhausted
# [dict/NTLM] …  CRACKED → dragon
```

### 4. Brute force

```bash
hashcrypt crack 3608bca1e44…c9282 -b "abcxyz" -l 3 3 -t 6       # sha256("xyz")
```
The keyspace is mathematically partitioned by **radix indexing** — workers scan disjoint
slices, no duplicated work, no RAM blow-up on huge keyspaces.

### 5. Multiprocessing engine

```bash
hashcrypt crack <md5> -b "abcdefgh" -l 6 6 -p -t 4       # ~44k h/s in pure Python
```

### 6. Salted candidates

```bash
hashcrypt crack 92ed27fdbab41578a1d7d43fc1e61d8a \
        -w wordlists/common_passwords.txt --salt=2024 --salt-pos prepend
# PASSWORD  2024dragon   (candidate = salt + word)
```

### 7. Audit history & statistics

```bash
hashcrypt history                 # per-session rows
hashcrypt history --found-only
hashcrypt stats                   # aggregated policy-report view
```
```text
  sessions        :         17
  cracked         :         14  (82.4% success rate)
  total attempts  : 14,401,456
  cpu time spent  :       45.6s
  best rate       :    330,661 h/s   [sha256 · threading × 8]
  by algorithm    : md5 × 9, sha256 × 5, ntlm × 3
```

### 8. Web dashboard (optional)

```bash
hashcrypt web --port 5000        # open http://127.0.0.1:5000
```
- paste a hash → **instant identification preview** as you type
- choose wordlist, algorithm, thread slider, brute-force charset/lengths
- watch progress live; **■ Stop** button aborts cooperatively
- recovered plaintext with one-click **COPY**
- audit-history table with CRACKED/FAILED badges + rate column

### 9. Generate reference hashes (for testing)

```bash
hashcrypt gen dragon --algorithms md5 ntlm sha256
```

---

## CLI reference

| Command | Purpose |
|---|---|
| `hashcrypt identify <hash>` | identify algorithm (length/charset/structure analysis) |
| `hashcrypt crack <hash>` | run dictionary / brute-force session |
| `hashcrypt history` | review saved audit records |
| `hashcrypt stats` | aggregate statistics (policy-review view) |
| `hashcrypt gen <word>` | generate hashes of a word for testing |
| `hashcrypt web` | launch Flask dashboard on `http://127.0.0.1:5000` |

Key `crack` options: `-w` wordlist · `-a` algorithm · `-b` charset · `-l MIN MAX`
lengths · `-t` workers · `-p` multiprocessing · `--salt`/`--salt-pos` · `--note` /
`--no-log` · `--db PATH` · exit codes: `0` cracked, `1` no match, `130` aborted.

---

## Run the tests

```bash
python3 tests/run_tests.py
# 32 passed, 0 failed
```
Covers identification, both engines (threaded & multiprocess), salting, the MD4
fallback (RFC 1320 vectors incl. multi-block messages) and SQLite auditing. CI runs
the same suite on Python 3.9 → 3.13 (`.github/workflows/ci.yml`).

---

## Design notes (for the report)

- **Chunked work avoids lock contention** — contiguous word slices; workers bump the
  shared counter only every 4096 attempts.
- **Mathematical keyspace partitioning** — brute-force candidates map directly from a
  linear index (`divmod`) so `[start, end)` slices are disjoint and cheap.
- **Abort-safe by construction** — every engine checks a cooperative stop event;
  multiprocessing workers share it through an `mp.Event` initializer.
- **MD4 availability** — OpenSSL 3 ships without MD4; a validated in-tree
  pure-python MD4 (RFC 1320) keeps NTLM cracking dependable.
- **Why only ~10–50k h/s?** This is a teaching methodology tool in pure Python.
  For production-grade audits use the same report format against `hashcat` / `john`.

---

## Project layout

```
hashcrypt/
├── identifier.py      Phase 1 — identification & structure analysis
├── cracker.py         Phase 2 — dictionary & brute-force engines (threads/proc)
├── cli.py             Phase 3 — console interface + pixel-art banner
├── webapp.py          Phase 3 — optional Flask dashboard
├── storage.py         Phase 4 — SQLite audit log & statistics
└── templates/index.html        dashboard UI (no CDN, works offline)
tests/run_tests.py    32 self-tests, all phases
wordlists/            bundled demo wordlist
data/audit_log.db     created at first run (gitignored)
pyproject.toml        pip-installable, `hashcrypt` console command
```

## License

MIT — see `LICENSE`.
