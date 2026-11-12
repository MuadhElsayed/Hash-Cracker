"""
HashCrypt web dashboard (optional — requires Flask).

Run with:  python cli.py web        (or)  python -m hashcrypt web
Provides: hash submission, live progress polling, stop button, brute-force
options, algorithm identification preview, and the SQLite audit history.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

try:
    from flask import Flask, jsonify, render_template, request
except ImportError:  # Flask is optional — CLI works without it
    Flask = None

if Flask is None:
    def run(host: str = "127.0.0.1", port: int = 5000):
        raise SystemExit("Flask is not installed — run:  pip install flask "
                         "(or install HashCrypt with: pip install hashcrypt[web])")
else:
    from . import __version__
    from . import cracker, identifier, storage

    app = Flask(__name__)

    # ---- in-memory job state (single job at a time keeps the demo simple) ----
    _job_lock = threading.Lock()
    _job: dict[str, Any] = {"state": "idle"}

    def _resolve_wordlist(path: str | None) -> str | None:
        """Fall back to the bundled demo wordlist when none is supplied."""
        if path and os.path.isfile(path):
            return path
        bundled = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "wordlists", "common_passwords.txt")
        return bundled if os.path.isfile(bundled) else None


    @app.route("/")
    def index():
        return render_template("index.html", version=__version__)


    @app.route("/identify", methods=["POST"])
    def identify():
        h = (request.form.get("hash") or (request.json or {}).get("hash", "")).strip()
        if not h:
            return jsonify(error="no hash supplied"), 400
        analysis = identifier.analyze_hash(h)
        return jsonify(length=analysis.length, charset=analysis.charset,
                       best=analysis.best, crackable=analysis.crackable,
                       candidates=[{"name": n, "confidence": c}
                                   for n, c in analysis.candidates])


    @app.route("/crack", methods=["POST"])
    def crack():
        h = (request.form.get("hash") or "").strip().lower()
        if not h:
            return jsonify(error="no hash supplied"), 400
        threads = min(max(int(request.form.get("threads", 4) or 4), 1), 64)
        algo_input = (request.form.get("algo") or "").strip() or None
        wordlist_in = (request.form.get("wordlist") or "").strip()
        charset_in = (request.form.get("charset") or "").strip()
        try:
            min_len = max(1, min(12, int(request.form.get("minlen", 1) or 1)))
            max_len = max(min_len, min(10, int(request.form.get("maxlen", 6) or 6)))
        except ValueError:
            min_len, max_len = 1, 6

        with _job_lock:
            if _job.get("state") == "running":
                return jsonify(error="a crack job is already running — stop it first"), 409
            _job.clear()
            _job.update({
                "state": "starting", "target": h, "hash": h,
                "algorithm": algo_input or "auto",
                "progress": 0, "total": 0, "percent": 0.0, "rate": 0.0,
                "started_at": time.time(), "threads": threads,
                "wordlist": _resolve_wordlist(wordlist_in),
                "charset": charset_in, "minlen": min_len, "maxlen": max_len,
                "found": False, "plaintext": None, "attempts": 0,
                "elapsed": 0.0, "method": None, "engine": None,
                "workers": threads, "stop_event": threading.Event(),
            })
            if _job["wordlist"] is None and not charset_in:
                _job["state"] = "error"
                _job["error"] = ("wordlist path not found and no brute-force "
                                 "charset provided")
                return jsonify(error=_job["error"]), 404

        stop_event = _job["stop_event"]

        def runner():
            try:
                def cb(count, total):
                    with _job_lock:
                        _job["progress"], _job["total"] = count, total
                        dt = max(time.time() - _job["started_at"], 1e-9)
                        _job["rate"] = count / dt

                with _job_lock:
                    _job["state"] = "running"
                    wl = _job["wordlist"]
                    charset = _job.get("charset") or None
                    lo, hi = _job["minlen"], _job["maxlen"]

                result = None
                # ---- dictionary phase first (if a wordlist is available) ----
                if wl:
                    words = cracker.load_wordlist(wl)
                    with _job_lock:
                        _job["total"] = len(words)
                    analysis = identifier.analyze_hash(h)
                    if algo_input:
                        algos = [cracker.resolve_algorithm(algo_input)]
                    elif analysis.crackable and len(h) == 32:
                        algos = ["md5", "ntlm"]
                    elif analysis.crackable:
                        algos = [analysis.crackable]
                    else:
                        algos = ["md5"]
                    for algo in algos:
                        with _job_lock:
                            _job["algorithm"] = algo
                        result = cracker.crack_dictionary(
                            h, algo, words, workers=threads,
                            progress_callback=cb, stop=stop_event)
                        result["algorithm"] = algo
                        result["method"] = "dictionary"
                        if result["found"] or result.get("aborted"):
                            break

                # ---- brute-force phase (charset given, no dictionary hit) ----
                if charset and not (result and (result["found"] or
                                                result.get("aborted"))):
                    analysis = identifier.analyze_hash(h)
                    if algo_input:
                        algo = cracker.resolve_algorithm(algo_input)
                    elif analysis.crackable:
                        algo = analysis.crackable        # sha256 etc. from length
                    else:
                        algo = "md5"
                    with _job_lock:
                        _job["algorithm"] = algo
                        _job["total"] = cracker._keyspace_size(len(charset), lo, hi)
                    result = cracker.crack_bruteforce(
                        h, algo, charset, lo, hi, workers=threads,
                        progress_callback=cb, stop=stop_event)
                    result["algorithm"] = algo
                    result["method"] = "bruteforce"

                result = result or {"found": False, "attempts": 0, "elapsed": 0.0}

                # ---- audit log --------------------------------------------------
                if not result.get("aborted"):
                    db = storage.AuditDB()
                    try:
                        db.log_session(storage.AuditRecord(
                            algorithm=result.get("algorithm") or algo_input or "md5",
                            target_hash=h,
                            method=result.get("method", "dictionary"),
                            found=bool(result.get("found")),
                            plaintext=result.get("plaintext"),
                            attempts=result.get("attempts", 0),
                            total_candidates=result.get("total_candidates") or
                                            _job.get("total", 0),
                            elapsed_sec=result.get("elapsed") or
                                        time.time() - _job["started_at"],
                            rate_hps=result.get("rate") or 0.0,
                            workers=threads,
                            engine=result.get("engine", "threading"),
                            wordlist=wl))
                    finally:
                        db.close()

                with _job_lock:
                    _job["state"] = ("aborted" if result.get("aborted") else "done")
                    _job["found"] = bool(result.get("found"))
                    _job["plaintext"] = result.get("plaintext")
                    _job["attempts"] = result.get("attempts", 0)
                    _job["progress"] = _job["attempts"]
                    _job["elapsed"] = result.get("elapsed") or _job.get("elapsed", 0)
                    # tiny runs never trigger the coarse callbacks — sync final
                    # counters from the engine result so cards aren't zeroed
                    _job["rate"] = (result.get("rate") or 0.0) or _job.get("rate", 0.0)
                    _job["method"] = result.get("method")
                    _job["engine"] = result.get("engine")
                    _job["algorithm"] = result.get("algorithm") or (algo_input or "auto")
            except Exception as exc:                     # surface errors to the UI
                with _job_lock:
                    _job["state"] = "error"
                    _job["error"] = f"{type(exc).__name__}: {exc}"

        threading.Thread(target=runner, daemon=True).start()
        return jsonify(state="running")


    @app.route("/stop", methods=["POST"])
    def stop():
        with _job_lock:
            ev = _job.get("stop_event")
            if ev is not None:
                ev.set()
                if _job.get("state") in ("running", "starting"):
                    _job["state"] = "stopping"
        return jsonify(ok=True)


    @app.route("/status")
    def status():
        with _job_lock:
            snap = {k: v for k, v in _job.items()
                    if k not in ("stop_event", "wordlist")}
        state = snap.get("state")
        total = snap.get("total") or 0
        if state in ("running", "starting", "stopping") and total:
            with _job_lock:
                pct = min(_job["progress"] / total * 100, 100.0)
        elif state == "done":
            pct = 100.0
        elif state == "aborted" and total:
            with _job_lock:
                pct = min(_job["progress"] / total * 100, 100.0)
        else:
            pct = 0.0
        snap["percent"] = round(pct, 1)
        return jsonify(snap)


    @app.route("/history")
    def history():
        db = storage.AuditDB()
        try:
            rows = db.history(limit=25)
            return jsonify(history=[dict(r) for r in rows])
        finally:
            db.close()


    def run(host: str = "127.0.0.1", port: int = 5000):
        print(f"Dashboard → http://{host}:{port}   (Ctrl+C to stop)")
        app.run(host=host, port=port)
