#!/usr/bin/env python3
"""Produce immutable lists of remaining exact names from all five recorded waves."""
import argparse
from collections import Counter
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window3"
OLDER = HERE.parent / "2026-11-14-https-window2"
HALF = HERE.parent / "2026-11-14-halfhour"
S = importlib.util.spec_from_file_location("checkpoint", HERE / "wave-checkpoint.py")
W = importlib.util.module_from_spec(S)
S.loader.exec_module(W)
WAVES = "abcde"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    a = p.parse_args()
    all_hosts = W.index(W.tsv(HALF / "12-next-https.tsv"), "host")
    first = W.index(W.tsv(OLDER / "98-remaining-unmeasured.tsv"), "host")
    held = W.index(W.tsv(OLDER / "98-measured-holds.tsv"), "host")
    prepared = W.index(W.tsv(HERE / "01-new-ready.tsv"), "host")
    excludes = W.index(W.tsv(HERE / "01-negative-operator.tsv"), "host")
    operator = W.index([r for f in sorted(PREV.glob("0*-operators-*.tsv")) for r in W.tsv(f)], "host")
    accepted = {r["host"] for r in W.tsv(OLDER / "11-final-decisions.tsv") if r["decision"] == "accept"}
    accepted.add("germesplit.com")
    prior = W.index(W.tsv(PREV / "08-wave-later.tsv"), "host")
    alternatives = W.index(W.tsv(HERE / "02-later-paths.tsv"), "host")
    new_fallbacks = W.index(W.tsv(HERE / "09-new-fallbacks.tsv"), "host")
    historical_urls = {r["url"] for f in sorted(OLDER.glob("0[89]-*-evidence-*.jsonl"))
                       + sorted(OLDER.glob("1[01]-*-evidence-*.jsonl"))
                       for r in W.jsonl(f) if r.get("id")}
    latest = {}
    latest_measurement = {}
    attempted_urls = set()
    for wave in WAVES:
        ev, _ = W.read_wave(wave)
        dec = W.index(W.tsv(HERE / f"{wave}-decisions.tsv"), "host")
        for r in ev:
            h = r["host"]
            attempted_urls.add(r["url"])
            r = dict(r, wave=wave, decision=dec[h]["decision"])
            latest[h] = r
            if r.get("id"):
                latest_measurement[h] = r
            if r["decision"] == "accept" and h in all_hosts:
                accepted.add(h)
    unmeasured, measured = [], []
    for host, old in all_hosts.items():
        if host in accepted:
            continue
        tried = latest.get(host, {})
        result = latest_measurement.get(host)
        if result is None and host in first:
            op = operator[host]
            ready = prepared.get(host)
            if host in excludes:
                status, note = "exclude_candidate", excludes[host]["reason"]
            elif tried.get("api_status") == 422:
                status, note = "retry_no_probes", "API отказал в создании измерения, записанного ID нет."
            elif tried:
                status, note = "submission_unknown", "Нет HTTP-ответа и ID. Не повторять вслепую."
            elif ready:
                status, note = "ready_first", "Оператор подтверждён в новом окне, замера ещё нет."
            else:
                status, note = op["status"], op["note"]
            unmeasured.append(dict(host=host, order=old["order"], status=status,
                                   exact_url=(ready or {}).get("url", tried.get("url", op["exact_url"])),
                                   operator_url=excludes[host]["operator_source"] if host in excludes
                                   else (ready or {}).get("primary", op["operator_source"]),
                                   operator=excludes[host]["operator"] if host in excludes
                                   else (ready or {}).get("operator", op["operator"]), note=note))
        else:
            if result:
                outcome, url, mid = result["decision"], result["url"], result["id"]
            else:
                original = held[host]
                outcome, url, mid = (original[k] for k in ("decision", "url", "id"))
            alt = alternatives.get(host)
            available = (new_fallbacks.get(host, {}).get("exact_url") or (alt or {}).get("exact_url")
                         or prior.get(host, {}).get("url", ""))
            if available in attempted_urls | historical_urls:
                available = ""
            measured.append(dict(host=host, order=old["order"], last_decision=outcome, last_url=url,
                                 id=mid, last_wave=result["wave"] if result else "window2",
                                 later_exact_url=available))
    for group, file in ((unmeasured, "10-unmeasured.tsv"), (measured, "10-measured-holds.tsv")):
        W.save_tsv(HERE / file, group, group[0].keys(), a.check)
    planned = {r["host"] for r in measured if r["later_exact_url"]}
    W.require(new_fallbacks.keys() <= planned, "new fallback URL already tried or no longer eligible")
    W.require(len(accepted) == 49 and len(unmeasured) == 25 and len(measured) == 85, "wrong original partition")
    W.require(len(latest) == 78 and len(latest_measurement) == 73 and len(attempted_urls) == 82, "wrong wave totals")
    print("Original 159:", len(accepted), len(measured), len(unmeasured))
    print("No new measurement:", dict(Counter(r["status"] for r in unmeasured)))
    print("Still unused fallback URLs:", sum(bool(r["later_exact_url"]) for r in measured))


if __name__ == "__main__":
    main()
