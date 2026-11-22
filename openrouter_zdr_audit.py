#!/usr/bin/env python3
"""openrouter-zdr-audit: were your OpenRouter requests caught in the
November 2026 provider incidents?

On 2026-11-22 OpenRouter announced it had off-boarded three providers
and removed 125 endpoints from Zero Data Retention (ZDR) eligibility,
after researchers (Dragos / HD Moore, ~2M canary prompts, July-Nov 2026)
showed customer prompts were copied, stored, or read at some providers.
OpenRouter itself was not breached. The three off-boarded providers
were NOT named publicly, so this tool never claims to know them.

What IS public, and what this tool checks, are the three incident
notices OpenRouter linked, each with a concrete exposure window:

  Novita   MiniMax requests forwarded to MiniMax's official API
           2026-05-28 .. 2026-11-11
  Phala    DeepSeek V4 Flash 0731 via Phala; an attacker controlled
           an inference server — treat contents as exposed
           2026-10-21 .. 2026-11-08
  Together AI  Stored prompt samples (MiniMax M2/M3, GLM-5.2, Kimi K2.6)
           downloaded by an unauthorized party
           2026-06-01 .. 2026-07-31 (sample dates Jun 24, Jul 4/8/14)

Give it your OpenRouter activity as JSONL — one request per line:
  {"model": "minimax/minimax-m2", "provider": "novita",
   "date": "2026-10-05", "id": "req-1"}

Verdicts per request: EXPOSED (inside a published incident window),
AT_RISK (same provider/model family, outside the window), UNKNOWN_ZDR
(sent on/after 2026-11-22, when 125 endpoints lost ZDR and the list
is not public — verify in your OpenRouter dashboard), CLEAR, or
SKIPPED (malformed line). Output ends with a rotate-secrets checklist.

Stdlib only. Python 3.8+. Reads only the file you hand it; nothing
leaves the machine. No API key needed — and never paste one into a log.
"""
import argparse
import json
import sys
from datetime import date

ZDR_REMOVAL_DATE = date(2026, 11, 22)

# (provider, model-matcher, start, end, label, advice)
INCIDENTS = [
    ("novita", "minimax", date(2026, 5, 28), date(2026, 11, 11),
     "Novita: MiniMax requests forwarded to MiniMax official API",
     "Rotate any secret sent in these prompts; request deletion from MiniMax."),
    ("phala", "deepseek-v4-flash", date(2026, 10, 21), date(2026, 11, 8),
     "Phala: DeepSeek V4 Flash 0731 requests, attacker-held inference server",
     "Treat contents as exposed; rotate every included secret now."),
    ("together", "minimax", date(2026, 6, 1), date(2026, 7, 31),
     "Together AI: stored prompt samples downloaded by an unauthorized party",
     "Samples were MiniMax M2/M3, GLM-5.2, Kimi K2.6; rotate secrets in them."),
    ("together", "glm-5", date(2026, 6, 1), date(2026, 7, 31),
     "Together AI: stored prompt samples downloaded by an unauthorized party",
     "Samples were MiniMax M2/M3, GLM-5.2, Kimi K2.6; rotate secrets in them."),
    ("together", "kimi-k2", date(2026, 6, 1), date(2026, 7, 31),
     "Together AI: stored prompt samples downloaded by an unauthorized party",
     "Samples were MiniMax M2/M3, GLM-5.2, Kimi K2.6; rotate secrets in them."),
]

NOTICE_PROVIDERS = ("novita", "phala", "together")


def parse_day(text):
    """Parse YYYY-MM-DD to a date, or None for anything else."""
    if not isinstance(text, str):
        return None
    try:
        parts = text.strip().split("-")
        if len(parts) != 3:
            return None
        return date(int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, TypeError):
        return None


def model_matches(model, needle):
    """Case-insensitive substring match on the model slug."""
    if not isinstance(model, str):
        return False
    return needle.lower() in model.lower()


def audit_request(req):
    """Audit one request dict. Returns (verdict, reason)."""
    model = req.get("model") if isinstance(req, dict) else None
    provider = req.get("provider") if isinstance(req, dict) else None
    day = parse_day(req.get("date")) if isinstance(req, dict) else None
    if not isinstance(req, dict) or not model or not provider:
        return "SKIPPED", "missing model or provider"
    if day is None:
        return "SKIPPED", "missing or malformed date (need YYYY-MM-DD)"
    prov = str(provider).lower()
    for inc_provider, needle, start, end, label, _advice in INCIDENTS:
        if prov == inc_provider and model_matches(model, needle) \
                and start <= day <= end:
            return "EXPOSED", "%s (%s..%s)" % (label, start, end)
    if prov in NOTICE_PROVIDERS:
        return ("AT_RISK",
                "provider %s published an incident notice; this request is "
                "outside the published windows, but the same provider/model "
                "family was affected" % provider)
    if day >= ZDR_REMOVAL_DATE:
        return ("UNKNOWN_ZDR",
                "sent on/after 2026-11-22, when 125 endpoints lost ZDR "
                "eligibility and OpenRouter has not published the list; "
                "verify this endpoint in your OpenRouter dashboard")
    return "CLEAR", "outside all published incident windows"


def audit_lines(lines):
    """Audit an iterable of JSONL lines. Returns (results, skipped)."""
    results = []
    for lineno, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            results.append({"line": lineno, "id": None, "model": None,
                            "provider": None, "date": None,
                            "verdict": "SKIPPED",
                            "reason": "not valid JSON"})
            continue
        verdict, reason = audit_request(req)
        results.append({"line": lineno, "id": req.get("id"),
                        "model": req.get("model"),
                        "provider": req.get("provider"),
                        "date": req.get("date"), "verdict": verdict,
                        "reason": reason})
    return results


def advice_for(verdict, reason):
    for _p, _n, _s, _e, label, advice in INCIDENTS:
        if reason.startswith(label):
            return advice
    if verdict == "AT_RISK":
        return "Check the provider notice for your exact dates; rotate secrets if in doubt."
    if verdict == "UNKNOWN_ZDR":
        return "Confirm ZDR status for this endpoint before sending secrets through it again."
    return ""


def format_report(results, source_label):
    lines = ["OpenRouter ZDR audit \u2014 %s" % source_label]
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        ident = r["id"] or ("line %d" % r["line"])
        lines.append("%s | %s | %s | %s | %s" % (
            ident, r["model"], r["provider"], r["date"], r["verdict"]))
        lines.append("  %s" % r["reason"])
    lines.append("===")
    order = ["EXPOSED", "AT_RISK", "UNKNOWN_ZDR", "CLEAR", "SKIPPED"]
    summary = ", ".join("%s: %d" % (v, counts.get(v, 0)) for v in order)
    lines.append("Summary (%d requests): %s" % (len(results), summary))
    exposed = [r for r in results if r["verdict"] == "EXPOSED"]
    if exposed:
        lines.append("Rotate secrets from these requests:")
        for r in exposed:
            ident = r["id"] or ("line %d" % r["line"])
            lines.append("  - %s: %s via %s on %s \u2014 %s" % (
                ident, r["model"], r["provider"], r["date"],
                advice_for(r["verdict"], r["reason"])))
    if counts.get("UNKNOWN_ZDR"):
        lines.append("UNKNOWN_ZDR means OpenRouter has not published which 125")
        lines.append("endpoints lost ZDR \u2014 this tool cannot confirm them for you.")
    return "\n".join(lines) + "\n"


def build_parser():
    p = argparse.ArgumentParser(
        description="Audit OpenRouter requests against the Nov 2026 "
                    "provider incident windows.")
    p.add_argument("--log", metavar="FILE",
                   help="JSONL activity export (one request per line); "
                        "reads stdin if omitted and not --demo")
    p.add_argument("--demo", action="store_true",
                   help="audit the bundled sample log (examples/sample-log.jsonl)")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output")
    p.add_argument("--fail-on", choices=["any", "exposed", "never"],
                   default="any",
                   help="which verdicts exit 1 (default: any finding)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    import os
    if args.demo:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "examples", "sample-log.jsonl")
        with open(log_path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        source = "demo log examples/sample-log.jsonl"
    elif args.log:
        with open(args.log, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        source = args.log
    else:
        lines = sys.stdin.read().splitlines()
        source = "stdin"

    results = audit_lines(lines)
    if args.json:
        print(json.dumps({"source": source, "results": results}, indent=2))
    else:
        print(format_report(results, source), end="")

    verdicts = [r["verdict"] for r in results]
    if args.fail_on == "never":
        return 0
    if args.fail_on == "exposed":
        return 1 if "EXPOSED" in verdicts else 0
    if any(v in ("EXPOSED", "AT_RISK", "UNKNOWN_ZDR") for v in verdicts):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
