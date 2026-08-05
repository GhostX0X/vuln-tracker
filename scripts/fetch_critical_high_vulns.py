import feedparser
import glob
import json
import os
import re
import urllib.request
from datetime import datetime, timezone

BASE_DIR = "vulnerabilities"
DATA_DIR = "vulnerabilities/data"          # structured per-day JSON, source of truth
SEEN_CVE_FILE = "vulnerabilities/.seen-cves.txt"
STATUS_FILE = "VULN-STATUS.md"
MAX_ENTRIES_PER_FEED = 50
TREND_DAYS = 14  # how many days to show in the STATUS.md trend chart

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

RSS_SOURCES = {
    "cvefeed.io (High/Critical)": "https://cvefeed.io/rssfeed/severity/high.xml",
}

WATCH_KEYWORDS = [
    "idor", "cors", "xss", "cross-site scripting", "csrf", "ssrf",
    "sql injection", "sqli", "auth bypass", "authentication bypass",
    "access control", "privilege escalation", "jwt", "oauth", "saml",
    "graphql", "deserialization", "xxe", "ssti", "path traversal",
    "file upload", "rce", "remote code execution", "command injection", "api",
    "android", "apk", "mobile app",
    "kubernetes", "k8s", "eks", "docker", "container escape", "aws", "cloud",
]
WATCH_PATTERN = re.compile("|".join(re.escape(k) for k in WATCH_KEYWORDS), re.I)

CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
STRUCTURED_SEVERITY_PATTERN = re.compile(
    r"Severity:\s*(?:</strong>)?\s*([0-9]+(?:\.[0-9]+)?)\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW)", re.I,
)
PUBLISHED_PATTERN = re.compile(
    r"Published\s*:?\s*(?:</strong>)?\s*([^|<]+?)\s*\|\s*([^<\n]+?ago)", re.I,
)
CVSS_PATTERN = re.compile(r"CVSS[:\s]*([0-9]+(?:\.[0-9]+)?)", re.I)
SEVERITY_WORD_PATTERN = re.compile(r"\b(critical|high|medium|low)\b", re.I)


def classify(text):
    m = STRUCTURED_SEVERITY_PATTERN.search(text)
    if m:
        return m.group(2).lower(), float(m.group(1))
    m = CVSS_PATTERN.search(text)
    if m:
        score = float(m.group(1))
        if score >= 9.0:
            return "critical", score
        if score >= 7.0:
            return "high", score
        return None, score
    m = SEVERITY_WORD_PATTERN.search(text)
    if m and m.group(1).lower() in ("critical", "high"):
        return m.group(1).lower(), None
    return None, None


def extract_reported_ago(text):
    m = PUBLISHED_PATTERN.search(text)
    return m.group(2).strip() if m else None


def entry_date(entry):
    if getattr(entry, "published_parsed", None):
        return datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def fetch_kev_ids():
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "vuln-tracker"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.load(resp)
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"WARNING: could not fetch CISA KEV catalog: {e}")
        return None


def load_seen_cve_ids():
    if os.path.exists(SEEN_CVE_FILE):
        with open(SEEN_CVE_FILE, encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    return set()


def save_seen_cve_id(cve_id):
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(SEEN_CVE_FILE, "a", encoding="utf-8") as f:
        f.write(cve_id + "\n")


def load_day_data(date_str):
    path = f"{DATA_DIR}/{date_str}.json"
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return []


def save_day_data(date_str, records):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(f"{DATA_DIR}/{date_str}.json", "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def render_day_markdown(date_str, records):
    """Regenerate the day's .md file grouped by severity (Critical
    section first, then High), sorted by CVSS score descending within
    each group. Overwrites the file — JSON is the source of truth."""
    critical = sorted(
        [r for r in records if r["severity"] == "critical"],
        key=lambda r: r["score"] or 0, reverse=True,
    )
    high = sorted(
        [r for r in records if r["severity"] == "high"],
        key=lambda r: r["score"] or 0, reverse=True,
    )
    kev_count = sum(1 for r in records if r["is_kev"])
    watch_count = sum(1 for r in records if r["is_watch"])

    lines = [f"# Critical & High Severity Vulnerabilities — {date_str}", ""]

    lines.append("```mermaid")
    lines.append("pie showData")
    lines.append(f'    title {date_str} — {len(records)} vulnerabilities')
    lines.append(f'    "Critical" : {len(critical)}')
    lines.append(f'    "High" : {len(high)}')
    lines.append("```")
    lines.append("")
    lines.append(f"🔥 Actively exploited (KEV): **{kev_count}**  |  ⭐ Watchlist matches: **{watch_count}**")
    lines.append("")

    def render_group(title_emoji_label, group):
        emoji, label = title_emoji_label
        if not group:
            return
        lines.append(f"## {emoji} {label} ({len(group)})")
        lines.append("")
        for r in group:
            score_str = f" (CVSS {r['score']})" if r["score"] is not None else ""
            flags = ""
            if r["is_kev"]:
                flags += " 🔥 **ACTIVELY EXPLOITED (KEV)**"
            if r["is_watch"]:
                flags += " ⭐ WATCHLIST"
            ago_str = f" — _reported {r['reported_ago']}_" if r["reported_ago"] else ""
            lines.append(
                f"- **{score_str.strip() or 'CVSS n/a'}**{flags} "
                f"[{r['title']}]({r['link']}) — _{r['source']}_ "
                f"({r['pub']}){ago_str}"
            )
        lines.append("")

    render_group(("🔴", "Critical"), critical)
    render_group(("🟠", "High"), high)

    os.makedirs(BASE_DIR, exist_ok=True)
    with open(f"{BASE_DIR}/{date_str}.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def render_status(touched_dates_summary):
    """touched_dates_summary: {date_str: {"critical": n, "high": n}}"""
    all_day_files = sorted(glob.glob(f"{DATA_DIR}/*.json"), reverse=True)
    date_counts = {}
    for path in all_day_files:
        date_str = os.path.basename(path).replace(".json", "")
        with open(path, encoding="utf-8") as f:
            records = json.load(f)
        date_counts[date_str] = len(records)

    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        f.write("# 🚨 Vulnerability Feed Status\n\n")
        f.write(f"Last checked: {datetime.now(timezone.utc).isoformat()} UTC\n\n")

        f.write("## 📅 Counts by date (latest first)\n\n")
        f.write("```\n")
        max_count = max(date_counts.values(), default=1) or 1
        for date_str, count in list(date_counts.items())[:TREND_DAYS]:
            bar_len = max(1, round((count / max_count) * 30)) if count else 0
            bar = "█" * bar_len
            f.write(f"{date_str} | {count:>3} {bar}\n")
        f.write("```\n\n")

        f.write("| Date | Count |\n|------|------:|\n")
        for date_str, count in list(date_counts.items())[:TREND_DAYS]:
            f.write(f"| {date_str} | {count} |\n")
        f.write("\n")

        f.write("See each day's file in `vulnerabilities/` for the full "
                 "Critical/High breakdown, KEV flags, and watchlist matches.\n")


def main():
    seen_cve_ids = load_seen_cve_ids()
    kev_ids = fetch_kev_ids()

    new_by_date = {}  # date_str -> list of new records this run
    run_stats = {"critical": 0, "high": 0, "kev": 0, "watch": 0}

    for source, url in RSS_SOURCES.items():
        feed = feedparser.parse(url)
        for entry in feed.entries[:MAX_ENTRIES_PER_FEED]:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            full_text = f"{title} {summary}"

            severity, score = classify(full_text)
            if severity not in ("critical", "high"):
                continue

            cve_match = CVE_ID_PATTERN.search(title) or CVE_ID_PATTERN.search(summary)
            cve_id = cve_match.group(0) if cve_match else None
            if cve_id:
                if cve_id in seen_cve_ids:
                    continue
                seen_cve_ids.add(cve_id)
                save_seen_cve_id(cve_id)

            is_kev = bool(kev_ids and cve_id and cve_id in kev_ids)
            is_watch = bool(WATCH_PATTERN.search(full_text))

            pub = entry_date(entry)
            date_str = pub.strftime("%Y-%m-%d")

            record = {
                "cve_id": cve_id,
                "title": title,
                "link": entry.get("link", ""),
                "source": source,
                "severity": severity,
                "score": score,
                "is_kev": is_kev,
                "is_watch": is_watch,
                "pub": pub.strftime("%Y-%m-%d %H:%M UTC"),
                "reported_ago": extract_reported_ago(full_text),
            }
            new_by_date.setdefault(date_str, []).append(record)

            run_stats[severity] += 1
            if is_kev:
                run_stats["kev"] += 1
            if is_watch:
                run_stats["watch"] += 1

    touched_summary = {}
    for date_str, new_records in new_by_date.items():
        existing = load_day_data(date_str)
        merged = existing + new_records
        save_day_data(date_str, merged)
        render_day_markdown(date_str, merged)
        touched_summary[date_str] = {
            "critical": sum(1 for r in merged if r["severity"] == "critical"),
            "high": sum(1 for r in merged if r["severity"] == "high"),
        }

    render_status(touched_summary)

    print(f"New this run — critical: {run_stats['critical']}, high: {run_stats['high']}, "
          f"KEV: {run_stats['kev']}, watchlist: {run_stats['watch']}")
    if kev_ids is None:
        print("WARNING: KEV catalog unavailable this run — KEV flags may be incomplete.")


if __name__ == "__main__":
    main()
