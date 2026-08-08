import feedparser
import glob
import json
import os
import re
import urllib.request
from datetime import datetime, timezone

BASE_DIR = "vulnerabilities"
DATA_DIR = "vulnerabilities/data"          # structured JSON, source of truth — mirrors year/month layout
SEEN_CVE_FILE = "vulnerabilities/.seen-cves.txt"
STATUS_FILE = "VULN-STATUS.md"
MAX_ENTRIES_PER_FEED = 50
TREND_DAYS = 14

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --------------------------------------------------------------------
# IMPORTANT: I cannot reach these domains from my sandbox to verify
# they're live/correctly formatted — test each one after your first
# real GitHub Actions run (which has full internet access) and drop
# any that don't parse cleanly.
#   - cvefeed.io High/Critical: confirmed working from your pasted sample.
#   - cvefeed.io Medium: same URL pattern as the high feed, UNVERIFIED.
#   - Others below are well-known feeds from general knowledge, also
#     UNVERIFIED — vendor feed URLs/formats do drift over time.
# --------------------------------------------------------------------
RSS_SOURCES = {
    "cvefeed.io (High/Critical)": "https://cvefeed.io/rssfeed/severity/high.xml",
    "cvefeed.io (Medium)": "https://cvefeed.io/rssfeed/severity/medium.xml",  # UNVERIFIED — guessed URL pattern
    # "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",   # UNVERIFIED
    # "Vulners": "https://vulners.com/rss.xml",                                    # UNVERIFIED
    # "Rapid7": "https://blog.rapid7.com/rss/",                                    # UNVERIFIED, blog not pure-CVE feed
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

VALID_SEVERITIES = ("critical", "high", "medium")


def classify(text):
    """Return (severity, cvss_score). severity is one of
    'critical'/'high'/'medium', or None to skip (low, or unclassifiable)."""
    m = STRUCTURED_SEVERITY_PATTERN.search(text)
    if m:
        sev = m.group(2).lower()
        score = float(m.group(1))
        return (sev, score) if sev in VALID_SEVERITIES else (None, score)

    m = CVSS_PATTERN.search(text)
    if m:
        score = float(m.group(1))
        if score >= 9.0:
            return "critical", score
        if score >= 7.0:
            return "high", score
        if score >= 4.0:
            return "medium", score
        return None, score

    m = SEVERITY_WORD_PATTERN.search(text)
    if m and m.group(1).lower() in VALID_SEVERITIES:
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


def date_parts(date_str):
    """'2026-08-05' -> ('2026', 'August', '05')"""
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    return dt.strftime("%Y"), dt.strftime("%B"), dt.strftime("%d")


def day_json_path(date_str):
    year, month, _ = date_parts(date_str)
    return f"{DATA_DIR}/{year}/{month}/{date_str}.json"


def day_md_path(date_str):
    year, month, _ = date_parts(date_str)
    return f"{BASE_DIR}/{year}/{month}/{date_str}.md"


def load_day_data(date_str):
    path = day_json_path(date_str)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return []


def save_day_data(date_str, records):
    path = day_json_path(date_str)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def escape_cell(text):
    return text.replace("|", "\\|")


def render_day_markdown(date_str, records):
    """Regenerate one day's .md file: Critical / High / Medium tables,
    sorted by CVSS descending, with a Source column per row (useful
    once multiple feeds are configured)."""
    groups = {
        sev: sorted(
            [r for r in records if r["severity"] == sev],
            key=lambda r: r["score"] or 0, reverse=True,
        )
        for sev in VALID_SEVERITIES
    }
    kev_count = sum(1 for r in records if r["is_kev"])
    watch_count = sum(1 for r in records if r["is_watch"])
    sources = sorted({r["source"] for r in records})

    lines = [f"# Critical, High & Medium Severity Vulnerabilities — {date_str}", ""]

    lines.append("```mermaid")
    lines.append(
        "%%{init: {'theme':'base', 'themeVariables': "
        "{'pie1':'#e63946', 'pie2':'#f4a300', 'pie3':'#facc15', "
        "'pieOpacity':'1', 'pieOuterStrokeWidth':'2px', "
        "'pieSectionTextColor':'#ffffff'}}}%%"
    )
    lines.append("pie showData")
    lines.append(f'    title {date_str} — {len(records)} vulnerabilities')
    lines.append(f'    "Critical" : {len(groups["critical"])}')
    lines.append(f'    "High" : {len(groups["high"])}')
    lines.append(f'    "Medium" : {len(groups["medium"])}')
    lines.append("```")
    lines.append("")

    # Per-source breakdown as a table (not a chart) — how much each
    # configured feed actually contributed today, by severity.
    if sources:
        lines.append("**Source status for this day:**")
        lines.append("")
        lines.append("| Source | Critical | High | Medium | Total |")
        lines.append("|--------|---------:|-----:|-------:|------:|")
        for src in sources:
            src_records = [r for r in records if r["source"] == src]
            c = sum(1 for r in src_records if r["severity"] == "critical")
            h = sum(1 for r in src_records if r["severity"] == "high")
            m = sum(1 for r in src_records if r["severity"] == "medium")
            lines.append(f"| {src} | {c} | {h} | {m} | {len(src_records)} |")
        lines.append("")

    lines.append(f"**KEV (actively exploited):** {kev_count}  **Watchlist matches:** {watch_count}")
    lines.append("")

    def render_group(label, group):
        if not group:
            return
        lines.append(f"## {label} ({len(group)})")
        lines.append("")
        lines.append("| CVSS | Flags | Source | CVE / Title | Reported |")
        lines.append("|------|-------|--------|-------------|----------|")
        for r in group:
            score_str = str(r["score"]) if r["score"] is not None else "—"
            flags = []
            if r["is_kev"]:
                flags.append("🔥 KEV")
            if r["is_watch"]:
                flags.append("⭐")
            flags_str = " ".join(flags) if flags else "—"
            title_cell = f"[{escape_cell(r['title'])}]({r['link']})"
            reported = r["reported_ago"] or r["pub"]
            lines.append(f"| {score_str} | {flags_str} | {r['source']} | {title_cell} | {reported} |")
        lines.append("")

    render_group("Critical", groups["critical"])
    render_group("High", groups["high"])
    render_group("Medium", groups["medium"])

    path = day_md_path(date_str)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def all_day_records():
    """{date_str: records} for every day that has data, across all years/months."""
    out = {}
    for path in glob.glob(f"{DATA_DIR}/*/*/*.json"):
        date_str = os.path.basename(path).replace(".json", "")
        with open(path, encoding="utf-8") as f:
            out[date_str] = json.load(f)
    return out


def render_month_index(year, month, day_records):
    """README.md inside vulnerabilities/{year}/{month}/ — GitHub renders
    this automatically when browsing the folder. Lists days latest-first,
    which is how we get 'latest on top' since GitHub's raw file listing
    is always alphabetical and can't be reordered."""
    days = sorted(day_records.items(), reverse=True)  # descending date string
    lines = [f"# {month} {year}", ""]
    lines.append("| Date | Critical | High | Medium | Total |")
    lines.append("|------|---------:|-----:|-------:|------:|")
    for date_str, records in days:
        c = sum(1 for r in records if r["severity"] == "critical")
        h = sum(1 for r in records if r["severity"] == "high")
        m = sum(1 for r in records if r["severity"] == "medium")
        lines.append(f"| [{date_str}]({date_str}.md) | {c} | {h} | {m} | {len(records)} |")
    path = f"{BASE_DIR}/{year}/{month}/README.md"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def render_year_index(year, months_data):
    """README.md inside vulnerabilities/{year}/ — months latest-first."""
    month_order = ["January", "February", "March", "April", "May", "June",
                   "July", "August", "September", "October", "November", "December"]
    present = [m for m in reversed(month_order) if m in months_data]
    lines = [f"# {year}", ""]
    lines.append("| Month | Critical | High | Medium | Total |")
    lines.append("|-------|---------:|-----:|-------:|------:|")
    for month in present:
        records_by_day = months_data[month]
        all_records = [r for day in records_by_day.values() for r in day]
        c = sum(1 for r in all_records if r["severity"] == "critical")
        h = sum(1 for r in all_records if r["severity"] == "high")
        m = sum(1 for r in all_records if r["severity"] == "medium")
        lines.append(f"| [{month}]({month}/) | {c} | {h} | {m} | {len(all_records)} |")
    path = f"{BASE_DIR}/{year}/README.md"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def render_root_index(years_data):
    """README.md inside vulnerabilities/ — years latest-first."""
    lines = ["# Vulnerability Archive", "", "| Year | Total logged |", "|------|-------------:|"]
    for year in sorted(years_data.keys(), reverse=True):
        total = sum(len(recs) for recs in years_data[year].values())
        lines.append(f"| [{year}]({year}/) | {total} |")
    path = f"{BASE_DIR}/README.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def render_status():
    day_records = all_day_records()
    date_counts = {d: len(r) for d, r in sorted(day_records.items(), reverse=True)}

    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        f.write("# 🚨 Vulnerability Feed Status\n\n")
        f.write(f"Last checked: {datetime.now(timezone.utc).isoformat()} UTC\n\n")

        f.write("## 📡 Configured sources\n\n")
        f.write("| Source | Feed URL |\n|--------|----------|\n")
        for name, url in RSS_SOURCES.items():
            f.write(f"| {name} | `{url}` |\n")
        f.write("\n")

        f.write("## 📅 Counts by date (latest first)\n\n")
        f.write("```\n")
        max_count = max(date_counts.values(), default=1) or 1
        for date_str, count in list(date_counts.items())[:TREND_DAYS]:
            bar_len = max(1, round((count / max_count) * 30)) if count else 0
            f.write(f"{date_str} | {count:>3} {'█' * bar_len}\n")
        f.write("```\n\n")

        f.write("| Date | Count |\n|------|------:|\n")
        for date_str, count in list(date_counts.items())[:TREND_DAYS]:
            year, month, _ = date_parts(date_str)
            f.write(f"| [{date_str}](vulnerabilities/{year}/{month}/{date_str}.md) | {count} |\n")
        f.write("\n")

        f.write("Browse `vulnerabilities/<year>/<month>/` for the full "
                 "archive — each folder has an index sorted latest-first.\n")


def main():
    seen_cve_ids = load_seen_cve_ids()
    kev_ids = fetch_kev_ids()

    new_by_date = {}
    run_stats = {"critical": 0, "high": 0, "medium": 0, "kev": 0, "watch": 0}

    for source, url in RSS_SOURCES.items():
        feed = feedparser.parse(url)
        if getattr(feed, "bozo", False) and not feed.entries:
            print(f"WARNING: feed '{source}' failed to parse or returned no entries — check the URL.")
            continue

        for entry in feed.entries[:MAX_ENTRIES_PER_FEED]:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            full_text = f"{title} {summary}"

            severity, score = classify(full_text)
            if severity not in VALID_SEVERITIES:
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

    for date_str, new_records in new_by_date.items():
        existing = load_day_data(date_str)
        save_day_data(date_str, existing + new_records)

    # Re-render everything from JSON — keeps template changes retroactive
    # and keeps the year/month index files in sync.
    day_records = all_day_records()
    for date_str, records in day_records.items():
        render_day_markdown(date_str, records)

    # Build year -> month -> {date: records} structure for the index pages.
    tree = {}
    for date_str, records in day_records.items():
        year, month, _ = date_parts(date_str)
        tree.setdefault(year, {}).setdefault(month, {})[date_str] = records

    for year, months in tree.items():
        for month, days in months.items():
            render_month_index(year, month, days)
        render_year_index(year, months)
    render_root_index(tree)

    render_status()

    print(f"New this run — critical: {run_stats['critical']}, high: {run_stats['high']}, "
          f"medium: {run_stats['medium']}, KEV: {run_stats['kev']}, watchlist: {run_stats['watch']}")
    if kev_ids is None:
        print("WARNING: KEV catalog unavailable this run — KEV flags may be incomplete.")


if __name__ == "__main__":
    main()
