import feedparser
import glob
import json
import os
import re
import urllib.request
from datetime import datetime, timezone

BASE_DIR = "vulnerabilities"
STATUS_FILE = "VULN-STATUS.md"
SEEN_CVE_FILE = "vulnerabilities/.seen-cves.txt"  # flat index, avoids re-scanning all history every run
MAX_ENTRIES_PER_FEED = 50

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

RSS_SOURCES = {
    "cvefeed.io (High/Critical)": "https://cvefeed.io/rssfeed/severity/high.xml",
    # "Tenable Research Advisories": "https://www.tenable.com/security/research.rss",
    # "Rapid7 Vulnerability & Exploit DB": "https://www.rapid7.com/rss/db/",
    # "Vulners": "https://vulners.com/rss.xml",
}

# --------------------------------------------------------------------
# Tuned for VAPT / bug bounty work: web app (API, auth, injection),
# mobile (Android/APK), and infra (K8s/EKS/cloud) — edit freely as
# your engagements shift focus.
# --------------------------------------------------------------------
WATCH_KEYWORDS = [
    # web app / API
    "idor", "cors", "xss", "cross-site scripting", "csrf", "ssrf",
    "sql injection", "sqli", "auth bypass", "authentication bypass",
    "access control", "privilege escalation", "jwt", "oauth", "saml",
    "graphql", "deserialization", "xxe", "ssti", "path traversal",
    "file upload", "rce", "remote code execution", "command injection",
    "api",
    # mobile
    "android", "apk", "mobile app",
    # infra / cloud
    "kubernetes", "k8s", "eks", "docker", "container escape",
    "aws", "cloud",
]
WATCH_PATTERN = re.compile("|".join(re.escape(k) for k in WATCH_KEYWORDS), re.I)

CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

STRUCTURED_SEVERITY_PATTERN = re.compile(
    r"Severity:\s*(?:</strong>)?\s*([0-9]+(?:\.[0-9]+)?)\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW)",
    re.I,
)
PUBLISHED_PATTERN = re.compile(
    r"Published\s*:?\s*(?:</strong>)?\s*([^|<]+?)\s*\|\s*([^<\n]+?ago)",
    re.I,
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
    """Pull CISA's Known Exploited Vulnerabilities catalog. Returns a
    set of CVE IDs actively exploited in the wild. Fails soft — if
    CISA is unreachable, KEV flagging is just skipped for this run
    rather than breaking the whole job."""
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "vuln-tracker"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.load(resp)
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"WARNING: could not fetch CISA KEV catalog: {e}")
        return None  # None = unknown, distinct from "fetched, empty"


def load_seen_cve_ids():
    if os.path.exists(SEEN_CVE_FILE):
        with open(SEEN_CVE_FILE, encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    return set()


def save_seen_cve_id(cve_id):
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(SEEN_CVE_FILE, "a", encoding="utf-8") as f:
        f.write(cve_id + "\n")


def append(date_str, line):
    os.makedirs(BASE_DIR, exist_ok=True)
    path = f"{BASE_DIR}/{date_str}.md"
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Critical & High Severity Vulnerabilities — {date_str}\n\n")
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def count_entries_per_day():
    counts = {}
    for path in glob.glob(f"{BASE_DIR}/*.md"):
        date_str = os.path.basename(path).replace(".md", "")
        with open(path, encoding="utf-8", errors="ignore") as f:
            counts[date_str] = sum(1 for line in f if line.startswith("- "))
    return dict(sorted(counts.items(), reverse=True))


def main():
    stats = {"critical": 0, "high": 0, "kev": 0, "watch": 0}
    new_this_run = []
    priority_this_run = []  # KEV and/or watchlist matches — the stuff to actually look at

    seen_cve_ids = load_seen_cve_ids()
    kev_ids = fetch_kev_ids()  # None if CISA fetch failed

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
            icon = "🔴" if severity == "critical" else "🟠"
            score_str = f" (CVSS {score})" if score is not None else ""
            reported_ago = extract_reported_ago(full_text)
            ago_str = f" — _reported {reported_ago}_" if reported_ago else ""
            flags = ""
            if is_kev:
                flags += " 🔥 **ACTIVELY EXPLOITED (KEV)**"
            if is_watch:
                flags += " ⭐ WATCHLIST"

            line = (
                f"- {icon} **[{severity.upper()}]**{score_str}{flags} "
                f"[{title}]({entry.get('link', '')}) — _{source}_ "
                f"({pub.strftime('%Y-%m-%d %H:%M UTC')}){ago_str}"
            )

            append(date_str, line)
            stats[severity] += 1
            new_this_run.append(line)
            if is_kev:
                stats["kev"] += 1
            if is_watch:
                stats["watch"] += 1
            if is_kev or is_watch:
                priority_this_run.append(line)

    date_counts = count_entries_per_day()

    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        f.write("# 🚨 Vulnerability Feed Status\n\n")
        f.write(f"Last checked: {datetime.now(timezone.utc).isoformat()} UTC\n\n")
        if kev_ids is None:
            f.write("> ⚠️ CISA KEV catalog could not be fetched this run — KEV flags may be incomplete.\n\n")
        f.write(f"- New critical this run: {stats['critical']}\n")
        f.write(f"- New high this run: {stats['high']}\n")
        f.write(f"- 🔥 Actively exploited (KEV) this run: {stats['kev']}\n")
        f.write(f"- ⭐ Watchlist matches this run: {stats['watch']}\n\n")

        f.write("## 📅 Counts by date (latest first)\n\n")
        f.write("| Date | Count |\n|------|------:|\n")
        for date_str, count in date_counts.items():
            f.write(f"| {date_str} | {count} |\n")
        f.write("\n")

        if priority_this_run:
            f.write("## 🎯 Priority — KEV or watchlist match\n\n")
            f.write("\n".join(priority_this_run) + "\n\n")

        if new_this_run:
            f.write("## Latest additions (all)\n\n")
            f.write("\n".join(new_this_run[:30]) + "\n")
        else:
            f.write("_No new critical/high vulns found this run._\n")


if __name__ == "__main__":
    main()
