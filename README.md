# Vuln Tracker

Automated GitHub Action that polls vulnerability RSS feeds every 15 minutes, filters for **Critical** and **High** severity CVEs only, cross-references each one against CISA's **Known Exploited Vulnerabilities (KEV)** catalog, and flags anything relevant to VAPT / bug bounty work (web API, mobile/Android, cloud/K8s) via a watchlist.

Built to stay on top of newly disclosed high-impact CVEs without manually checking feeds throughout the day.

## What it does

- Pulls from [cvefeed.io](https://cvefeed.io)'s high/critical severity RSS feed on a schedule
- Parses out CVE ID, CVSS score, and severity directly from the feed
- Cross-checks every CVE against CISA's KEV catalog — flags anything **actively being exploited in the wild**, regardless of CVSS score
- Flags anything matching a watchlist of keywords relevant to offensive security work (IDOR, CORS, XSS, SSRF, auth bypass, JWT/OAuth, GraphQL, RCE, Android/APK, Kubernetes/EKS, cloud, etc.)
- Deduplicates by CVE ID so the same vulnerability never gets logged twice, even across different days or feeds
- Groups results by severity (Critical, then High) sorted by CVSS score, rendered as tables with a per-day pie chart
- Commits results back to this repo automatically — no manual steps after initial setup

## Repo structure

```
scripts/
  fetch_critical_high_vulns.py   # the tracker script
.github/workflows/
  vuln-tracker.yml               # scheduled GitHub Action (runs every 15 min)
vulnerabilities/
  data/                          # structured JSON per day — source of truth, don't edit by hand
  .seen-cves.txt                 # flat index of every CVE ID ever logged, for fast dedup
  YYYY-MM-DD.md                  # rendered daily report (auto-generated from data/)
VULN-STATUS.md                   # dashboard: date/count table + trend chart, check this first
```

## Where to look day-to-day

- **`VULN-STATUS.md`** — start here. Shows a count-by-date trend chart so you can see at a glance whether things have been quiet or spiking.
- **`vulnerabilities/YYYY-MM-DD.md`** — full breakdown for a given day: pie chart, then a Critical table and a High table, each sorted by CVSS score. Entries flagged 🔥 are in CISA's KEV list (actively exploited); entries flagged ⭐ match the watchlist.

## Setup

1. In repo **Settings → Actions → General → Workflow permissions**, select **"Read and write permissions"** (needed so the Action can commit results back).
2. Trigger a manual run from the **Actions** tab (`Critical/High Vulnerability Tracker` → `Run workflow`) to confirm it works before relying on the schedule.
3. After that, the cron in `vuln-tracker.yml` runs automatically — no further action needed.

## Customizing

- **Add more feeds**: edit `RSS_SOURCES` in `scripts/fetch_critical_high_vulns.py`.
- **Adjust the watchlist**: edit `WATCH_KEYWORDS` in the same file — add terms specific to whatever you're currently testing.
- **Change the schedule**: edit the `cron` line in `.github/workflows/vuln-tracker.yml`.

## Notes

- The KEV check fails soft — if CISA's feed is briefly unreachable, that run just skips KEV flagging and logs a warning instead of failing outright.
- GitHub auto-disables scheduled workflows after 60 days with no commits to the repo. As long as the tracker is committing its own results regularly, this won't be an issue.
