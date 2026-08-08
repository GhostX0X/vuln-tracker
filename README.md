# Vuln Tracker

An automated GitHub Action that continuously monitors vulnerability disclosure feeds, filters for **Critical**, **High**, and **Medium** severity CVEs, cross-references every finding against CISA's **Known Exploited Vulnerabilities (KEV)** catalog, and flags anything relevant to offensive security work — web/API, mobile (Android/APK), and cloud/Kubernetes — via a configurable watchlist.

Built to eliminate manual feed-checking: new critical-impact CVEs are surfaced automatically, prioritized by real-world exploitation status rather than CVSS score alone.

---

## Features

- **Multi-source ingestion** — pulls from one or more configured vulnerability RSS feeds on a schedule (currently [cvefeed.io](https://cvefeed.io); more feeds can be added independently).
- **CISA KEV cross-check** — every CVE is checked against the actively-exploited-in-the-wild catalog. A KEV match is flagged regardless of severity, since real-world exploitation is a stronger prioritization signal than CVSS alone.
- **Offensive-security watchlist** — entries matching keywords relevant to VAPT/bug bounty work (IDOR, CORS, XSS, SSRF, auth bypass, JWT/OAuth, GraphQL, RCE, Android/APK, Kubernetes/EKS, cloud, etc.) are flagged separately.
- **Cross-run, cross-feed deduplication** — every CVE ID is tracked in a persistent index, so the same vulnerability is never logged twice even if it reappears across different feeds or days.
- **Severity-grouped, chart-backed reports** — each day's findings are rendered as Critical / High / Medium tables sorted by CVSS score, with a per-day distribution chart and a per-source contribution breakdown.
- **Organized, browsable archive** — reports are structured into `year → month → day`, with an auto-generated index at each level sorted latest-first.
- **Fully autonomous** — the Action commits its own results back to this repository on a schedule. No manual maintenance required after initial setup.

---

## Repository structure

```
.
├── VULN-STATUS.md              Dashboard — start here
├── scripts/
│   └── fetch_critical_high_vulns.py
├── .github/workflows/
│   └── vuln-tracker.yml        Scheduled GitHub Action
└── vulnerabilities/
    ├── README.md               Archive index (years, latest first)
    ├── <year>/
    │   ├── README.md           Year index (months, latest first)
    │   └── <month>/
    │       ├── README.md       Month index (days, latest first)
    │       └── <date>.md       Daily report
    └── data/<year>/<month>/    Structured JSON — source of truth
```

---

## Where to look

- **`VULN-STATUS.md`** — the dashboard. Lists every configured source and a count-by-date trend chart, so you can tell at a glance whether activity has been quiet or spiking.
- **`vulnerabilities/<year>/<month>/<date>.md`** — full daily breakdown: severity distribution chart, per-source contribution table, then Critical/High/Medium tables sorted by CVSS. 🔥 marks a KEV (actively exploited) match; ⭐ marks a watchlist match.
- **`vulnerabilities/<year>/<month>/README.md`** — browse an entire month at a glance, latest day first.

---

## Configuration

| To change... | Edit... |
|---|---|
| Feed sources | `RSS_SOURCES` in `scripts/fetch_critical_high_vulns.py` |
| Watchlist keywords | `WATCH_KEYWORDS` in the same file |
| Run frequency | the `cron` line in `.github/workflows/vuln-tracker.yml` |

---

## Notes & limitations

- The KEV lookup fails soft — if CISA's catalog is briefly unreachable, that run logs a warning and continues without KEV flags rather than failing outright.
- GitHub automatically disables scheduled workflows after 60 days with no commits to the repository. Since the tracker commits its own output regularly, this is a non-issue under normal operation.
- Feed severity classification depends on each source's own formatting; entries are cross-checked but not independently re-verified against NVD.

---

## Roadmap

Planned or under consideration:

- **Webhook alerts** — push KEV matches and watchlist hits to Slack/Discord in real time, instead of relying on someone checking the repo.
- **EPSS scoring** — sort findings by exploitation-probability score (FIRST.org) alongside CVSS and KEV status, for finer-grained prioritization.
- **Additional feed sources** — expand beyond the current feed for broader coverage and cross-source confirmation.
- **Configurable per-run digest** — an optional summary issue/comment posted once a day instead of relying solely on the file archive.

Have a feature you'd want prioritized? Let us know.

---

## Contributing

Suggestions and improvements are welcome — additional feed sources, watchlist tuning, report formatting, or general reliability fixes. Open an issue or submit a pull request with a clear description of the change and, where relevant, sample feed output that motivated it.

## Feedback

Found a bug, a feed that stopped working, or a false positive/negative in severity or KEV matching? Open an issue with the CVE ID and a link to the source entry — that's usually enough to reproduce and fix quickly.
