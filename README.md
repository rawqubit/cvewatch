# cvewatch 👁️

> **Automated CVE monitoring daemon** with AI-powered triage and Slack/Discord alerting. Filters by your tech stack so you only get notified about vulnerabilities that actually affect you.

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/rawqubit/cvewatch/actions/workflows/ci.yml/badge.svg)](https://github.com/rawqubit/cvewatch/actions/workflows/ci.yml)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4.1-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com/)
[![NVD](https://img.shields.io/badge/Data-NVD%20API%202.0-blue?style=flat-square)](https://nvd.nist.gov/developers/vulnerabilities)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## Overview

Security teams are drowning in CVE noise. The NVD publishes 50–100 new vulnerabilities every day, but only a handful are relevant to any given organization's stack. Without filtering, teams either miss critical vulnerabilities or suffer alert fatigue from irrelevant ones.

`cvewatch` solves this by combining **real-time NVD polling** with **AI-powered relevance triage** — so your team only gets paged for CVEs that actually affect your infrastructure.

---

## Features

- **Real-time NVD polling** — monitors the NVD API 2.0 for new and modified CVEs
- **AI relevance triage** — GPT-4.1 assesses each CVE against your declared tech stack
- **Stack-aware filtering** — define your stack once, get only relevant alerts
- **Slack & Discord webhooks** — color-coded, actionable alerts with patch urgency
- **Patch urgency classification** — `immediate` / `this_week` / `this_month` / `monitor`
- **Weekly digest mode** — generate a summary of the week's CVEs for your stack
- **Single CVE analysis** — deep-dive any CVE with AI-generated attack scenarios
- **Configurable CVSS threshold** — filter out low-severity noise
- **Daemon mode** — runs continuously with configurable polling intervals

---

## Installation

```bash
git clone https://github.com/rawqubit/cvewatch.git
cd cvewatch
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."

# Optional: configure alerting
export CVEWATCH_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export CVEWATCH_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
```

---

## Usage

### Analyze a specific CVE

```bash
python main.py fetch CVE-2021-44228
python main.py fetch CVE-2024-1234 --stack "java,log4j,spring"
```

### Start the monitoring daemon

```bash
# Monitor for CVEs affecting your stack, CVSS >= 7.0
python main.py watch --stack "python,django,redis,nginx" --cvss-min 7.0

# With Slack alerting, check every 30 minutes
python main.py watch \
  --stack "node,express,mongodb" \
  --slack-webhook $CVEWATCH_SLACK_WEBHOOK \
  --interval 1800

# Run once (useful for cron jobs)
python main.py watch --stack "rust,tokio,openssl" --once
```

### Generate a weekly digest

```bash
python main.py digest --days 7 --stack "python,fastapi,postgres" --output markdown > weekly.md
python main.py digest --days 30 --cvss-min 9.0  # Critical CVEs only
```

---

## Slack Alert Example

```
🔐 CVE-2021-44228 — CVSS 10.0
────────────────────────────────
A remote code execution vulnerability in Apache Log4j2 allows
attackers to execute arbitrary code via crafted log messages.

Urgency:   IMMEDIATE
Relevance: High
Affected:  java, log4j, spring-boot

Actions:
• Upgrade log4j2 to 2.17.1 or later immediately
• Apply WAF rules to block ${jndi: patterns
• Audit all applications using log4j
```

---

## Architecture

```
cvewatch/
├── main.py          # CLI + daemon + alerting
└── requirements.txt
```

### Data Flow

```
NVD API 2.0 (polling every N seconds)
    │
    ▼
┌─────────────────────────────────────────────┐
│  CVE Filter                                 │
│  • CVSS score >= threshold                  │
│  • Not previously seen (dedup by CVE ID)    │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  AI Triage (GPT-4.1-mini)                   │
│  • Relevance to declared tech stack         │
│  • Patch urgency classification             │
│  • Affected component identification        │
│  • Immediate action recommendations         │
└─────────────────────────────────────────────┘
    │
    ▼ (if relevance = high | medium)
┌─────────────────────────────────────────────┐
│  Alert Dispatch                             │
│  • Slack webhook (color-coded by urgency)   │
│  • Discord webhook (embed format)           │
│  • Rich terminal output                     │
└─────────────────────────────────────────────┘
```

---

## Cron Integration

```bash
# Run daily digest and post to Slack
0 9 * * 1 cd /opt/cvewatch && python main.py watch \
  --stack "python,django,postgres" \
  --slack-webhook $SLACK_WEBHOOK \
  --once >> /var/log/cvewatch.log 2>&1
```

---

## Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "main.py", "watch", "--stack", "python,nginx", "--interval", "3600"]
```

---

## Contributing

Priority areas:
- Additional alerting integrations (PagerDuty, OpsGenie, email)
- EPSS score integration for exploit prediction
- GitHub Advisory Database as an additional data source
- Persistent state (SQLite) for historical tracking

---

## License

MIT License — see [LICENSE](LICENSE) for details.
