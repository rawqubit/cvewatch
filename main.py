#!/usr/bin/env python3
"""
cvewatch: Automated CVE monitoring and intelligent alerting daemon.

Polls the NVD API for new and recently modified CVEs, uses AI to triage
severity and relevance based on your tech stack, and delivers enriched
alerts to Slack, Discord, or email — so your team is never blindsided.

Usage:
    python main.py watch --stack "python,django,nginx,postgres"
    python main.py watch --slack-webhook https://hooks.slack.com/... --cvss-min 7.0
    python main.py fetch CVE-2024-1234
    python main.py digest --days 7 --stack "rust,tokio,openssl"
"""

import json
import time
import os
import click
import requests
from datetime import datetime, timedelta, timezone
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
ai_client = OpenAI()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------------------------
# NVD API helpers
# ---------------------------------------------------------------------------

def fetch_recent_cves(hours: int = 24, cvss_min: float = 0.0) -> list[dict]:
    """Fetch CVEs published or modified in the last N hours from NVD."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    try:
        resp = requests.get(NVD_BASE, params=params, timeout=20,
                            headers={"User-Agent": "cvewatch/1.0"})
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        results = []
        for v in vulns:
            cve = v.get("cve", {})
            score = _extract_cvss(cve)
            if score >= cvss_min:
                results.append(cve)
        return results
    except Exception as e:
        console.print(f"[bold red]NVD API error: {e}[/bold red]")
        return []


def fetch_cve_by_id(cve_id: str) -> dict | None:
    """Fetch a specific CVE by ID."""
    try:
        resp = requests.get(NVD_BASE, params={"cveId": cve_id}, timeout=15,
                            headers={"User-Agent": "cvewatch/1.0"})
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return vulns[0].get("cve") if vulns else None
    except Exception as e:
        console.print(f"[bold red]NVD fetch error: {e}[/bold red]")
        return None


def _extract_cvss(cve: dict) -> float:
    """Extract the highest available CVSS score from a CVE record."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore", 0.0)
    return 0.0


def _extract_description(cve: dict) -> str:
    descs = cve.get("descriptions", [])
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "No description available.")
    return descs[0].get("value", "No description available.") if descs else "No description available."


def _extract_cpe_list(cve: dict) -> list[str]:
    cpes = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpes.append(match.get("criteria", ""))
    return cpes[:20]


# ---------------------------------------------------------------------------
# AI triage
# ---------------------------------------------------------------------------

def ai_triage_cve(cve: dict, stack: list[str]) -> dict:
    """Use AI to assess CVE relevance and impact for a given tech stack."""
    cve_id = cve.get("id", "Unknown")
    description = _extract_description(cve)
    score = _extract_cvss(cve)
    cpes = _extract_cpe_list(cve)

    prompt = f"""You are a security engineer triaging CVEs for a development team.

Tech Stack: {', '.join(stack) if stack else 'general'}
CVE ID: {cve_id}
CVSS Score: {score}
Description: {description}
Affected CPEs (sample): {', '.join(cpes[:10]) if cpes else 'Not specified'}

Provide a JSON response:
{{
  "relevance": "high"|"medium"|"low"|"not_applicable",
  "relevance_score": 0.0-1.0,
  "affected_components": ["list of stack components affected"],
  "exploit_likelihood": "high"|"medium"|"low",
  "summary": "2-3 sentence plain English summary",
  "immediate_actions": ["action1", "action2"],
  "patch_urgency": "immediate"|"this_week"|"this_month"|"monitor"
}}"""

    try:
        response = ai_client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are a senior security engineer specializing in vulnerability management."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        return json.loads(response.choices[0].message.content)
    except Exception:
        return {
            "relevance": "unknown",
            "relevance_score": 0.5,
            "summary": description[:300],
            "immediate_actions": ["Review CVE details manually"],
            "patch_urgency": "monitor",
        }


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def send_slack_alert(webhook_url: str, cve: dict, triage: dict):
    """Send a formatted CVE alert to a Slack webhook."""
    cve_id = cve.get("id", "Unknown")
    score = _extract_cvss(cve)
    urgency = triage.get("patch_urgency", "monitor")
    color = {"immediate": "#FF0000", "this_week": "#FF8C00",
             "this_month": "#FFD700", "monitor": "#36A64F"}.get(urgency, "#808080")

    payload = {
        "attachments": [{
            "color": color,
            "title": f"🔐 {cve_id} — CVSS {score}",
            "title_link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "text": triage.get("summary", ""),
            "fields": [
                {"title": "Urgency", "value": urgency.replace("_", " ").title(), "short": True},
                {"title": "Relevance", "value": triage.get("relevance", "unknown").title(), "short": True},
                {"title": "Affected", "value": ", ".join(triage.get("affected_components", [])) or "—", "short": False},
                {"title": "Actions", "value": "\n".join(f"• {a}" for a in triage.get("immediate_actions", [])), "short": False},
            ],
            "footer": "cvewatch",
            "ts": int(time.time()),
        }]
    }
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        console.print(f"[yellow]Slack alert failed: {e}[/yellow]")


def send_discord_alert(webhook_url: str, cve: dict, triage: dict):
    """Send a formatted CVE alert to a Discord webhook."""
    cve_id = cve.get("id", "Unknown")
    score = _extract_cvss(cve)
    urgency = triage.get("patch_urgency", "monitor")
    color_map = {"immediate": 0xFF0000, "this_week": 0xFF8C00, "this_month": 0xFFD700, "monitor": 0x36A64F}

    payload = {
        "embeds": [{
            "title": f"🔐 {cve_id} — CVSS {score}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "description": triage.get("summary", ""),
            "color": color_map.get(urgency, 0x808080),
            "fields": [
                {"name": "Urgency", "value": urgency.replace("_", " ").title(), "inline": True},
                {"name": "Relevance", "value": triage.get("relevance", "unknown").title(), "inline": True},
                {"name": "Immediate Actions", "value": "\n".join(f"• {a}" for a in triage.get("immediate_actions", [])[:3]) or "—"},
            ],
            "footer": {"text": "cvewatch"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
    }
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        console.print(f"[yellow]Discord alert failed: {e}[/yellow]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("1.0.0", prog_name="cvewatch")
def cli():
    """cvewatch — Automated CVE monitoring and intelligent alerting daemon."""
    pass


@cli.command()
@click.argument("cve_id")
@click.option("--stack", default="", help="Comma-separated tech stack for relevance analysis.")
def fetch(cve_id, stack):
    """Fetch and analyze a specific CVE.

    \b
    Example:
        python main.py fetch CVE-2021-44228
        python main.py fetch CVE-2024-1234 --stack "java,log4j,spring"
    """
    console.print(Panel(f"[bold cyan]Fetching {cve_id}...[/bold cyan]", expand=False))
    cve = fetch_cve_by_id(cve_id)
    if not cve:
        console.print(f"[bold red]CVE {cve_id} not found.[/bold red]")
        return

    stack_list = [s.strip() for s in stack.split(",") if s.strip()] if stack else []
    triage = ai_triage_cve(cve, stack_list)

    score = _extract_cvss(cve)
    desc = _extract_description(cve)
    urgency = triage.get("patch_urgency", "monitor")
    urgency_color = {"immediate": "bold red", "this_week": "bold yellow",
                     "this_month": "yellow", "monitor": "green"}.get(urgency, "white")

    console.print(Panel(
        f"[bold]{cve_id}[/bold]  CVSS: [bold red]{score}[/bold red]\n\n"
        f"[dim]{desc[:400]}[/dim]\n\n"
        f"Patch Urgency: [{urgency_color}]{urgency.replace('_', ' ').title()}[/{urgency_color}]\n"
        f"Relevance: {triage.get('relevance', 'unknown').title()}\n"
        f"Affected: {', '.join(triage.get('affected_components', [])) or '—'}",
        title="CVE Analysis",
        expand=False,
    ))

    if triage.get("immediate_actions"):
        console.print("[bold yellow]Immediate Actions:[/bold yellow]")
        for action in triage["immediate_actions"]:
            console.print(f"  • {action}")


@cli.command()
@click.option("--stack", default="", help="Comma-separated tech stack (e.g. 'python,django,nginx').")
@click.option("--cvss-min", default=7.0, show_default=True, help="Minimum CVSS score to alert on.")
@click.option("--interval", default=3600, show_default=True, help="Polling interval in seconds.")
@click.option("--slack-webhook", default=None, envvar="CVEWATCH_SLACK_WEBHOOK")
@click.option("--discord-webhook", default=None, envvar="CVEWATCH_DISCORD_WEBHOOK")
@click.option("--once", is_flag=True, default=False, help="Run once and exit (no daemon loop).")
def watch(stack, cvss_min, interval, slack_webhook, discord_webhook, once):
    """Start the CVE monitoring daemon.

    \b
    Examples:
        python main.py watch --stack "python,django,redis" --cvss-min 7.0
        python main.py watch --slack-webhook $SLACK_WEBHOOK --interval 1800
        python main.py watch --once --stack "rust,tokio"
    """
    stack_list = [s.strip() for s in stack.split(",") if s.strip()] if stack else []
    console.print(Panel(
        f"[bold cyan]cvewatch daemon started[/bold cyan]\n"
        f"Stack: {', '.join(stack_list) or 'all'}\n"
        f"CVSS min: {cvss_min} | Interval: {interval}s\n"
        f"Slack: {'configured' if slack_webhook else 'not configured'} | "
        f"Discord: {'configured' if discord_webhook else 'not configured'}",
        expand=False
    ))

    seen_ids = set()

    while True:
        console.print(f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — Polling NVD...[/dim]")
        cves = fetch_recent_cves(hours=max(1, interval // 3600 + 1), cvss_min=cvss_min)
        new_cves = [c for c in cves if c.get("id") not in seen_ids]

        if new_cves:
            console.print(f"[bold green]{len(new_cves)} new CVEs found.[/bold green]")
            for cve in new_cves:
                seen_ids.add(cve.get("id"))
                triage = ai_triage_cve(cve, stack_list)
                if triage.get("relevance") in ("high", "medium") or not stack_list:
                    cve_id = cve.get("id")
                    score = _extract_cvss(cve)
                    console.print(f"  [bold red]{cve_id}[/bold red] CVSS {score} — {triage.get('patch_urgency', '?')}")
                    if slack_webhook:
                        send_slack_alert(slack_webhook, cve, triage)
                    if discord_webhook:
                        send_discord_alert(discord_webhook, cve, triage)
        else:
            console.print("[dim]No new CVEs above threshold.[/dim]")

        if once:
            break
        time.sleep(interval)


@cli.command()
@click.option("--days", default=7, show_default=True, help="Number of days to look back.")
@click.option("--stack", default="", help="Comma-separated tech stack for relevance filtering.")
@click.option("--cvss-min", default=7.0, show_default=True)
@click.option("--output", default="table", type=click.Choice(["table", "json", "markdown"]))
def digest(days, stack, cvss_min, output):
    """Generate a weekly CVE digest for your tech stack.

    \b
    Example:
        python main.py digest --days 7 --stack "node,express,mongodb" --output markdown
    """
    stack_list = [s.strip() for s in stack.split(",") if s.strip()] if stack else []
    console.print(Panel(f"[bold cyan]Generating {days}-day CVE digest...[/bold cyan]", expand=False))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        task = progress.add_task("Fetching CVEs from NVD...", total=None)
        cves = fetch_recent_cves(hours=days * 24, cvss_min=cvss_min)
        progress.update(task, description=f"Triaging {len(cves)} CVEs with AI...")
        triaged = [(cve, ai_triage_cve(cve, stack_list)) for cve in cves[:30]]

    if output == "json":
        print(json.dumps([
            {"cve_id": c.get("id"), "cvss": _extract_cvss(c), "triage": t}
            for c, t in triaged
        ], indent=2))
        return

    table = Table(title=f"CVE Digest — Last {days} days (CVSS ≥ {cvss_min})",
                  show_header=True, header_style="bold red")
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("CVSS", width=6)
    table.add_column("Relevance", width=12)
    table.add_column("Urgency", width=14)
    table.add_column("Summary", max_width=60)

    for cve, triage in sorted(triaged, key=lambda x: _extract_cvss(x[0]), reverse=True):
        score = _extract_cvss(cve)
        urgency = triage.get("patch_urgency", "monitor")
        urgency_color = {"immediate": "bold red", "this_week": "bold yellow",
                         "this_month": "yellow", "monitor": "green"}.get(urgency, "white")
        table.add_row(
            cve.get("id", "?"),
            str(score),
            triage.get("relevance", "?"),
            f"[{urgency_color}]{urgency.replace('_', ' ')}[/{urgency_color}]",
            triage.get("summary", "")[:120],
        )

    console.print(table)


if __name__ == "__main__":
    cli()
