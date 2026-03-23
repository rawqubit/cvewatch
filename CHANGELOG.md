# Changelog

All notable changes to **cvewatch** are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) | Versioning: [SemVer](https://semver.org/)

## [1.1.0] - 2025-03-01
### Added
- Tech stack filtering with AI relevance scoring
- Discord webhook support alongside Slack
- CVSS v3.1 enrichment + AI-generated patch urgency classification
- `--dry-run` flag for alert config testing
- Daemon mode with configurable polling interval (`--interval`)

### Fixed
- NVD API 2.0 rate limit handling with exponential backoff
- Fixed false alerts below configurable CVSS threshold

## [1.0.0] - 2024-09-20
### Added
- Initial release: NVD API 2.0 polling with AI triage
- Slack webhook alerting with rich CVE summaries
- Tech stack filter via `--stack` flag
