# Threat Dashboard — Operation Digital Fortitude

A Flask-based incident response dashboard for visualizing APT threat campaigns, tracking IOCs, mapping attack chains, and managing incident reports. Built with a dark, tactical UI themed around the "Fenrir Wolves" IR team.

## Features

### Dashboard
- Attack chain timeline with MITRE ATT&CK technique mapping
- Suspicious IP & phishing domain IOC panels
- Threat intelligence feed with predicted next moves
- Actionable recommendations with MITRE mitigation IDs
- Real-time incident stats (IOCs, compromised users, affected systems)

### Network Map
- Upload draw.io XML diagrams to visualize network topology
- Color-coded nodes (External, DMZ, Internal, Compromised)
- Storyboard view showing attack phases from initial access to defense evasion

### IR Reports
- Searchable incident report cards with analyst attribution
- Filter by severity (Critical/High/Medium), category (Malware, Lateral Movement, Recon)
- Detailed metadata: operation ID, discovery DTG, hostile IPs, affected hosts

### Admin Console
- Full CRUD for all dashboard data (IPs, domains, timeline events, recommendations)
- Inline editing with date/time pickers
- One-click save to persist changes to `data.json`

## Tech Stack

- **Backend:** Flask, Flask-CORS
- **Frontend:** Vanilla HTML/CSS/JS, Chart.js
- **Fonts:** Black Ops One, Rajdhani (Google Fonts)
- **Data:** JSON-based persistence via `data.json`

## Quick Start

### Prerequisites
- Python 3.8+

### Installation

```bash
pip install flask flask-cors
```

### Run

```bash
bash start_server.sh
```

Or manually:

```bash
python3 server.py
```

The server runs on **http://0.0.0.0:8089**.

## Pages & Routes

| Route | Description |
|-------|-------------|
| `/` | Main threat dashboard with timeline, IOCs, and stats |
| `/network-map` | Network topology visualizer with draw.io upload |
| `/reports` | Searchable incident response report cards |
| `/admin` | Admin console for editing all dashboard data |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/data` | GET | Retrieve all dashboard data (timeline, IPs, domains, recommendations, threat intel) |
| `/api/data` | POST | Update dashboard data (accepts full JSON payload) |
| `/api/iocs` | GET | Retrieve IOC list (IPs, domains, file hashes) |
| `/api/upload-map` | POST | Upload a draw.io XML network diagram |

## File Structure

```
dashboard/
├── server.py           # Flask application (routes, API, templates)
├── dashboard.html      # Main dashboard frontend
├── data.json           # Persisted incident data (editable via admin)
├── start_server.sh     # Quick-start script
├── .gitignore
├── uploads/
│   └── network_map.xml # Uploaded draw.io diagram
└── __pycache__/
```

## Data

All incident data is stored in `data.json` and loaded on startup. The structure includes:
- `timeline` — Attack chain events with MITRE ATT&CK mappings
- `suspicious_ips` — Tracked hostile/recon IPs with status
- `phishing_domains` — Identified phishing & C2 domains
- `threat_intel` — Predicted adversary next moves
- `recommendations` — Active remediation actions

## Future Upgrades

- **Reusable template engine** — Decouple the dashboard from hardcoded campaign data so it becomes a reusable framework. Load incident data dynamically via JSON configuration files rather than baking content into the HTML, allowing the same dashboard to be deployed for any incident response scenario without code changes.

- **Multi-APT selector** — Add an APT picker (dropdown or route parameter) so analysts can switch between different threat actor campaigns (APT28, APT41, Lazarus, etc.) and load their respective IOCs, timelines, reports, and threat intelligence on the fly. Support loading separate data profiles per campaign.

- **Theme & style customization** — Add a theme switcher with multiple visual presets (e.g., Wolf Den blue, red team dark, SOC green) so teams can customize the look without touching CSS. Support custom logos, accent colors, and font preferences loaded via config. Enable per-team branding for organizations running their own IR dashboards.
