# Wazuh SOC — Standalone React SPA

## Overview

Migrate the monolithic `wazuh-soc.html` (544 lines, 67KB) into a standalone React Vite SPA
at `/home/aiagent/wazuh-soc/`, reusing the existing Python API proxy at `http://localhost:8095/wazuh-api/*`.

## Motivation

- Current 67KB monolith is hard to maintain — inline HTML strings for rendering
- No component reuse — duplicated patterns across pages
- No build step, no HMR, no code splitting
- Broken HTML in topbar from partial platform-style merge
- Need a proper foundation for SOC improvements

## Architecture

```
/home/aiagent/wazuh-soc/
├── index.html
├── package.json
├── vite.config.js             # proxy /wazuh-api → http://localhost:8095
├── src/
│   ├── main.jsx               # React root
│   ├── App.jsx                # Router + Layout shell
│   ├── api/
│   │   └── wazuh.js           # fetch wrapper → /wazuh-api/*
│   ├── hooks/
│   │   └── useApi.js          # Generic fetch hook (data/loading/error)
│   ├── components/
│   │   ├── Layout.jsx         # Sidebar + Topbar + <Outlet>
│   │   ├── Sidebar.jsx        # Collapsible nav
│   │   ├── Topbar.jsx         # Title + refresh + nav links
│   │   ├── KpiCard.jsx        # KPI metric display
│   │   ├── DataTable.jsx      # Reusable table with sort
│   │   ├── StatusBadge.jsx    # Agent status badge
│   │   ├── SeverityBadge.jsx  # Alert severity badge
│   │   ├── FilterTabs.jsx     # Filter tab group
│   │   ├── LoadingSpinner.jsx
│   │   ├── ErrorState.jsx     # With retry button
│   │   ├── EmptyState.jsx
│   │   ├── Toast.jsx          # Toast notification system
│   │   └── NLPanel.jsx        # Natural language query panel
│   ├── pages/
│   │   ├── Dashboard.jsx      # KPIs + 3 charts
│   │   ├── Agents.jsx         # Agent list with filter
│   │   ├── AgentDetail.jsx    # Agent detail + tabs (SCA/FIM/Vulns/Inventory)
│   │   ├── SCA.jsx            # SCA compliance overview
│   │   ├── FIM.jsx            # File integrity events
│   │   ├── Vulnerabilities.jsx# Vulnerability list
│   │   ├── Mitre.jsx          # MITRE ATT&CK techniques
│   │   ├── Rules.jsx          # Rules & Decoders
│   │   ├── Events.jsx         # Alert event feed
│   │   ├── Topology.jsx       # OS/Version distribution
│   │   ├── Threats.jsx        # OTX Threat Intel
│   │   ├── Autopilot.jsx      # SOC Autopilot case list
│   │   ├── AutopilotCase.jsx  # Case detail + actions
│   │   ├── Manager.jsx        # Manager health daemons
│   │   ├── Groups.jsx         # Agent groups
│   │   ├── AlertDetail.jsx    # Alert detail + remediation
│   │   └── Help.jsx           # Help page
│   └── styles/
│       └── global.css         # Cyber-dark theme
```

## Stack

- **Framework:** React 18 + React Router v6 (hash routing: `#/agents`, `#/events`)
- **Build:** Vite 5
- **Charts:** Chart.js 4 + react-chartjs-2
- **HTTP:** Native `fetch` — no Axios needed
- **State:** React hooks + Context (toast notifications, NL panel)
- **Styling:** Single global CSS (evolved cyber-dark theme)
- **No TypeScript** (plain JSX for faster migration)

## API Integration

Python server runs on port **8095** (uvicorn). Vite dev server proxies `/wazuh-api` → `http://localhost:8095`.

The `useApi` hook wraps fetch with loading/error/data states:
```js
const { data, loading, error } = useApi('/wazuh-api/overview');
```

## Pages & Routes

| Route              | Page              | API Endpoints                        |
|--------------------|-------------------|--------------------------------------|
| `#/`               | Dashboard         | `/overview`, `/events/stats`         |
| `#/agents`         | Agents            | `/agents?limit=500`                  |
| `#/agent/:id`      | AgentDetail       | `/agents/:id`, `/agents/:id/sca`, etc|
| `#/sca`            | SCA               | `/overview/sca`                      |
| `#/fim`            | FIM               | `/overview/fim`                      |
| `#/vulnerabilities`| Vulnerabilities   | `/overview/vulnerabilities`          |
| `#/mitre`          | Mitre             | `/mitre`                             |
| `#/rules`          | Rules             | `/rules`, `/decoders`                |
| `#/events`         | Events            | `/events`, `/events/stats`           |
| `#/topology`       | Topology          | `/overview`, `/topology`             |
| `#/threats`        | Threats           | `/otx/status`, `/otx/iocs`           |
| `#/autopilot`      | Autopilot         | `/autopilot/cases`, `/autopilot/stats`|
| `#/autopilot/case/:id` | AutopilotCase | `/autopilot/cases/:id`               |
| `#/manager`        | Manager           | `/manager`, `/manager/info`          |
| `#/groups`         | Groups            | `/groups`                            |
| `#/alert/:id`      | AlertDetail       | `/events`, remediation API           |
| `#/help`           | Help              | Static content                       |

## UI/UX

- **Theme:** Cyber-dark — `#07090d` background, `#00e5ff` cyan accent, `#00ff88` green, `#ff4757` red, `#ff9500` amber
- **Sidebar:** Collapsible, 12 nav items with icons, active indicator
- **Topbar:** Page title, refresh button, Home/Help/DevDocs links
- **KPIs:** Animated counter cards in responsive grid
- **Tables:** Sticky headers, sortable columns, row hover, status badges
- **Charts:** Doughnut + bar, legend bottom, consistent palette
- **States:** Every page handles loading (spinner), error (message + retry), empty (message)
- **NL Panel:** Slide-out bottom-right panel for natural language queries

## Performance

- **Code splitting:** `React.lazy` + `Suspense` per page route
- **Virtual scrolling:** `react-window` for agent lists (500+ rows)
- **Chart management:** `react-chartjs-2` handles lifecycle — no manual destroy
- **Debounced search:** Input delay before API calls
- **Memoization:** `React.memo` on table rows, `useMemo` on filtered data

## Deployment

- **Development:** `npm run dev` — Vite on port 5173, proxies `/wazuh-api` to port 8095
- **Production:** `npm run build` → `dist/` folder of static files
  - Option A: Serve `dist/` from Python (add static mount in `app.py`)
  - Option B: Serve via nginx reverse proxy

## Migration Path

1. Scaffold Vite + React project at `/home/aiagent/wazuh-soc/`
2. Build shared components (Layout, Sidebar, KpiCard, DataTable, etc.)
3. Implement pages one by one, following the nav order
4. Wire up routing and verify each page matches current behavior
5. Add NL panel and toast system
6. Build and deploy
7. Update `index-platform.html` link to point to new SOC app
