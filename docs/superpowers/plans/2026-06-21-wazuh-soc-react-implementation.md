# Wazuh SOC React SPA — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone React Vite SPA at `/home/aiagent/wazuh-soc/` that replaces `wazuh-soc.html` with a component-based architecture, better UI/UX, and performance improvements, reusing the existing Python API proxy at `localhost:8095`.

**Architecture:** React 18 + React Router v6 hash-based SPA. Vite dev server proxies `/wazuh-api` to Python server. Pages code-split via `React.lazy`. Chart.js via `react-chartjs-2`. Single global CSS cyber-dark theme.

**Tech Stack:** React 18, Vite 5, React Router v6, Chart.js 4 + react-chartjs-2, react-window (virtual scrolling), plain JSX.

---

### Task 1: Scaffold Vite + React project

**Files:**
- Create: `/home/aiagent/wazuh-soc/package.json`
- Create: `/home/aiagent/wazuh-soc/vite.config.js`
- Create: `/home/aiagent/wazuh-soc/index.html`

- [ ] **Step 1: Create project directory and package.json**

```bash
mkdir -p /home/aiagent/wazuh-soc/src/{api,hooks,context,components,pages,styles}
```

Create `/home/aiagent/wazuh-soc/package.json`:

```json
{
  "name": "wazuh-soc",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "chart.js": "^4.4.7",
    "react": "^18.3.1",
    "react-chartjs-2": "^5.2.0",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.0",
    "react-window": "^1.8.10"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.1",
    "vite": "^5.4.0"
  }
}
```

- [ ] **Step 2: Create vite.config.js**

Create `/home/aiagent/wazuh-soc/vite.config.js`:

```js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/wazuh-api': {
        target: 'http://localhost:8095',
        changeOrigin: true,
      },
    },
  },
});
```

- [ ] **Step 3: Create index.html**

Create `/home/aiagent/wazuh-soc/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Wazuh SOC — Mission Control</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>" />
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.jsx"></script>
</body>
</html>
```

- [ ] **Step 4: Install dependencies**

```bash
cd /home/aiagent/wazuh-soc && npm install
```

- [ ] **Step 5: Create .gitignore**

```bash
echo -e "node_modules\ndist\n.env" > /home/aiagent/wazuh-soc/.gitignore
```

---

### Task 2: Global CSS Theme

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/styles/global.css`

- [ ] **Step 1: Write global.css**

Create `/home/aiagent/wazuh-soc/src/styles/global.css`:

```css
:root {
  --bg: #07090d;
  --bg-card: #111827;
  --bg-hover: #1e293b;
  --bg-input: #05070a;
  --border: #2d2d3d;
  --border-accent: rgba(84, 214, 255, 0.18);
  --text: #e7f6ff;
  --text-secondary: #8fa6b5;
  --cyan: #00e5ff;
  --green: #00ff88;
  --amber: #ff9500;
  --red: #ff4757;
  --blue: #3b82f6;
  --accent: #00b4d8;
  --radius: 12px;
  --radius-sm: 8px;
  --sidebar-width: 220px;
  --sidebar-collapsed: 56px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

html, body {
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
}

#root { display: flex; height: 100vh; overflow: hidden; }

a { color: inherit; text-decoration: none; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #2d2d3d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #475569; }

/* ── Layout ── */
.app-layout { display: flex; height: 100vh; width: 100%; overflow: hidden; }

.main-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
}

.content-area {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
}

/* ── Sidebar ── */
.sidebar {
  width: var(--sidebar-width);
  min-width: var(--sidebar-width);
  background: var(--bg-card);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  transition: width 0.2s, min-width 0.2s;
  overflow: hidden;
  z-index: 100;
}

.sidebar.collapsed {
  width: var(--sidebar-collapsed);
  min-width: var(--sidebar-collapsed);
}

.sidebar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}

.sidebar.collapsed .sidebar-header { justify-content: center; padding: 12px 0; }

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 8px;
}

.sidebar-logo-icon { font-size: 20px; color: var(--cyan); }
.sidebar-logo-text { font-weight: 700; font-size: 16px; white-space: nowrap; }
.sidebar.collapsed .sidebar-logo-text { display: none; }

.sidebar-toggle {
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 18px;
  padding: 4px 8px;
  border-radius: var(--radius-sm);
}

.sidebar-toggle:hover { background: var(--bg-hover); color: var(--text); }
.sidebar.collapsed .sidebar-toggle { position: absolute; left: 50%; transform: translateX(-50%); }

.sidebar-nav {
  flex: 1;
  padding: 8px 0;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  color: var(--text-secondary);
  white-space: nowrap;
  border-left: 3px solid transparent;
  cursor: pointer;
  transition: background 0.15s, color 0.15s;
}

.nav-item:hover { background: var(--bg-hover); color: var(--text); }
.nav-item.active { background: var(--bg-hover); color: var(--cyan); border-left-color: var(--cyan); }

.nav-icon { font-size: 16px; width: 20px; text-align: center; flex-shrink: 0; }
.sidebar.collapsed .nav-item { justify-content: center; padding: 10px 0; }
.sidebar.collapsed .nav-label { display: none; }

.sidebar-footer {
  border-top: 1px solid var(--border);
  padding: 8px 0;
  display: flex;
  flex-direction: column;
  align-items: stretch;
}

.sidebar.collapsed .sidebar-footer { display: none; }

/* ── Topbar ── */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 24px;
  border-bottom: 1px solid var(--border-accent);
  background: rgba(5, 8, 13, 0.9);
  backdrop-filter: blur(10px);
  flex-shrink: 0;
}

.topbar-left h1 {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 10px;
}

/* ── Buttons ── */
.btn {
  background: var(--bg-card);
  color: var(--text);
  border: 1px solid var(--border);
  padding: 6px 14px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-size: 13px;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
  transition: border-color 0.15s, background 0.15s;
}

.btn:hover { background: var(--bg-hover); border-color: var(--accent); }
.btn-primary { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 600; }
.btn-primary:hover { background: #0098c7; }
.btn-danger { background: var(--red); color: #fff; border-color: var(--red); }
.btn-amber { background: var(--amber); color: #000; border-color: var(--amber); }
.btn-sm { padding: 4px 10px; font-size: 12px; }

.nav-btn {
  background: linear-gradient(135deg, rgba(0, 229, 255, 0.25), rgba(33, 150, 243, 0.35));
  color: var(--text);
  border: 1px solid rgba(0, 229, 255, 0.35);
  border-radius: var(--radius-sm);
  padding: 6px 14px;
  font-size: 13px;
  font-weight: 700;
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
}

.nav-btn-home {
  background: #334155;
  color: #e2e8f0;
  border: 1px solid #475569;
  padding: 6px 14px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
}

/* ── Cards ── */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 16px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.card-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* ── KPI Row ── */
.kpi-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  text-align: center;
}

.kpi-value { font-size: 28px; font-weight: 700; }
.kpi-label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
.kpi-sub { font-size: 11px; margin-top: 2px; color: var(--text-secondary); }

/* ── Tables ── */
.table-container { overflow-x: auto; }

table { width: 100%; border-collapse: collapse; }

th, td {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}

th {
  color: var(--text-secondary);
  font-weight: 600;
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.5px;
  cursor: pointer;
  user-select: none;
}

th:hover { color: var(--text); }
tr:hover { background: var(--bg-hover); }
tr.clickable { cursor: pointer; }

/* ── Badges ── */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
}

.badge-green { background: rgba(0, 255, 136, 0.15); color: var(--green); }
.badge-red { background: rgba(255, 71, 87, 0.15); color: var(--red); }
.badge-amber { background: rgba(255, 149, 0, 0.15); color: var(--amber); }
.badge-gray { background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }
.badge-accent { background: rgba(0, 180, 216, 0.15); color: var(--accent); }

.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.status-active { background: var(--green); }
.status-offline { background: var(--red); }
.status-never_connected { background: var(--text-secondary); }

/* ── Severity Classes ── */
.severity-critical { background: rgba(255, 71, 87, 0.2); color: var(--red); }
.severity-high { background: rgba(255, 149, 0, 0.2); color: var(--amber); }
.severity-medium { background: rgba(0, 180, 216, 0.2); color: var(--accent); }
.severity-low { background: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }

/* ── Charts ── */
.chart-container { position: relative; height: 250px; }

/* ── Grids ── */
.cols-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.cols-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
.col-span-2 { grid-column: span 2; }

/* ── Detail ── */
.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 20px;
}

.detail-info { display: flex; flex-direction: column; gap: 4px; }
.detail-name { font-size: 22px; font-weight: 700; }
.detail-meta { font-size: 12px; color: var(--text-secondary); display: flex; gap: 16px; flex-wrap: wrap; }
.detail-actions { display: flex; gap: 8px; }

/* ── Tabs ── */
.tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
.tab { padding: 10px 20px; cursor: pointer; color: var(--text-secondary); border-bottom: 2px solid transparent; font-size: 13px; transition: color 0.15s; }
.tab:hover { color: var(--text); }
.tab.active { color: var(--cyan); border-bottom-color: var(--cyan); }

/* ── Filter Tabs ── */
.filter-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.filter-tab {
  padding: 4px 12px;
  border-radius: 12px;
  cursor: pointer;
  font-size: 12px;
  color: var(--text-secondary);
  background: transparent;
  border: 1px solid transparent;
  transition: all 0.15s;
}
.filter-tab:hover { color: var(--text); border-color: var(--border); }
.filter-tab.active { background: var(--bg-hover); color: var(--cyan); border-color: var(--cyan); }

/* ── States ── */
.loading { text-align: center; padding: 40px; color: var(--text-secondary); }
.loading-spinner { display: inline-block; width: 24px; height: 24px; border: 2px solid var(--border); border-top-color: var(--cyan); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.empty-state { text-align: center; padding: 40px; color: var(--text-secondary); }
.error-state { text-align: center; padding: 20px; color: var(--red); }
.error-state .btn { margin-top: 8px; }

/* ── Toast ── */
.toast-container {
  position: fixed;
  top: 16px;
  right: 16px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.toast {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 16px;
  min-width: 280px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
  animation: slideIn 0.3s ease;
  font-size: 13px;
}

.toast-success { border-left: 3px solid var(--green); }
.toast-error { border-left: 3px solid var(--red); }
.toast-info { border-left: 3px solid var(--accent); }

@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

/* ── NL Panel ── */
.nl-panel {
  position: fixed;
  bottom: 80px;
  right: 24px;
  width: 380px;
  max-height: 480px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  display: none;
  flex-direction: column;
  z-index: 200;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  overflow: hidden;
}

.nl-panel.open { display: flex; }

.nl-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  font-weight: 600;
  font-size: 14px;
}

.nl-close { cursor: pointer; color: var(--text-secondary); font-size: 16px; padding: 0 4px; }
.nl-close:hover { color: var(--text); }

.nl-messages {
  flex: 1;
  overflow-y: auto;
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-height: 200px;
  max-height: 340px;
}

.nl-msg {
  padding: 8px 12px;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.5;
  max-width: 90%;
  white-space: pre-wrap;
}

.nl-bot { background: var(--bg); color: var(--text); align-self: flex-start; border: 1px solid var(--border); }
.nl-user { background: rgba(0, 180, 216, 0.12); color: var(--accent); align-self: flex-end; border: 1px solid rgba(0, 180, 216, 0.25); }

.nl-input-row {
  display: flex;
  gap: 6px;
  padding: 10px 12px;
  border-top: 1px solid var(--border);
}

.nl-input-row input {
  flex: 1;
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 13px;
  outline: none;
}

.nl-input-row input:focus { border-color: var(--accent); }

.nl-toggle {
  cursor: pointer;
  padding: 6px 12px;
  font-size: 12px;
  color: var(--text-secondary);
  text-align: center;
  border-top: 1px solid var(--border);
  transition: color 0.15s;
}

.nl-toggle:hover { color: var(--cyan); }

/* ── Mitre Grid ── */
.mitre-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 4px; }
.mitre-cell { padding: 8px; border-radius: var(--radius-sm); text-align: center; cursor: pointer; font-size: 11px; }
.mitre-cell:hover { opacity: 0.8; }

/* ── Misc ── */
.group-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 10px;
  background: var(--bg-hover);
  font-size: 11px;
  margin: 2px;
}

.last-updated { font-size: 11px; color: var(--text-secondary); white-space: nowrap; }

.help-page { max-width: 800px; margin: 0 auto; }
.help-list { list-style: none; padding: 0; }
.help-list li {
  padding: 6px 0 6px 20px;
  color: var(--text-secondary);
  line-height: 1.6;
  position: relative;
  font-size: 13px;
}
.help-list li::before { content: "\25B8"; position: absolute; left: 0; color: var(--cyan); }

/* ── Responsive ── */
@media (max-width: 768px) {
  .cols-2, .cols-3 { grid-template-columns: 1fr; }
  .kpi-row { grid-template-columns: repeat(2, 1fr); }
  .sidebar { width: var(--sidebar-collapsed); min-width: var(--sidebar-collapsed); }
  .sidebar .sidebar-logo-text,
  .sidebar .nav-label { display: none; }
  .sidebar-footer { display: none; }
  .topbar { flex-direction: column; align-items: stretch; gap: 8px; }
  .topbar-right { justify-content: flex-start; }
}
```

---

### Task 3: API Client + useApi Hook

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/api/wazuhApi.js`
- Create: `/home/aiagent/wazuh-soc/src/hooks/useApi.js`

- [ ] **Step 1: Create API client**

Create `/home/aiagent/wazuh-soc/src/api/wazuhApi.js`:

```js
const API = '/wazuh-api';

export async function apiGet(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  const data = await res.json();
  return data.data || data;
}

export async function apiPut(path) {
  const res = await fetch(API + path, { method: 'PUT' });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

export async function apiPost(path, body) {
  const res = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}
```

- [ ] **Step 2: Create useApi hook**

Create `/home/aiagent/wazuh-soc/src/hooks/useApi.js`:

```js
import { useState, useEffect, useCallback } from 'react';

export function useApi(fetchFn, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const execute = useCallback(() => {
    setLoading(true);
    setError(null);
    fetchFn()
      .then(setData)
      .catch(setError)
      .finally(() => setLoading(false));
  }, deps);

  useEffect(() => { execute(); }, [execute]);

  return { data, loading, error, refetch: execute };
}
```

---

### Task 4: Toast Context

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/context/ToastContext.jsx`

- [ ] **Step 1: Create Toast context**

Create `/home/aiagent/wazuh-soc/src/context/ToastContext.jsx`:

```jsx
import { createContext, useContext, useState, useCallback } from 'react';

const ToastContext = createContext();

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  }, []);

  return (
    <ToastContext.Provider value={addToast}>
      {children}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast-${t.type}`}>{t.message}</div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
```

---

### Task 5: Shared Components

**Files:**
- Create: all files in `/home/aiagent/wazuh-soc/src/components/`

- [ ] **Step 1: Create KpiCard**

`/home/aiagent/wazuh-soc/src/components/KpiCard.jsx`:

```jsx
export default function KpiCard({ value, label, sub, color = 'accent' }) {
  const colorMap = {
    green: 'var(--green)', red: 'var(--red)', amber: 'var(--amber)',
    accent: 'var(--accent)', secondary: 'var(--text-secondary)',
  };
  return (
    <div className="kpi-card">
      <div className="kpi-value" style={{ color: colorMap[color] || colorMap.accent }}>{value}</div>
      <div className="kpi-label">{label}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}
```

- [ ] **Step 2: Create StatusBadge**

`/home/aiagent/wazuh-soc/src/components/StatusBadge.jsx`:

```jsx
export default function StatusBadge({ status }) {
  const cls = status === 'active' ? 'badge-green' : status === 'offline' ? 'badge-red' : 'badge-gray';
  const dotCls = status === 'active' ? 'status-active' : status === 'offline' ? 'status-offline' : 'status-never_connected';
  return (
    <span className={`badge ${cls}`}>
      <span className={`status-dot ${dotCls}`}></span>
      {status}
    </span>
  );
}
```

- [ ] **Step 3: Create SeverityBadge**

`/home/aiagent/wazuh-soc/src/components/SeverityBadge.jsx`:

```jsx
export default function SeverityBadge({ severity }) {
  const s = (severity || '').toLowerCase();
  const map = { critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low' };
  return <span className={`badge ${map[s] || 'severity-low'}`}>{s}</span>;
}
```

- [ ] **Step 4: Create FilterTabs**

`/home/aiagent/wazuh-soc/src/components/FilterTabs.jsx`:

```jsx
import { useState } from 'react';

export default function FilterTabs({ tabs, onChange, initial = 'all' }) {
  const [active, setActive] = useState(initial);
  const handle = (key) => {
    setActive(key);
    if (onChange) onChange(key);
  };
  return (
    <div className="filter-tabs">
      {tabs.map(t => (
        <span
          key={t.key}
          className={`filter-tab ${active === t.key ? 'active' : ''}`}
          onClick={() => handle(t.key)}
        >{t.label}</span>
      ))}
    </div>
  );
}
```

- [ ] **Step 5: Create LoadingSpinner**

`/home/aiagent/wazuh-soc/src/components/LoadingSpinner.jsx`:

```jsx
export default function LoadingSpinner({ text = 'Loading...' }) {
  return (
    <div className="loading">
      <div className="loading-spinner"></div>
      <div style={{ marginTop: 12 }}>{text}</div>
    </div>
  );
}
```

- [ ] **Step 6: Create ErrorState**

`/home/aiagent/wazuh-soc/src/components/ErrorState.jsx`:

```jsx
export default function ErrorState({ message, onRetry }) {
  return (
    <div className="error-state">
      <div>{message}</div>
      {onRetry && <button className="btn" onClick={onRetry}>Retry</button>}
    </div>
  );
}
```

- [ ] **Step 7: Create EmptyState**

`/home/aiagent/wazuh-soc/src/components/EmptyState.jsx`:

```jsx
export default function EmptyState({ message = 'No data available.' }) {
  return <div className="empty-state">{message}</div>;
}
```

- [ ] **Step 8: Create DataTable**

`/home/aiagent/wazuh-soc/src/components/DataTable.jsx`:

```jsx
import { useState } from 'react';

export default function DataTable({ columns, data, onRowClick }) {
  const [sortKey, setSortKey] = useState(null);
  const [sortDir, setSortDir] = useState('asc');

  const handleSort = (key) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const sorted = sortKey
    ? [...data].sort((a, b) => {
        const va = a[sortKey], vb = b[sortKey];
        if (va == null) return 1;
        if (vb == null) return -1;
        const cmp = typeof va === 'string' ? va.localeCompare(vb) : va - vb;
        return sortDir === 'asc' ? cmp : -cmp;
      })
    : data;

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            {columns.map(col => (
              <th key={col.key} onClick={() => col.sortable !== false && handleSort(col.key)}>
                {col.label}{sortKey === col.key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr key={row._key || row.id || i} className={onRowClick ? 'clickable' : ''}
                onClick={() => onRowClick && onRowClick(row)}>
              {columns.map(col => (
                <td key={col.key}>{col.render ? col.render(row) : row[col.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 9: Create NLPanel**

`/home/aiagent/wazuh-soc/src/components/NLPanel.jsx`:

```jsx
import { useState, useRef, useEffect } from 'react';

export default function NLPanel({ open, onClose }) {
  const [messages, setMessages] = useState([
    { role: 'bot', text: 'Hi! Ask me about your network. Try "show offline devices" or "site health".' },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const msgsRef = useRef(null);

  useEffect(() => {
    if (msgsRef.current) msgsRef.current.scrollTop = msgsRef.current.scrollHeight;
  }, [messages]);

  const handleSend = async () => {
    const q = input.trim();
    if (!q || loading) return;
    setInput('');
    setMessages(prev => [...prev, { role: 'user', text: q }, { role: 'bot', text: 'Thinking...' }]);
    setLoading(true);
    try {
      const res = await fetch('/wazuh-api/nl/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q }),
      });
      const d = await res.json();
      let txt = d.message || 'No response.';
      const r = d.results;
      if (r) {
        if (r.type === 'overview') {
          txt += `<br><br><span style="color:var(--accent)">&#128268; ${r.devices_total} devices</span> &middot; <span style="color:var(--green)">${r.devices_online} online</span> &middot; <span style="color:var(--red)">${r.devices_offline} offline</span> &middot; <span style="color:var(--amber)">${r.alerts_open} alerts</span>`;
        } else if (r.type === 'offline_devices' && r.items) {
          txt += r.items.map(i => `<br>&#128308; [${i.severity}] ${escHtml(i.title)}`).join('');
        } else if (r.type === 'critical_alerts' && r.items) {
          txt += r.items.map(i => `<br>&#128308; [${i.severity}] ${escHtml(i.title)} <span style="color:var(--text-secondary)">${escHtml(i.site)}</span>`).join('');
        } else if (r.type === 'device_detail') {
          txt = `<b>${escHtml(r.ip)}</b><br>Name: ${escHtml(r.friendly_name || r.hostname || '-')}<br>Type: ${escHtml(r.device_type)}<br>Vendor: ${escHtml(r.vendor)}<br>Status: ${escHtml(r.status)}`;
        }
      }
      setMessages(prev => [...prev.slice(0, -1), { role: 'bot', text: txt, html: true }]);
    } catch (e) {
      setMessages(prev => [...prev.slice(0, -1), { role: 'bot', text: `Error: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`nl-panel ${open ? 'open' : ''}`}>
      <div className="nl-header">
        <span>Ask SOC</span>
        <span className="nl-close" onClick={onClose}>&#10005;</span>
      </div>
      <div className="nl-messages" ref={msgsRef}>
        {messages.map((m, i) => (
          <div key={i} className={`nl-msg nl-${m.role}`}
              dangerouslySetInnerHTML={m.html ? { __html: m.text } : undefined}>
            {!m.html && m.text}
          </div>
        ))}
      </div>
      <div className="nl-input-row">
        <input value={input} onChange={e => setInput(e.target.value)}
               onKeyDown={e => e.key === 'Enter' && handleSend()}
               placeholder="Ask a question..." />
        <button className="btn btn-sm btn-primary" onClick={handleSend} disabled={loading}>&#10148;</button>
      </div>
    </div>
  );
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
```

---

### Task 6: Layout, Sidebar, Topbar, and App Shell

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/components/Sidebar.jsx`
- Create: `/home/aiagent/wazuh-soc/src/components/Topbar.jsx`
- Create: `/home/aiagent/wazuh-soc/src/components/Layout.jsx`
- Create: `/home/aiagent/wazuh-soc/src/main.jsx`
- Create: `/home/aiagent/wazuh-soc/src/App.jsx`

- [ ] **Step 1: Create Sidebar**

`/home/aiagent/wazuh-soc/src/components/Sidebar.jsx`:

```jsx
import { useLocation, useNavigate } from 'react-router-dom';

const NAV_ITEMS = [
  { path: '/', label: 'Command Center', icon: '\u25A0' },
  { path: '/agents', label: 'Agents', icon: '\u25CF' },
  { path: '/sca', label: 'SCA Compliance', icon: '\u2714' },
  { path: '/fim', label: 'File Integrity', icon: '\u270F' },
  { path: '/vulnerabilities', label: 'Vulnerabilities', icon: '\u26A0' },
  { path: '/mitre', label: 'MITRE ATT&CK', icon: '\u2694' },
  { path: '/rules', label: 'Rules & Decoders', icon: '\u2699' },
  { path: '/events', label: 'Events & Alerts', icon: '\u26A1' },
  { path: '/topology', label: 'Topology', icon: '\u267B' },
  { path: '/threats', label: 'Threat Intel', icon: '\u2764' },
  { path: '/autopilot', label: 'SOC Autopilot', icon: '\u2601' },
  { path: '/manager', label: 'Manager Health', icon: '\u2605' },
  { path: '/groups', label: 'Groups', icon: '\u2602' },
  { path: '/help', label: 'Help', icon: '\u2753' },
];

export default function Sidebar({ collapsed, onToggle }) {
  const location = useLocation();
  const navigate = useNavigate();
  const activePath = location.pathname;

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <span className="sidebar-logo-icon">&#9733;</span>
          <span className="sidebar-logo-text">Wazuh SOC</span>
        </div>
        <button className="sidebar-toggle" onClick={onToggle} title="Toggle sidebar">
          {collapsed ? '\u2192' : '\u2190'}
        </button>
      </div>
      <nav className="sidebar-nav">
        {NAV_ITEMS.map(item => (
          <a
            key={item.path}
            className={`nav-item ${activePath === item.path ? 'active' : ''}`}
            onClick={(e) => { e.preventDefault(); navigate(item.path); }}
            href={`#${item.path}`}
            title={collapsed ? item.label : undefined}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </a>
        ))}
      </nav>
      <div className="sidebar-footer">
        <a className="nav-btn-home" href="http://localhost:8095/index-platform.html" target="_blank" rel="noopener noreferrer">
          &#9664; Home
        </a>
      </div>
    </aside>
  );
}
```

- [ ] **Step 2: Create Topbar**

`/home/aiagent/wazuh-soc/src/components/Topbar.jsx`:

```jsx
import { useLocation } from 'react-router-dom';

const PAGE_TITLES = {
  '/': 'Command Center',
  '/agents': 'Agents',
  '/sca': 'SCA Compliance',
  '/fim': 'File Integrity Monitoring',
  '/vulnerabilities': 'Vulnerabilities',
  '/mitre': 'MITRE ATT&CK',
  '/rules': 'Rules & Decoders',
  '/events': 'Events & Alerts',
  '/topology': 'Topology',
  '/threats': 'Threat Intelligence',
  '/autopilot': 'SOC Autopilot',
  '/manager': 'Manager Health',
  '/groups': 'Groups',
  '/help': 'Help',
};

export default function Topbar({ onRefresh, lastUpdated }) {
  const location = useLocation();
  const path = location.pathname;
  const title = PAGE_TITLES[path] || 'Wazuh SOC';

  return (
    <div className="topbar">
      <div className="topbar-left">
        <h1>{title}</h1>
      </div>
      <div className="topbar-right">
        {lastUpdated && <span className="last-updated">Updated: {lastUpdated}</span>}
        <button className="btn" onClick={onRefresh}>&#8635; Refresh</button>
        <a className="nav-btn" href="http://localhost:8095/help.html" target="_blank" rel="noopener noreferrer">? Help</a>
        <a className="nav-btn" href="http://localhost:8095/devdocs.html" target="_blank" rel="noopener noreferrer">DevDocs</a>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Create Layout**

`/home/aiagent/wazuh-soc/src/components/Layout.jsx`:

```jsx
import { useState } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import Sidebar from './Sidebar';
import Topbar from './Topbar';
import NLPanel from './NLPanel';

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [nlOpen, setNlOpen] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const navigate = useNavigate();

  const handleRefresh = () => {
    navigate(0);
    setLastUpdated(new Date().toLocaleTimeString());
  };

  return (
    <div className="app-layout">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />
      <div className="main-area">
        <Topbar onRefresh={handleRefresh} lastUpdated={lastUpdated} />
        <div className="content-area">
          <Outlet />
        </div>
      </div>
      <div className="nl-toggle" onClick={() => setNlOpen(o => !o)}>
        {nlOpen ? 'Close' : '\uD83D\uDD0D Ask'}
      </div>
      <NLPanel open={nlOpen} onClose={() => setNlOpen(false)} />
    </div>
  );
}
```

- [ ] **Step 4: Create main.jsx**

`/home/aiagent/wazuh-soc/src/main.jsx`:

```jsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import App from './App';
import { ToastProvider } from './context/ToastContext';
import './styles/global.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <HashRouter>
      <ToastProvider>
        <App />
      </ToastProvider>
    </HashRouter>
  </React.StrictMode>
);
```

- [ ] **Step 5: Create App.jsx with lazy routes**

`/home/aiagent/wazuh-soc/src/App.jsx`:

```jsx
import { lazy, Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import LoadingSpinner from './components/LoadingSpinner';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Agents = lazy(() => import('./pages/Agents'));
const AgentDetail = lazy(() => import('./pages/AgentDetail'));
const SCA = lazy(() => import('./pages/SCA'));
const FIM = lazy(() => import('./pages/FIM'));
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'));
const Mitre = lazy(() => import('./pages/Mitre'));
const Rules = lazy(() => import('./pages/Rules'));
const Events = lazy(() => import('./pages/Events'));
const Topology = lazy(() => import('./pages/Topology'));
const Threats = lazy(() => import('./pages/Threats'));
const Autopilot = lazy(() => import('./pages/Autopilot'));
const AutopilotCase = lazy(() => import('./pages/AutopilotCase'));
const Manager = lazy(() => import('./pages/Manager'));
const Groups = lazy(() => import('./pages/Groups'));
const AlertDetail = lazy(() => import('./pages/AlertDetail'));
const Help = lazy(() => import('./pages/Help'));

function SuspenseWrapper({ children }) {
  return <Suspense fallback={<LoadingSpinner />}>{children}</Suspense>;
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<SuspenseWrapper><Dashboard /></SuspenseWrapper>} />
        <Route path="agents" element={<SuspenseWrapper><Agents /></SuspenseWrapper>} />
        <Route path="agent/:id" element={<SuspenseWrapper><AgentDetail /></SuspenseWrapper>} />
        <Route path="sca" element={<SuspenseWrapper><SCA /></SuspenseWrapper>} />
        <Route path="fim" element={<SuspenseWrapper><FIM /></SuspenseWrapper>} />
        <Route path="vulnerabilities" element={<SuspenseWrapper><Vulnerabilities /></SuspenseWrapper>} />
        <Route path="mitre" element={<SuspenseWrapper><Mitre /></SuspenseWrapper>} />
        <Route path="rules" element={<SuspenseWrapper><Rules /></SuspenseWrapper>} />
        <Route path="events" element={<SuspenseWrapper><Events /></SuspenseWrapper>} />
        <Route path="topology" element={<SuspenseWrapper><Topology /></SuspenseWrapper>} />
        <Route path="threats" element={<SuspenseWrapper><Threats /></SuspenseWrapper>} />
        <Route path="autopilot" element={<SuspenseWrapper><Autopilot /></SuspenseWrapper>} />
        <Route path="autopilot/case/:id" element={<SuspenseWrapper><AutopilotCase /></SuspenseWrapper>} />
        <Route path="manager" element={<SuspenseWrapper><Manager /></SuspenseWrapper>} />
        <Route path="groups" element={<SuspenseWrapper><Groups /></SuspenseWrapper>} />
        <Route path="alert/:id" element={<SuspenseWrapper><AlertDetail /></SuspenseWrapper>} />
        <Route path="help" element={<SuspenseWrapper><Help /></SuspenseWrapper>} />
      </Route>
    </Routes>
  );
}
```

---

### Task 7: Dashboard Page

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/pages/Dashboard.jsx`

- [ ] **Step 1: Create Dashboard**

`/home/aiagent/wazuh-soc/src/pages/Dashboard.jsx`:

```jsx
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import KpiCard from '../components/KpiCard';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import { Chart as ChartJS, ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import { useMemo } from 'react';

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const chartOptions = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { position: 'bottom', labels: { color: '#8fa6b5' } } },
};

const barOptions = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: { x: { ticks: { color: '#8fa6b5' } }, y: { ticks: { color: '#8fa6b5' }, beginAtZero: true } },
};

export default function Dashboard() {
  const r = useApi(() => Promise.all([apiGet('/overview'), apiGet('/events/stats')]), []);
  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const [d, ev] = r.data;
  const sev = ev.severity || {};
  const totalAlerts = (sev.Critical || 0) + (sev.High || 0) + (sev.Medium || 0) + (sev.Low || 0);
  const totalVuln = useMemo(() => {
    let t = 0;
    if (d.vulnerabilities) for (const k in d.vulnerabilities) t += (d.vulnerabilities[k] || 0);
    return t;
  }, [d]);
  const threatScore = sev.Critical ? Math.min(100, Math.round((sev.Critical / Math.max(1, totalAlerts)) * 100)) : 0;

  const statusData = { labels: ['Active', 'Offline', 'Never Connected'], datasets: [{ data: [d.active, d.offline, d.never_connected || 0], backgroundColor: ['#00ff88', '#ff4757', '#8fa6b5'], borderWidth: 0 }] };

  const osLabels = d.os_distribution ? Object.keys(d.os_distribution) : [];
  const osData = d.os_distribution ? { labels: osLabels, datasets: [{ label: 'Agents', data: osLabels.map(l => d.os_distribution[l]), backgroundColor: '#00b4d8' }] } : null;

  const alertData = { labels: ['Critical', 'High', 'Medium', 'Low'], datasets: [{ data: [sev.Critical || 0, sev.High || 0, sev.Medium || 0, sev.Low || 0], backgroundColor: ['#ff4757', '#ff9500', '#00b4d8', '#8fa6b5'], borderWidth: 0 }] };

  const scaColor = d.sca_score >= 80 ? 'green' : d.sca_score >= 50 ? 'amber' : 'red';
  const threatColor = threatScore > 50 ? 'red' : threatScore > 20 ? 'amber' : 'green';

  return (
    <>
      <div className="kpi-row">
        <KpiCard value={d.total_agents} label="Total Agents" color="accent" />
        <KpiCard value={d.active} label="Active" color="green" />
        <KpiCard value={d.offline} label="Offline" color="red" />
        <KpiCard value={totalVuln} label="Vulnerabilities" color="amber" />
        <KpiCard value={`${d.sca_score}%`} label="SCA Score" color={scaColor} />
        <KpiCard value={`${threatScore}%`} label="Threat Index" color={threatColor} sub={`${totalAlerts} alerts / 24h`} />
      </div>

      <div className="cols-3">
        <div className="card">
          <div className="card-header"><div className="card-title">Agent Status</div></div>
          <div className="chart-container"><Doughnut data={statusData} options={chartOptions} /></div>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">OS Distribution</div></div>
          <div className="chart-container">
            {osData ? <Bar data={osData} options={barOptions} /> : <div className="empty-state">No OS data</div>}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Alert Severity (24h)</div></div>
          <div className="chart-container"><Doughnut data={alertData} options={chartOptions} /></div>
        </div>
      </div>
    </>
  );
}
```

---

### Task 8: Agents + AgentDetail Pages

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/pages/Agents.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/AgentDetail.jsx`

- [ ] **Step 1: Create Agents page**

`/home/aiagent/wazuh-soc/src/pages/Agents.jsx`:

```jsx
import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import StatusBadge from '../components/StatusBadge';
import FilterTabs from '../components/FilterTabs';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import { FixedSizeList as List } from 'react-window';

function timeAgo(d) {
  if (!d || d === '9999-12-31T23:59:59+00:00') return 'Just now';
  const sec = (Date.now() - new Date(d).getTime()) / 1000;
  if (sec < 60) return 'Just now';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
  return Math.floor(sec / 86400) + 'd ago';
}

const FILTER_TABS = [
  { key: 'all', label: 'All' },
  { key: 'active', label: 'Active' },
  { key: 'offline', label: 'Offline' },
];

const COLUMNS = ['ID', 'Name', 'IP', 'OS', 'Status', 'Version', 'Last Seen'];

export default function Agents() {
  const r = useApi(() => apiGet('/agents?limit=500'), []);
  const [filter, setFilter] = useState('all');
  const navigate = useNavigate();

  const items = useMemo(() => {
    const raw = r.data ? (r.data.affected_items || r.data) : [];
    return filter === 'all' ? raw : raw.filter(a => a.status === filter);
  }, [r.data, filter]);

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const Row = ({ index, style }) => {
    const a = items[index];
    if (!a) return null;
    const os = a.os ? (a.os.name || '') + ' ' + (a.os.version || '') : 'Unknown';
    return (
      <tr style={style} className="clickable" onClick={() => navigate(`/agent/${a.id}`)}>
        <td>{a.id}</td>
        <td>{a.name}</td>
        <td>{a.ip}</td>
        <td>{os.substring(0, 30)}</td>
        <td><StatusBadge status={a.status} /></td>
        <td>{a.version || '-'}</td>
        <td>{timeAgo(a.lastKeepAlive)}</td>
      </tr>
    );
  };

  return (
    <>
      <FilterTabs tabs={FILTER_TABS} onChange={setFilter} />
      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>{COLUMNS.map(c => <th key={c}>{c}</th>)}</tr>
            </thead>
            <tbody style={{ height: Math.min(items.length * 42, 600), display: 'block', overflowY: 'auto' }}>
              <List height={Math.min(items.length * 42, 600)} itemCount={items.length} itemSize={42} width="100%">
                {Row}
              </List>
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 2: Create AgentDetail page**

`/home/aiagent/wazuh-soc/src/pages/AgentDetail.jsx`:

```jsx
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useApi } from '../hooks/useApi';
import { apiGet, apiPut } from '../api/wazuhApi';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';
import { useToast } from '../context/ToastContext';

const TABS = ['overview', 'sca', 'fim', 'vulnerabilities', 'inventory'];

export default function AgentDetail() {
  const { id } = useParams();
  const r = useApi(() => apiGet(`/agents/${id}`), [id]);
  const [tab, setTab] = useState('overview');
  const toast = useToast();

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const agent = r.data.affected_items ? r.data.affected_items[0] : r.data;
  const os = agent.os || {};

  const handleRestart = () => {
    apiPut(`/agents/${id}/restart`)
      .then(() => toast(`Agent ${id} restarted`, 'success'))
      .catch(e => toast(`Failed: ${e.message}`, 'error'));
  };

  const handleScan = () => {
    apiPut(`/agents/${id}/scan/syscheck`)
      .then(() => toast(`Syscheck triggered for ${id}`, 'success'))
      .catch(e => toast(`Failed: ${e.message}`, 'error'));
  };

  return (
    <>
      <div className="detail-header">
        <div className="detail-info">
          <div className="detail-name">{agent.name}</div>
          <div className="detail-meta">
            <span>ID: {agent.id}</span>
            <span>IP: {agent.ip}</span>
            <span>OS: {os.name || 'Unknown'} {os.version || ''}</span>
            <StatusBadge status={agent.status} />
            <span>v{agent.version || '-'}</span>
          </div>
        </div>
        <div className="detail-actions">
          <button className="btn btn-primary" onClick={handleRestart}>Restart</button>
          <button className="btn btn-amber" onClick={handleScan}>Syscheck</button>
        </div>
      </div>

      <div className="tabs">
        {TABS.map(t => (
          <span key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </span>
        ))}
      </div>

      <TabContent agent={agent} tab={tab} id={id} />
    </>
  );
}

function TabContent({ agent, tab, id }) {
  const os = agent.os || {};

  if (tab === 'overview') {
    return (
      <div className="cols-2">
        <div className="card">
          <div className="card-header"><div className="card-title">Hardware & OS</div></div>
          <table><tbody>
            <tr><td>Hostname</td><td>{agent.name}</td></tr>
            <tr><td>OS</td><td>{os.name || '-'}</td></tr>
            <tr><td>Version</td><td>{os.version || '-'}</td></tr>
            <tr><td>Platform</td><td>{os.platform || '-'}</td></tr>
            <tr><td>Architecture</td><td>{os.arch || '-'}</td></tr>
            <tr><td>IP</td><td>{agent.ip}</td></tr>
            <tr><td>Manager</td><td>{agent.manager || '-'}</td></tr>
            <tr><td>Last Seen</td><td>{agent.lastKeepAlive ? new Date(agent.lastKeepAlive).toLocaleString() : '-'}</td></tr>
            <tr><td>Registered</td><td>{agent.dateAdd ? new Date(agent.dateAdd).toLocaleString() : '-'}</td></tr>
            <tr><td>Groups</td><td>{(agent.group || []).map(g => <span key={g} className="group-badge">{g}</span>) || '-'}</td></tr>
          </tbody></table>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Status</div></div>
          <table><tbody>
            <tr><td>Status</td><td><StatusBadge status={agent.status} /></td></tr>
            <tr><td>Config Status</td><td>{agent.group_config_status || '-'}</td></tr>
            <tr><td>Node</td><td>{agent.node_name || '-'}</td></tr>
          </tbody></table>
        </div>
      </div>
    );
  }

  return <AgentTabPanel tab={tab} id={id} />;
}

function AgentTabPanel({ tab, id }) {
  const apiPath = tab === 'inventory' ? null : `/agents/${id}/${tab}?limit=100`;
  const r = apiPath ? useApi(() => apiGet(apiPath), [id, tab]) : null;

  if (tab === 'sca') {
    if (r.loading) return <LoadingSpinner />;
    if (r.error) return <ErrorState message={r.error.message} />;
    const items = r.data.affected_items || [];
    return (
      <div className="card">
        <div className="table-container">
          <table><thead><tr><th>Policy</th><th>Score</th><th>Passed</th><th>Failed</th></tr></thead>
            <tbody>
              {items.map((p, i) => (
                <tr key={i}>
                  <td>{p.name || p.policy_id}</td>
                  <td className={p.score >= 80 ? 'text-green' : p.score >= 50 ? 'text-amber' : 'text-red'}>{p.score != null ? `${p.score}%` : '-'}</td>
                  <td>{p.passed || 0}</td>
                  <td>{p.failed || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  if (tab === 'fim') {
    if (r.loading) return <LoadingSpinner />;
    if (r.error) return <ErrorState message={r.error.message} />;
    const items = r.data.affected_items || [];
    return (
      <div className="card">
        <div className="table-container">
          <table><thead><tr><th>File</th><th>Event</th><th>Date</th></tr></thead>
            <tbody>
              {items.map((f, i) => (
                <tr key={i}><td>{f.file || f.path || '-'}</td><td>{f.type || f.event || '-'}</td><td>{f.date || f.mtime ? new Date(f.date || f.mtime).toLocaleString() : '-'}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  if (tab === 'vulnerabilities') {
    if (r.loading) return <LoadingSpinner />;
    if (r.error) return <ErrorState message={r.error.message} />;
    const items = r.data.affected_items || [];
    return (
      <div className="card">
        <div className="table-container">
          <table><thead><tr><th>CVE</th><th>Package</th><th>Severity</th><th>CVSS</th><th>Status</th><th>Title</th></tr></thead>
            <tbody>
              {items.map((v, i) => (
                <tr key={i}><td>{v.cve || '-'}</td><td>{v.package?.name || '-'}</td><td><SeverityBadge severity={v.severity} /></td><td>{v.cvss_score || '-'}</td><td>{v.status || '-'}</td><td>{(v.title || '').substring(0, 50)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  if (tab === 'inventory') {
    return <InventoryPanel id={id} />;
  }

  return null;
}

function InventoryPanel({ id }) {
  const pkg = useApi(() => apiGet(`/agents/${id}/packages?limit=50`), [id]);
  const ports = useApi(() => apiGet(`/agents/${id}/ports?limit=50`), [id]);

  return (
    <div className="cols-2">
      <div className="card">
        <div className="card-header"><div className="card-title">Packages</div></div>
        {pkg.loading ? <LoadingSpinner /> : pkg.error ? <ErrorState message={pkg.error.message} /> : (
          <table><tbody>{(pkg.data?.affected_items || []).slice(0, 20).map((p, i) => (
            <tr key={i}><td>{p.name}</td><td>{p.version}</td></tr>
          ))}</tbody></table>
        )}
      </div>
      <div className="card">
        <div className="card-header"><div className="card-title">Open Ports</div></div>
        {ports.loading ? <LoadingSpinner /> : ports.error ? <ErrorState message={ports.error.message} /> : (
          <table><tbody>{(ports.data?.affected_items || []).slice(0, 20).map((p, i) => (
            <tr key={i}><td>{p.local_ip || '-'}:{p.local_port}</td><td>{p.protocol || '-'}</td><td>{p.state || '-'}</td></tr>
          ))}</tbody></table>
        )}
      </div>
    </div>
  );
}
```

---

### Task 9: Events + SCA + FIM + Vulnerabilities Pages

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/pages/Events.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/SCA.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/FIM.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/Vulnerabilities.jsx`

- [ ] **Step 1: Create Events page**

`/home/aiagent/wazuh-soc/src/pages/Events.jsx`:

```jsx
import { useState, useMemo } from 'react';
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import KpiCard from '../components/KpiCard';
import SeverityBadge from '../components/SeverityBadge';
import FilterTabs from '../components/FilterTabs';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

export default function Events() {
  const r = useApi(() => Promise.all([apiGet('/events?size=100'), apiGet('/events/stats')]), []);
  const [filter, setFilter] = useState('all');

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const [eventsRes, stats] = r.data;
  const items = eventsRes.affected_items || [];
  const sev = stats.severity || {};

  const filtered = useMemo(() => {
    if (filter === 'all') return items;
    return items.filter(e => {
      const lvl = e.level || 0;
      const sv = lvl >= 12 ? 'critical' : lvl >= 7 ? 'high' : lvl >= 4 ? 'medium' : 'low';
      return sv === filter;
    });
  }, [items, filter]);

  const columns = [
    { key: 'timestamp', label: 'Time', render: r => new Date(r.timestamp).toLocaleString() },
    { key: 'severity', label: 'Level', render: r => {
      const lvl = r.level || 0;
      const sv = lvl >= 12 ? 'critical' : lvl >= 7 ? 'high' : lvl >= 4 ? 'medium' : 'low';
      return <SeverityBadge severity={sv} />;
    }},
    { key: 'rule_id', label: 'Rule' },
    { key: 'description', label: 'Description', render: r => (r.description || '').substring(0, 80) },
    { key: 'agent', label: 'Agent', render: r => r.agent ? (r.agent.name || r.agent.id || '-') : '-' },
    { key: 'groups', label: 'Group', render: r => (r.groups || []).slice(0, 2).join(', ') },
  ];

  return (
    <>
      <div className="kpi-row">
        <KpiCard value={sev.Critical || 0} label="Critical (12+)" color="red" />
        <KpiCard value={sev.High || 0} label="High (7-11)" color="amber" />
        <KpiCard value={sev.Medium || 0} label="Medium (4-6)" color="accent" />
        <KpiCard value={sev.Low || 0} label="Low (0-3)" color="secondary" />
      </div>
      <div className="card">
        <div className="card-header">
          <div className="card-title">Recent Alerts ({filtered.length})</div>
          <FilterTabs tabs={[
            { key: 'all', label: 'All' },
            { key: 'critical', label: 'Critical' },
            { key: 'high', label: 'High' },
            { key: 'medium', label: 'Medium' },
          ]} onChange={setFilter} />
        </div>
        <DataTable columns={columns} data={filtered} />
      </div>
    </>
  );
}
```

- [ ] **Step 2: Create SCA page**

`/home/aiagent/wazuh-soc/src/pages/SCA.jsx`:

```jsx
import { useNavigate } from 'react-router-dom';
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import KpiCard from '../components/KpiCard';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

export default function SCA() {
  const r = useApi(() => apiGet('/overview/sca'), []);
  const navigate = useNavigate();

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const items = r.data.affected_items || [];
  const scores = items.filter(i => i.score != null).map(i => i.score);
  const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const avgColor = avg >= 80 ? 'green' : avg >= 50 ? 'amber' : 'red';

  const columns = [
    { key: 'agent_id', label: 'Agent', render: r => r.agent_id || '-' },
    { key: 'policy', label: 'Policy', render: r => r.policy || '-' },
    { key: 'score', label: 'Score', render: r => {
      const s = r.score;
      const c = s >= 80 ? 'green' : s >= 50 ? 'amber' : 'red';
      return <span style={{ color: `var(--${c})` }}>{s != null ? `${s}%` : '-'}</span>;
    }},
    { key: 'passed', label: 'Passed' },
    { key: 'failed', label: 'Failed' },
  ];

  return (
    <>
      <div className="kpi-row">
        <KpiCard value={`${avg}%`} label="Avg Compliance" color={avgColor} />
        <KpiCard value={items.length} label="Policies" color="accent" />
      </div>
      <div className="card">
        <DataTable columns={columns} data={items} onRowClick={row => navigate(`/agent/${row.agent_id}`)} />
      </div>
    </>
  );
}
```

- [ ] **Step 3: Create FIM page**

`/home/aiagent/wazuh-soc/src/pages/FIM.jsx`:

```jsx
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';

export default function FIM() {
  const r = useApi(() => apiGet('/overview/fim'), []);
  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const items = r.data.affected_items || [];
  if (!items.length) return <EmptyState message="No FIM events" />;

  const columns = [
    { key: 'agent_id', label: 'Agent' },
    { key: 'file', label: 'File', render: r => r.file || r.path || '-' },
    { key: 'type', label: 'Event', render: r => r.type || 'modified' },
    { key: 'date', label: 'Date', render: r => r.date || r.mtime ? new Date(r.date || r.mtime).toLocaleString() : '-' },
  ];

  return (
    <div className="card">
      <DataTable columns={columns} data={items} />
    </div>
  );
}
```

- [ ] **Step 4: Create Vulnerabilities page**

`/home/aiagent/wazuh-soc/src/pages/Vulnerabilities.jsx`:

```jsx
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import KpiCard from '../components/KpiCard';
import SeverityBadge from '../components/SeverityBadge';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';

export default function Vulnerabilities() {
  const r = useApi(() => apiGet('/overview/vulnerabilities'), []);

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const items = r.data.affected_items || [];
  if (!items.length) return <div className="card"><EmptyState message="Vulnerability Detector not enabled on this Wazuh server." /></div>;

  const sum = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  items.forEach(v => {
    const s = (v.severity || '').toLowerCase();
    const key = s.charAt(0).toUpperCase() + s.slice(1);
    if (sum[key] !== undefined) sum[key]++;
  });

  const columns = [
    { key: 'cve', label: 'CVE', render: r => r.cve || '-' },
    { key: 'agent_id', label: 'Agent' },
    { key: 'package', label: 'Package', render: r => r.package?.name || '-' },
    { key: 'severity', label: 'Severity', render: r => <SeverityBadge severity={r.severity} /> },
    { key: 'cvss_score', label: 'CVSS' },
    { key: 'status', label: 'Status' },
    { key: 'title', label: 'Title', render: r => (r.title || '').substring(0, 50) },
  ];

  return (
    <>
      <div className="kpi-row">
        <KpiCard value={sum.Critical} label="Critical" color="red" />
        <KpiCard value={sum.High} label="High" color="amber" />
        <KpiCard value={sum.Medium} label="Medium" color="accent" />
        <KpiCard value={sum.Low} label="Low" color="secondary" />
      </div>
      <div className="card">
        <DataTable columns={columns} data={items} />
      </div>
    </>
  );
}
```

---

### Task 10: Autopilot Pages

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/pages/Autopilot.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/AutopilotCase.jsx`

- [ ] **Step 1: Create Autopilot page**

`/home/aiagent/wazuh-soc/src/pages/Autopilot.jsx`:

```jsx
import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import KpiCard from '../components/KpiCard';
import SeverityBadge from '../components/SeverityBadge';
import FilterTabs from '../components/FilterTabs';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

function timeAgo(d) {
  if (!d) return '-';
  const sec = (Date.now() - new Date(d).getTime()) / 1000;
  if (sec < 60) return 'Just now';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
  return Math.floor(sec / 86400) + 'd ago';
}

function caseStatusBadge(s) {
  const m = { open: 'badge-gray', triaged: 'badge-accent', awaiting_approval: 'badge-amber', approved: 'badge-green', resolved: 'badge-green', closed: 'badge-gray', rejected: 'badge-red', partial: 'badge-amber' };
  return `<span class="badge ${m[s] || 'badge-gray'}">${s}</span>`;
}

export default function Autopilot() {
  const r = useApi(() => Promise.all([apiGet('/autopilot/cases'), apiGet('/autopilot/stats')]), []);
  const [filter, setFilter] = useState('all');
  const navigate = useNavigate();

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const [casesRes, stats] = r.data;
  const cases = casesRes.affected_items || [];
  const pending = cases.filter(c => c.status === 'awaiting_approval').length;

  const filtered = useMemo(() => {
    if (filter === 'all') return cases;
    return cases.filter(c => c.status === filter);
  }, [cases, filter]);

  const columns = [
    { key: 'id', label: 'ID', render: r => `#${r.id}` },
    { key: 'title', label: 'Title', render: r => (r.title || '').substring(0, 50) },
    { key: 'severity', label: 'Severity', render: r => <SeverityBadge severity={r.severity} /> },
    { key: 'status', label: 'Status', render: r => <span dangerouslySetInnerHTML={{ __html: caseStatusBadge(r.status) }} /> },
    { key: 'alert_count', label: 'Alerts' },
    { key: 'mitre', label: 'MITRE', render: r => r.mitre?.technique_id ? <span className="badge badge-accent">{r.mitre.technique_id}</span> : '-' },
    { key: 'updated_at', label: 'Updated', render: r => timeAgo(r.updated_at) },
  ];

  return (
    <>
      <div className="kpi-row">
        <KpiCard value={stats.last_24h || 0} label="Last 24h" color="accent" />
        <KpiCard value={stats.critical || 0} label="Critical" color="red" />
        <KpiCard value={stats.high || 0} label="High" color="amber" />
        <KpiCard value={pending} label="Awaiting" color="amber" />
        <KpiCard value={stats.resolved || 0} label="Resolved" color="green" />
        <KpiCard value={stats.avg_triage_time ? `${Math.round(stats.avg_triage_time)}s` : '-'} label="Avg Triage" color="secondary" />
      </div>
      <div className="card">
        <div className="card-header">
          <div className="card-title">Active Cases ({cases.length})</div>
          <FilterTabs tabs={[
            { key: 'all', label: 'All' },
            { key: 'awaiting_approval', label: 'Pending' },
            { key: 'open', label: 'Open' },
            { key: 'resolved', label: 'Resolved' },
          ]} onChange={setFilter} />
        </div>
        <DataTable columns={columns} data={filtered} onRowClick={row => navigate(`/autopilot/case/${row.id}`)} />
      </div>
    </>
  );
}
```

- [ ] **Step 2: Create AutopilotCase page**

`/home/aiagent/wazuh-soc/src/pages/AutopilotCase.jsx`:

```jsx
import { useParams, useNavigate } from 'react-router-dom';
import { useApi } from '../hooks/useApi';
import { apiGet, apiPost } from '../api/wazuhApi';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import { useToast } from '../context/ToastContext';

function caseStatusBadge(s) {
  const m = { open: 'badge-gray', triaged: 'badge-accent', awaiting_approval: 'badge-amber', approved: 'badge-green', resolved: 'badge-green', closed: 'badge-gray', rejected: 'badge-red', partial: 'badge-amber' };
  return `<span class="badge ${m[s] || 'badge-gray'}">${s}</span>`;
}

function formatDate(d) {
  if (!d) return '-';
  return new Date(d).toLocaleString();
}

export default function AutopilotCase() {
  const { id } = useParams();
  const r = useApi(() => apiGet(`/autopilot/cases/${id}`), [id]);
  const toast = useToast();
  const navigate = useNavigate();

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const c = r.data;
  const isPending = c.status === 'awaiting_approval';
  const isApproved = c.status === 'approved';

  const handleApprove = () => {
    apiPost(`/autopilot/cases/${id}/approve`)
      .then(() => { toast(`Case #${id} approved`, 'success'); r.refetch(); })
      .catch(e => toast(`Failed: ${e.message}`, 'error'));
  };

  const handleReject = () => {
    apiPost(`/autopilot/cases/${id}/reject`)
      .then(() => { toast(`Case #${id} rejected`, 'info'); r.refetch(); })
      .catch(e => toast(`Failed: ${e.message}`, 'error'));
  };

  const handleExecute = () => {
    if (!confirm(`Execute response plan for Case #${id}?`)) return;
    apiPost(`/autopilot/cases/${id}/execute`)
      .then(() => { toast(`Case #${id} execution triggered`, 'success'); r.refetch(); })
      .catch(e => toast(`Failed: ${e.message}`, 'error'));
  };

  return (
    <>
      <div className="detail-header">
        <div className="detail-info">
          <div className="detail-name">Case #{c.id}</div>
          <div className="detail-meta">
            <SeverityBadge severity={c.severity} />
            <span dangerouslySetInnerHTML={{ __html: caseStatusBadge(c.status) }} />
            <span>{c.alert_count || 0} alerts</span>
            <span>Created: {formatDate(c.created_at)}</span>
            {c.confidence && <span>Confidence: {Math.round(c.confidence * 100)}%</span>}
            {c.mitre?.technique_id && <span className="badge badge-accent">{c.mitre.technique_id} {c.mitre.technique || ''}</span>}
          </div>
        </div>
        <div className="detail-actions">
          {isPending && <><button className="btn btn-primary" onClick={handleApprove}>Approve</button><button className="btn btn-danger" onClick={handleReject}>Reject</button></>}
          {isApproved && <button className="btn btn-primary" onClick={handleExecute}>Execute Plan</button>}
          <button className="btn" onClick={() => navigate('/autopilot')}>Back</button>
        </div>
      </div>

      <div className="cols-2">
        <div className="card">
          <div className="card-header"><div className="card-title">Description</div></div>
          <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, fontSize: 13 }}>{c.description || 'No description'}</p>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Entities ({(c.entities || []).length})</div></div>
          {c.entities?.length ? (
            <table><tbody>{c.entities.map((e, i) => (
              <tr key={i}><td>{e.type}</td><td>{e.value}</td><td><span className="badge badge-gray">{e.role || ''}</span></td></tr>
            ))}</tbody></table>
          ) : <div className="empty-state">No entities</div>}
        </div>
        {c.response_plan && (
          <div className="card col-span-2">
            <div className="card-header"><div className="card-title">Response Plan</div></div>
            <p style={{ marginBottom: 12 }}><strong>Risk:</strong> <SeverityBadge severity={c.response_plan.risk_level || c.severity} /></p>
            <p style={{ marginBottom: 12, color: 'var(--text-secondary)', fontSize: 13 }}>{c.response_plan.summary || ''}</p>
            <table><thead><tr><th>Action</th><th>Target</th><th>Rationale</th></tr></thead>
              <tbody>{(c.response_plan.actions || []).map((a, i) => (
                <tr key={i}><td><span className="badge badge-accent">{a.type}</span></td><td>{a.target || '-'}</td><td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{(a.rationale || '').substring(0, 100)}</td></tr>
              ))}</tbody>
            </table>
          </div>
        )}
        {c.actions?.length > 0 && (
          <div className="card col-span-2">
            <div className="card-header"><div className="card-title">Executed Actions</div></div>
            <table><thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Detail</th></tr></thead>
              <tbody>{c.actions.map((a, i) => (
                <tr key={i}><td>{a.action}</td><td>{a.target || '-'}</td><td>{a.status === 'failed' ? <span className="badge badge-red">Failed</span> : a.status === 'requested' ? <span className="badge badge-amber">Requested</span> : <span className="badge badge-green">Done</span>}</td><td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{(a.detail || '').substring(0, 80)}</td></tr>
              ))}</tbody>
            </table>
          </div>
        )}
        <div className="card col-span-2">
          <div className="card-header"><div className="card-title">Timeline ({(c.events || []).length})</div></div>
          <div style={{ maxHeight: 300, overflowY: 'auto' }}>
            <table><tbody>
              {(c.events || []).slice().reverse().map((ev, i) => (
                <tr key={i}><td style={{ whiteSpace: 'nowrap' }}>{formatDate(ev.timestamp)}</td>
                  <td><span className={`badge ${ev.type === 'approved' ? 'badge-green' : ev.type === 'rejected' ? 'badge-red' : ev.type === 'triaged' || ev.type === 'investigated' ? 'badge-accent' : 'badge-gray'}`}>{ev.type}</span></td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{ev.alert_id || ''}</td></tr>
              ))}
            </tbody></table>
          </div>
        </div>
      </div>
    </>
  );
}
```

---

### Task 11: Threats (OTX) Page

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/pages/Threats.jsx`

- [ ] **Step 1: Create Threats page**

`/home/aiagent/wazuh-soc/src/pages/Threats.jsx`:

```jsx
import { useState, useMemo } from 'react';
import { useApi } from '../hooks/useApi';
import { apiGet, apiPost } from '../api/wazuhApi';
import KpiCard from '../components/KpiCard';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import { useToast } from '../context/ToastContext';

export default function Threats() {
  const otx = useApi(() => apiGet('/otx/status'), []);
  const iocs = useApi(() => apiGet('/otx/iocs'), []);
  const toast = useToast();

  const [typeFilter, setTypeFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  if (otx.loading || iocs.loading) return <LoadingSpinner />;
  if (otx.error) return <ErrorState message={otx.error.message} onRetry={otx.refetch} />;
  if (iocs.error) return <ErrorState message={iocs.error.message} onRetry={iocs.refetch} />;

  const status = otx.data;
  const items = iocs.data?.iocs || [];
  const enabled = status.enabled;

  const filtered = useMemo(() => {
    let f = items;
    if (typeFilter) f = f.filter(i => i.type === typeFilter);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      f = f.filter(i => i.value.toLowerCase().includes(q));
    }
    return f;
  }, [items, typeFilter, searchQuery]);

  const typeCounts = {};
  items.forEach(i => { typeCounts[i.type] = (typeCounts[i.type] || 0) + 1; });

  const typeLabels = Object.keys(typeCounts).sort();

  const handleRefresh = () => {
    apiPost('/otx/refresh')
      .then(d => {
        if (d.status === 'error') toast(`OTX update failed: ${d.message || 'unknown'}`, 'error');
        else toast(`OTX updated: ${d.total_iocs} IOCs`, 'success');
        otx.refetch(); iocs.refetch();
      })
      .catch(e => toast(`OTX refresh failed: ${e.message}`, 'error'));
  };

  const handleDownloadCSV = () => {
    if (!items.length) { toast('No IOCs to download', 'error'); return; }
    apiGet('/otx/iocs').then(d => {
      const lines = ['type,value,category'];
      (d.iocs || []).forEach(i => lines.push(`${i.type},${i.value},${i.category || ''}`));
      const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'otx_iocs.csv';
      a.click();
      toast('Downloaded', 'success');
    }).catch(e => toast(`Download failed: ${e.message}`, 'error'));
  };

  const typeLabel = (t) => {
    const map = { ip: 'IP', domain: 'Domain', md5: 'MD5', sha1: 'SHA1', sha256: 'SHA256', url: 'URL' };
    return map[t] || t;
  };

  const typeColor = (t) => {
    if (t === 'ip') return 'badge-red';
    if (t === 'domain') return 'badge-amber';
    if (t.includes('sha') || t === 'md5') return 'badge-accent';
    return 'badge-gray';
  };

  const columns = [
    { key: 'type', label: 'Type', render: r => <span className={`badge ${typeColor(r.type)}`}>{typeLabel(r.type)}</span> },
    { key: 'value', label: 'Value', render: r => <span style={{ fontFamily: 'monospace', fontSize: 13 }}>{r.value}</span> },
    { key: 'category', label: 'Category', render: r => <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{r.category || ''}</span> },
  ];

  return (
    <>
      <div className="kpi-row">
        <KpiCard value={enabled ? 'Active' : 'Inactive'} label="OTX Integration" color={enabled ? 'green' : 'red'} />
        <KpiCard value={status.total_iocs || 0} label="Total IOCs" color="accent" />
        <KpiCard value={status.ips || 0} label="Malicious IPs" color="amber" />
        <KpiCard value={status.domains || 0} label="Malicious Domains" color="accent" />
        <KpiCard value={status.hashes || 0} label="File Hashes" color="secondary" />
      </div>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16, flexWrap: 'wrap' }}>
        <span style={{ color: 'var(--text-secondary)', fontSize: 13, marginRight: 4 }}>Filter:</span>
        <button className={`btn ${typeFilter === '' ? 'btn-primary' : ''}`} onClick={() => setTypeFilter('')}>All</button>
        {typeLabels.map(t => (
          <button key={t} className={`btn ${typeFilter === t ? 'btn-primary' : ''}`} onClick={() => setTypeFilter(t)}>
            {t} ({typeCounts[t]})
          </button>
        ))}
        {enabled && <><button className="btn" onClick={handleRefresh}>Refresh</button><button className="btn" onClick={handleDownloadCSV}>Download CSV</button></>}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header"><div className="card-title">Integration Details</div></div>
        <table><tbody>
          <tr><td>Status</td><td><span className={`badge ${enabled ? 'badge-green' : 'badge-red'}`}>{enabled ? 'Active' : 'Inactive'}</span></td></tr>
          <tr><td>Rules File</td><td>{status.size_bytes ? `${(status.size_bytes / 1024).toFixed(1)} KB` : '\u2014'}</td></tr>
          <tr><td>Last Updated</td><td>{status.last_updated ? new Date(status.last_updated).toLocaleString() : '\u2014'}</td></tr>
          <tr><td>IOC Count</td><td>{status.total_iocs || 0}</td></tr>
          <tr><td>Pulse Sources</td><td>{status.pulse_count || '\u2014'}</td></tr>
        </tbody></table>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Indicators of Compromise <span style={{ fontWeight: 400, color: 'var(--text-secondary)', fontSize: 12 }}>({filtered.length}/{items.length})</span></div>
          <input
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text)', padding: '6px 12px', borderRadius: 4, width: 200, fontSize: 13 }}
            placeholder="Search IOCs..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
        </div>
        {filtered.length ? (
          <div className="table-container" style={{ maxHeight: 500, overflowY: 'auto' }}>
            <DataTable columns={columns} data={filtered} />
          </div>
        ) : <div className="empty-state">No IOCs match your filter.</div>}
      </div>
    </>
  );
}
```

---

### Task 12: Remaining Pages (MITRE, Rules, Topology, Manager, Groups, AlertDetail, Help)

**Files:**
- Create: `/home/aiagent/wazuh-soc/src/pages/Mitre.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/Rules.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/Topology.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/Manager.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/Groups.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/AlertDetail.jsx`
- Create: `/home/aiagent/wazuh-soc/src/pages/Help.jsx`

- [ ] **Step 1: Create MITRE page**

`/home/aiagent/wazuh-soc/src/pages/Mitre.jsx`:

```jsx
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

export default function Mitre() {
  const r = useApi(() => apiGet('/mitre'), []);
  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const items = r.data.affected_items || [];
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Techniques ({items.length})</div></div>
      <div className="mitre-grid">
        {items.slice(0, 100).map((t, i) => (
          <div
            key={i}
            className="mitre-cell"
            style={{ background: `rgba(0, 180, 216, ${Math.min(0.3 + (t.score || 0) / 100, 1)})` }}
            title={t.description || ''}
          >{t.id || t.technique || '-'}</div>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create Rules page**

`/home/aiagent/wazuh-soc/src/pages/Rules.jsx`:

```jsx
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

export default function Rules() {
  const r = useApi(() => Promise.all([apiGet('/rules?limit=50'), apiGet('/decoders?limit=50')]), []);

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const [rulesRes, decodersRes] = r.data;
  const rules = rulesRes.affected_items || [];
  const decoders = decodersRes.affected_items || [];

  const ruleColumns = [
    { key: 'id', label: 'ID' },
    { key: 'level', label: 'Level' },
    { key: 'description', label: 'Description', render: r => (r.description || '').substring(0, 80) },
    { key: 'groups', label: 'Group', render: r => (r.groups || []).join(', ') },
  ];

  const decoderColumns = [
    { key: 'name', label: 'Name' },
    { key: 'parent', label: 'Parent' },
    { key: 'filename', label: 'Filename' },
  ];

  return (
    <>
      <div className="card">
        <div className="card-header"><div className="card-title">Rules ({rules.length}+)</div></div>
        <DataTable columns={ruleColumns} data={rules} />
      </div>
      <div className="card">
        <div className="card-header"><div className="card-title">Decoders ({decoders.length}+)</div></div>
        <DataTable columns={decoderColumns} data={decoders} />
      </div>
    </>
  );
}
```

- [ ] **Step 3: Create Topology page**

`/home/aiagent/wazuh-soc/src/pages/Topology.jsx`:

```jsx
import { useEffect, useRef } from 'react';
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import KpiCard from '../components/KpiCard';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import { Chart as ChartJS, ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const chartOpts = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { position: 'bottom', labels: { color: '#8fa6b5' } } },
};

const barOpts = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: { x: { ticks: { color: '#8fa6b5' } }, y: { ticks: { color: '#8fa6b5' }, beginAtZero: true } },
};

export default function Topology() {
  const r = useApi(() => Promise.all([apiGet('/overview'), apiGet('/topology')]), []);

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const [ov, topo] = r.data;
  const byOs = topo.os || {};
  const byVer = topo.version || {};
  const osLabels = Object.keys(byOs).length ? Object.keys(byOs) : Object.keys(ov.os_distribution || {});
  const osValues = Object.keys(byOs).length ? Object.values(byOs) : Object.values(ov.os_distribution || {});

  const osData = osLabels.length ? {
    labels: osLabels,
    datasets: [{ data: osValues, backgroundColor: ['#00b4d8', '#00ff88', '#ff9500', '#ff4757', '#8fa6b5', '#7c3aed'], borderWidth: 0 }],
  } : null;

  const verLabels = Object.keys(byVer);
  const verData = verLabels.length ? {
    labels: verLabels,
    datasets: [{ label: 'Agents', data: verLabels.map(l => byVer[l]), backgroundColor: '#00b4d8' }],
  } : null;

  return (
    <>
      <div className="kpi-row">
        <KpiCard value={ov.total_agents} label="Total Agents" color="accent" />
        <KpiCard value={ov.active} label="Active" color="green" />
        <KpiCard value={ov.offline} label="Offline" color="red" />
      </div>
      <div className="cols-2">
        <div className="card">
          <div className="card-header"><div className="card-title">OS Distribution</div></div>
          <div className="chart-container">
            {osData ? <Doughnut data={osData} options={chartOpts} /> : <div className="empty-state">No OS data</div>}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Agent Versions</div></div>
          <div className="chart-container">
            {verData ? <Bar data={verData} options={barOpts} /> : <div className="empty-state">No version data</div>}
          </div>
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 4: Create Manager page**

`/home/aiagent/wazuh-soc/src/pages/Manager.jsx`:

```jsx
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

export default function Manager() {
  const r = useApi(() => Promise.all([apiGet('/manager'), apiGet('/manager/info')]), []);

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const [daemonsRes, mgrRes] = r.data;
  const daemons = daemonsRes.affected_items ? daemonsRes.affected_items[0] : {};
  const mgr = mgrRes.affected_items ? mgrRes.affected_items[0] : {};
  const dl = Object.keys(daemons).filter(k => k !== 'name');

  return (
    <>
      <div className="kpi-row">
        {dl.map(d => {
          const running = daemons[d] === 'running';
          return (
            <div key={d} className="kpi-card">
              <div className="kpi-value" style={{ fontSize: 14, color: running ? 'var(--green)' : 'var(--red)' }}>
                {running ? 'Running' : 'Stopped'}
              </div>
              <div className="kpi-label">{d}</div>
            </div>
          );
        })}
      </div>
      <div className="cols-2">
        <div className="card">
          <div className="card-header"><div className="card-title">Manager Info</div></div>
          <table><tbody>
            <tr><td>Version</td><td>{mgr.version || '-'}</td></tr>
            <tr><td>Hostname</td><td>{mgr.hostname || mgr.name || '-'}</td></tr>
            <tr><td>Type</td><td>{mgr.type || '-'}</td></tr>
          </tbody></table>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Cluster</div></div>
          <table><tbody>
            <tr><td>Status</td><td>{mgr.cluster_status || 'N/A'}</td></tr>
            <tr><td>Node</td><td>{mgr.node_name || mgr.node || '-'}</td></tr>
          </tbody></table>
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 5: Create Groups page**

`/home/aiagent/wazuh-soc/src/pages/Groups.jsx`:

```jsx
import { useApi } from '../hooks/useApi';
import { apiGet } from '../api/wazuhApi';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

export default function Groups() {
  const r = useApi(() => apiGet('/groups'), []);

  if (r.loading) return <LoadingSpinner />;
  if (r.error) return <ErrorState message={r.error.message} onRetry={r.refetch} />;

  const items = r.data.affected_items || [];
  const columns = [
    { key: 'name', label: 'Group' },
    { key: 'count', label: 'Count' },
  ];

  return (
    <div className="card">
      <DataTable columns={columns} data={items} />
    </div>
  );
}
```

- [ ] **Step 6: Create AlertDetail page**

`/home/aiagent/wazuh-soc/src/pages/AlertDetail.jsx`:

```jsx
import { useParams } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { apiGet } from '../api/wazuhApi';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      apiGet('/events?size=1').catch(() => null),
      fetch(`http://127.0.0.1:8000/api/v1/remediation/suggest/${id}`, {
        headers: { 'x-api-key': 'mission-test-key-123' },
      }).then(r => r.json()).catch(() => null),
    ]).then(([ev, rem]) => {
      const items = ev?.affected_items || [];
      setAlert(items[0] || {});
      setRemediation(rem);
    }).catch(e => setError(e.message))
    .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingSpinner />;
  if (error) return <ErrorState message={error} />;

  const a = alert || {};
  const ruleLevel = a.rule?.level || 0;
  const sev = ruleLevel >= 12 ? 'critical' : ruleLevel >= 8 ? 'high' : ruleLevel >= 5 ? 'medium' : 'low';

  return (
    <>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button className="btn" onClick={() => window.history.back()}>&#9664; Back</button>
      </div>
      <div className="cols-2">
        <div className="card">
          <div className="card-header"><div className="card-title">Alert Details</div></div>
          <table><tbody>
            <tr><td>ID</td><td style={{ fontFamily: 'monospace' }}>{id}</td></tr>
            <tr><td>Severity</td><td><SeverityBadge severity={sev} /></td></tr>
            <tr><td>Rule</td><td>{a.rule ? (a.rule.description || a.rule.id || '') : '-'}</td></tr>
            <tr><td>Agent</td><td>{a.agent ? (a.agent.name || a.agent.id || '') : '-'}</td></tr>
            <tr><td>Timestamp</td><td>{a.timestamp ? new Date(a.timestamp).toLocaleString() : '-'}</td></tr>
            <tr><td>Location</td><td>{a.location || '-'}</td></tr>
          </tbody></table>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Remediation</div></div>
          {remediation?.suggested_actions?.length ? (
            <table><thead><tr><th>Action</th><th>Detail</th></tr></thead>
              <tbody>{remediation.suggested_actions.map((act, i) => (
                <tr key={i}><td><span className="badge badge-accent">{act.action}</span></td><td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{act.detail || ''}</td></tr>
              ))}</tbody>
            </table>
          ) : <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>No remediation suggestions available.</div>}
          {remediation?.device && (
            <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>Device</div>
              <table><tbody>
                <tr><td>IP</td><td style={{ fontFamily: 'monospace' }}>{remediation.device.ip || '-'}</td></tr>
                <tr><td>Hostname</td><td>{remediation.device.hostname || '-'}</td></tr>
                <tr><td>Type</td><td>{remediation.device.device_type || '-'}</td></tr>
                <tr><td>Status</td><td><span className={`badge ${remediation.device.status === 'ONLINE' ? 'badge-green' : 'badge-red'}`}>{remediation.device.status || '-'}</span></td></tr>
              </tbody></table>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 7: Create Help page**

`/home/aiagent/wazuh-soc/src/pages/Help.jsx`:

```jsx
export default function Help() {
  return (
    <div className="help-page">
      <div className="card">
        <div className="card-header"><div className="card-title">Navigation</div></div>
        <ul className="help-list">
          <li>Use the sidebar to switch between pages. Click the arrow to collapse it.</li>
          <li>Command Center shows KPIs, agent status, OS distribution, and alert severity.</li>
          <li>Click any agent row to drill down into SCA, FIM, Vulnerabilities, and Inventory.</li>
          <li>Events &amp; Alerts shows the real-time feed with severity filtering.</li>
          <li>SOC Autopilot manages AI-generated security cases with approve/reject/execute workflow.</li>
          <li>Threat Intel shows AlienVault OTX integration status and IOC counts.</li>
          <li>Click Refresh in the topbar to reload the current page data.</li>
          <li>Use the search box to find agents by name or IP.</li>
        </ul>
      </div>
    </div>
  );
}
```

---

### Task 13: Build & Verify

- [ ] **Step 1: Build the project**

```bash
cd /home/aiagent/wazuh-soc && npm run build
```

Expected: `dist/` directory created with static files.

- [ ] **Step 2: Verify dev server starts**

```bash
cd /home/aiagent/wazuh-soc && npm run dev
```

Visit http://localhost:5173. Should see the SOC app with sidebar navigation. Dashboard should call `/wazuh-api/overview` (proxied to Python on port 8095).

- [ ] **Step 3: Initialize git repo**

```bash
cd /home/aiagent/wazuh-soc && git init && git add -A && git commit -m "feat: initial Wazuh SOC React SPA scaffold"
```

---

## Self-Review

**Spec coverage:**
- Architecture: Tasks 1-6 cover the full project scaffold, routing, layout, and shared components. ✓
- All 17 pages: Tasks 7-12 cover every page from the spec (Dashboard, Agents, AgentDetail, SCA, FIM, Vulns, MITRE, Rules, Events, Topology, Threats, Autopilot, AutopilotCase, Manager, Groups, AlertDetail, Help). ✓
- API integration: Task 3 covers wazuhApi.js + useApi hook. ✓
- Toast notifications: Task 4 covers ToastContext. ✓
- NL Panel: Included in Task 5 (NLPanel component), wired in Layout. ✓
- Chart.js: Dashboard and Topology use react-chartjs-2. ✓
- Virtual scrolling: Agents page uses react-window. ✓
- Code splitting: App.jsx uses React.lazy per route. ✓
- Cyber-dark theme: Task 2 has complete global.css. ✓

**No placeholders, no TBDs, no TODOs.** Every file has complete code.

**Type consistency:** All component imports match their exports. All API function names match. All route paths match between App.jsx and page components.
