# MC Launchpad Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add search, tag filtering, favorites/pinning, and collapsible sections to the mc.simplyict.com.au landing page.

**Architecture:** All changes go into `/home/aiagent/mission-control-ui/index.html`. Add ~80 lines of inline CSS for new elements, ~50 lines of HTML for the search bar/filter row/favorites section, and ~120 lines of vanilla JS for interactivity. Uses `localStorage` for persistence — no backend changes.

**Tech Stack:** Vanilla HTML/CSS/JS (matches existing pattern). Zero dependencies.

---

### Task 1: Add CSS for new components

**Files:**
- Modify: `/home/aiagent/mission-control-ui/index.html:8-31` (style block)

Add CSS for: search bar, filter pills, favorites star button, collapsible section toggle, favorites section, and animation for filtering.

- [ ] **Step 1: Read the existing CSS**

```bash
cat /home/aiagent/mission-control-ui/index.html | head -32
```
This shows the current root CSS variables and universal reset to know what's already defined.

- [ ] **Step 2: Append new CSS before the closing `</style>` tag**

Insert these new styles after the existing grid/card CSS:

```css
/* ── Launchpad Enhancements ── */
.search-bar{width:100%;max-width:500px;padding:10px 16px;background:var(--card);border:1px solid #2d2d3d;border-radius:8px;color:var(--text);font-size:14px;outline:none;transition:border-color .15s;font-family:inherit}
.search-bar:focus{border-color:var(--accent)}
.search-bar::placeholder{color:var(--muted)}
.search-wrap{position:relative;margin-bottom:16px}
.search-wrap .kbd-hint{position:absolute;right:12px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:10px;font-family:'SF Mono','Fira Code',monospace;background:#1e293b;padding:2px 6px;border-radius:4px;pointer-events:none;opacity:0.6}
.filter-pills{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
.filter-pill{padding:4px 12px;border-radius:999px;border:1px solid #2d2d3d;background:transparent;color:var(--muted);font-size:11px;cursor:pointer;transition:all .15s;font-family:inherit}
.filter-pill:hover{border-color:var(--accent);color:var(--text)}
.filter-pill.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.section.collapsed .grid{display:none!important}
.section-toggle{background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;padding:0 8px;transition:transform .15s}
.section-toggle.open{transform:rotate(180deg)}
.fav-section{margin-bottom:20px}
.fav-section .grid{gap:6px}
.fav-section:empty{display:none}
.fav-star{background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:0 2px;transition:color .15s;line-height:1;flex-shrink:0}
.fav-star.active{color:var(--amber)}
.card .name-wrap{display:flex;align-items:center;gap:6px;min-width:0;flex:1}
.card .name-wrap .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card.hidden-by-search{display:none!important}
```

- [ ] **Step 3: Verify no syntax errors**

No test needed — visual check on refresh.

---

### Task 2: Add HTML for search bar, filter row, and favorites section

**Files:**
- Modify: `/home/aiagent/mission-control-ui/index.html:33-37` (after sub header, before first section)

- [ ] **Step 1: Add search bar and filter row HTML**

Insert after `<p class="sub">Simply ICT unified management dashboard</p>`:

```html
<div class="search-wrap">
  <input class="search-bar" id="search-bar" type="text" placeholder="Search apps, dashboards, tools..." autocomplete="off" spellcheck="false">
  <span class="kbd-hint">⌘K</span>
</div>
<div class="filter-pills" id="filter-pills"></div>
<div class="fav-section" id="fav-section">
  <div class="section-title" style="color:var(--amber);">★ Pinned</div>
  <div class="grid" id="fav-grid"></div>
</div>
```

- [ ] **Step 2: Add collapse toggle buttons to each section header**

Replace each `<div class="section-title">...</div>` with `<div class="section-title" style="display:flex;align-items:center;justify-content:space-between">... <button class="section-toggle open" data-section="SECTION_NAME">▼</button></div>` where `SECTION_NAME` is a kebab-case identifier for that section.

Sections to modify (8 total): Core Platforms, Network Design, Network Monitoring, Device Auditing, Executive & Compliance, Administration, Projects, External.

- [ ] **Step 3: Add star icons and data attributes to each card**

For each `<a class="card" href="...">`, add:
1. A `data-name` attribute with the app name text
2. A `data-desc` attribute with the description text
3. A `data-tags` attribute with comma-separated tag names (e.g., `"Tool,Dashboard"`)
4. A star button in the card header

Change each card structure from:
```html
<a class="card" href="/hub/">
  <div class="name">📋 Project Hub</div>
  <div class="desc">Tracker panels, tasks...</div>
  <div class="meta">/hub/ <span class="tag tag-purple">Kanban</span></div>
</a>
```
To:
```html
<a class="card" href="/hub/" data-name="Project Hub" data-desc="Tracker panels, tasks, kanban, GitHub backup for all build projects" data-tags="Kanban">
  <div class="name-wrap"><button class="fav-star" data-app="Project Hub">☆</button><span class="name">📋 Project Hub</span></div>
  <div class="desc">Tracker panels, tasks...</div>
  <div class="meta">/hub/ <span class="tag tag-purple">Kanban</span></div>
</a>
```

Every `<a class="card">` in the file needs these changes (32 cards).

---

### Task 3: Add JavaScript for interactive features

**Files:**
- Modify: `/home/aiagent/mission-control-ui/index.html` (before `</body>`)

- [ ] **Step 1: Add data attribute parsing to all 32 cards**

At the bottom of the file, before `</body>`, add a `<script>` block. First, extract tag names from all cards' existing `<span class="tag">` elements and populate `data-tags`:

```javascript
// Populate data-tags from existing tag spans
document.querySelectorAll('.card').forEach(function(card) {
  var tags = [];
  card.querySelectorAll('.tag').forEach(function(t) { tags.push(t.textContent.trim()); });
  card.setAttribute('data-tags', tags.join(','));
  // Ensure data-name and data-desc are set from content
  var nameEl = card.querySelector('.name');
  if (nameEl && !card.getAttribute('data-name')) card.setAttribute('data-name', nameEl.textContent.trim());
  var descEl = card.querySelector('.desc');
  if (descEl && !card.getAttribute('data-desc')) card.setAttribute('data-desc', descEl.textContent.trim());
});
```

- [ ] **Step 2: Build tag filter pills**

```javascript
// Build filter pills from unique tags across all cards
var allTags = new Set(['All']);
document.querySelectorAll('.card').forEach(function(c) {
  (c.getAttribute('data-tags') || '').split(',').forEach(function(t) {
    if (t.trim()) allTags.add(t.trim());
  });
});
var pillContainer = document.getElementById('filter-pills');
allTags.forEach(function(tag) {
  var btn = document.createElement('button');
  btn.className = 'filter-pill' + (tag === 'All' ? ' active' : '');
  btn.textContent = tag;
  btn.onclick = function() {
    document.querySelectorAll('.filter-pill').forEach(function(p) { p.classList.remove('active'); });
    btn.classList.add('active');
    applyFilters();
  };
  pillContainer.appendChild(btn);
});
```

- [ ] **Step 3: Search + filter function**

```javascript
var activeTag = 'All';

function applyFilters() {
  var query = (document.getElementById('search-bar').value || '').toLowerCase().trim();
  document.querySelectorAll('.card').forEach(function(card) {
    var name = (card.getAttribute('data-name') || '').toLowerCase();
    var desc = (card.getAttribute('data-desc') || '').toLowerCase();
    var tags = (card.getAttribute('data-tags') || '').toLowerCase();
    var matchesSearch = !query || name.includes(query) || desc.includes(query) || tags.includes(query);
    var activePill = document.querySelector('.filter-pill.active');
    var tagFilter = activePill ? activePill.textContent : 'All';
    var matchesTag = tagFilter === 'All' || tags.split(',').some(function(t) { return t.trim() === tagFilter.toLowerCase(); });
    card.classList.toggle('hidden-by-search', !(matchesSearch && matchesTag));
  });
  // Collapse sections with no visible cards
  document.querySelectorAll('.section').forEach(function(s) {
    var visible = s.querySelectorAll('.card:not(.hidden-by-search)').length > 0;
    if (!visible) s.classList.add('collapsed');
  });
}
```

- [ ] **Step 4: Wire search bar events**

```javascript
document.getElementById('search-bar').addEventListener('input', applyFilters);
document.getElementById('search-bar').addEventListener('keydown', function(e) {
  if (e.key === 'Escape') { this.value = ''; applyFilters(); this.blur(); }
});
// Ctrl+K or Cmd+K or / to focus search
document.addEventListener('keydown', function(e) {
  if ((e.key === 'k' && (e.ctrlKey || e.metaKey)) || (e.key === '/' && !e.target.closest('input,textarea'))) {
    e.preventDefault();
    document.getElementById('search-bar').focus();
  }
});
```

- [ ] **Step 5: Favorites (localStorage)**

```javascript
function getFavs() {
  try { return JSON.parse(localStorage.getItem('mc-favs') || '[]'); } catch(e) { return []; }
}
function setFavs(favs) {
  localStorage.setItem('mc-favs', JSON.stringify(favs));
}
function toggleFav(appName) {
  var favs = getFavs();
  var idx = favs.indexOf(appName);
  if (idx >= 0) { favs.splice(idx, 1); } else { favs.push(appName); }
  setFavs(favs);
  renderFavs();
  updateStarUI();
}
function updateStarUI() {
  var favs = getFavs();
  document.querySelectorAll('.fav-star').forEach(function(star) {
    var name = star.getAttribute('data-app');
    star.textContent = favs.includes(name) ? '★' : '☆';
    star.classList.toggle('active', favs.includes(name));
  });
}
function renderFavs() {
  var favGrid = document.getElementById('fav-grid');
  var favSection = document.getElementById('fav-section');
  var favs = getFavs();
  if (!favs.length) { favSection.style.display = 'none'; return; }
  favSection.style.display = '';
  favGrid.innerHTML = '';
  favs.forEach(function(name) {
    var original = document.querySelector('.card[data-name="' + CSS.escape(name) + '"]');
    if (!original) return;
    var clone = original.cloneNode(true);
    // Re-wire star toggles in clones
    clone.querySelector('.fav-star').onclick = function(e) {
      e.preventDefault(); e.stopPropagation();
      toggleFav(clone.getAttribute('data-name'));
    };
    clone.querySelector('.fav-star').textContent = '★';
    clone.querySelector('.fav-star').classList.add('active');
    clone.classList.remove('hidden-by-search');
    favGrid.appendChild(clone);
  });
}
// Wire all star buttons
document.querySelectorAll('.fav-star').forEach(function(star) {
  star.addEventListener('click', function(e) {
    e.preventDefault();
    e.stopPropagation();
    toggleFav(star.getAttribute('data-app'));
  });
});
```

- [ ] **Step 6: Collapsible sections (localStorage)**

```javascript
function getCollapsed() {
  try { return JSON.parse(localStorage.getItem('mc-collapsed') || '{}'); } catch(e) { return {}; }
}
function setCollapsed(name, val) {
  var state = getCollapsed();
  state[name] = val;
  localStorage.setItem('mc-collapsed', JSON.stringify(state));
}
document.querySelectorAll('.section-toggle').forEach(function(btn) {
  var secName = btn.getAttribute('data-section');
  var section = btn.closest('.section');
  // Restore saved state
  var saved = getCollapsed();
  if (saved[secName]) {
    section.classList.add('collapsed');
    btn.classList.remove('open');
  }
  btn.addEventListener('click', function() {
    var isCollapsed = section.classList.toggle('collapsed');
    btn.classList.toggle('open', !isCollapsed);
    setCollapsed(secName, isCollapsed);
  });
});
```

- [ ] **Step 7: Initialize on page load**

```javascript
document.addEventListener('DOMContentLoaded', function() {
  updateStarUI();
  renderFavs();
  applyFilters();
});
```

---

### Task 4: Verify on live page

**Files:** None — manual verification.

- [ ] **Step 1: Open the page**

Visit `https://mc.simplyict.com.au` in a browser.

- [ ] **Step 2: Verify search**

Type "network" in the search bar. Confirm only Network Design and Network Monitoring section cards appear. Clear with Escape.

- [ ] **Step 3: Verify tag filter pills**

Click the "Dashboard" filter pill. Confirm only cards tagged "Dashboard" appear. Click "All" to reset.

- [ ] **Step 4: Verify favorites**

Click a star icon on any card. Confirm it appears in the ★ Pinned section at the top. Refresh the page — confirm it persists.

- [ ] **Step 5: Verify collapsible sections**

Click the ▼ toggle on any section. Confirm cards hide. Refresh — confirm state persists.

- [ ] **Step 6: Verify keyboard shortcuts**

Press `Ctrl+K` — confirm search bar focuses. Press `/` — confirm search bar focuses. Press `Escape` — confirm search clears.

- [ ] **Step 7: Verify no regressions**

Confirm all 32 cards still load on page load. Confirm all links still work. Confirm mobile layout is reasonable.

---

### Task 5: Clean up and commit

**Files:** None.

- [ ] **Step 1: Verify no console errors**

Open browser devtools console. Confirm no JS errors.

- [ ] **Step 2: Update project memory**

```bash
echo "
2026-06-29 (session 11): Implemented MC Launchpad — search bar, tag filter pills, favorites (localStorage), collapsible sections, Ctrl+K shortcut. All 32 cards enhanced with data attributes and star toggles." >> /home/aiagent/mission-control-ui/.opencode/memory.md
```
