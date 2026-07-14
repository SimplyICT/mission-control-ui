# Mission Control Launchpad — Portal Enhancement

## Problem
The `mc.simplyict.com.au` landing page (`index.html`) currently lists 32 app links in 8 sections as a flat scrollable grid. As more apps are added, finding the right app requires scrolling through all sections. There is no search, filtering, or personalization.

## Approach: App Drawer / Launchpad
Preserve the existing card layout but add three enhancements: **search**, **tag-based filtering**, and **favorites/pinning**. These make the portal scale from ~30 to 100+ apps without structural redesign.

## Design

### 1. Search Bar
- Prominent input at page top, styled consistently with the dark theme
- `Ctrl+K` / `Cmd+K` or `/` keyboard shortcut focuses the search bar
- `Escape` clears the search
- Filters all cards in real-time by matching name, description, and tag text
- Matching sections remain visible; sections with zero matches are collapsed/hidden
- No backend — pure JS `filter()` on the existing card DOM

### 2. Tag Filter Pills
- Row of clickable pill buttons below the search bar: "All", "Dashboard", "Tool", "Vault", "SOC", "Kanban", "Link", etc.
- Tags extracted from the existing `tag` class text in each card (`.tag-green`, `.tag-accent`, etc.)
- Clicking a pill shows only cards with that tag
- "All" resets the tag filter
- Stackable with search (both filters can be active simultaneously)

### 3. Favorites / Pinned
- Each card gets a small star (★) button in its top-right corner
- Clicking toggles favorited state
- State persisted in `localStorage` (no backend changes)
- Favorited cards appear in a sticky "Favorites" section at the top of the page, before all other sections
- Empty favorites section is hidden when no cards are pinned

### 4. Collapsible Sections
- Each section header gets a collapse/expand toggle (▲/▼)
- Collapsed state persisted in `localStorage`
- All sections default to expanded on first visit
- Collapsed sections hide their card grid but keep the title visible

### 5. Implementation
- Vanilla JavaScript (~100 lines) appended to `index.html`
- All styles added inline to `index.html` (matches existing pattern)
- No external dependencies, no framework, no backend changes
- Card markup unchanged except for a `data-tags` attribute and a star icon

## Design Decisions
- **No backend changes**: Everything uses `localStorage` for persistence. This avoids touching nginx, Flask, or Python backends.
- **Vanilla JS only**: The existing page is pure HTML/CSS; adding jQuery or a framework would be disproportionate.
- **Backward compatible**: All existing cards, links, sections, and styling remain identical. Users who don't interact with the new features see the same page.
- **Search over full text**: We match against card name, description, and tags so results are comprehensive.

## Files Touched
- `/home/aiagent/mission-control-ui/index.html` — only file modified

## Future Considerations
- If the portal grows beyond ~150 items, consider lazy-loading sections or pagination
- Analytics on which apps are most-used could inform a future "most used" section
- A `manifest.json` or `service worker` could make the page available offline
