(function () {
  'use strict';

  const dataStore = window.FISSURE_ROADMAP_DATA || {};
  const sunburst = document.getElementById('sunburst-chart');
  const treemap = document.getElementById('treemap-chart');
  const yearButtons = document.getElementById('year-buttons');
  const snapshotLabel = document.getElementById('snapshot-label');
  const searchBox = document.getElementById('search');
  const searchMeta = document.getElementById('search-meta');
  const searchResults = document.getElementById('search-results');
  const selectedLabel = document.getElementById('selected-label');
  const childList = document.getElementById('child-list');
  const statusLine = document.getElementById('status-line');
  const summary = document.getElementById('summary');
  const legend = document.getElementById('legend');
  const changesSincePrior = document.getElementById('changes-since-prior');
  const changesCount = document.getElementById('changes-count');
  const phasedOutGroup = document.getElementById('phased-out-group');
  const phasedOutList = document.getElementById('phased-out-list');
  const consolidatedGroup = document.getElementById('consolidated-group');
  const consolidatedList = document.getElementById('consolidated-list');

  const stateByFig = new Map();
  const VALID_STATUSES = new Set(['complete', 'partial', 'planned']);
  let currentYear = '';
  let activeSearch = null;

  function availableYears() {
    return Object.keys(dataStore).sort((a, b) => Number(a) - Number(b));
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function titleCaseStatus(status) {
    if (status === 'complete') return 'Completed';
    if (status === 'partial') return 'Not complete · work in progress';
    if (status === 'planned') return 'Not complete · planned';
    return '';
  }

  function updateInfo(label, children, meta) {
    selectedLabel.textContent = label || 'None';
    if (meta && VALID_STATUSES.has(meta.status)) {
      const introduced = meta.introduced ? ' · Introduced ' + meta.introduced : '';
      statusLine.textContent = 'Status: ' + titleCaseStatus(meta.status) + introduced;
    } else {
      statusLine.textContent = '';
    }
    childList.innerHTML = (children && children.length)
      ? children.map(c => '<li>' + escapeHtml(c) + '</li>').join('')
      : '<li>(no children)</li>';
  }

  function buildState(fig) {
    const tr = (fig.data && fig.data[0]) || {ids: [], parents: [], labels: []};
    const ids = tr.ids || [];
    const parents = tr.parents || [];
    const labels = tr.labels || [];
    const customdata = tr.customdata || [];
    const parentById = {};
    const labelById = {};
    const childrenById = {};
    const metaById = {};

    for (let i = 0; i < ids.length; i++) {
      const id = ids[i];
      const parent = parents[i] || '';
      const label = labels[i] || '';
      parentById[id] = parent;
      labelById[id] = label;
      if (!childrenById[parent]) childrenById[parent] = [];
      childrenById[parent].push(label);

      const row = customdata[i];
      if (Array.isArray(row) && VALID_STATUSES.has(row[0])) {
        metaById[id] = {status: row[0], introduced: row[1], note: row[2] || ''};
      }
    }

    const topIds = ids.filter((id, i) => (parents[i] || '') === '');
    let currentRoot = '';
    if (topIds.length === 1) currentRoot = topIds[0];
    else if (ids.length) currentRoot = ids[0];

    stateByFig.set(fig, {
      ids, parents, labels, parentById, labelById, childrenById, metaById, rootId: currentRoot, currentRoot
    });
  }

  function attachClickHandler(fig) {
    if (fig.__fissureRoadmapClickHandler) {
      fig.removeListener('plotly_click', fig.__fissureRoadmapClickHandler);
    }

    const handler = d => {
      const pt = d.points[0];
      const clickedId = pt.id;
      const state = stateByFig.get(fig);
      if (!state) return;

      const clickedLabel = state.labelById[clickedId] || pt.label || '';
      const isClickingFocused = clickedId === state.currentRoot;
      const nextRootId = isClickingFocused
        ? (state.parentById[clickedId] || state.currentRoot)
        : clickedId;

      state.currentRoot = nextRootId;
      const children = state.childrenById[nextRootId] || [];
      updateInfo(
        state.labelById[nextRootId] || clickedLabel,
        children,
        children.length ? null : state.metaById[nextRootId]
      );
    };

    fig.__fissureRoadmapClickHandler = handler;
    fig.on('plotly_click', handler);
  }

  function requestedInitialYear() {
    const years = availableYears();
    const params = new URLSearchParams(window.location.search);
    const requestedYear = params.get('year');
    return dataStore[requestedYear] ? requestedYear : years[years.length - 1];
  }

  function populateYearButtons(selectedYear) {
    yearButtons.innerHTML = '';
    for (const year of availableYears()) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'year-button';
      button.textContent = year;
      button.dataset.year = year;
      button.setAttribute('aria-pressed', year === selectedYear ? 'true' : 'false');
      button.addEventListener('click', () => {
        if (year !== currentYear) renderYear(year);
      });
      yearButtons.appendChild(button);
    }
  }

  function syncYearButtons(year) {
    yearButtons.querySelectorAll('.year-button').forEach(button => {
      button.setAttribute('aria-pressed', button.dataset.year === year ? 'true' : 'false');
    });
  }

  function branchLegendHtml() {
    return [
      '<span class="branch-key"><span class="branch-dot" style="background:#2CA02C"></span>RF Reverse Engineering</span>',
      '<span class="branch-key"><span class="branch-dot" style="background:#FFBB78"></span>Operational Capabilities</span>',
      '<span class="branch-key"><span class="branch-dot" style="background:#1F77B4"></span>Platform &amp; Enablers</span>'
    ].join('');
  }

  function renderSummary(snapshot) {
    const s = snapshot.summary;
    if (!s) {
      const tr = snapshot.sunburst && snapshot.sunburst.data && snapshot.sunburst.data[0];
      const ids = (tr && tr.ids) || [];
      const parents = new Set((tr && tr.parents) || []);
      const leafGoals = ids.filter(id => !parents.has(id)).length;
      summary.innerHTML =
        '<span class="summary-chip"><b>' + leafGoals + '</b> roadmap objectives</span>' +
        '<span class="summary-chip">Original snapshot</span>';
      legend.innerHTML =
        '<span class="legend-item"><span class="legend-swatch legacy-color"></span>Treemap color = implemented/current at snapshot</span>' +
        '<span class="legend-item"><span class="legend-swatch" style="background:#F1F3F5"></span>Treemap gray = roadmap goal</span>' +
        '<span class="legend-item">Sunburst colors show hierarchy only</span>' +
        branchLegendHtml();
      legend.style.display = 'flex';
      return;
    }

    const percent = s.total ? Math.round((s.complete / s.total) * 100) : 0;
    const chips = [
      '<span class="summary-chip"><b>' + s.complete + ' of ' + s.total + '</b> completed · <b>' + percent + '%</b></span>',
      '<span class="summary-chip"><b>' + (s.total - s.complete) + '</b> remaining</span>',
      '<span class="summary-chip"><b>' + s.new + '</b> introduced this snapshot</span>'
    ];
    if (snapshot.lineageSummary && snapshot.lineageSummary.reconciled) {
      chips.push(
        '<span class="summary-chip"><b>' + snapshot.lineageSummary.reconciled +
        '</b> prior-year objectives reconciled</span>'
      );
    }
    summary.innerHTML = chips.join('');
    legend.innerHTML =
      '<span class="legend-item"><span class="legend-check">✓</span>Completed objective</span>' +
      '<span class="legend-item"><span class="legend-swatch" style="background:#F1F3F5"></span>Remaining objective</span>' +
      branchLegendHtml();
    legend.style.display = 'flex';
  }

  function renderChangesSincePrior(snapshot) {
    const phased = snapshot.phasedOut || [];
    const consolidated = snapshot.consolidated || [];
    const total = phased.length + consolidated.length;

    if (!total) {
      changesSincePrior.style.display = 'none';
      changesSincePrior.open = false;
      changesCount.textContent = '';
      phasedOutList.innerHTML = '';
      consolidatedList.innerHTML = '';
      return;
    }

    changesSincePrior.style.display = 'block';
    changesSincePrior.open = false;
    changesCount.textContent = '(' + total + ')';

    phasedOutGroup.style.display = phased.length ? 'block' : 'none';
    consolidatedGroup.style.display = consolidated.length ? 'block' : 'none';
    phasedOutList.innerHTML = phased.map(x => '<li>' + escapeHtml(x) + '</li>').join('');
    consolidatedList.innerHTML = consolidated.map(x => '<li>' + escapeHtml(x) + '</li>').join('');
  }

  function chartLayout(layout, chartType) {
    const copy = JSON.parse(JSON.stringify(layout || {}));
    delete copy.title;

    // Treemap drill-down uses Plotly's pathbar along the top edge. Keep
    // enough headroom that the back/breadcrumb controls are never clipped.
    const topMargin = chartType === 'treemap' ? 52 : 18;
    copy.margin = Object.assign({t: topMargin, l: 20, r: 20, b: 20}, copy.margin || {});
    copy.margin.t = topMargin;
    return copy;
  }

  function chartConfig(config) {
    return Object.assign({}, config || {}, {
      responsive: true,
      displaylogo: false
    });
  }

  async function renderYear(year) {
    const snapshot = dataStore[year];
    if (!snapshot) return;

    currentYear = year;
    syncYearButtons(year);
    snapshotLabel.textContent = 'Updated ' + (snapshot.snapshot || year);
    searchBox.value = '';
    activeSearch = null;
    searchResults.innerHTML = '';
    searchMeta.textContent = 'Search the entire selected snapshot.';
    updateInfo('None', [], null);
    renderSummary(snapshot);
    renderChangesSincePrior(snapshot);

    await Promise.all([
      Plotly.react(
        sunburst,
        snapshot.sunburst.data,
        chartLayout(snapshot.sunburst.layout, 'sunburst'),
        chartConfig(snapshot.sunburst.config)
      ),
      Plotly.react(
        treemap,
        snapshot.treemap.data,
        chartLayout(snapshot.treemap.layout, 'treemap'),
        chartConfig(snapshot.treemap.config)
      )
    ]);

    stateByFig.clear();
    [sunburst, treemap].forEach(fig => {
      buildState(fig);
      attachClickHandler(fig);
    });

    const url = new URL(window.location.href);
    url.searchParams.set('year', year);
    window.history.replaceState({}, '', url);
  }

  function resultPath(state, id) {
    const parts = [];
    let cursor = id;
    while (cursor) {
      const label = state.labelById[cursor];
      if (label) parts.unshift(label);
      cursor = state.parentById[cursor] || '';
    }
    return parts.join(' > ');
  }

  function isWithinScope(state, id, scopeRoot) {
    if (!scopeRoot) return true;
    let cursor = id;
    while (cursor) {
      if (cursor === scopeRoot) return true;
      cursor = state.parentById[cursor] || '';
    }
    return false;
  }

  function renderSearchResults(selectedId) {
    if (!activeSearch) {
      searchResults.innerHTML = '';
      searchMeta.textContent = 'Search the entire selected snapshot.';
      return;
    }

    const state = stateByFig.get(treemap) || stateByFig.get(sunburst);
    if (!state) return;

    const matches = activeSearch.matches || [];
    searchMeta.textContent = matches.length + (matches.length === 1 ? ' match' : ' matches') +
      ' across the selected snapshot. Click a result to show it within its parent area.';

    if (!matches.length) {
      searchResults.innerHTML = '<li><span style="display:block;padding:5px 8px">No matches</span></li>';
      return;
    }

    searchResults.innerHTML = matches.map(match => {
      const parentId = state.parentById[match.id] || '';
      const parentLabel = state.labelById[parentId] || '';
      const context = parentLabel ? '<small>' + escapeHtml(parentLabel) + '</small>' : '';
      const selectedClass = match.id === selectedId ? ' is-selected' : '';
      return '<li class="search-result' + selectedClass + '"><button type="button" data-roadmap-id="' +
        escapeHtml(match.id) + '" title="' + escapeHtml(resultPath(state, match.id)) + '">' +
        '<span>' + escapeHtml(match.label) + '</span>' + context + '</button></li>';
    }).join('');
  }

  function applySearch(term) {
    const state = stateByFig.get(treemap) || stateByFig.get(sunburst);
    if (!state) return;

    const normalized = (term || '').toLowerCase().trim();
    if (!normalized) {
      activeSearch = null;
      renderSearchResults(null);
      return;
    }

    // Search always covers the entire selected-year snapshot. Navigation or
    // drill-down must not change the search scope or result set.
    activeSearch = {
      scopeRoot: state.rootId,
      term: normalized,
      matches: []
    };

    for (let i = 0; i < state.labels.length; i++) {
      const id = state.ids[i];
      const label = state.labels[i] || '';
      if (isWithinScope(state, id, activeSearch.scopeRoot) && label.toLowerCase().includes(normalized)) {
        activeSearch.matches.push({id, label});
      }
    }

    renderSearchResults(null);
  }

  async function focusSearchResult(id) {
    const state = stateByFig.get(treemap);
    if (!state || !state.labelById[id]) return;

    // Show the result one level below the treemap root so its siblings and
    // surrounding roadmap area stay visible instead of isolating the node.
    const parentId = state.parentById[id] || id;
    state.currentRoot = parentId;

    await Plotly.restyle(treemap, {level: parentId}, [0]);

    // Keep the original search result set visible and show details for the
    // actual result while the treemap stays at its parent for context.
    renderSearchResults(id);
    const children = state.childrenById[id] || [];
    updateInfo(
      state.labelById[id],
      children,
      children.length ? null : state.metaById[id]
    );

  }

  searchBox.addEventListener('input', e => {
    applySearch(e.target.value || '');
  });

  searchResults.addEventListener('click', e => {
    const button = e.target.closest('button[data-roadmap-id]');
    if (!button) return;
    focusSearchResult(button.dataset.roadmapId);
  });

  const initialYear = requestedInitialYear();
  populateYearButtons(initialYear);
  renderYear(initialYear);
})();
