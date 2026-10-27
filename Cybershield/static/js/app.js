/**
 * CyberShield: Login Event Monitor — Frontend Application Engine
 * Pure Vanilla JavaScript: API integration, real-time polling, Chart.js, attack lab
 */

const app = {
  currentView: 'dashboard',
  pollingIntervalMs: 1000,
  pollTimer: null,
  isPolling: true,
  charts: {
    timeline: null,
    doughnut: null,
    bar: null
  },
  cachedRules: [],
  currentReviewAlert: null,
  seenEventIds: new Set(),

  // -------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------
  init() {
    this.setupEventListeners();
    this.setupCharts();
    this.navigateTo('dashboard');
    this.fetchDashboard();
    this.startPolling();
    this.loadSettings();
  },

  // -------------------------------------------------------------
  // Navigation & View Routing
  // -------------------------------------------------------------
  navigateTo(viewId) {
    this.currentView = viewId;

    // Toggle nav items
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === viewId);
    });

    // Toggle view sections
    document.querySelectorAll('.page-view').forEach(view => {
      view.classList.toggle('active', view.id === `view-${viewId}`);
    });

    // Update Navbar Title
    const titleMap = {
      'dashboard': { icon: 'fa-chart-line', title: 'Operations Dashboard' },
      'live-monitor': { icon: 'fa-satellite-dish', title: 'Live Event Monitor' },
      'test-lab': { icon: 'fa-flask-vial', title: 'Attack & Verification Lab' },
      'detection-rules': { icon: 'fa-shield-halved', title: 'Detection Rules Engine' },
      'flagged-accounts': { icon: 'fa-user-ninja', title: 'Flagged Accounts & Profiles' },
      'alert-history': { icon: 'fa-triangle-exclamation', title: 'Security Alert History' },
      'reports': { icon: 'fa-file-invoice', title: 'Security Audit & Compliance Reports' },
      'settings': { icon: 'fa-sliders', title: 'System & Ingestion Settings' }
    };

    const info = titleMap[viewId] || { icon: 'fa-shield-halved', title: 'CyberShield' };
    const titleEl = document.getElementById('page-title');
    if (titleEl) {
      titleEl.innerHTML = `<i class="fa-solid ${info.icon}" style="color: var(--accent-cyan);"></i><span>${info.title}</span>`;
    }

    // Refresh view data immediately upon navigation
    if (viewId === 'dashboard') this.fetchDashboard();
    else if (viewId === 'live-monitor') this.fetchEventsFeed();
    else if (viewId === 'detection-rules') this.fetchRules();
    else if (viewId === 'flagged-accounts') this.fetchAccounts();
    else if (viewId === 'alert-history') this.fetchAlerts();
    else if (viewId === 'reports') this.fetchReports();

    // Close mobile menu if open
    document.getElementById('sidebar')?.classList.remove('mobile-open');
  },

  // -------------------------------------------------------------
  // Polling Loop
  // -------------------------------------------------------------
  startPolling() {
    this.stopPolling();
    this.pollTimer = setInterval(() => {
      if (!this.isPolling) return;
      this.fetchDashboard(false); // background refresh

      if (this.currentView === 'live-monitor') {
        this.fetchEventsFeed(false);
      } else if (this.currentView === 'flagged-accounts') {
        this.fetchAccounts(false);
      } else if (this.currentView === 'alert-history') {
        this.fetchAlerts(false);
      }
    }, this.pollingIntervalMs);
  },

  stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  },

  // -------------------------------------------------------------
  // Event Listeners Setup
  // -------------------------------------------------------------
  setupEventListeners() {
    // Nav Items
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const view = item.dataset.view;
        if (view) this.navigateTo(view);
      });
    });

    // Mobile Hamburger
    document.getElementById('mobile-menu-btn')?.addEventListener('click', () => {
      document.getElementById('sidebar')?.classList.toggle('mobile-open');
    });

    // Quick Simulator Bar
    document.getElementById('quick-sim-start')?.addEventListener('click', () => this.startSimulator());
    document.getElementById('quick-sim-pause')?.addEventListener('click', () => this.pauseSimulator());
    document.getElementById('quick-sim-stop')?.addEventListener('click', () => this.stopSimulator());

    // Live Monitor Simulator Deck
    document.getElementById('deck-sim-start')?.addEventListener('click', () => this.startSimulatorFromDeck());
    document.getElementById('deck-sim-pause')?.addEventListener('click', () => this.pauseSimulator());
    document.getElementById('deck-sim-stop')?.addEventListener('click', () => this.stopSimulator());

    // Manual Event Ingestion
    document.getElementById('btn-submit-manual-event')?.addEventListener('click', () => this.submitManualEvent());

    // Filter controls
    document.getElementById('events-search-filter')?.addEventListener('input', () => this.fetchEventsFeed());
    document.getElementById('events-status-filter')?.addEventListener('change', () => this.fetchEventsFeed());
    document.getElementById('refresh-events-btn')?.addEventListener('click', () => this.fetchEventsFeed());

    document.getElementById('accounts-search')?.addEventListener('input', () => this.fetchAccounts());
    document.getElementById('accounts-risk-filter')?.addEventListener('change', () => this.fetchAccounts());

    document.getElementById('alerts-search')?.addEventListener('input', () => this.fetchAlerts());
    document.getElementById('alerts-status-filter')?.addEventListener('change', () => this.fetchAlerts());
    document.getElementById('alerts-severity-filter')?.addEventListener('change', () => this.fetchAlerts());

    // Settings
    document.getElementById('btn-save-settings')?.addEventListener('click', () => this.saveSettings());

    // Reset Modals
    document.getElementById('global-reset-btn')?.addEventListener('click', () => this.openModal('reset-confirm-modal'));
    document.getElementById('confirm-reset-execute-btn')?.addEventListener('click', () => this.executeDemoReset());

    // Alert Review Modal Save
    document.getElementById('modal-alert-save-btn')?.addEventListener('click', () => this.saveAlertReview());
  },

  // -------------------------------------------------------------
  // Chart.js Visualizations
  // -------------------------------------------------------------
  setupCharts() {
    // 1. Timeline Line Chart
    const ctxTimeline = document.getElementById('timelineChart')?.getContext('2d');
    if (ctxTimeline) {
      this.charts.timeline = new Chart(ctxTimeline, {
        type: 'line',
        data: {
          labels: ['--:--'],
          datasets: [
            {
              label: 'Successful Logins',
              data: [0],
              borderColor: '#10b981',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              tension: 0.35,
              fill: true,
              borderWidth: 2,
              pointRadius: 3,
              pointBackgroundColor: '#10b981'
            },
            {
              label: 'Failed Logins',
              data: [0],
              borderColor: '#ef4444',
              backgroundColor: 'rgba(239, 68, 68, 0.15)',
              tension: 0.35,
              fill: true,
              borderWidth: 2,
              pointRadius: 4,
              pointBackgroundColor: '#ef4444'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
            },
            tooltip: {
              mode: 'index',
              intersect: false
            }
          },
          scales: {
            x: {
              grid: { color: '#1a2744' },
              ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: '#1a2744' },
              ticks: { color: '#64748b', precision: 0 }
            }
          }
        }
      });
    }

    // 2. Status Doughnut Chart
    const ctxDoughnut = document.getElementById('statusDoughnutChart')?.getContext('2d');
    if (ctxDoughnut) {
      this.charts.doughnut = new Chart(ctxDoughnut, {
        type: 'doughnut',
        data: {
          labels: ['Authorized (Success)', 'Failed Attempts'],
          datasets: [{
            data: [1, 0],
            backgroundColor: ['#10b981', '#ef4444'],
            borderColor: '#0f182c',
            borderWidth: 3,
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
            }
          }
        }
      });
    }

    // 3. Account Failures Horizontal Bar Chart
    const ctxBar = document.getElementById('accountFailuresBarChart')?.getContext('2d');
    if (ctxBar) {
      this.charts.bar = new Chart(ctxBar, {
        type: 'bar',
        data: {
          labels: ['None'],
          datasets: [{
            label: 'Failed Login Attempts',
            data: [0],
            backgroundColor: 'rgba(239, 68, 68, 0.75)',
            borderColor: '#ef4444',
            borderWidth: 1,
            borderRadius: 4
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: '#1a2744' },
              ticks: { color: '#64748b', precision: 0 }
            },
            y: {
              grid: { display: false },
              ticks: { color: '#38bdf8', font: { family: 'JetBrains Mono', size: 11 } }
            }
          }
        }
      });
    }
  },

  // -------------------------------------------------------------
  // Data Fetching: Dashboard
  // -------------------------------------------------------------
  async fetchDashboard(showLoading = true) {
    try {
      const res = await fetch('/api/dashboard');
      const json = await res.json();
      if (!json.success) return;

      const d = json.data;

      // Update Metric Numbers
      this.setElText('dash-total-events', d.total_events.toLocaleString());
      this.setElText('dash-success-logins', d.total_success.toLocaleString());
      this.setElText('dash-failed-logins', d.total_failure.toLocaleString());
      this.setElText('dash-flagged-accounts', d.flagged_accounts.toLocaleString());
      this.setElText('dash-total-alerts', d.total_alerts.toLocaleString());
      this.setElText('dash-rejected-events', d.rejected_count.toLocaleString());

      // Percentages
      const total = d.total_events || 0;
      const successRate = total > 0 ? ((d.total_success / total) * 100).toFixed(1) : 0;
      const failureRate = total > 0 ? ((d.total_failure / total) * 100).toFixed(1) : 0;
      this.setElText('dash-success-rate', `${successRate}% Authorized`);
      this.setElText('dash-failure-rate', `${failureRate}% Failure rate`);
      this.setElText('dash-crit-alerts', `${d.critical_alerts} Critical Alerts`);

      // Update Sidebar Badges
      this.setElText('sidebar-flagged-badge', d.flagged_accounts);
      this.setElText('sidebar-alert-badge', d.total_alerts);
      this.setElText('sidebar-pipeline-meta', `Queue: ${d.queue_depth} | ${d.throughput_per_sec} evt/s`);

      // Update Simulator Indicators
      this.updateSimulatorStatusUI(d.simulator);

      // Update Charts
      this.updateCharts(d);

      // Update Recent Alerts on Dashboard
      this.renderRecentAlerts(d.recent_alerts);

      // Update Live Feed Ticker
      this.renderRecentEventsTicker(d.recent_events);

    } catch (err) {
      console.error('fetchDashboard error:', err);
    }
  },

  updateCharts(data) {
    // 1. Timeline Chart
    if (this.charts.timeline) {
      const timeline = data.timeline || [];
      if (timeline.length > 0) {
        this.charts.timeline.data.labels = timeline.map(t => t.time_bucket);
        this.charts.timeline.data.datasets[0].data = timeline.map(t => t.successes);
        this.charts.timeline.data.datasets[1].data = timeline.map(t => t.failures);
      } else {
        this.charts.timeline.data.labels = ['--:--'];
        this.charts.timeline.data.datasets[0].data = [0];
        this.charts.timeline.data.datasets[1].data = [0];
      }
      this.charts.timeline.update('none');
    }

    // 2. Status Doughnut Chart
    if (this.charts.doughnut) {
      const s = data.total_success || 0;
      const f = data.total_failure || 0;
      if (s === 0 && f === 0) {
        this.charts.doughnut.data.datasets[0].data = [1, 0];
      } else {
        this.charts.doughnut.data.datasets[0].data = [s, f];
      }
      this.charts.doughnut.update('none');
    }

    // 3. Account Failures Bar Chart
    if (this.charts.bar) {
      const topFailing = data.top_failing_accounts || [];
      if (topFailing.length > 0) {
        this.charts.bar.data.labels = topFailing.map(a => a.account_id);
        this.charts.bar.data.datasets[0].data = topFailing.map(a => a.failed_logins);
      } else {
        this.charts.bar.data.labels = ['No Failed Logins'];
        this.charts.bar.data.datasets[0].data = [0];
      }
      this.charts.bar.update('none');
    }
  },

  renderRecentAlerts(alerts) {
    const container = document.getElementById('dash-alerts-list');
    if (!container) return;

    if (!alerts || alerts.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <i class="fa-solid fa-shield-heart empty-icon" style="color: var(--accent-emerald);"></i>
          <div class="empty-title">All Systems Secure</div>
          <div class="empty-subtitle">No alerts generated yet. Trigger attacks via Attack Lab to test.</div>
        </div>
      `;
      return;
    }

    container.innerHTML = alerts.map(a => `
      <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 12px; margin-bottom: 10px; display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;">
        <div>
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
            <span class="badge ${this.getSeverityBadgeClass(a.severity)}">${a.severity}</span>
            <span style="font-weight: 600; color: var(--text-primary); font-size: 0.85rem;">${this.escapeHtml(a.rule_name)}</span>
            <span class="mono-cell" style="font-size: 0.75rem;">${a.account_id ? `@${a.account_id}` : ''}</span>
          </div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.35;">${this.escapeHtml(a.reason)}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 4px;">
            <i class="fa-regular fa-clock"></i> ${this.formatTimestamp(a.timestamp)} | Status: <span class="badge ${this.getStatusBadgeClass(a.status)}">${a.status}</span>
          </div>
        </div>
        <button class="btn btn-sm btn-outline" onclick="app.openReviewModal('${a.alert_id}')" style="flex-shrink: 0;">
          <i class="fa-solid fa-pen-to-square"></i> Review
        </button>
      </div>
    `).join('');
  },

  renderRecentEventsTicker(events) {
    const tbody = document.getElementById('dash-live-events-tbody');
    if (!tbody) return;

    if (!events || events.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Waiting for login events...</td></tr>`;
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td class="mono-cell">${this.formatTimestamp(e.timestamp)}</td>
        <td class="mono-cell" style="font-weight: 600;">${this.escapeHtml(e.account_id)}</td>
        <td><span class="source-tag">${this.escapeHtml(e.source)}</span></td>
        <td><span class="badge ${e.status === 'SUCCESS' ? 'badge-success' : 'badge-failure'}">${e.status}</span></td>
      </tr>
    `).join('');
  },

  // -------------------------------------------------------------
  // Simulator Controls
  // -------------------------------------------------------------
  async startSimulator() {
    try {
      const res = await fetch('/api/simulator/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: null, speed_ms: 500, mode: 'mixed' })
      });
      const data = await res.json();
      if (data.success) {
        this.showToast('success', 'Simulator started: Streaming mixed login traffic');
        this.fetchDashboard();
      }
    } catch (err) {
      this.showToast('error', `Failed to start simulator: ${err}`);
    }
  },

  async startSimulatorFromDeck() {
    const mode = document.getElementById('sim-mode-select')?.value || 'mixed';
    const countVal = document.getElementById('sim-count-select')?.value;
    const count = countVal ? parseInt(countVal) : null;
    const speed_ms = parseInt(document.getElementById('sim-speed-select')?.value || '500');
    const target_account = document.getElementById('sim-target-select')?.value || null;

    try {
      const res = await fetch('/api/simulator/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count, speed_ms, mode, target_account })
      });
      const data = await res.json();
      if (data.success) {
        this.showToast('success', `Simulator started: ${mode.toUpperCase()} mode (${speed_ms}ms)`);
        this.fetchDashboard();
      }
    } catch (err) {
      this.showToast('error', `Simulator error: ${err}`);
    }
  },

  async pauseSimulator() {
    try {
      const res = await fetch('/api/simulator/pause', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        this.showToast('warning', 'Simulator paused');
        this.fetchDashboard();
      }
    } catch (err) {
      this.showToast('error', `Pause failed: ${err}`);
    }
  },

  async stopSimulator() {
    try {
      const res = await fetch('/api/simulator/stop', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        this.showToast('info', 'Simulator stopped');
        this.fetchDashboard();
      }
    } catch (err) {
      this.showToast('error', `Stop failed: ${err}`);
    }
  },

  updateSimulatorStatusUI(sim) {
    if (!sim) return;
    const state = sim.state || 'STOPPED';

    // Top quick bar
    const quickDot = document.getElementById('quick-sim-dot');
    const quickText = document.getElementById('quick-sim-state');
    if (quickDot && quickText) {
      quickText.textContent = state;
      if (state === 'RUNNING') {
        quickDot.style.backgroundColor = 'var(--accent-emerald)';
        quickDot.style.boxShadow = '0 0 8px var(--accent-emerald)';
      } else if (state === 'PAUSED') {
        quickDot.style.backgroundColor = 'var(--accent-amber)';
        quickDot.style.boxShadow = '0 0 8px var(--accent-amber)';
      } else {
        quickDot.style.backgroundColor = 'var(--text-muted)';
        quickDot.style.boxShadow = 'none';
      }
    }

    // Monitor Deck badge
    const deckBadge = document.getElementById('monitor-sim-status-badge');
    if (deckBadge) {
      deckBadge.textContent = `${state} (${sim.generated_count || 0}${sim.target_count ? ` / ${sim.target_count}` : ''} events)`;
      deckBadge.className = `badge ${state === 'RUNNING' ? 'badge-success' : state === 'PAUSED' ? 'badge-warning' : 'badge-info'}`;
    }
  },

  // -------------------------------------------------------------
  // Live Event Feed Table
  // -------------------------------------------------------------
  async fetchEventsFeed(showLoading = true) {
    try {
      const search = document.getElementById('events-search-filter')?.value.trim() || '';
      const status = document.getElementById('events-status-filter')?.value || '';

      let url = '/api/events?limit=100';
      if (status) url += `&status=${encodeURIComponent(status)}`;

      const res = await fetch(url);
      const json = await res.json();
      if (!json.success) return;

      let events = json.data || [];
      if (search) {
        const s = search.toLowerCase();
        events = events.filter(e => 
          (e.account_id && e.account_id.toLowerCase().includes(s)) ||
          (e.source && e.source.toLowerCase().includes(s)) ||
          (e.event_id && e.event_id.toLowerCase().includes(s))
        );
      }

      const tbody = document.getElementById('events-feed-tbody');
      if (!tbody) return;

      if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No matching events found.</td></tr>`;
        return;
      }

      tbody.innerHTML = events.map(e => {
        const isNew = !this.seenEventIds.has(e.event_id);
        if (isNew) this.seenEventIds.add(e.event_id);
        const flashClass = isNew ? 'new-event-flash' : '';

        return `
          <tr class="${flashClass}">
            <td class="mono-cell">${this.escapeHtml(e.event_id)}</td>
            <td class="mono-cell" style="font-weight: 600; color: var(--text-primary);">${this.escapeHtml(e.account_id)}</td>
            <td class="mono-cell">${this.formatTimestamp(e.timestamp)}</td>
            <td><span class="source-tag">${this.escapeHtml(e.source)}</span></td>
            <td><span class="badge ${e.status === 'SUCCESS' ? 'badge-success' : 'badge-failure'}">${e.status}</span></td>
            <td class="mono-cell" style="color: var(--text-muted); font-size: 0.75rem;">${this.formatTimestamp(e.created_at)}</td>
          </tr>
        `;
      }).join('');

    } catch (err) {
      console.error('fetchEventsFeed error:', err);
    }
  },

  toggleManualInjector() {
    const body = document.getElementById('manual-injector-body');
    const arrow = document.getElementById('manual-injector-arrow');
    if (!body) return;
    const isHidden = body.style.display === 'none';
    body.style.display = isHidden ? 'block' : 'none';
    if (arrow) arrow.className = isHidden ? 'fa-solid fa-chevron-up' : 'fa-solid fa-chevron-down';
  },

  async submitManualEvent() {
    const account_id = document.getElementById('manual-account')?.value.trim();
    const status = document.getElementById('manual-status')?.value;
    const source = document.getElementById('manual-source')?.value;
    const event_id = document.getElementById('manual-id')?.value.trim();

    if (!account_id) {
      this.showToast('error', 'Account ID is required');
      return;
    }

    const payload = {
      account_id,
      status,
      source,
      timestamp: new Date().toISOString()
    };
    if (event_id) payload.event_id = event_id;

    try {
      const res = await fetch('/api/events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        this.showToast('success', `Event ingested: ${data.event_id} (${status})`);
        this.fetchEventsFeed();
        this.fetchDashboard();
      } else {
        this.showToast('error', `Rejected: ${data.reason}`);
      }
    } catch (err) {
      this.showToast('error', `Submission error: ${err}`);
    }
  },

  // -------------------------------------------------------------
  // Attack & Test Lab (Hackathon Scenarios)
  // -------------------------------------------------------------
  async runDemoScenario(scenario) {
    this.logToTerminal(`>>> [EXECUTE SCENARIO] Triggering '${scenario}' test...`, 'info');

    try {
      const res = await fetch(`/api/demo/trigger/${scenario}`, { method: 'POST' });
      const data = await res.json();

      this.logToTerminal(`<<< [RESPONSE HTTP ${res.status}] \n${JSON.stringify(data, null, 2)}`, res.ok ? 'success' : 'error');

      if (res.ok) {
        this.showToast('success', `Scenario '${scenario}' executed successfully!`);
        this.fetchDashboard();
        if (this.currentView === 'live-monitor') this.fetchEventsFeed();
        if (this.currentView === 'flagged-accounts') this.fetchAccounts();
        if (this.currentView === 'alert-history') this.fetchAlerts();
      } else {
        this.showToast('error', `Scenario error: ${data.error || 'Failed'}`);
      }
    } catch (err) {
      this.logToTerminal(`!!! [NETWORK ERROR] ${err}`, 'error');
      this.showToast('error', `Execution failed: ${err}`);
    }
  },

  logToTerminal(text, type = 'info') {
    const term = document.getElementById('test-terminal-output');
    if (!term) return;

    const timeStr = new Date().toISOString().substring(11, 19);
    term.textContent += `\n\n[${timeStr}] ${text}`;
    term.scrollTop = term.scrollHeight;
  },

  clearTerminal() {
    const term = document.getElementById('test-terminal-output');
    if (term) {
      term.textContent = '[Console Cleared] Ready for scenario triggers.';
    }
  },

  // -------------------------------------------------------------
  // Detection Rules Configuration
  // -------------------------------------------------------------
  async fetchRules() {
    try {
      const res = await fetch('/api/rules');
      const json = await res.json();
      if (!json.success) return;

      this.cachedRules = json.data || [];
      const container = document.getElementById('rules-cards-container');
      if (!container) return;

      container.innerHTML = this.cachedRules.map(r => this.renderRuleCard(r)).join('');
    } catch (err) {
      console.error('fetchRules error:', err);
    }
  },

  renderRuleCard(rule) {
    const isRule1 = rule.name.includes('Repeated Failed');
    const isRule2 = rule.name.includes('Unusual Source');
    const isRule3 = rule.name.includes('Duplicate');
    const isRule4 = rule.name.includes('Malformed');

    const ruleIdSafe = rule.name.replace(/[^a-zA-Z0-9]/g, '_');

    return `
      <div class="rule-card">
        <div>
          <div class="rule-header">
            <div>
              <div class="rule-title">${this.escapeHtml(rule.name)}</div>
              <span class="badge ${this.getSeverityBadgeClass(rule.severity)}" style="margin-top: 4px;">Severity: ${rule.severity}</span>
            </div>
            <label class="toggle-switch">
              <input type="checkbox" id="rule-enabled-${ruleIdSafe}" ${rule.enabled ? 'checked' : ''}>
              <span class="toggle-slider"></span>
            </label>
          </div>

          <div class="rule-desc">${this.escapeHtml(rule.description)}</div>

          <div class="rule-config-form">
            ${isRule1 ? `
              <div class="form-group" style="margin-bottom: 10px;">
                <label class="form-label">Failure Threshold: <b id="val-thresh-${ruleIdSafe}">${rule.config.threshold || 5} attempts</b></label>
                <input type="range" class="form-input" id="cfg-thresh-${ruleIdSafe}" min="2" max="15" value="${rule.config.threshold || 5}" 
                       oninput="document.getElementById('val-thresh-${ruleIdSafe}').textContent = this.value + ' attempts'">
              </div>
              <div class="form-group" style="margin-bottom: 10px;">
                <label class="form-label">Sliding Time Window: <b id="val-win-${ruleIdSafe}">${rule.config.window_seconds || 300}s</b></label>
                <input type="number" class="form-input" id="cfg-win-${ruleIdSafe}" value="${rule.config.window_seconds || 300}" min="10" max="3600">
              </div>
            ` : ''}

            ${isRule2 ? `
              <div class="form-group" style="margin-bottom: 10px;">
                <label class="form-label">Min Distinct Sources: <b id="val-src-${ruleIdSafe}">${rule.config.min_sources || 3} sources</b></label>
                <input type="number" class="form-input" id="cfg-src-${ruleIdSafe}" value="${rule.config.min_sources || 3}" min="2" max="10">
              </div>
              <div class="form-group" style="margin-bottom: 10px;">
                <label class="form-label">Time Window: <b>${rule.config.window_seconds || 300}s</b></label>
                <input type="number" class="form-input" id="cfg-win-${ruleIdSafe}" value="${rule.config.window_seconds || 300}" min="10" max="3600">
              </div>
            ` : ''}

            <div class="form-group" style="margin-bottom: 0;">
              <label class="form-label">Severity Level</label>
              <select class="form-select" id="cfg-sev-${ruleIdSafe}">
                <option value="CRITICAL" ${rule.severity === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                <option value="HIGH" ${rule.severity === 'HIGH' ? 'selected' : ''}>HIGH</option>
                <option value="MEDIUM" ${rule.severity === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                <option value="INFORMATIONAL" ${rule.severity === 'INFORMATIONAL' ? 'selected' : ''}>INFORMATIONAL</option>
              </select>
            </div>
          </div>
        </div>

        <button class="btn btn-primary btn-sm" onclick="app.saveRuleConfig('${rule.name}')">
          <i class="fa-solid fa-floppy-disk"></i> Update Rule Parameters
        </button>
      </div>
    `;
  },

  async saveRuleConfig(ruleName) {
    const ruleIdSafe = ruleName.replace(/[^a-zA-Z0-9]/g, '_');
    const enabled = document.getElementById(`rule-enabled-${ruleIdSafe}`)?.checked;
    const severity = document.getElementById(`cfg-sev-${ruleIdSafe}`)?.value;

    const config = { severity };
    const threshEl = document.getElementById(`cfg-thresh-${ruleIdSafe}`);
    if (threshEl) config.threshold = parseInt(threshEl.value);

    const winEl = document.getElementById(`cfg-win-${ruleIdSafe}`);
    if (winEl) config.window_seconds = parseInt(winEl.value);

    const srcEl = document.getElementById(`cfg-src-${ruleIdSafe}`);
    if (srcEl) config.min_sources = parseInt(srcEl.value);

    try {
      const res = await fetch(`/api/rules/${encodeURIComponent(ruleName)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, config })
      });
      const data = await res.json();
      if (data.success) {
        this.showToast('success', `Rule '${ruleName}' configuration updated`);
        this.fetchRules();
      } else {
        this.showToast('error', `Update failed: ${data.error}`);
      }
    } catch (err) {
      this.showToast('error', `Error updating rule: ${err}`);
    }
  },

  // -------------------------------------------------------------
  // Flagged Accounts
  // -------------------------------------------------------------
  async fetchAccounts(showLoading = true) {
    try {
      const search = document.getElementById('accounts-search')?.value.trim().toLowerCase() || '';
      const riskFilter = document.getElementById('accounts-risk-filter')?.value || 'ALL';

      const res = await fetch('/api/accounts');
      const json = await res.json();
      if (!json.success) return;

      let accounts = json.data || [];

      // Filter by risk and search
      if (riskFilter !== 'ALL') {
        accounts = accounts.filter(a => a.risk_level === riskFilter);
      }
      if (search) {
        accounts = accounts.filter(a => a.account_id.toLowerCase().includes(search));
      }

      const tbody = document.getElementById('accounts-tbody');
      if (!tbody) return;

      if (accounts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="empty-state">No matching account profiles found.</td></tr>`;
        return;
      }

      tbody.innerHTML = accounts.map(a => `
        <tr>
          <td class="mono-cell" style="font-weight: 700; font-size: 0.9rem;">${this.escapeHtml(a.account_id)}</td>
          <td><span class="badge ${this.getRiskBadgeClass(a.risk_level)}">${a.risk_level}</span></td>
          <td class="mono-cell">${a.total_attempts}</td>
          <td class="mono-cell" style="color: var(--accent-emerald);">${a.successful_logins}</td>
          <td class="mono-cell" style="color: var(--accent-rose); font-weight: 700;">${a.failed_logins}</td>
          <td>
            <div style="display: flex; align-items: center; gap: 6px;">
              <span class="mono-cell" style="font-size: 0.8rem;">${a.failure_rate}%</span>
              <div style="flex: 1; height: 5px; width: 60px; background: var(--bg-surface-elevated); border-radius: 4px; overflow: hidden;">
                <div style="width: ${Math.min(a.failure_rate, 100)}%; height: 100%; background: ${a.failure_rate > 50 ? 'var(--accent-rose)' : 'var(--accent-emerald)'};"></div>
              </div>
            </div>
          </td>
          <td>
            ${(a.distinct_sources || []).map(s => `<span class="source-tag">${this.escapeHtml(s)}</span>`).join('') || '<span style="color: var(--text-muted);">-</span>'}
          </td>
          <td>
            <span class="badge ${a.alert_count > 0 ? 'badge-danger' : 'badge-low'}">${a.alert_count} Alerts</span>
          </td>
          <td>
            <button class="btn btn-sm btn-outline" onclick="app.viewAccountAlerts('${a.account_id}')">
              <i class="fa-solid fa-list-check"></i> Filter Alerts
            </button>
          </td>
        </tr>
      `).join('');

    } catch (err) {
      console.error('fetchAccounts error:', err);
    }
  },

  viewAccountAlerts(accountId) {
    this.navigateTo('alert-history');
    const searchEl = document.getElementById('alerts-search');
    if (searchEl) searchEl.value = accountId;
    this.fetchAlerts();
  },

  // -------------------------------------------------------------
  // Alert History & Review Modal
  // -------------------------------------------------------------
  async fetchAlerts(showLoading = true) {
    try {
      const search = document.getElementById('alerts-search')?.value.trim() || '';
      const status = document.getElementById('alerts-status-filter')?.value || 'ALL';
      const severity = document.getElementById('alerts-severity-filter')?.value || 'ALL';

      let url = '/api/alerts?limit=100';
      if (status !== 'ALL') url += `&status=${encodeURIComponent(status)}`;
      if (severity !== 'ALL') url += `&severity=${encodeURIComponent(severity)}`;
      if (search) url += `&account_id=${encodeURIComponent(search)}`;

      const res = await fetch(url);
      const json = await res.json();
      if (!json.success) return;

      const alerts = json.data || [];
      const tbody = document.getElementById('alerts-history-tbody');
      if (!tbody) return;

      if (alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No security alerts matching current filters.</td></tr>`;
        return;
      }

      tbody.innerHTML = alerts.map(a => `
        <tr>
          <td class="mono-cell">${this.escapeHtml(a.alert_id)}</td>
          <td class="mono-cell">${this.formatTimestamp(a.timestamp)}</td>
          <td class="mono-cell" style="font-weight: 600;">${a.account_id ? this.escapeHtml(a.account_id) : '<span style="color: var(--text-muted);">SYSTEM</span>'}</td>
          <td style="font-weight: 500;">${this.escapeHtml(a.rule_name)}</td>
          <td><span class="badge ${this.getSeverityBadgeClass(a.severity)}">${a.severity}</span></td>
          <td><span class="badge ${this.getStatusBadgeClass(a.status)}">${a.status}</span></td>
          <td style="max-width: 320px; font-size: 0.8rem; color: var(--text-secondary);">${this.escapeHtml(a.reason)}</td>
          <td>
            <button class="btn btn-sm btn-outline" onclick="app.openReviewModal('${a.alert_id}')">
              <i class="fa-solid fa-pen-to-square"></i> Review
            </button>
          </td>
        </tr>
      `).join('');

    } catch (err) {
      console.error('fetchAlerts error:', err);
    }
  },

  async openReviewModal(alertId) {
    try {
      const res = await fetch(`/api/alerts?limit=100`);
      const json = await res.json();
      const alert = (json.data || []).find(a => a.alert_id === alertId);
      if (!alert) return;

      this.currentReviewAlert = alert;
      const detailsContainer = document.getElementById('modal-alert-details');
      if (detailsContainer) {
        detailsContainer.innerHTML = `
          <div><b>Alert ID:</b> ${this.escapeHtml(alert.alert_id)}</div>
          <div><b>Rule Name:</b> ${this.escapeHtml(alert.rule_name)}</div>
          <div><b>Severity:</b> <span class="badge ${this.getSeverityBadgeClass(alert.severity)}">${alert.severity}</span></div>
          <div><b>Account ID:</b> ${alert.account_id || 'SYSTEM'}</div>
          <div><b>Detected Reason:</b> ${this.escapeHtml(alert.reason)}</div>
          <div><b>Related Events:</b> ${(alert.related_events || []).join(', ') || 'N/A'}</div>
          <div><b>Timestamp:</b> ${alert.timestamp}</div>
        `;
      }

      const statusSelect = document.getElementById('modal-alert-status');
      if (statusSelect) statusSelect.value = alert.status || 'OPEN';

      const notesText = document.getElementById('modal-alert-notes');
      if (notesText) notesText.value = alert.notes || '';

      this.openModal('alert-review-modal');
    } catch (err) {
      this.showToast('error', `Failed to open alert: ${err}`);
    }
  },

  async saveAlertReview() {
    if (!this.currentReviewAlert) return;

    const alertId = this.currentReviewAlert.alert_id;
    const status = document.getElementById('modal-alert-status')?.value;
    const notes = document.getElementById('modal-alert-notes')?.value;

    try {
      const res = await fetch(`/api/alerts/${encodeURIComponent(alertId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes })
      });
      const data = await res.json();
      if (data.success) {
        this.showToast('success', `Alert ${alertId} updated to ${status}`);
        this.closeModal('alert-review-modal');
        this.fetchAlerts();
        this.fetchDashboard();
      } else {
        this.showToast('error', `Update failed: ${data.error}`);
      }
    } catch (err) {
      this.showToast('error', `Review error: ${err}`);
    }
  },

  // -------------------------------------------------------------
  // Reports View
  // -------------------------------------------------------------
  async fetchReports() {
    try {
      const res = await fetch('/api/reports');
      const json = await res.json();
      if (!json.success) return;

      const d = json.data;
      const s = d.summary;

      // Render Metrics
      const grid = document.getElementById('reports-metrics-grid');
      if (grid) {
        grid.innerHTML = `
          <div class="metric-card">
            <div class="metric-header"><span class="metric-title">Total Logins</span></div>
            <div class="metric-value">${s.total_events}</div>
          </div>
          <div class="metric-card success">
            <div class="metric-header"><span class="metric-title">Success Logins</span></div>
            <div class="metric-value" style="color: var(--accent-emerald);">${s.total_success}</div>
          </div>
          <div class="metric-card danger">
            <div class="metric-header"><span class="metric-title">Failed Logins</span></div>
            <div class="metric-value" style="color: var(--accent-rose);">${s.total_failure}</div>
          </div>
          <div class="metric-card purple">
            <div class="metric-header"><span class="metric-title">Rejected Events</span></div>
            <div class="metric-value" style="color: var(--accent-purple);">${s.rejected_count}</div>
          </div>
          <div class="metric-card warning">
            <div class="metric-header"><span class="metric-title">Flagged Accounts</span></div>
            <div class="metric-value" style="color: var(--accent-amber);">${s.flagged_accounts}</div>
          </div>
          <div class="metric-card danger">
            <div class="metric-header"><span class="metric-title">Total Alerts</span></div>
            <div class="metric-value">${s.total_alerts}</div>
          </div>
        `;
      }

      // Rules Breakdown Table
      const rulesTbody = document.getElementById('reports-rules-tbody');
      if (rulesTbody) {
        const rules = d.alerts_by_rule || [];
        if (rules.length === 0) {
          rulesTbody.innerHTML = `<tr><td colspan="3" class="empty-state">No alerts recorded yet.</td></tr>`;
        } else {
          rulesTbody.innerHTML = rules.map(r => `
            <tr>
              <td><b>${this.escapeHtml(r.rule_name)}</b></td>
              <td><span class="badge ${this.getSeverityBadgeClass(r.severity)}">${r.severity}</span></td>
              <td class="mono-cell" style="font-weight: 700;">${r.count}</td>
            </tr>
          `).join('');
        }
      }

      // Source Distribution Table
      const sourcesTbody = document.getElementById('reports-sources-tbody');
      if (sourcesTbody) {
        const sources = d.source_breakdown || [];
        if (sources.length === 0) {
          sourcesTbody.innerHTML = `<tr><td colspan="3" class="empty-state">No source traffic yet.</td></tr>`;
        } else {
          sourcesTbody.innerHTML = sources.map(src => `
            <tr>
              <td><span class="source-tag">${this.escapeHtml(src.source)}</span></td>
              <td class="mono-cell">${src.count}</td>
              <td class="mono-cell" style="color: var(--accent-rose);">${src.failures}</td>
            </tr>
          `).join('');
        }
      }

    } catch (err) {
      console.error('fetchReports error:', err);
    }
  },

  // -------------------------------------------------------------
  // Settings & Reset
  // -------------------------------------------------------------
  async loadSettings() {
    try {
      const res = await fetch('/api/settings');
      const json = await res.json();
      if (!json.success) return;

      const d = json.data;
      const polEl = document.getElementById('setting-unknown-policy');
      if (polEl) polEl.value = d.unknown_account_policy || 'AUTO_CREATE';

      const intervalEl = document.getElementById('setting-polling-interval');
      if (intervalEl) intervalEl.value = String(d.polling_interval_ms || 1000);
      this.pollingIntervalMs = d.polling_interval_ms || 1000;
    } catch (err) {
      console.error('loadSettings error:', err);
    }
  },

  async saveSettings() {
    const unknown_account_policy = document.getElementById('setting-unknown-policy')?.value;
    const polling_interval_ms = parseInt(document.getElementById('setting-polling-interval')?.value || '1000');

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ unknown_account_policy, polling_interval_ms })
      });
      const data = await res.json();
      if (data.success) {
        this.pollingIntervalMs = polling_interval_ms;
        this.startPolling();
        this.showToast('success', 'System settings updated successfully');
      }
    } catch (err) {
      this.showToast('error', `Save settings failed: ${err}`);
    }
  },

  async executeDemoReset() {
    try {
      const res = await fetch('/api/demo/reset', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        this.seenEventIds.clear();
        this.closeModal('reset-confirm-modal');
        this.clearTerminal();
        this.showToast('info', 'All demo data wiped. System reset to baseline.');
        this.fetchDashboard();
        if (this.currentView === 'live-monitor') this.fetchEventsFeed();
        if (this.currentView === 'flagged-accounts') this.fetchAccounts();
        if (this.currentView === 'alert-history') this.fetchAlerts();
      }
    } catch (err) {
      this.showToast('error', `Reset failed: ${err}`);
    }
  },

  // -------------------------------------------------------------
  // Modals & Toasts
  // -------------------------------------------------------------
  openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.add('active');
  },

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('active');
  },

  showToast(type, message) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const iconMap = {
      'success': 'fa-circle-check',
      'error': 'fa-circle-xmark',
      'warning': 'fa-triangle-exclamation',
      'info': 'fa-circle-info'
    };
    const icon = iconMap[type] || 'fa-bell';

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px;">
        <i class="fa-solid ${icon}"></i>
        <span style="font-size: 0.85rem;">${this.escapeHtml(message)}</span>
      </div>
      <button style="background: none; border: none; color: var(--text-muted); cursor: pointer;" onclick="this.parentElement.remove()">&times;</button>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  },

  // -------------------------------------------------------------
  // Utilities
  // -------------------------------------------------------------
  setElText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  },

  formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
      const dt = new Date(ts);
      return dt.toISOString().replace('T', ' ').substring(11, 19);
    } catch {
      return ts;
    }
  },

  getSeverityBadgeClass(sev) {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  },

  getStatusBadgeClass(status) {
    switch (status) {
      case 'RESOLVED': return 'badge-resolved';
      case 'INVESTIGATING': return 'badge-investigating';
      case 'FALSE_POSITIVE': return 'badge-info';
      default: return 'badge-open';
    }
  },

  getRiskBadgeClass(risk) {
    switch (risk) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  },

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
};

// Auto-boot on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  app.init();
});
