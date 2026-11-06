// ============================================================
//  NocSentinel Admin Dashboard — app.js
// ============================================================

// ── Global State ─────────────────────────────────────────────
const state = {
    token: localStorage.getItem('jwt_token') || null,
    currentView: 'dashboard',
    devices: [],
    blacklist: [],
    whitelist: [],
    selectedDevice: null,
    processPollInterval: null,
    dashboardInterval: null,
    _confirmResolve: null,
    _confirmReject: null,
    deviceFilter: 'all',   // 'all' | 'online' | 'offline'
    // Cooldown tracking
    cooldownPollInterval: null,  // polls API every 3s
    cooldownTickInterval: null,  // ticks every 1s to update display
    cooldownExpiresAt: null,  // Date object when quarantine ends
    cooldownTotalSecs: 0,     // total duration (for progress bar)
};

const API_BASE = '/api';

// ── DOM Cache ─────────────────────────────────────────────────
const els = {
    loginModal: document.getElementById('login-modal'),
    appLayout: document.getElementById('app-layout'),
    loginForm: document.getElementById('login-form'),
    logoutBtn: document.getElementById('logout-btn'),
    navItems: document.querySelectorAll('.nav-item'),
    viewSections: document.querySelectorAll('.view-section'),
    pageTitle: document.getElementById('current-page-title'),
    lastUpdate: document.getElementById('last-update-label'),
    toastContainer: document.getElementById('toast-container'),
    clock: document.getElementById('clock'),
    deviceSearch: document.getElementById('device-search'),
    refreshBtn: document.getElementById('refresh-btn'),
};

// ── Initialisation ────────────────────────────────────────────
function init() {
    updateClock();
    setInterval(updateClock, 1000);

    if (state.token) { showApp(); }
    else { els.loginModal.classList.add('active'); }

    setupEventListeners();
}

function updateClock() {
    els.clock.textContent = new Date().toLocaleTimeString();
}

function showApp() {
    els.loginModal.classList.remove('active');
    els.appLayout.classList.remove('hidden');
    switchView('dashboard');
}

// ── Event Listeners ───────────────────────────────────────────
function setupEventListeners() {
    // Login
    els.loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const u = document.getElementById('username').value;
        const p = document.getElementById('password').value;
        const errEl = document.getElementById('login-error');
        errEl.textContent = '';
        try {
            const res = await fetch(`${API_BASE}/v1/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: u, password: p }),
            });
            if (res.ok) {
                const data = await res.json();
                state.token = data.access_token;
                localStorage.setItem('jwt_token', state.token);
                showApp();
            } else {
                errEl.textContent = 'Invalid credentials. Please try again.';
            }
        } catch {
            errEl.textContent = 'Connection error. Is the server running?';
        }
    });

    // Logout
    els.logoutBtn.addEventListener('click', () => {
        state.token = null;
        localStorage.removeItem('jwt_token');
        clearInterval(state.dashboardInterval);
        els.appLayout.classList.add('hidden');
        els.loginModal.classList.add('active');
    });

    // Nav
    els.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(item.getAttribute('data-target'));
            ui.closeSidebar();
        });
    });

    // Outer tabs (Blacklist / Whitelist)
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        });
    });

    // Scope tabs (inside BL / WL)
    document.querySelectorAll('.scope-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const list = btn.dataset.list;
            const scope = btn.dataset.scope;
            // deactivate siblings
            btn.closest('.scope-tabs').querySelectorAll('.scope-tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            // switch panels
            const prefix = list === 'blacklist' ? 'bl' : 'wl';
            document.querySelectorAll(`[id^="${prefix}-scope-"]`).forEach(p => p.classList.remove('active'));
            document.getElementById(`${prefix}-scope-${scope}`).classList.add('active');
        });
    });

    // Add-list form submit
    document.getElementById('add-list-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await app.submitListForm();
    });

    // Priority badge toggles (add-list modal)
    document.querySelectorAll('.p-badge').forEach(b => {
        b.addEventListener('click', () => b.classList.toggle('selected'));
    });

    // Device search — live filter
    els.deviceSearch.addEventListener('input', () => app.renderDevices());

    // Device status filter pills
    document.querySelectorAll('.filter-pill').forEach(pill => {
        pill.addEventListener('click', () => {
            state.deviceFilter = pill.dataset.filter;
            document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            app.renderDevices();
        });
    });

    // Manual refresh button
    els.refreshBtn.addEventListener('click', () => app.refreshCurrentView());

    // Server config save
    document.getElementById('server-config-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('config-save-btn');
        ui.setLoading(btn, true, 'Saving…');
        const payload = {
            global_max_bandwidth_kbps: parseFloat(document.getElementById('cfg_global_bw').value),
            optimization_interval_sec: parseInt(document.getElementById('cfg_opt_int').value),
            active_optimizer: document.getElementById('cfg_optimizer').value,
            max_offline_queue_size: parseInt(document.getElementById('cfg_queue_size').value),
            security_actions_enabled: document.getElementById('cfg_security_actions_enabled').value === 'true',
            global_ai_enabled: document.getElementById('cfg_ai_enabled').value === 'true',
            ai_api_key: document.getElementById('cfg_ai_key').value || null,
        };
        try {
            await apiCall('/server-config', 'PUT', payload);
            ui.showToast('Server configuration saved!', 'success');
        } catch { /* toast shown by apiCall */ }
        finally { ui.setLoading(btn, false, '<i class="fa-solid fa-floppy-disk"></i> Save Configuration'); }
    });
}

// ── View Routing ──────────────────────────────────────────────
function switchView(target) {
    els.navItems.forEach(i => i.classList.remove('active'));
    document.querySelector(`.nav-item[data-target="${target}"]`)?.classList.add('active');

    els.viewSections.forEach(s => s.classList.add('hidden'));
    document.getElementById(`view-${target}`)?.classList.remove('hidden');

    const titles = {
        dashboard: 'Dashboard Overview',
        devices: 'Device Management',
        policies: 'Policy Center',
        lists: 'Hash Lists',
        logs: 'System Logs',
        config: 'Server Configuration',
    };
    els.pageTitle.textContent = titles[target] || target;
    state.currentView = target;

    clearInterval(state.dashboardInterval);
    if (target === 'dashboard') {
        app.loadDevices();
        state.dashboardInterval = setInterval(() => {
            if (state.currentView === 'dashboard') app.loadDevices();
        }, 30000);
    }
    if (target === 'devices') app.loadDevices();
    if (target === 'policies') app.loadPolicies();
    if (target === 'lists') app.loadLists();
    if (target === 'logs') app.fetchLogs(true);
    if (target === 'config') app.loadConfig();
}

// ── API Helper ────────────────────────────────────────────────
async function apiCall(endpoint, method = 'GET', body = null) {
    const headers = { Authorization: `Bearer ${state.token}` };
    if (body) headers['Content-Type'] = 'application/json';

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const res = await fetch(`${API_BASE}${endpoint}`, options);
    if (res.status === 401) { els.logoutBtn.click(); throw new Error('Unauthorized'); }

    if (!res.ok) {
        let msg = `Error ${res.status}`;
        try { const err = await res.json(); msg = err.detail || msg; } catch { }
        ui.showToast(msg, 'error');
        throw new Error(msg);
    }
    return res.json();
}

// ── Application Logic ─────────────────────────────────────────
const app = {

    async loadDevices() {
        try {
            const data = await apiCall('/devices');
            state.devices = data;
            this.renderDevices();
            this.updateDashboardMetrics();
            this.updateLastUpdate();
        } catch { }
    },

    updateLastUpdate() {
        const now = new Date().toLocaleTimeString();
        if (els.lastUpdate) els.lastUpdate.textContent = `Last updated: ${now}`;
    },

    updateDashboardMetrics() {
        const total = state.devices.length;
        const atRisk = state.devices.filter(d => d.risk_durumu).length;
        const safe = total - atRisk;

        document.getElementById('metric-total-devices').textContent = total;
        document.getElementById('metric-risk-devices').textContent = atRisk;
        document.getElementById('metric-safe-devices').textContent = safe;

        const ctx = document.getElementById('riskChart');
        if (window.riskChartObj) window.riskChartObj.destroy();
        window.riskChartObj = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Protected', 'At Risk'],
                datasets: [{
                    data: [safe, atRisk],
                    backgroundColor: ['#10b981', '#ef4444'],
                    borderWidth: 0,
                }],
            },
            options: {
                cutout: '72%',
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#64748b', font: { size: 12 } } },
                },
            },
        });

        this.loadEvents();
    },

    async loadEvents() {
        try {
            const evts = await apiCall('/events');
            const cont = document.getElementById('recent-events-list');
            cont.innerHTML = '';
            if (!evts.length) { cont.innerHTML = '<div class="loader">No recent events.</div>'; return; }
            evts.slice(0, 15).forEach(e => {
                const cat = (e.kategori || 'INFO').toUpperCase();
                const item = document.createElement('div');
                item.className = `event-item ${cat}`;
                item.innerHTML = `
                    <span class="event-cat">${cat}</span>
                    <span class="event-msg">${e.mesaj}</span>
                    <span class="event-time">${new Date(e.zaman_damgasi).toLocaleTimeString()}</span>`;
                cont.appendChild(item);
            });
        } catch {
            const cont = document.getElementById('recent-events-list');
            if (cont) cont.innerHTML = '<div class="loader">Could not load events.</div>';
        }
    },

    renderDevices() {
        const tbody = document.getElementById('devices-tbody');
        const query = (els.deviceSearch.value || '').toLowerCase();
        // Metin araması filtresi
        const textFiltered = query
            ? state.devices.filter(d =>
                d.id.toLowerCase().includes(query) ||
                (d.ip_adresi || '').toLowerCase().includes(query))
            : [...state.devices];

        // Online/Offline durum filtresi
        const filtered = state.deviceFilter === 'all'
            ? textFiltered
            : textFiltered.filter(d => {
                const online = this._isOnline(d.son_gorulme);
                return state.deviceFilter === 'online' ? online : !online;
            });

        // Cihazları alfabetik sıraya göre listele (30+ cihazda karışıklığı önler)
        filtered.sort((a, b) => a.id.localeCompare(b.id, 'tr'));

        if (!filtered.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted" style="padding:30px">
                ${query || state.deviceFilter !== 'all' ? 'No devices match your filter.' : 'No registered devices.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = '';
        filtered.forEach(d => {
            const statusBadge = d.risk_durumu
                ? '<span class="badge badge-danger">At Risk</span>'
                : '<span class="badge badge-success">Safe</span>';
            const lastSeen = d.son_gorulme ? this._timeAgo(d.son_gorulme) : 'Never';
            const connBadge = this._isOnline(d.son_gorulme)
                ? '<span class="badge badge-success" style="margin-left:4px">Online</span>'
                : '<span class="badge badge-danger"  style="margin-left:4px">Offline</span>';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${d.id}</strong>${connBadge}</td>
                <td><code style="font-size:0.82rem">${d.ip_adresi || '—'}</code></td>
                <td>
                    <select class="priority-select" data-id="${d.id}"
                            style="width:70px;padding:5px 8px"
                            onchange="app._onPriorityChange('${d.id}', this)">
                        ${[...Array(10).keys()].map(i =>
                `<option value="${i + 1}" ${d.pc_priority === i + 1 ? 'selected' : ''}>${i + 1}</option>`
            ).join('')}
                    </select>
                </td>
                <td>${statusBadge}</td>
                <td style="font-size:0.83rem;color:var(--text-muted)">${lastSeen}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="ui.openDeviceModal('${d.id}')">
                        <i class="fa-solid fa-screwdriver-wrench"></i> Manage
                    </button>
                </td>`;
            tbody.appendChild(tr);
        });
    },

    _debounceTimers: {},
    _onPriorityChange(id, select) {
        clearTimeout(this._debounceTimers[id]);
        this._debounceTimers[id] = setTimeout(() => {
            this.updatePriority(id, select.value);
        }, 600);
    },

    /**
     * Son görülme tarihine göre cihazın çevrimiçi olup olmadığını döner.
     * Eşik: 180 saniye (3 dakika — varsayılan 30sn telemetride 5-6 kayıp paketi tolere eder).
     */
    _isOnline(sonGorulme) {
        if (!sonGorulme) return false;
        const diffSec = (Date.now() - new Date(sonGorulme).getTime()) / 1000;
        return diffSec < 180;
    },

    async updatePriority(pcName, priority) {
        try {
            await apiCall(`/devices/${pcName}/priority`, 'PATCH', { pc_priority: parseInt(priority) });
            ui.showToast(`Priority updated for ${pcName}`, 'success');
        } catch { }
    },

    _timeAgo(isoStr) {
        const diff = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000);
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return new Date(isoStr).toLocaleDateString();
    },

    async sendManualAction(action) {
        if (!state.selectedDevice) return;
        const ok = await ui.confirm(
            `Send ${action} to ${state.selectedDevice}?`,
            'Confirm Action'
        );
        if (!ok) return;
        const durationInput = document.getElementById('manual_duration').value;
        const payload = { action };
        if (durationInput) payload.duration = parseInt(durationInput);
        try {
            await apiCall(`/devices/${state.selectedDevice}/action`, 'POST', payload);
            ui.showToast(`${action} sent to ${state.selectedDevice}`, 'success');
            setTimeout(() => this.loadDevices(), 2000);
            // Refresh cooldown banner immediately
            setTimeout(() => ui.fetchAndRenderCooldown(state.selectedDevice), 800);
        } catch { }
    },

    async requestProcessList() {
        if (!state.selectedDevice) return;
        const btn = document.getElementById('fetch-processes-btn');
        ui.setLoading(btn, true, 'Fetching…');

        try {
            await apiCall(`/devices/${state.selectedDevice}/processes`);
            ui.showToast('Process list requested — waiting for MQTT response…', 'success');

            document.getElementById('process-table-body').innerHTML =
                '<tr><td colspan="6" class="text-center"><div class="loader">Waiting for device response…</div></td></tr>';

            const sleep = ms => new Promise(r => setTimeout(r, ms));
            let attempts = 0;
            const maxAttempts = 60; // 15 seconds (30 * 500ms)

            // Polling loop
            while (attempts < maxAttempts) {
                await sleep(500);
                attempts++;

                // If user selected another device while polling, stop polling
                if (!document.getElementById('fetch-processes-btn')) {
                    break;
                }

                try {
                    const res = await apiCall(`/devices/${state.selectedDevice}/processes/result`);
                    if (res.status === 'success' && res.processes) {
                        this.renderProcessList(res.processes);
                        ui.setLoading(btn, false, '<i class="fa-solid fa-bolt"></i> Fetch Processes');
                        return; // Exit on success
                    }
                } catch {
                    // Ignore errors during poll, wait for next attempt
                }
            }

            // If we reach here, it timed out
            document.getElementById('process-table-body').innerHTML =
                '<tr><td colspan="6" class="text-center text-muted">Timeout — device did not respond.</td></tr>';
            ui.setLoading(btn, false, '<i class="fa-solid fa-bolt"></i> Fetch Processes');
            ui.showToast('Timeout: Device did not respond.', 'error');

        } catch {
            ui.setLoading(btn, false, '<i class="fa-solid fa-bolt"></i> Fetch Processes');
        }
    },

    renderProcessList(procs) {
        const tbody = document.getElementById('process-table-body');
        if (!procs.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">No processes found.</td></tr>';
            return;
        }
        // Store for search filter
        state._processList = procs;
        procs.sort((a, b) => b.ram_mb - a.ram_mb);
        this._renderProcessRows(procs);
    },

    _getEntryForHash(hash, listData) {
        if (!hash || !listData) return null;
        return listData.find(d => d.hash_sha256 === hash && (!d.device_scope_id || d.device_scope_id === state.selectedDevice));
    },

    _renderProcessRows(procs) {
        const tbody = document.getElementById('process-table-body');
        tbody.innerHTML = procs.map(p => {
            const hashDisplay = p.hash_sha256
                ? `<span style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)" title="${p.hash_sha256}">
                       ${p.hash_sha256.slice(0, 16)}&hellip;
                   </span>
                   <button class="btn btn-sm" style="padding:2px 6px;font-size:0.75rem;background:rgba(0,0,0,0.05);border:none;cursor:pointer" 
                           onclick="ui.copyHash('${p.hash_sha256}')" title="Copy full hash">
                       <i class="fa-regular fa-copy"></i>
                   </button>`
                : '<span style="color:var(--text-light);font-size:0.8rem">N/A</span>';

            const blBtn = p.hash_sha256
                ? `<button class="btn btn-sm" style="padding:3px 7px;font-size:0.76rem;background:var(--danger-light);color:var(--danger);border:1px solid rgba(239,68,68,0.2);" 
                           onclick="ui.quickAddToList('blacklist','${p.name}','${p.hash_sha256}')" title="Add to Blacklist">
                       <i class="fa-solid fa-ban"></i> BL
                   </button>` : '';
            const wlBtn = p.hash_sha256
                ? `<button class="btn btn-sm" style="padding:3px 7px;font-size:0.76rem;background:var(--success-light);color:var(--success);border:1px solid rgba(16,185,129,0.2);" 
                           onclick="ui.quickAddToList('whitelist','${p.name}','${p.hash_sha256}')" title="Add to Whitelist">
                       <i class="fa-solid fa-circle-check"></i> WL
                   </button>` : '';

            const blEntry = app._getEntryForHash(p.hash_sha256, state.blacklist);
            const wlEntry = app._getEntryForHash(p.hash_sha256, state.whitelist);

            let statusBadge = '';
            if (blEntry) {
                statusBadge = `<span class="badge badge-danger" style="margin-left:8px;font-size:0.65rem" title="${blEntry.aciklama || ''}">BL</span>`;
            } else if (wlEntry) {
                statusBadge = `<span class="badge badge-success" style="margin-left:8px;font-size:0.65rem" title="${wlEntry.aciklama || ''}">WL</span>`;
            }

            const killDisabled = blEntry ? 'disabled title="Process is blacklisted (auto-killed)"' : 'title="Kill process"';

            return `<tr data-proc-name="${p.name.toLowerCase()}" data-proc-pid="${p.pid}">
                <td>${p.pid}</td>
                <td><strong>${p.name}</strong>${statusBadge}${p.exe_path ? `<div style="font-size:0.72rem;color:var(--text-light);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${p.exe_path}">${p.exe_path}</div>` : ''}</td>
                <td>${p.cpu.toFixed(1)}%</td>
                <td>${p.ram_mb} MB</td>
                <td>${hashDisplay}</td>
                <td>
                    <div style="display:flex;gap:4px;flex-wrap:wrap">
                        ${blBtn}${wlBtn}
                        <button class="btn btn-sm btn-danger" style="padding:3px 7px;font-size:0.76rem" onclick="app.killProcess(${p.pid}, '${p.name.replace(/'/g, "\\'")}')"
                                ${killDisabled}>
                            <i class="fa-solid fa-skull-crossbones"></i> Kill
                        </button>
                    </div>
                </td>
            </tr>`;
        }).join('');
    },

    async killProcess(pid, name) {
        const ok = await ui.confirm(`Kill process "${name}" (PID: ${pid})?`, 'Kill Process');
        if (!ok) return;
        try {
            await apiCall(`/devices/${state.selectedDevice}/kill-process?pid=${pid}&process_name=${name}`, 'POST');
            ui.showToast(`Kill command sent for PID ${pid}`, 'success');
            setTimeout(() => this.requestProcessList(), 2000);
        } catch { }
    },

    async loadPolicies() {
        const cont = document.getElementById('policies-container');
        cont.innerHTML = '<div class="loader">Loading policies…</div>';
        try {
            const policies = await apiCall('/policies');
            cont.innerHTML = '';
            policies.forEach(p => {
                cont.innerHTML += `
                    <div class="policy-card">
                        <h4>
                            <span>${p.aciklama}</span>
                            <span class="priority-badge">Level ${p.priority_level}</span>
                        </h4>
                        <div class="policy-form-group">
                            <label>Restrict Time (s)</label>
                            <input type="number" id="pol_res_${p.priority_level}" value="${p.restrict_duration_sec}">
                        </div>
                        <div class="policy-form-group">
                            <label>Isolate Time (s)</label>
                            <input type="number" id="pol_iso_${p.priority_level}" value="${p.isolate_duration_sec}">
                        </div>
                        <div class="policy-form-group">
                            <label>Lockdown Time (s)</label>
                            <input type="number" id="pol_lck_${p.priority_level}" value="${p.lockdown_duration_sec}">
                        </div>
                        <div class="policy-form-group">
                            <label>Threshold (Restrict)</label>
                            <input type="number" step="0.1" id="pol_tr_${p.priority_level}" value="${p.risk_threshold_restrict}">
                        </div>
                        <div class="policy-form-group">
                            <label>Threshold (Isolate)</label>
                            <input type="number" step="0.1" id="pol_ti_${p.priority_level}" value="${p.risk_threshold_isolate}">
                        </div>
                        <div class="policy-form-group">
                            <label>Threshold (Lockdown)</label>
                            <input type="number" step="0.1" id="pol_tl_${p.priority_level}" value="${p.risk_threshold_lockdown}">
                        </div>
                        <div class="policy-form-group" style="flex-direction:row;align-items:center;gap:8px;margin-top:6px">
                            <input type="checkbox" id="pol_ai_${p.priority_level}" ${p.ai_analysis_enabled ? 'checked' : ''} style="width:auto">
                            <label for="pol_ai_${p.priority_level}" style="margin:0;cursor:pointer">AI Analysis Enabled</label>
                        </div>
                        <div class="policy-form-group" style="flex-direction:row;align-items:center;gap:8px;margin-top:2px">
                            <input type="checkbox" id="pol_exempt_${p.priority_level}" ${p.auto_isolate_exempt ? 'checked' : ''} style="width:auto">
                            <label for="pol_exempt_${p.priority_level}" style="margin:0;cursor:pointer">Auto-Isolate Exempt</label>
                        </div>
                        <button class="btn btn-sm btn-outline btn-block mt-2" onclick="app.savePolicy(${p.priority_level})">
                            Save Level ${p.priority_level}
                        </button>
                    </div>`;
            });
        } catch { }
    },

    async savePolicy(level) {
        const payload = {
            restrict_duration_sec: parseInt(document.getElementById(`pol_res_${level}`).value),
            isolate_duration_sec: parseInt(document.getElementById(`pol_iso_${level}`).value),
            lockdown_duration_sec: parseInt(document.getElementById(`pol_lck_${level}`).value),
            risk_threshold_restrict: parseFloat(document.getElementById(`pol_tr_${level}`).value),
            risk_threshold_isolate: parseFloat(document.getElementById(`pol_ti_${level}`).value),
            risk_threshold_lockdown: parseFloat(document.getElementById(`pol_tl_${level}`).value),
            ai_analysis_enabled: document.getElementById(`pol_ai_${level}`).checked,
            auto_isolate_exempt: document.getElementById(`pol_exempt_${level}`).checked,
        };
        try {
            await apiCall(`/policies/${level}`, 'PUT', payload);
            ui.showToast(`Policy Level ${level} saved!`, 'success');
        } catch { }
    },

    // ── Lists ────────────────────────────────────────────────
    async loadLists() {
        try {
            const [bl, wl] = await Promise.all([apiCall('/blacklist'), apiCall('/whitelist')]);
            state.blacklist = bl || [];
            state.whitelist = wl || [];
            this._populateScopeSelects('blacklist', state.blacklist);
            this._populateScopeSelects('whitelist', state.whitelist);
            this._renderBadgeCounts();

            // Retain currently active scopes instead of always resetting to 'global'
            const blScope = document.querySelector('.scope-tab-btn.active[data-list="blacklist"]')?.dataset.scope || 'global';
            const wlScope = document.querySelector('.scope-tab-btn.active[data-list="whitelist"]')?.dataset.scope || 'global';

            ui.renderScopePanel('blacklist', blScope);
            ui.renderScopePanel('whitelist', wlScope);
        } catch { }
    },

    _populateScopeSelects(type, data) {
        const prefix = type === 'blacklist' ? 'bl' : 'wl';

        // Priority levels
        const pSel = document.getElementById(`${prefix}-priority-select`);
        const oldP = pSel.value;
        const priorities = [...new Set(data.filter(d => d.priority_scope).map(d => d.priority_scope))].sort((a, b) => a - b);
        pSel.innerHTML = '<option value="">— Select Level —</option>' +
            priorities.map(p => `<option value="${p}" ${p == oldP ? 'selected' : ''}>Priority ${p}</option>`).join('');

        // Devices
        const dSel = document.getElementById(`${prefix}-device-select`);
        const oldD = dSel.value;
        const devices = [...new Set(data.filter(d => d.device_scope_id).map(d => d.device_scope_id))].sort();
        dSel.innerHTML = '<option value="">— Select Device —</option>' +
            devices.map(d => `<option value="${d}" ${d === oldD ? 'selected' : ''}>${d}</option>`).join('');
    },

    _renderBadgeCounts() {
        const count = (data, filter) => data.filter(filter).length;
        // BL
        document.getElementById('bl-global-count').textContent = count(state.blacklist, d => !d.priority_scope && !d.device_scope_id) || '';
        document.getElementById('bl-priority-count').textContent = count(state.blacklist, d => !!d.priority_scope) || '';
        document.getElementById('bl-device-count').textContent = count(state.blacklist, d => !!d.device_scope_id) || '';
        // WL
        document.getElementById('wl-global-count').textContent = count(state.whitelist, d => !d.priority_scope && !d.device_scope_id) || '';
        document.getElementById('wl-priority-count').textContent = count(state.whitelist, d => !!d.priority_scope) || '';
        document.getElementById('wl-device-count').textContent = count(state.whitelist, d => !!d.device_scope_id) || '';
    },

    async deleteListItem(type, id) {
        const ok = await ui.confirm('Delete this entry?', 'Delete Hash');
        if (!ok) return;
        try {
            await apiCall(`/${type}/${id}`, 'DELETE');
            ui.showToast('Entry deleted', 'success');
            this.loadLists();
        } catch { }
    },

    async submitListForm() {
        const type = document.getElementById('list_type').value;
        const id = document.getElementById('list_id').value;
        const name = document.getElementById('list_name').value;
        const hash = document.getElementById('list_hash').value;
        const desc = document.getElementById('list_desc').value;
        const risk = document.getElementById('list_risk').value;
        const scopeType = document.getElementById('list_scope_type').value;

        // Edit Mode
        if (id) {
            const payload = { aciklama: desc || null };
            if (type === 'blacklist') payload.risk_puani = parseInt(risk);

            try {
                await apiCall(`/${type}/${id}`, 'PUT', payload);
                ui.showToast('Entry updated successfully!', 'success');
                ui.closeModal('add-list-modal');
                document.getElementById('add-list-form').reset();
                document.getElementById('list_id').value = '';
                this.loadLists();
            } catch { }
            return;
        }

        // Add Mode
        const payload = {
            hash_sha256: hash,
            islem_adi: name || null,
            aciklama: desc || null,
        };
        if (type === 'blacklist') payload.risk_puani = parseInt(risk);

        if (scopeType === 'priority') {
            const sel = Array.from(document.querySelectorAll('.p-badge.selected')).map(b => parseInt(b.dataset.val));
            if (!sel.length) { ui.showToast('Select at least one priority level.', 'error'); return; }
            payload.priority_scopes = sel;
        }
        if (scopeType === 'device') {
            const devStr = document.getElementById('list_scope_device').value;
            if (!devStr.trim()) { ui.showToast('Enter at least one device name.', 'error'); return; }
            payload.device_scope_ids = devStr.split(',').map(s => s.trim()).filter(Boolean);
        }

        try {
            await apiCall(`/${type}`, 'POST', payload);
            ui.showToast('Hash added successfully!', 'success');

            // BUG FIX 1: If added to blacklist, check if it's running on the currently managed device and kill it
            if (type === 'blacklist' && state.selectedDevice && state._processList) {
                const isGlobal = scopeType === 'global';
                const isTargetDevice = scopeType === 'device' && payload.device_scope_ids.includes(state.selectedDevice);
                // We ignore priority scope for auto-kill here to avoid complexity, but global and device scopes are handled
                if (isGlobal || isTargetDevice) {
                    const proc = state._processList.find(p => p.hash_sha256 === hash);
                    if (proc) {
                        try {
                            await apiCall(`/devices/${state.selectedDevice}/kill-process?pid=${proc.pid}&process_name=${encodeURIComponent(proc.name)}`, 'POST');
                            ui.showToast(`Process ${proc.name} auto-killed!`, 'success');
                        } catch (e) {
                            console.error('Auto-kill failed', e);
                        }
                    }
                }
            }

            ui.closeModal('add-list-modal');
            document.getElementById('add-list-form').reset();
            document.getElementById('list_id').value = '';
            document.querySelectorAll('.p-badge.selected').forEach(b => b.classList.remove('selected'));
            await this.loadLists();

            // UI Guncellemesi: Liste eklendikten sonra modal aciksa surecleri tekrar render et (butonlari disabled/aktif yapmak icin)
            if (state.currentView === 'devices' && state.selectedDevice && state._processList) {
                this._renderProcessRows(state._processList);
            }
        } catch { }
    },

    openEditListModal(type, id) {
        const list = type === 'blacklist' ? state.blacklist : state.whitelist;
        const entry = list.find(e => e.id === id);
        if (!entry) return;

        document.getElementById('list_type').value = type;
        document.getElementById('list_id').value = entry.id;
        document.getElementById('add-list-title').textContent = type === 'blacklist' ? 'Edit Blacklist Entry' : 'Edit Whitelist Entry';

        const nameField = document.getElementById('list_name');
        const hashField = document.getElementById('list_hash');

        nameField.value = entry.islem_adi || '';
        hashField.value = entry.hash_sha256 || '';

        nameField.disabled = true;
        hashField.disabled = true;
        document.getElementById('group_scope_container').style.display = 'none';
        ui.toggleScopeInputs();

        document.getElementById('list_desc').value = entry.aciklama || '';
        if (type === 'blacklist') {
            document.getElementById('group_risk_score').style.display = 'block';
            document.getElementById('list_risk').value = entry.risk_puani || 50;
        } else {
            document.getElementById('group_risk_score').style.display = 'none';
        }

        document.getElementById('list_submit_btn').innerHTML = '<i class="fa-solid fa-check"></i> Save Changes';
        document.getElementById('add-list-modal').classList.add('active');
    },

    async loadConfig() {
        try {
            const cfg = await apiCall('/server-config');
            document.getElementById('cfg_global_bw').value = cfg.global_max_bandwidth_kbps;
            document.getElementById('cfg_opt_int').value = cfg.optimization_interval_sec;
            document.getElementById('cfg_optimizer').value = cfg.active_optimizer;
            document.getElementById('cfg_queue_size').value = cfg.max_offline_queue_size;
            document.getElementById('cfg_security_actions_enabled').value = (cfg.security_actions_enabled !== false) ? 'true' : 'false';
            document.getElementById('cfg_ai_enabled').value = cfg.global_ai_enabled ? 'true' : 'false';
            document.getElementById('cfg_ai_key').value = cfg.ai_api_key || '';
        } catch { }
    },

    refreshCurrentView() {
        switchView(state.currentView);
    },

    // ── Logs ───────────────────────────────────────────────────────
    logsOffset: 0,
    async fetchLogs(reset = false) {
        if (reset) {
            app.logsOffset = 0;
            document.getElementById('logs-table-body').innerHTML = '';
            document.getElementById('btn-load-more-logs').style.display = 'none';
        }

        const indicator = document.getElementById('logs-loading-indicator');
        const loadMoreBtn = document.getElementById('btn-load-more-logs');
        indicator.style.display = 'block';
        loadMoreBtn.style.display = 'none';

        const startDate = document.getElementById('filter-log-start').value;
        const endDate = document.getElementById('filter-log-end').value;
        const deviceId = document.getElementById('filter-log-device').value.trim();
        const priority = document.getElementById('filter-log-priority').value;

        const params = new URLSearchParams();
        params.append('limit', 50);
        params.append('offset', app.logsOffset);

        if (startDate) {
            // Append seconds/Z so Python isoformat parsing handles it properly or just pass it as is (local time)
            params.append('start_date', new Date(startDate).toISOString());
        }
        if (endDate) {
            params.append('end_date', new Date(endDate).toISOString());
        }
        if (deviceId) params.append('istemci_id', deviceId);
        if (priority) params.append('pc_priority', priority);

        try {
            const data = await apiCall(`/logs?${params.toString()}`);
            if (data && data.logs) {
                const tbody = document.getElementById('logs-table-body');
                if (data.logs.length === 0 && app.logsOffset === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No logs found matching criteria.</td></tr>';
                } else {
                    let html = '';
                    data.logs.forEach(log => {
                        const dateStr = log.zaman_damgasi ? new Date(log.zaman_damgasi).toLocaleString() : '-';
                        let catClass = 'text-muted';
                        if (log.kategori === 'WARNING') catClass = 'text-warning';
                        if (log.kategori === 'CRITICAL' || log.kategori === 'EMERGENCY') catClass = 'text-danger';
                        if (log.kategori === 'INFO') catClass = 'text-success';

                        html += `
                            <tr>
                                <td class="mono" style="font-size:0.85em;">${dateStr}</td>
                                <td><span class="badge ${log.pc_priority >= 8 ? 'badge-danger' : 'badge-secondary'}">${log.istemci_id || '-'}</span></td>
                                <td class="${catClass}"><b>${log.kategori || '-'}</b></td>
                                <td style="max-width:300px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${log.mesaj || ''}">${log.mesaj || '-'}</td>
                                <td>${log.aksiyon ? '<span class="badge badge-warning">' + log.aksiyon + '</span>' : '-'}</td>
                            </tr>
                        `;
                    });
                    tbody.innerHTML += html;
                    app.logsOffset += data.logs.length;

                    if (app.logsOffset < data.total) {
                        loadMoreBtn.style.display = 'inline-block';
                    }
                }
            }
        } catch (err) {
            console.error("Failed to fetch logs", err);
            ui.showToast('Failed to load logs', 'error');
        } finally {
            indicator.style.display = 'none';
        }
    },
};

// ── UI Helpers ────────────────────────────────────────────────
const ui = {

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        els.toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    },

    /**
     * Async confirm dialog — returns Promise<boolean>
     */
    confirm(message, title = 'Confirm') {
        return new Promise((resolve, reject) => {
            state._confirmResolve = resolve;
            state._confirmReject = reject;
            document.getElementById('confirm-title').textContent = title;
            document.getElementById('confirm-message').textContent = message;
            document.getElementById('confirm-modal').classList.add('active');
        });
    },
    resolveConfirm() {
        document.getElementById('confirm-modal').classList.remove('active');
        if (state._confirmResolve) { state._confirmResolve(true); state._confirmResolve = null; }
    },
    rejectConfirm() {
        document.getElementById('confirm-modal').classList.remove('active');
        if (state._confirmResolve) { state._confirmResolve(false); state._confirmResolve = null; }
    },

    openDeviceModal(id) {
        state.selectedDevice = id;
        state._processList = [];
        // Cihazın bağlantı durumunu bul (state.devices listesinden)
        const deviceData = state.devices.find(d => d.id === id);
        const onlineBadge = deviceData && app._isOnline(deviceData.son_gorulme)
            ? ' <span class="badge badge-success" style="font-size:0.7rem;vertical-align:middle">Online</span>'
            : ' <span class="badge badge-danger"  style="font-size:0.7rem;vertical-align:middle">Offline</span>';
        document.getElementById('modal-device-title').innerHTML = `Manage Device: ${id}${onlineBadge}`;
        document.getElementById('process-table-body').innerHTML =
            '<tr><td colspan="6" class="text-center text-muted">Click Fetch to load data</td></tr>';
        document.getElementById('process-search').value = '';
        if (state.processPollInterval) clearInterval(state.processPollInterval);
        document.getElementById('device-modal').classList.add('active');
        // Start cooldown tracking
        ui.startCooldownTracking(id);
    },

    showAddListModal(type) {
        document.getElementById('list_type').value = type;
        document.getElementById('list_id').value = '';
        document.getElementById('add-list-title').textContent =
            type === 'blacklist' ? 'Add to Blacklist' : 'Add to Whitelist';
        document.getElementById('group_risk_score').style.display =
            type === 'blacklist' ? 'block' : 'none';

        document.getElementById('list_name').disabled = false;
        document.getElementById('list_hash').disabled = false;
        document.getElementById('group_scope_container').style.display = 'block';
        document.getElementById('list_submit_btn').innerHTML = '<i class="fa-solid fa-check"></i> Save';
        document.getElementById('add-list-form').reset();

        ui.toggleScopeInputs();
        document.getElementById('add-list-modal').classList.add('active');
    },

    closeModal(id) {
        document.getElementById(id).classList.remove('active');
        if (id === 'device-modal') {
            if (state.processPollInterval) clearInterval(state.processPollInterval);
            ui.stopCooldownTracking();
        }
    },

    toggleScopeInputs() {
        const type = document.getElementById('list_scope_type').value;
        document.getElementById('group_scope_priority').style.display = type === 'priority' ? 'block' : 'none';
        document.getElementById('group_scope_device').style.display = type === 'device' ? 'block' : 'none';
    },

    /**
     * Render the table for a given list type + scope combination.
     * Called by scope-tab click handlers and after data load.
     */
    renderScopePanel(type, scope) {
        const data = type === 'blacklist' ? state.blacklist : state.whitelist;
        const prefix = type === 'blacklist' ? 'bl' : 'wl';

        let rules;
        if (scope === 'global') {
            rules = data.filter(d => !d.priority_scope && !d.device_scope_id);
        } else if (scope === 'priority') {
            const sel = document.getElementById(`${prefix}-priority-select`).value;
            rules = sel ? data.filter(d => d.priority_scope == sel) : [];
        } else if (scope === 'device') {
            const sel = document.getElementById(`${prefix}-device-select`).value;
            rules = sel ? data.filter(d => d.device_scope_id === sel) : [];
        }

        const tableId = `${prefix}-${scope}-table`;
        const cont = document.getElementById(tableId);
        if (!cont) return;

        if (!rules.length) {
            cont.innerHTML = '<div class="loader" style="padding:20px">No entries for this selection.</div>';
            return;
        }

        const rows = rules.map(d => `
            <tr>
                <td>
                    <div><strong>${d.islem_adi || '—'}</strong></div>
                    <div><code style="font-size:0.75rem;color:var(--text-muted)">${d.hash_sha256}</code></div>
                </td>
                ${type === 'blacklist'
                ? `<td><span class="badge badge-danger">${d.risk_puani}</span></td>`
                : `<td>${d.aciklama || '—'}</td>`}
                <td>
                    <button class="btn btn-sm btn-outline" onclick="app.openEditListModal('${type}', ${d.id})" title="Edit">
                        <i class="fa-solid fa-pen"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="app.deleteListItem('${type}', ${d.id})" title="Delete">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            </tr>`).join('');

        cont.innerHTML = `
            <div class="table-responsive" style="border-radius:var(--radius-md);border:1px solid var(--border-glass)">
                <table class="data-table">
                    <thead><tr>
                        <th>Process / Hash</th>
                        ${type === 'blacklist' ? '<th>Risk</th>' : '<th>Description</th>'}
                        <th>Actions</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    },

    /**
     * Button loading state helper.
     * @param {HTMLElement} btn
     * @param {boolean} loading
     * @param {string} [label] HTML to set when not loading
     */
    setLoading(btn, loading, label = '') {
        btn.disabled = loading;
        if (loading) {
            btn.dataset.origHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
        } else {
            btn.innerHTML = label || btn.dataset.origHtml || label;
        }
    },

    toggleApiKeyVisibility() {
        const input = document.getElementById('cfg_ai_key');
        const icon = document.getElementById('api-key-eye');
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fa-regular fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fa-regular fa-eye';
        }
    },

    filterProcessTable() {
        const q = (document.getElementById('process-search')?.value || '').toLowerCase().trim();
        if (!state._processList?.length) return;
        const filtered = q
            ? state._processList.filter(p =>
                p.name.toLowerCase().includes(q) ||
                String(p.pid).includes(q))
            : state._processList;
        app._renderProcessRows(filtered);
    },

    copyHash(hash) {
        navigator.clipboard.writeText(hash).then(() => {
            ui.showToast('Hash copied to clipboard!', 'success');
        }).catch(() => {
            // Fallback for non-secure contexts
            const el = document.createElement('textarea');
            el.value = hash;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
            ui.showToast('Hash copied!', 'success');
        });
    },

    /**
     * Open the Add List modal pre-filled with process data, scoped to the current device.
     * @param {'blacklist'|'whitelist'} type
     * @param {string} procName  - process name
     * @param {string} hash      - SHA-256 hex string
     */
    async quickAddToList(type, procName, hash) {
        const otherType = type === 'blacklist' ? 'whitelist' : 'blacklist';
        const otherData = type === 'blacklist' ? state.whitelist : state.blacklist;

        const existingOther = app._getEntryForHash(hash, otherData);
        let descToCopy = '';

        if (existingOther) {
            const move = await ui.confirm(`This process is currently in the ${otherType}. Do you want to move it to the ${type}?`, 'Move List Entry');
            if (!move) return;
            descToCopy = existingOther.aciklama || '';
        }

        // Pre-fill add-list modal
        document.getElementById('list_type').value = type;
        document.getElementById('list_id').value = '';
        document.getElementById('add-list-title').textContent =
            type === 'blacklist' ? 'Add to Blacklist' : 'Add to Whitelist';
        document.getElementById('list_name').value = procName;
        document.getElementById('list_hash').value = hash;

        document.getElementById('list_name').disabled = false;
        document.getElementById('list_hash').disabled = false;
        document.getElementById('group_scope_container').style.display = 'block';
        document.getElementById('list_submit_btn').innerHTML = '<i class="fa-solid fa-check"></i> Save';

        document.getElementById('list_desc').value = descToCopy;
        document.getElementById('list_risk').value = '50';

        // Default scope: device-specific (current device)
        const scopeSel = document.getElementById('list_scope_type');
        scopeSel.value = 'device';
        document.getElementById('list_scope_device').value = state.selectedDevice || '';

        // Show/hide risk score and scope inputs
        document.getElementById('group_risk_score').style.display =
            type === 'blacklist' ? 'block' : 'none';
        ui.toggleScopeInputs();

        document.getElementById('add-list-modal').classList.add('active');
    },

    toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebar-overlay').classList.toggle('visible');
    },
    closeSidebar() {
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebar-overlay').classList.remove('visible');
    },

    // ── Cooldown Banner ────────────────────────────────────────
    /**
     * Start polling cooldown status every 3 seconds + 1s countdown tick.
     */
    startCooldownTracking(pcName) {
        this.stopCooldownTracking();
        this.fetchAndRenderCooldown(pcName);
        state.cooldownPollInterval = setInterval(() => this.fetchAndRenderCooldown(pcName), 3000);
        state.cooldownTickInterval = setInterval(() => this._tickCooldownDisplay(), 1000);
    },

    stopCooldownTracking() {
        clearInterval(state.cooldownPollInterval);
        clearInterval(state.cooldownTickInterval);
        state.cooldownPollInterval = null;
        state.cooldownTickInterval = null;
        state.cooldownExpiresAt = null;
        state.cooldownTotalSecs = 0;
    },

    async fetchAndRenderCooldown(pcName) {
        try {
            const data = await apiCall(`/devices/${pcName}/cooldown`);
            this._renderCooldownBanner(data);
        } catch {
            // Silently ignore – banner stays as-is
        }
    },

    _renderCooldownBanner(data) {
        const banner = document.getElementById('cooldown-banner');
        const icon = document.getElementById('cooldown-icon');
        const label = document.getElementById('cooldown-action-label');
        const timer = document.getElementById('cooldown-timer');
        const sub = document.getElementById('cooldown-sub');
        const progWrap = document.getElementById('cooldown-progress-wrap');
        const progBar = document.getElementById('cooldown-progress-bar');

        // Remove all state classes
        banner.className = 'cooldown-banner';
        icon.className = 'cooldown-icon';
        progBar.className = 'cooldown-progress-bar';
        timer.className = 'cooldown-timer';

        if (data.active && data.seconds_remaining > 0) {
            const act = (data.last_action || 'RESTRICT').toLowerCase();
            const iconMap = {
                restrict: 'fa-solid fa-wifi',
                isolate: 'fa-solid fa-circle-stop',
                lockdown: 'fa-solid fa-lock',
            };
            const colorMap = {
                restrict: 'warning',
                isolate: 'danger',
                lockdown: 'purple',
            };
            const labelMap = {
                restrict: 'RESTRICT Active',
                isolate: 'ISOLATE Active',
                lockdown: 'LOCKDOWN Active',
            };

            banner.classList.add(`active-${act}`);
            icon.className = `${iconMap[act] || 'fa-solid fa-lock'} cooldown-icon ${act}-clr`;
            label.textContent = labelMap[act] || `${act.toUpperCase()} Active`;
            label.style.color = act === 'lockdown' ? '#7c3aed' : `var(--${colorMap[act] || 'warning'})`;

            // Store expiry for 1s tick
            state.cooldownExpiresAt = new Date(data.expires_at);
            if (!state.cooldownTotalSecs || state.cooldownTotalSecs < data.seconds_remaining) {
                state.cooldownTotalSecs = data.seconds_remaining; // rough initial total
            }

            timer.textContent = this._formatSeconds(data.seconds_remaining);
            sub.textContent = data.expires_at
                ? `Ends at ${new Date(data.expires_at).toLocaleTimeString()}`
                : '';

            // Progress bar
            progWrap.style.display = 'block';
            progBar.classList.add(`${act}-bar`);
            const pct = Math.min(100, (data.seconds_remaining / (state.cooldownTotalSecs || data.seconds_remaining)) * 100);
            progBar.style.width = `${pct}%`;

        } else if (data.last_action === 'RECOVER' || (!data.active && data.risk_durumu === false)) {
            banner.classList.add('active-recover');
            icon.className = 'fa-solid fa-circle-check cooldown-icon recover-clr';
            label.textContent = 'RECOVERED — Device is Clean';
            label.style.color = 'var(--success)';
            timer.className = 'cooldown-timer idle';
            timer.textContent = '';
            sub.textContent = 'No active restriction.';
            progWrap.style.display = 'none';
            state.cooldownExpiresAt = null;

        } else {
            // Idle / unknown
            icon.className = 'fa-solid fa-circle-check cooldown-icon idle-clr';
            label.textContent = 'No Active Restriction';
            label.style.color = 'var(--text-muted)';
            timer.className = 'cooldown-timer idle';
            timer.textContent = '';
            sub.textContent = data.risk_durumu ? 'Device is at risk (auto-quarantine).' : 'Device is operating normally.';
            progWrap.style.display = 'none';
            state.cooldownExpiresAt = null;
        }
    },

    /** Called every 1s to decrement the displayed countdown without an API call */
    _tickCooldownDisplay() {
        if (!state.cooldownExpiresAt) return;
        const remaining = Math.max(0, Math.round((state.cooldownExpiresAt - Date.now()) / 1000));
        const timer = document.getElementById('cooldown-timer');
        if (timer) timer.textContent = this._formatSeconds(remaining);

        // Update progress bar
        const progBar = document.getElementById('cooldown-progress-bar');
        if (progBar && state.cooldownTotalSecs > 0) {
            const pct = Math.min(100, (remaining / state.cooldownTotalSecs) * 100);
            progBar.style.width = `${pct}%`;
        }

        if (remaining === 0) {
            state.cooldownExpiresAt = null;
            // Let next poll cycle re-render idle state
        }
    },

    _formatSeconds(s) {
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        if (h > 0) return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
        return `${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
    },
};

// ── Bootstrap ─────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', init);
