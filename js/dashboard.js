// ==========================================
// DASHBOARD ORCHESTRATION
// Home Network Security Assessment
// ==========================================

const Dashboard = (() => {

  // ── Bootstrap ─────────────────────────────────────────────────
  function init() {
    renderHeaderScore();
    renderHeaderStats();
    renderDeviceList();
    renderRiskMatrix();

    // Sub-modules
    NetworkGraph.init();
    ChecklistManager.init();
    ThreatsManager.init();

    setupTabs();
    setupTopologyToggle();
    startClock();
  }

  // ── Header score ring ─────────────────────────────────────────
  function renderHeaderScore() {
    const score = computeOverallScore();
    document.getElementById('overall-score').textContent = score;

    const ring  = document.getElementById('header-score-ring');
    const C     = 314; // circumference for r=50
    ring.style.strokeDashoffset = C - (score / 100) * C;

    const col = getRiskColor(score);
    ring.style.stroke = col;
    ring.style.filter = `drop-shadow(0 0 8px ${col})`;
  }

  function renderHeaderStats() {
    const scored  = DEVICES.filter(d => d.securityScore !== null);
    const critical = scored.filter(d => d.securityScore <= 30).length;
    const high     = scored.filter(d => d.securityScore > 30 && d.securityScore <= 50).length;

    document.getElementById('stat-devices').textContent  = DEVICES.length - 1; // exclude 'internet' node
    document.getElementById('stat-critical').textContent = critical;
    document.getElementById('stat-high').textContent     = high;
    document.getElementById('stat-threats').textContent  = 0;
  }

  // ── Device sidebar ────────────────────────────────────────────
  function renderDeviceList() {
    const list = document.getElementById('device-list');
    list.innerHTML = '';

    DEVICES
      .filter(d => d.id !== 'internet')
      .forEach(device => {
        const score    = device.securityScore;
        const rColor   = score !== null ? getRiskColor(score) : '#00d4ff';

        const item = document.createElement('div');
        item.className       = 'device-item';
        item.id              = `sidebar-device-${device.id}`;
        item.dataset.deviceId = device.id;
        item.style.setProperty('--risk-color', rColor);

        item.innerHTML = `
          <div class="device-icon-wrap">${device.icon}</div>
          <div class="device-info">
            <div class="device-name">${device.name}</div>
            <div class="device-type">${device.type}</div>
          </div>
          ${score !== null ? `
            <div class="device-risk-badge" style="color:${rColor};border-color:${rColor}">${score}</div>
          ` : ''}
        `;

        item.addEventListener('click', () => selectDevice(device.id));
        list.appendChild(item);
      });
  }

  // ── Risk Matrix view ──────────────────────────────────────────
  function renderRiskMatrix() {
    const matrix = document.getElementById('risk-matrix');
    matrix.innerHTML = '';

    DEVICES
      .filter(d => d.securityScore !== null)
      .forEach(device => {
        const score  = device.securityScore;
        const rColor = getRiskColor(score);
        const rLevel = getRiskLevel(score);

        const barsHTML = device.breakdown
          ? Object.entries(device.breakdown).map(([key, val]) => {
              const bc = getBreakdownColor(val);
              return `
                <div class="rmbar-row">
                  <span class="rmbar-label">${getBreakdownLabel(key)}</span>
                  <div class="rmbar-track">
                    <div class="rmbar-fill" style="width:${val}%;background:${bc}"></div>
                  </div>
                  <span style="font-size:10px;font-family:var(--font-mono);color:${bc};width:24px;text-align:right">${val}</span>
                </div>`;
            }).join('')
          : '';

        const card = document.createElement('div');
        card.className = 'risk-matrix-card';
        card.innerHTML = `
          <div class="rmcard-header">
            <span class="rmcard-icon">${device.icon}</span>
            <span class="rmcard-name">${device.name}</span>
            <span class="rmcard-score" style="color:${rColor}">${score}</span>
          </div>
          <div style="font-size:9px;font-weight:700;letter-spacing:1px;color:${rColor};margin-bottom:10px;font-family:var(--font-mono)">${rLevel.label}</div>
          <div class="rmcard-bars">${barsHTML}</div>
        `;

        card.addEventListener('click', () => {
          // Switch to topology and select the device
          document.getElementById('btn-view-topology').click();
          selectDevice(device.id);
        });

        matrix.appendChild(card);
      });
  }

  // ── Device selection ──────────────────────────────────────────
  function selectDevice(deviceId) {
    // Highlight sidebar
    document.querySelectorAll('.device-item').forEach(el => {
      el.classList.toggle('active', el.dataset.deviceId === deviceId);
    });

    // Update canvas
    NetworkGraph.selectNode(deviceId);

    // Populate detail panel
    showDeviceDetail(deviceId);

    // Switch to Details tab
    switchTab('details');
  }

  function showDeviceDetail(deviceId) {
    const device = DEVICES.find(d => d.id === deviceId);
    if (!device) return;

    document.getElementById('no-device-selected').style.display  = 'none';
    const content = document.getElementById('device-detail-content');
    content.style.display = 'block';

    const score  = device.securityScore;
    const rColor = score !== null ? getRiskColor(score)   : '#00d4ff';
    const rLevel = score !== null ? getRiskLevel(score)   : null;

    // Score ring: r=36 → C ≈ 226
    const C2     = 226;
    const offset = score !== null ? C2 - (score / 100) * C2 : C2;

    const breakdownHTML = device.breakdown
      ? Object.entries(device.breakdown).map(([key, val]) => {
          const bc = getBreakdownColor(val);
          return `
            <div class="breakdown-item">
              <div class="breakdown-header">
                <span class="breakdown-label">${getBreakdownLabel(key)}</span>
                <span class="breakdown-value" style="color:${bc}">${val}</span>
              </div>
              <div class="breakdown-bar">
                <div class="breakdown-fill" style="width:${val}%;background:${bc}"></div>
              </div>
            </div>`;
        }).join('')
      : '<div style="color:var(--text-muted);font-size:12px;padding:4px 0">No breakdown data</div>';

    const vulnHTML = device.vulnerabilities.length
      ? device.vulnerabilities.map(v => {
          const vc = PRIORITY_COLORS_MAP[v.severity] || '#ff4757';
          return `
            <div class="vuln-item" style="border-left-color:${vc}">
              <span class="vuln-severity ${v.severity}">${v.severity.toUpperCase()}</span>
              <span class="vuln-text">${v.text}</span>
            </div>`;
        }).join('')
      : '<div class="vuln-item" style="border-left-color:var(--green);"><span class="vuln-severity low">CLEAN</span><span class="vuln-text">No vulnerabilities detected</span></div>';

    const recHTML = device.recommendations.length
      ? device.recommendations.map(r => `
          <div class="rec-item">
            <span class="rec-icon">→</span>
            <span class="rec-text">${r}</span>
          </div>`).join('')
      : '<div style="color:var(--text-muted);font-size:12px;padding:4px 0">No recommendations</div>';

    content.innerHTML = `
      <div class="detail-device-header">
        <div class="detail-device-icon">${device.icon}</div>
        <div class="detail-device-info">
          <h3>${device.name}</h3>
          <div class="detail-device-model">${device.model}</div>
          ${device.ipAddress ? `<div class="detail-device-ip">${device.ipAddress}</div>` : ''}
        </div>
        ${rLevel ? `
          <div class="detail-risk-badge" style="background:${rColor}18;color:${rColor};border:1px solid ${rColor}40">
            ${rLevel.label}
          </div>
        ` : ''}
      </div>

      ${score !== null ? `
      <div class="detail-score-section">
        <div class="detail-score-ring">
          <svg viewBox="0 0 80 80">
            <circle cx="40" cy="40" r="36" class="detail-ring-bg"/>
            <circle cx="40" cy="40" r="36" class="detail-ring-fill"
              style="stroke:${rColor};stroke-dashoffset:${offset};filter:drop-shadow(0 0 4px ${rColor})"/>
          </svg>
          <div class="detail-ring-text">
            <span class="detail-ring-number" style="color:${rColor}">${score}</span>
            <span class="detail-ring-label">Score</span>
          </div>
        </div>
        <div class="detail-score-breakdown">
          ${breakdownHTML}
        </div>
      </div>
      ` : ''}

      ${device.firmware ? `
      <div class="detail-meta-row">
        <span class="detail-meta-label">Firmware</span>
        <span class="detail-meta-value">${device.firmware}</span>
      </div>
      ` : ''}

      <div class="detail-section">
        <div class="detail-section-title">
          ⚠ Vulnerabilities
          <span style="color:var(--red);font-family:var(--font-mono)">(${device.vulnerabilities.length})</span>
        </div>
        ${vulnHTML}
      </div>

      <div class="detail-section">
        <div class="detail-section-title">✓ Recommendations</div>
        ${recHTML}
      </div>
    `;
  }

  // ── Tab system ────────────────────────────────────────────────
  function setupTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
  }

  function switchTab(name) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `content-${name}`));
  }

  // ── Topology / Matrix toggle ──────────────────────────────────
  function setupTopologyToggle() {
    const btnTopo   = document.getElementById('btn-view-topology');
    const btnMatrix = document.getElementById('btn-view-matrix');
    const cvs       = document.getElementById('network-canvas');
    const mtx       = document.getElementById('risk-matrix');

    btnTopo.addEventListener('click', () => {
      cvs.style.display = 'block';
      mtx.style.display = 'none';
      btnTopo.classList.add('active');
      btnMatrix.classList.remove('active');
    });

    btnMatrix.addEventListener('click', () => {
      cvs.style.display = 'none';
      mtx.style.display = 'grid';
      btnTopo.classList.remove('active');
      btnMatrix.classList.add('active');
    });
  }

  // ── Clock ─────────────────────────────────────────────────────
  function startClock() {
    const tick = () => {
      const now = new Date();
      document.getElementById('scan-time').textContent =
        'Last scan: ' + now.toLocaleTimeString('en-US', { hour12: false });
    };
    tick();
    setInterval(tick, 30_000);
  }

  return { init, selectDevice };
})();

// ── Kick-off ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => Dashboard.init());
