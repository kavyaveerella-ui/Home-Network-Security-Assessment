// ==========================================
// SECURITY HARDENING CHECKLIST
// Home Network Security Assessment
// ==========================================

const CHECKLIST_DATA = [
  {
    category: '🌐 Network Infrastructure',
    items: [
      { id: 'cl-01', title: 'Update router firmware',         desc: 'Apply latest firmware to patch RCE and authentication bypass CVEs', priority: 'critical' },
      { id: 'cl-02', title: 'Disable UPnP on router',         desc: 'Prevents devices from automatically opening external firewall ports',  priority: 'high' },
      { id: 'cl-03', title: 'Disable WPS',                    desc: 'Eliminates Pixie Dust and PIN-brute-force attack vectors',            priority: 'high' },
      { id: 'cl-04', title: 'Create isolated IoT VLAN/SSID',  desc: 'Segment smart home devices away from personal computers and NAS',     priority: 'high' },
      { id: 'cl-05', title: 'Enable DNS-over-HTTPS (DoH)',     desc: 'Encrypts DNS queries — prevents ISP snooping and MITM attacks',       priority: 'medium' },
      { id: 'cl-06', title: 'Enable SPI router firewall',      desc: 'Stateful Packet Inspection with strict inbound blocking rules',       priority: 'high' },
    ],
  },
  {
    category: '🔐 Authentication & Access',
    items: [
      { id: 'cl-07', title: 'Change all default passwords',    desc: 'Router, modem, printer, all IoT devices — every device must have a unique password', priority: 'critical' },
      { id: 'cl-08', title: 'Use WPA3 or WPA2-AES Wi-Fi',     desc: 'Disable WEP, WPA-TKIP — use a 16+ character passphrase',            priority: 'high' },
      { id: 'cl-09', title: 'Disable Telnet on all devices',   desc: 'Replace Telnet with SSH or disable remote management entirely',      priority: 'critical' },
      { id: 'cl-10', title: 'Restrict router admin to LAN',    desc: 'Disable WAN-side remote management of router admin panel',           priority: 'medium' },
    ],
  },
  {
    category: '💻 Endpoint Security',
    items: [
      { id: 'cl-11', title: 'Install all pending OS updates',  desc: 'Apply critical and security patches on Windows, macOS, Android',    priority: 'high' },
      { id: 'cl-12', title: 'Enable full-disk encryption',     desc: 'BitLocker on Windows, FileVault on macOS — protects stolen devices', priority: 'high' },
      { id: 'cl-13', title: 'Enable Windows Defender',         desc: 'Real-time antivirus protection must be active at all times',         priority: 'critical' },
      { id: 'cl-14', title: 'Revoke excessive app permissions', desc: 'Remove unnecessary location, mic, camera permissions on mobile',    priority: 'medium' },
      { id: 'cl-15', title: 'Disable Bluetooth when idle',     desc: 'Reduces exposure to BlueBorne, BIAS, and BLESA attacks',            priority: 'low' },
      { id: 'cl-16', title: 'Remove admin privileges from daily account', desc: 'Run daily tasks as a Standard user to limit malware impact', priority: 'medium' },
    ],
  },
  {
    category: '🏠 IoT & Smart Devices',
    items: [
      { id: 'cl-17', title: 'Update all IoT firmware',         desc: 'Apply updates to smart TVs, cameras, thermostats, and bulbs',       priority: 'critical' },
      { id: 'cl-18', title: 'Disable ACR on Smart TV',         desc: 'Opt out of Automatic Content Recognition and ad tracking',          priority: 'high' },
      { id: 'cl-19', title: 'Secure printer with PIN-to-print', desc: 'Require PIN authentication for print jobs — restrict port 9100',    priority: 'critical' },
      { id: 'cl-20', title: 'Disable DLNA/UPnP on media devices', desc: 'Turn off unnecessary network discovery protocols',               priority: 'medium' },
      { id: 'cl-21', title: 'Update printer firmware',         desc: 'Patch HP/Canon/Epson RCE and privilege escalation vulnerabilities',  priority: 'high' },
    ],
  },
  {
    category: '📊 Monitoring & Privacy',
    items: [
      { id: 'cl-22', title: 'Enable router access logging',    desc: 'Log all connection attempts and blocked traffic for review',         priority: 'medium' },
      { id: 'cl-23', title: 'Set up network intrusion detection', desc: 'Consider Firewalla, pfSense, or OPNsense for IDS/IPS capabilities', priority: 'medium' },
      { id: 'cl-24', title: 'Review connected devices monthly', desc: 'Audit router DHCP table for unauthorized or unknown devices',       priority: 'low' },
    ],
  },
];

const ChecklistManager = (() => {
  let state = {};

  function init() {
    try {
      const saved = localStorage.getItem('hnsa-checklist-v2');
      if (saved) state = JSON.parse(saved);
    } catch (e) { state = {}; }

    render();
  }

  function render() {
    const container = document.getElementById('checklist-container');
    container.innerHTML = '';

    CHECKLIST_DATA.forEach(category => {
      const catEl = document.createElement('div');
      catEl.className = 'checklist-category';

      const titleEl = document.createElement('div');
      titleEl.className = 'checklist-category-title';
      titleEl.textContent = category.category;
      catEl.appendChild(titleEl);

      category.items.forEach(item => {
        const isChecked = !!state[item.id];
        const itemEl = document.createElement('div');
        itemEl.className = `checklist-item${isChecked ? ' checked' : ''}`;
        itemEl.id = `checklist-item-${item.id}`;

        const pColor = PRIORITY_COLORS_MAP[item.priority] || '#00d4ff';

        itemEl.innerHTML = `
          <div class="checklist-checkbox">
            <span class="checklist-checkbox-icon">✓</span>
          </div>
          <div class="checklist-item-content">
            <div class="checklist-item-title">${item.title}</div>
            <div class="checklist-item-desc">${item.desc}</div>
          </div>
          <div class="checklist-priority" style="
            background: ${pColor}18;
            color: ${pColor};
            border: 1px solid ${pColor}40;
          ">${item.priority.toUpperCase()}</div>
        `;

        itemEl.addEventListener('click', () => toggle(item.id, itemEl));
        catEl.appendChild(itemEl);
      });

      container.appendChild(catEl);
    });

    updateScore();
  }

  function toggle(id, el) {
    state[id] = !state[id];
    el.classList.toggle('checked', state[id]);
    try { localStorage.setItem('hnsa-checklist-v2', JSON.stringify(state)); } catch (e) {}
    updateScore();
  }

  function updateScore() {
    const allItems = CHECKLIST_DATA.flatMap(c => c.items);
    const total = allItems.length;
    const checked = allItems.filter(item => state[item.id]).length;
    const pct = Math.round((checked / total) * 100);

    document.getElementById('checklist-pct').textContent = `${pct}%`;
    document.getElementById('checklist-progress').style.width = `${pct}%`;

    // Update color of progress fill
    const fill = document.getElementById('checklist-progress');
    if (pct < 40) {
      fill.style.background = 'linear-gradient(90deg, #ff4757, #ff6b35)';
    } else if (pct < 70) {
      fill.style.background = 'linear-gradient(90deg, #ffb347, #ffd700)';
    } else {
      fill.style.background = 'linear-gradient(90deg, #00d4ff, #00ff87)';
    }
  }

  return { init };
})();
