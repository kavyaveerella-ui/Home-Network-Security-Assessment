// ==========================================
// SIMULATED THREAT FEED
// Home Network Security Assessment
// ==========================================

const THREAT_TEMPLATES = [
  { severity: 'critical', msg: 'Port scan detected from {ip} — targeting Printer on port 9100 (JetDirect)', device: 'Printer' },
  { severity: 'critical', msg: 'Brute-force attack on router admin panel — {n} failed login attempts in 60s', device: 'Router' },
  { severity: 'critical', msg: 'Telnet authentication attempt on Printer port 23 — credential stuffing pattern', device: 'Printer' },
  { severity: 'critical', msg: 'Known malware C2 callback blocked: {ip} → *.darknode.ru (Mirai botnet IoC)', device: 'IoT Devices' },
  { severity: 'high',     msg: 'UPnP port mapping added automatically: WAN:54{n} → 192.168.1.14{n2} (IoT Hub)', device: 'IoT Devices' },
  { severity: 'high',     msg: 'Smart TV contacting ad-tracking server: analytics.samsung.com (ACR telemetry)', device: 'Smart TV' },
  { severity: 'high',     msg: 'Unencrypted MQTT traffic intercepted on port 1883 — device commands exposed', device: 'IoT Devices' },
  { severity: 'high',     msg: 'Outdated TLS 1.0 negotiated: Printer → mail-relay.corp.com (deprecated cipher)', device: 'Printer' },
  { severity: 'high',     msg: 'IoT Hub initiating outbound connections to {n} distinct country ASNs in 10 min', device: 'IoT Devices' },
  { severity: 'high',     msg: 'Windows Defender disabled on Laptop — real-time protection off, system exposed', device: 'Laptop' },
  { severity: 'medium',   msg: 'Bluetooth probe request detected near Smartphone — unknown MAC: {mac}', device: 'Smartphone' },
  { severity: 'medium',   msg: 'DNS query for suspicious domain flagged: *.update-service-{n}.net → blocked', device: 'Laptop' },
  { severity: 'medium',   msg: 'SMB broadcast from Laptop detected — share enumeration possible on LAN', device: 'Laptop' },
  { severity: 'medium',   msg: 'Guest Wi-Fi client attempted to reach main LAN (192.168.1.0/24) — blocked', device: 'Router' },
  { severity: 'medium',   msg: 'Smart TV firmware update failed — update server unreachable, device stays vulnerable', device: 'Smart TV' },
  { severity: 'medium',   msg: 'SNMP walk request received on Printer from 192.168.1.254 — unknown host', device: 'Printer' },
  { severity: 'medium',   msg: 'Smartphone attempted auto-connect to open SSID: "Airport_Free_WiFi"', device: 'Smartphone' },
  { severity: 'low',      msg: 'New unrecognized device joined network — MAC: {mac} (vendor: unknown)', device: 'Router' },
  { severity: 'low',      msg: 'DHCP lease renewed: Smartphone (192.168.1.115) → assigned for 24h', device: 'Smartphone' },
  { severity: 'low',      msg: 'Router NTP sync failed — system clock drift detected (3.2 seconds)', device: 'Router' },
  { severity: 'low',      msg: 'Modem upstream power level elevated — possible line quality degradation', device: 'Modem' },
  { severity: 'low',      msg: 'Smart TV microphone activity detected during idle period — no active input', device: 'Smart TV' },
];

const ThreatsManager = (() => {
  let allThreats = [];
  let currentFilter = 'all';
  let totalCount = 0;
  let intervalId = null;

  function randIp()  { return `185.${Math.floor(Math.random()*200+20)}.${Math.floor(Math.random()*200)}.${Math.floor(Math.random()*250+1)}`; }
  function randN()   { return Math.floor(Math.random() * 90 + 10); }
  function randN2()  { return Math.floor(Math.random() * 5); }
  function randMac() {
    return Array.from({length: 6}, () => Math.floor(Math.random()*255).toString(16).padStart(2,'0').toUpperCase()).join(':');
  }

  function buildMessage(template) {
    return template.msg
      .replace('{ip}',  randIp())
      .replace('{n}',   randN())
      .replace('{n2}',  randN2())
      .replace('{mac}', randMac());
  }

  function makeTimestamp(offsetMinutes = 0) {
    const d = new Date();
    d.setMinutes(d.getMinutes() - offsetMinutes);
    return d.toLocaleTimeString('en-US', { hour12: false });
  }

  function generateThreat(template) {
    return {
      id:       Date.now() + Math.random(),
      severity: template.severity,
      message:  buildMessage(template),
      device:   template.device,
      time:     makeTimestamp(0),
    };
  }

  function addThreat(threat, prepend = true) {
    if (prepend) {
      allThreats.unshift(threat);
    } else {
      allThreats.push(threat);
    }
    if (allThreats.length > 200) allThreats.pop();

    totalCount++;
    document.getElementById('threat-badge').textContent = totalCount;
    document.getElementById('stat-threats').textContent = totalCount;

    if (prepend) renderOneThreat(threat, true);
  }

  function renderOneThreat(threat, atTop = true) {
    if (currentFilter !== 'all' && threat.severity !== currentFilter) return;

    const list = document.getElementById('threats-list');
    const el   = createThreatEl(threat);

    if (atTop && list.firstChild) {
      list.insertBefore(el, list.firstChild);
    } else {
      list.appendChild(el);
    }

    // Prune DOM to 60 visible items
    while (list.children.length > 60) list.removeChild(list.lastChild);
  }

  function createThreatEl(threat) {
    const el = document.createElement('div');
    el.className = `threat-item ${threat.severity}`;
    el.dataset.severity = threat.severity;
    el.innerHTML = `
      <div class="threat-severity-dot"></div>
      <div class="threat-content">
        <div class="threat-message">${threat.message}</div>
        <div class="threat-meta">
          <span class="threat-device">${threat.device}</span>
          <span class="threat-time">${threat.time}</span>
        </div>
      </div>
    `;
    return el;
  }

  function applyFilter(severity) {
    currentFilter = severity;

    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.severity === severity);
    });

    const list = document.getElementById('threats-list');
    list.innerHTML = '';

    const filtered = severity === 'all'
      ? allThreats
      : allThreats.filter(t => t.severity === severity);

    filtered.slice(0, 60).forEach(t => renderOneThreat(t, false));
  }

  function init() {
    // Seed with realistic initial history (oldest → newest)
    const seeds = [
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'critical' && t.device === 'Printer'), offset: 28 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'critical' && t.device === 'Router'),  offset: 24 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'high'     && t.device === 'IoT Devices' && t.msg.includes('UPnP')), offset: 20 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'high'     && t.device === 'Smart TV'), offset: 17 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'high'     && t.device === 'IoT Devices' && t.msg.includes('MQTT')), offset: 14 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'medium'   && t.device === 'Laptop' && t.msg.includes('SMB')), offset: 10 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'medium'   && t.device === 'Smartphone'), offset: 7 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'low'      && t.device === 'Router' && t.msg.includes('DHCP')), offset: 3 },
      { tmpl: THREAT_TEMPLATES.find(t => t.severity === 'high'     && t.device === 'Laptop' && t.msg.includes('Defender')), offset: 1 },
    ];

    seeds.reverse().forEach(({ tmpl, offset }) => {
      if (!tmpl) return;
      const t = {
        id:       Date.now() + Math.random(),
        severity: tmpl.severity,
        message:  buildMessage(tmpl),
        device:   tmpl.device,
        time:     makeTimestamp(offset),
      };
      allThreats.push(t);
      totalCount++;
    });

    document.getElementById('threat-badge').textContent = totalCount;
    document.getElementById('stat-threats').textContent = totalCount;

    // Setup filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => applyFilter(btn.dataset.severity));
    });

    applyFilter('all');

    // Live feed: new threat every 5–9 seconds
    intervalId = setInterval(() => {
      if (Math.random() > 0.25) {
        const tmpl = THREAT_TEMPLATES[Math.floor(Math.random() * THREAT_TEMPLATES.length)];
        addThreat(generateThreat(tmpl), true);
      }
    }, 6000);
  }

  return { init };
})();
