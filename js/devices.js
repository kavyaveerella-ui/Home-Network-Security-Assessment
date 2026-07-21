// ==========================================
// DEVICE DATA MODEL & RISK SCORING
// Home Network Security Assessment
// ==========================================

const RISK_LEVELS = {
  critical: { label: 'CRITICAL', color: '#ff2d55', range: [0, 30] },
  high:     { label: 'HIGH',     color: '#ff4757', range: [31, 50] },
  medium:   { label: 'MEDIUM',   color: '#ffb347', range: [51, 70] },
  low:      { label: 'LOW',      color: '#00ff87', range: [71, 100] },
};

const PRIORITY_COLORS_MAP = {
  critical: '#ff2d55',
  high:     '#ff4757',
  medium:   '#ffb347',
  low:      '#00ff87',
};

function getRiskLevel(score) {
  if (score <= 30) return RISK_LEVELS.critical;
  if (score <= 50) return RISK_LEVELS.high;
  if (score <= 70) return RISK_LEVELS.medium;
  return RISK_LEVELS.low;
}

function getRiskColor(score) {
  return getRiskLevel(score).color;
}

function getBreakdownColor(score) {
  if (score <= 30) return '#ff2d55';
  if (score <= 50) return '#ff4757';
  if (score <= 70) return '#ffb347';
  return '#00ff87';
}

function getBreakdownLabel(key) {
  const labels = {
    firmware:       'Firmware',
    authentication: 'Auth',
    encryption:     'Encryption',
    openPorts:      'Open Ports',
    cveRisk:        'CVE Risk',
  };
  return labels[key] || key;
}

const DEVICES = [
  {
    id: 'internet',
    name: 'Internet',
    type: 'External Gateway',
    icon: '🌐',
    model: 'External Network',
    ipAddress: null,
    macAddress: null,
    firmware: null,
    securityScore: null,
    isInfrastructure: true,
    parent: null,
    canvasPos: { x: 0.5, y: 0.07 },
    breakdown: null,
    vulnerabilities: [],
    recommendations: [],
  },
  {
    id: 'modem',
    name: 'Cable Modem',
    type: 'Modem',
    icon: '📡',
    model: 'ARRIS SB8200 (DOCSIS 3.1)',
    ipAddress: '192.168.100.1',
    macAddress: 'A4:3E:51:2B:8C:1F',
    firmware: 'v9.1.93L.20210507 (May 2021)',
    securityScore: 68,
    isInfrastructure: true,
    parent: 'internet',
    canvasPos: { x: 0.5, y: 0.22 },
    breakdown: {
      firmware:       55,
      authentication: 65,
      encryption:     80,
      openPorts:      75,
      cveRisk:        65,
    },
    vulnerabilities: [
      { severity: 'medium', text: 'Firmware from May 2021 — over 3 years without security update' },
      { severity: 'medium', text: 'Web management interface accessible on LAN without enforced HTTPS' },
      { severity: 'low',    text: 'Default admin credentials may not have been rotated since install' },
    ],
    recommendations: [
      'Update modem firmware to the latest available version via ISP or manufacturer',
      'Enable HTTPS-only access on the management interface',
      'Change default admin username and password immediately',
      'Disable remote management if not actively required by ISP',
    ],
  },
  {
    id: 'router',
    name: 'Wi-Fi Router',
    type: 'Router / Access Point',
    icon: '📶',
    model: 'TP-Link Archer AX73 (Wi-Fi 6)',
    ipAddress: '192.168.1.1',
    macAddress: 'C8:3A:35:7D:9E:01',
    firmware: 'v1.2.2 Build 20220930 (Sep 2022)',
    securityScore: 52,
    isInfrastructure: true,
    parent: 'modem',
    canvasPos: { x: 0.5, y: 0.40 },
    breakdown: {
      firmware:       45,
      authentication: 60,
      encryption:     70,
      openPorts:      40,
      cveRisk:        45,
    },
    vulnerabilities: [
      { severity: 'high',   text: 'UPnP enabled — allows devices to open external firewall ports without authorization' },
      { severity: 'high',   text: 'Firmware 2 years out of date — 6 known CVEs including CVE-2023-1389 (RCE)' },
      { severity: 'high',   text: 'WPS (Wi-Fi Protected Setup) enabled — susceptible to Pixie Dust brute-force attack' },
      { severity: 'medium', text: 'Guest network not fully isolated — can reach main LAN subnet' },
      { severity: 'medium', text: 'DNS-over-HTTPS not configured — DNS queries transmitted in plaintext' },
      { severity: 'low',    text: 'Admin interface reachable from Wi-Fi without separate management VLAN' },
    ],
    recommendations: [
      'Update router firmware immediately — known RCE vulnerability present',
      'Disable UPnP — configure port forwarding manually for required services',
      'Disable WPS to eliminate Pixie Dust attack surface',
      'Enable DNS-over-HTTPS (DoH) with Cloudflare 1.1.1.1 or Quad9',
      'Create a dedicated IoT SSID with VLAN isolation from the main network',
      'Enable SPI (Stateful Packet Inspection) firewall with strict inbound rules',
      'Restrict admin panel access to wired connections only',
    ],
  },
  {
    id: 'laptop',
    name: 'Laptop',
    type: 'Endpoint / PC',
    icon: '💻',
    model: 'Windows 11 / Intel Core i7-12700H',
    ipAddress: '192.168.1.101',
    macAddress: '3C:52:A1:6D:2F:08',
    firmware: 'Windows 11 22H2 (Build 22621.3737)',
    securityScore: 63,
    isInfrastructure: false,
    parent: 'router',
    canvasPos: { x: 0.14, y: 0.75 },
    breakdown: {
      firmware:       60,
      authentication: 70,
      encryption:     72,
      openPorts:      58,
      cveRisk:        55,
    },
    vulnerabilities: [
      { severity: 'high',   text: 'Windows Defender Real-Time Protection currently disabled — system unprotected' },
      { severity: 'high',   text: '47 pending Windows security updates not yet installed (oldest: 9 months)' },
      { severity: 'medium', text: 'Primary user account runs with Administrator privileges — violation of least privilege' },
      { severity: 'medium', text: 'SMB file sharing active — network shares discoverable and accessible on LAN' },
      { severity: 'low',    text: 'BitLocker full-disk encryption not enabled — data at risk if device is stolen' },
      { severity: 'low',    text: 'RDP (Remote Desktop) enabled on port 3389 — unnecessary attack surface' },
    ],
    recommendations: [
      'Enable Windows Defender Real-Time Protection and run a full system scan',
      'Install all pending Windows Update security patches',
      'Create a Standard (non-admin) user account for daily use',
      'Disable SMB sharing if not needed, or restrict with a strong password',
      'Enable BitLocker on all drives (requires TPM 2.0)',
      'Disable RDP if remote access is not actively used',
      'Enable Windows Firewall with custom inbound rules',
    ],
  },
  {
    id: 'smartphone',
    name: 'Smartphone',
    type: 'Mobile Device',
    icon: '📱',
    model: 'Google Pixel 7 (Android 13)',
    ipAddress: '192.168.1.115',
    macAddress: '5A:8C:BD:12:3F:77',
    firmware: 'Android 13 — Security Patch: September 2023',
    securityScore: 72,
    isInfrastructure: false,
    parent: 'router',
    canvasPos: { x: 0.30, y: 0.81 },
    breakdown: {
      firmware:       70,
      authentication: 85,
      encryption:     80,
      openPorts:      70,
      cveRisk:        55,
    },
    vulnerabilities: [
      { severity: 'medium', text: 'Security patch 10 months out of date — September 2023 patch level' },
      { severity: 'medium', text: '12 installed apps have unnecessary location or microphone permissions' },
      { severity: 'medium', text: 'Bluetooth constantly active — exposure to BlueBorne & BIAS attack variants' },
      { severity: 'low',    text: 'Auto-join open Wi-Fi networks enabled — risk of MITM via evil twin APs' },
      { severity: 'low',    text: 'Google Play Protect disabled in developer settings' },
    ],
    recommendations: [
      'Apply latest Android security patches (Settings → System → System Update)',
      'Review and revoke unnecessary app permissions in Settings → Privacy',
      'Disable Bluetooth when not actively using a paired device',
      'Disable "Connect to open networks" in Wi-Fi settings',
      'Re-enable Google Play Protect for real-time app scanning',
      'Enable PIN/biometric lock with a 6-digit minimum PIN',
    ],
  },
  {
    id: 'smarttv',
    name: 'Smart TV',
    type: 'IoT / Media Device',
    icon: '📺',
    model: 'Samsung QLED 4K QN85A (2021)',
    ipAddress: '192.168.1.120',
    macAddress: 'B8:D7:AF:55:0C:3E',
    firmware: 'Tizen OS 5.5 — Build 2021.11',
    securityScore: 35,
    isInfrastructure: false,
    parent: 'router',
    canvasPos: { x: 0.50, y: 0.85 },
    breakdown: {
      firmware:       25,
      authentication: 30,
      encryption:     45,
      openPorts:      35,
      cveRisk:        40,
    },
    vulnerabilities: [
      { severity: 'critical', text: 'Tizen OS firmware 3+ years old — 15 unpatched CVEs including CVE-2022-41715 (arbitrary code execution)' },
      { severity: 'high',     text: 'ACR (Automatic Content Recognition) transmitting viewing history to Samsung ad servers' },
      { severity: 'high',     text: 'Built-in microphone listening by default — no hardware mute indicator or physical switch' },
      { severity: 'high',     text: 'Anynet+ (HDMI-CEC) hub accessible without authentication from LAN' },
      { severity: 'medium',   text: 'Open inbound ports: 8080 (HTTP), 9191 (SmartThings), 52235 (DLNA/UPnP), 7676 (remote)' },
      { severity: 'medium',   text: 'Not isolated from main LAN — can reach personal computers and printers' },
    ],
    recommendations: [
      'Update Tizen OS firmware immediately — critical CVEs present (Settings → Support → Software Update)',
      'Disable ACR: Settings → Terms & Privacy → Viewing Information Services → Off',
      'Mute microphone: Settings → General → Voice → Bixby Voice Wake-up → Off',
      'Isolate Smart TV to a dedicated IoT VLAN via router settings',
      'Disable DLNA/UPnP if local streaming is not in use',
      'Consider blocking TV outbound internet access via router firewall rules',
    ],
  },
  {
    id: 'printer',
    name: 'Network Printer',
    type: 'Peripheral',
    icon: '🖨️',
    model: 'HP LaserJet Pro M404n',
    ipAddress: '192.168.1.130',
    macAddress: '90:1B:0E:7A:44:C2',
    firmware: 'Firmware v002.1839A (December 2020)',
    securityScore: 28,
    isInfrastructure: false,
    parent: 'router',
    canvasPos: { x: 0.70, y: 0.81 },
    breakdown: {
      firmware:       20,
      authentication: 15,
      encryption:     30,
      openPorts:      25,
      cveRisk:        50,
    },
    vulnerabilities: [
      { severity: 'critical', text: 'Default admin credentials (admin / admin) still active on EWS web interface' },
      { severity: 'critical', text: 'Telnet service running on port 23 — all data (including credentials) in cleartext' },
      { severity: 'high',     text: 'Firmware 4+ years old — 8 known CVEs including CVE-2021-39237 (printer RCE)' },
      { severity: 'high',     text: 'Raw print port 9100 (JetDirect) requires no authentication — anyone on LAN can print' },
      { severity: 'medium',   text: 'SNMP v1/v2c enabled with default community string "public" — full device info exposed' },
      { severity: 'medium',   text: 'HTTP management interface active — login credentials sent in plaintext over LAN' },
    ],
    recommendations: [
      'Change admin password immediately via HP Embedded Web Server (http://192.168.1.130)',
      'Disable Telnet on the management port — enable SSH only if remote access is needed',
      'Update printer firmware via HP Support or EWS → Firmware Update',
      'Enable print job authentication (PIN-to-release) on JetDirect port',
      'Disable SNMP v1/v2c or change community string from "public" to a complex value',
      'Force HTTPS on EWS and disable plaintext HTTP',
      'Isolate printer to a dedicated VLAN accessible only from trusted endpoints',
    ],
  },
  {
    id: 'iot',
    name: 'IoT Devices',
    type: 'Smart Home Cluster',
    icon: '🏠',
    model: 'Hub + 5 Smart Devices (Thermostat, Cameras, Bulbs)',
    ipAddress: '192.168.1.140 – 192.168.1.145',
    macAddress: 'Multiple (6 devices)',
    firmware: 'Various — 2019 to 2022 builds',
    securityScore: 22,
    isInfrastructure: false,
    parent: 'router',
    canvasPos: { x: 0.86, y: 0.75 },
    breakdown: {
      firmware:       20,
      authentication: 15,
      encryption:     25,
      openPorts:      30,
      cveRisk:        20,
    },
    vulnerabilities: [
      { severity: 'critical', text: '3 of 5 devices using factory default credentials — trivially exploitable' },
      { severity: 'critical', text: 'All IoT devices on main LAN — unrestricted access to personal computers and NAS' },
      { severity: 'high',     text: 'UPnP active on 4 devices — automatically creating external port mappings on router' },
      { severity: 'high',     text: 'Unencrypted MQTT communication on port 1883 — device commands readable on LAN' },
      { severity: 'high',     text: '3 devices with no firmware updates in 2+ years — multiple unpatched CVEs' },
      { severity: 'medium',   text: 'Security cameras syncing to cloud without local encryption disclosure or audit trail' },
    ],
    recommendations: [
      'Change all IoT device passwords from factory defaults immediately',
      'Create a dedicated IoT SSID (2.4 GHz) with VLAN isolation — internet access only, no LAN access',
      'Disable UPnP on all IoT devices via their respective apps or admin panels',
      'Migrate to encrypted MQTT (TLS on port 8883) via MQTT broker configuration',
      'Enable automatic firmware update on all devices that support it; manually update others',
      'Consider Home Assistant for local-only smart home control (no cloud dependency)',
      'Review and restrict camera cloud storage — use local storage where possible',
    ],
  },
];

function computeOverallScore() {
  const scoredDevices = DEVICES.filter(d => d.securityScore !== null);
  if (!scoredDevices.length) return 0;
  const total = scoredDevices.reduce((sum, d) => sum + d.securityScore, 0);
  return Math.round(total / scoredDevices.length);
}
