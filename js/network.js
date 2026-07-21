// ==========================================
// NETWORK TOPOLOGY CANVAS VISUALIZATION
// Animated network graph with particles
// ==========================================

const NetworkGraph = (() => {
  let canvas, ctx;
  let W, H;
  let time = 0;
  let hoveredId  = null;
  let selectedId = null;
  let packets    = [];

  // Resolved pixel positions
  const nodeMap = {};

  // ── Initialize ────────────────────────────────────────────────
  function init() {
    canvas = document.getElementById('network-canvas');
    ctx    = canvas.getContext('2d');

    resize();
    window.addEventListener('resize', resize);
    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('click',     onClick);
    canvas.addEventListener('mouseleave', () => { hoveredId = null; canvas.style.cursor = 'default'; });

    spawnPackets();
    requestAnimationFrame(loop);
  }

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    W = rect.width;
    H = rect.height;
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    buildNodeMap();
  }

  function buildNodeMap() {
    DEVICES.forEach(d => {
      nodeMap[d.id] = {
        x:      d.canvasPos.x * W,
        y:      d.canvasPos.y * H,
        r:      d.isInfrastructure ? 30 : 26,
        device: d,
        phase:  Math.random() * Math.PI * 2,
      };
    });
  }

  // ── Packet spawning ───────────────────────────────────────────
  function spawnPackets() {
    packets = [];
    DEVICES.forEach(d => {
      if (!d.parent) return;
      for (let i = 0; i < 4; i++) {
        packets.push({
          fromId:   d.parent,
          toId:     d.id,
          t:        Math.random(),          // position along edge [0,1]
          speed:    0.0025 + Math.random() * 0.0025,
          size:     1.5 + Math.random() * 1.5,
          reverse:  Math.random() > 0.5,
        });
      }
    });
  }

  // ── Draw helpers ──────────────────────────────────────────────
  function scoreColor(score) {
    if (score === null) return '#00d4ff';
    return getRiskColor(score);
  }

  function lerp(a, b, t) { return a + (b - a) * t; }

  function drawEdge(na, nb, color) {
    const grad = ctx.createLinearGradient(na.x, na.y, nb.x, nb.y);
    grad.addColorStop(0,   'rgba(0,212,255,0.18)');
    grad.addColorStop(0.5, `${color}44`);
    grad.addColorStop(1,   'rgba(0,212,255,0.10)');

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(na.x, na.y);
    ctx.lineTo(nb.x, nb.y);
    ctx.strokeStyle = grad;
    ctx.lineWidth   = 1.5;
    ctx.stroke();
    ctx.restore();
  }

  function drawPacket(pkt) {
    const na = nodeMap[pkt.fromId];
    const nb = nodeMap[pkt.toId];
    if (!na || !nb) return;

    const t  = pkt.reverse ? 1 - pkt.t : pkt.t;
    const x  = lerp(na.x, nb.x, t);
    const y  = lerp(na.y, nb.y, t);
    const sc = scoreColor(nb.device.securityScore);

    ctx.save();
    // Glow halo
    const g = ctx.createRadialGradient(x, y, 0, x, y, pkt.size * 4);
    g.addColorStop(0, `${sc}99`);
    g.addColorStop(1, 'transparent');
    ctx.beginPath();
    ctx.arc(x, y, pkt.size * 4, 0, Math.PI * 2);
    ctx.fillStyle = g;
    ctx.fill();
    // Core dot
    ctx.beginPath();
    ctx.arc(x, y, pkt.size, 0, Math.PI * 2);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
    ctx.restore();
  }

  function drawNode(n) {
    const { x, y, r, device, phase } = n;
    const isHov = hoveredId  === device.id;
    const isSel = selectedId === device.id;
    const score = device.securityScore;
    const col   = scoreColor(score);
    const pulse = Math.sin(time * 1.8 + phase) * 0.5 + 0.5; // 0→1

    ctx.save();

    // ── Danger-pulse ring (critical/high risk only) ──
    if (score !== null && score <= 50) {
      const pr = r + 10 + pulse * 10;
      const pg = ctx.createRadialGradient(x, y, r, x, y, pr);
      pg.addColorStop(0, `${col}35`);
      pg.addColorStop(1, 'transparent');
      ctx.beginPath();
      ctx.arc(x, y, pr, 0, Math.PI * 2);
      ctx.fillStyle = pg;
      ctx.fill();
    }

    // ── Selection dashed ring ──
    if (isSel) {
      ctx.beginPath();
      ctx.arc(x, y, r + 10, 0, Math.PI * 2);
      ctx.strokeStyle = col;
      ctx.lineWidth   = 2;
      ctx.setLineDash([5, 4]);
      ctx.lineDashOffset = -(time * 28);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // ── Hover ring ──
    if (isHov && !isSel) {
      ctx.beginPath();
      ctx.arc(x, y, r + 7, 0, Math.PI * 2);
      ctx.strokeStyle = `${col}70`;
      ctx.lineWidth   = 1.5;
      ctx.stroke();
    }

    // ── Soft ambient glow ──
    const ag = ctx.createRadialGradient(x, y, r * 0.5, x, y, r + 4 + pulse * 4);
    ag.addColorStop(0, `${col}22`);
    ag.addColorStop(1, 'transparent');
    ctx.beginPath();
    ctx.arc(x, y, r + 4 + pulse * 4, 0, Math.PI * 2);
    ctx.fillStyle = ag;
    ctx.fill();

    // ── Main node fill ──
    const ng = ctx.createRadialGradient(x - r * 0.25, y - r * 0.25, 0, x, y, r);
    ng.addColorStop(0, '#162140');
    ng.addColorStop(1, '#050b18');
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = ng;
    ctx.fill();

    // ── Node border ──
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    if (score !== null && score <= 30) {
      // Critical: animated dashed border
      ctx.setLineDash([6, 3]);
      ctx.lineDashOffset = -(time * 18);
    }
    ctx.strokeStyle = (isHov || isSel) ? col : `${col}80`;
    ctx.lineWidth   = (isHov || isSel) ? 2.5 : 1.5;
    ctx.stroke();
    ctx.setLineDash([]);

    // ── Emoji icon ──
    ctx.font          = `${Math.round(r * 0.72)}px serif`;
    ctx.textAlign     = 'center';
    ctx.textBaseline  = 'middle';
    ctx.fillText(device.icon, x, y);

    // ── Label below node ──
    ctx.font          = `500 11px "Inter", sans-serif`;
    ctx.textBaseline  = 'top';
    ctx.fillStyle     = (isHov || isSel) ? '#e8f4ff' : '#7ba5cc';
    ctx.fillText(device.name, x, y + r + 6);

    // ── Score badge ──
    if (score !== null) {
      const bx = x + r * 0.72;
      const by = y - r * 0.72;
      ctx.beginPath();
      ctx.arc(bx, by, 11, 0, Math.PI * 2);
      ctx.fillStyle   = '#050b18';
      ctx.fill();
      ctx.strokeStyle = col;
      ctx.lineWidth   = 1.5;
      ctx.stroke();
      ctx.font          = `bold 9px "JetBrains Mono", monospace`;
      ctx.fillStyle     = col;
      ctx.textAlign     = 'center';
      ctx.textBaseline  = 'middle';
      ctx.fillText(`${score}`, bx, by);
    }

    ctx.restore();
  }

  // ── Hit testing ───────────────────────────────────────────────
  function hitTest(px, py) {
    for (const id of Object.keys(nodeMap)) {
      const n  = nodeMap[id];
      const dx = px - n.x;
      const dy = py - n.y;
      if (Math.hypot(dx, dy) <= n.r + 10) return id;
    }
    return null;
  }

  function onMouseMove(e) {
    const rect = canvas.getBoundingClientRect();
    hoveredId  = hitTest(e.clientX - rect.left, e.clientY - rect.top);
    canvas.style.cursor = hoveredId ? 'pointer' : 'default';
  }

  function onClick(e) {
    const rect = canvas.getBoundingClientRect();
    const hit  = hitTest(e.clientX - rect.left, e.clientY - rect.top);
    if (hit) {
      selectedId = hit;
      Dashboard.selectDevice(hit);
    }
  }

  // ── Main render loop ──────────────────────────────────────────
  function loop() {
    time += 0.016;

    // Advance packets
    packets.forEach(p => {
      p.t += p.speed;
      if (p.t >= 1) p.t = 0;
    });

    ctx.clearRect(0, 0, W, H);

    // Draw edges
    DEVICES.forEach(d => {
      if (!d.parent) return;
      const na = nodeMap[d.parent];
      const nb = nodeMap[d.id];
      if (na && nb) drawEdge(na, nb, scoreColor(d.securityScore));
    });

    // Draw packets
    packets.forEach(drawPacket);

    // Draw nodes (infra first, then endpoints)
    const ORDER = ['internet', 'modem', 'router', 'laptop', 'smartphone', 'smarttv', 'printer', 'iot'];
    ORDER.forEach(id => { if (nodeMap[id]) drawNode(nodeMap[id]); });

    requestAnimationFrame(loop);
  }

  // ── Public API ────────────────────────────────────────────────
  function selectNode(id) { selectedId = id; }

  return { init, selectNode };
})();
