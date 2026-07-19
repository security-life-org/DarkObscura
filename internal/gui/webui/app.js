// DarkObscura UI — served from the Go binary (`dobscura --gui`). Calls the
// in-process backend (/api/scan) and renders a rich, live intelligence dashboard.
import * as THREE from './vendor/three.module.js';

const $ = (id) => document.getElementById(id);

/* ── API auth: attach the token (from ?token=) to every /api/ request ── */
const API_TOKEN = new URLSearchParams(location.search).get('token') || '';
function withTok(u) {
  if (!API_TOKEN) return u;
  try {
    const url = new URL(u, location.origin);
    if (url.pathname.startsWith('/api/')) url.searchParams.set('token', API_TOKEN);
    return url.pathname + url.search;
  } catch { return u; }
}
if (API_TOKEN) {
  const _fetch = window.fetch.bind(window);
  window.fetch = (u, o) => _fetch(typeof u === 'string' ? withTok(u) : u, o);
  const _ES = window.EventSource;
  const Wrapped = function (u, o) { return new _ES(withTok(u), o); };
  Wrapped.CONNECTING = _ES.CONNECTING; Wrapped.OPEN = _ES.OPEN; Wrapped.CLOSED = _ES.CLOSED;
  window.EventSource = Wrapped;
}
const SEV = { critical: '#ff2d55', high: '#ff9f43', medium: '#ffcc55', low: '#79839c' };

/* ───────── mode switching ───────── */
const views = document.querySelectorAll('.view');
function setMode(mode) {
  document.querySelectorAll('.modes button').forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
  views.forEach((v) => v.classList.toggle('active', v.id === mode));
  if (mode === 'zen') requestAnimationFrame(resize);
}
document.querySelectorAll('.modes button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode)));

/* ───────── command palette ───────── */
const palette = $('palette'), pInput = palette.querySelector('input'), pList = palette.querySelector('ul');
const commands = [
  { ic: '◎', label: 'Switch to Zen dashboard', run: () => setMode('zen') },
  { ic: '▤', label: 'View discovered parameters', run: () => setMode('params') },
  { ic: '⇄', label: 'Open Tactical intercept', run: () => setMode('tactical') },
  { ic: '⌘', label: 'Open God / Kernel mode', run: () => setMode('god') },
  { ic: '⚡', label: 'Start scan on current target', run: runScan },
  { ic: '🕷', label: 'Crawl target — discover attack surface', run: () => crawlTarget() },
  { ic: '⚔', label: 'Race-condition test (marker: REDEEMED)', run: () => raceTest() },
  { ic: '🧬', label: 'HTTP request-smuggling probe', run: () => smuggleTest() },
  { ic: '📄', label: 'Export HTML report', run: () => exportReport() },
  { ic: '⬇', label: 'Export findings as JSON', run: () => exportFindings() },
  { ic: '🔎', label: 'Fingerprint tech + CVEs', run: () => fingerprintTarget() },
  { ic: '📦', label: 'Run Nuclei templates', run: () => templatesTarget() },
  { ic: '🌐', label: 'Client-side checks (CORS/cache/CSP)', run: () => clientsideTarget() },
  { ic: '🧩', label: 'DOM-XSS analysis', run: () => domTarget() },
  { ic: '🔑', label: 'Scan for leaked secrets', run: () => secretsTarget() },
  { ic: '🪝', label: 'Subdomain takeover check (host)', run: () => takeoverTarget() },
  { ic: '📡', label: 'gRPC reflection fuzz (host:port)', run: () => grpcTarget() },
];
let psel = 0, pfiltered = commands.slice();
function renderPalette(f = '') {
  pfiltered = commands.filter((c) => c.label.toLowerCase().includes(f.toLowerCase()));
  if (psel >= pfiltered.length) psel = 0;
  pList.innerHTML = '';
  pfiltered.forEach((c, i) => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="ic">${c.ic}</span> ${c.label}`;
    if (i === psel) li.classList.add('sel');
    li.onclick = () => { c.run(); closeP(); };
    pList.appendChild(li);
  });
}
const openP = () => { palette.classList.add('open'); pInput.value = ''; psel = 0; renderPalette(); pInput.focus(); };
const closeP = () => palette.classList.remove('open');
window.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); openP(); }
  else if (e.key === 'Escape') closeP();
  else if (palette.classList.contains('open')) {
    if (e.key === 'ArrowDown') { psel = Math.min(psel + 1, pfiltered.length - 1); renderPalette(pInput.value); }
    else if (e.key === 'ArrowUp') { psel = Math.max(psel - 1, 0); renderPalette(pInput.value); }
    else if (e.key === 'Enter' && pfiltered[psel]) { pfiltered[psel].run(); closeP(); }
  }
});
pInput.addEventListener('input', () => { psel = 0; renderPalette(pInput.value); });

/* ───────── WebGL attack graph ───────── */
const canvas = $('graph'), labelsEl = $('labels'), tooltip = $('tooltip');
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 1000);
camera.position.z = 62;
const FOV = 55 * Math.PI / 180;
const zPlane = new THREE.Plane(new THREE.Vector3(0, 0, 1), 0);
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

function resize() {
  const wrap = canvas.parentElement;
  const w = wrap.clientWidth || 800, h = wrap.clientHeight || 500;
  renderer.setSize(w, h, false);
  camera.aspect = w / h; camera.updateProjectionMatrix();
}
new ResizeObserver(resize).observe(canvas.parentElement);
window.addEventListener('resize', resize);
requestAnimationFrame(resize);

const COLORS = { endpoint: 0x35d0a5, param: 0xffcc55, risk: 0xff9f43, vuln: 0xff2d55 };
let graphNodes = [];  // {mesh, halo, data, labelEl}

function clearGraph() {
  for (const n of graphNodes) { scene.remove(n.mesh); if (n.halo) scene.remove(n.halo); n.labelEl.remove(); }
  scene.children.filter((c) => c.isLine).forEach((l) => scene.remove(l));
  graphNodes = [];
}

function addNode(n) {
  const isVuln = n.type === 'vuln', isEp = n.type === 'endpoint';
  const r = isEp ? 2.6 : isVuln ? 2.8 : 2.1;
  const mesh = new THREE.Mesh(new THREE.SphereGeometry(r, 32, 32),
    new THREE.MeshBasicMaterial({ color: COLORS[n.type] }));
  mesh.position.set(n.x, n.y, 0); mesh.userData = n;
  scene.add(mesh);
  let halo = null;
  if (isVuln) {
    halo = new THREE.Mesh(new THREE.SphereGeometry(r * 1.8, 32, 32),
      new THREE.MeshBasicMaterial({ color: 0xff2d55, transparent: true, opacity: 0.18 }));
    halo.position.copy(mesh.position); scene.add(halo);
  }
  const labelEl = document.createElement('div');
  labelEl.className = 'node-label' + (isVuln ? ' vuln' : isEp ? ' ep' : '');
  labelEl.innerHTML = n.label + (n.risk && !isEp && !isVuln ? `<span class="risk-tag">${n.risk}</span>` : '');
  labelsEl.appendChild(labelEl);
  graphNodes.push({ mesh, halo, data: n, labelEl });
}

function edge(a, b) {
  const g = new THREE.BufferGeometry().setFromPoints([a, b]);
  scene.add(new THREE.Line(g, new THREE.LineBasicMaterial({ color: 0x2c3346, transparent: true, opacity: 0.6 })));
}

function buildGraph(nodes, edges) {
  clearGraph();
  const byId = new Map();
  nodes.forEach((n) => { addNode(n); byId.set(n.id, n); });
  edges.forEach(([a, b]) => edge(
    new THREE.Vector3(byId.get(a).x, byId.get(a).y, 0),
    new THREE.Vector3(byId.get(b).x, byId.get(b).y, 0)));
  if (typeof fitView === 'function') fitView();
}

// radial layout: endpoint center, params on a ring.
function layoutScan(host, params, vulnSet) {
  const nodes = [{ id: 'root', type: 'endpoint', x: 0, y: 0, label: host || 'target' }];
  const edges = [];
  // Multi-ring radial layout: spread nodes across concentric rings so labels
  // don't collide when there are many params. fitView() then frames them all.
  const perRing = 14, ringGap = 16, baseR = 22;
  params.forEach((p, i) => {
    const ring = Math.floor(i / perRing);
    const inRing = i % perRing;
    const countInRing = Math.min(perRing, params.length - ring * perRing);
    const R = baseR + ring * ringGap;
    const a = (inRing / Math.max(1, countInRing)) * Math.PI * 2 - Math.PI / 2 + ring * 0.4;
    const vuln = vulnSet.has(p.name);
    nodes.push({
      id: 'p' + i, label: p.name, risk: p.risk,
      type: vuln ? 'vuln' : (p.risk === 'high' || p.risk === 'critical' ? 'risk' : 'param'),
      x: Math.cos(a) * R, y: Math.sin(a) * R * 0.82,
      detail: p, vuln,
    });
    edges.push(['root', 'p' + i]);
  });
  buildGraph(nodes, edges);
}

// initial idle graph
buildGraph(
  [{ id: 'root', type: 'endpoint', x: 0, y: 0, label: 'awaiting target' },
   { id: 'a', type: 'param', x: -24, y: 8, label: 'id', risk: 'high' },
   { id: 'b', type: 'risk', x: 24, y: 10, label: 'redirect', risk: 'high' },
   { id: 'c', type: 'param', x: 0, y: -20, label: 'q', risk: 'medium' }],
  [['root', 'a'], ['root', 'b'], ['root', 'c']]);

// project + place labels, pulse halos, hover tooltip
const ray = new THREE.Raycaster(), mouse = new THREE.Vector2();
let hovered = null;
canvas.addEventListener('mousemove', (e) => {
  const r = canvas.getBoundingClientRect();
  mouse.x = ((e.clientX - r.left) / r.width) * 2 - 1;
  mouse.y = -((e.clientY - r.top) / r.height) * 2 + 1;
  ray.setFromCamera(mouse, camera);
  const hit = ray.intersectObjects(graphNodes.map((n) => n.mesh))[0];
  hovered = hit ? hit.object.userData : null;
  if (hovered && hovered.detail) {
    const p = hovered.detail;
    tooltip.style.display = 'block';
    tooltip.style.left = (e.clientX - r.left + 14) + 'px';
    tooltip.style.top = (e.clientY - r.top + 10) + 'px';
    tooltip.innerHTML = `<div class="t-title">${hovered.label} ${hovered.vuln ? '⚠' : ''}</div>` +
      `location: ${p.location || '—'}<br>risk: ${p.risk}<br>` +
      (p.reasons || []).map((x) => `· ${x}`).join('<br>');
  } else { tooltip.style.display = 'none'; }
});
canvas.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });

/* ── camera controls: wheel-zoom (toward cursor), drag-pan, dbl-click fit ── */
function cursorWorld(e) {
  const r = canvas.getBoundingClientRect();
  mouse.x = ((e.clientX - r.left) / r.width) * 2 - 1;
  mouse.y = -((e.clientY - r.top) / r.height) * 2 + 1;
  ray.setFromCamera(mouse, camera);
  const pt = new THREE.Vector3();
  return ray.ray.intersectPlane(zPlane, pt) ? pt : null;
}
canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  const before = cursorWorld(e);
  const factor = Math.exp(e.deltaY * 0.0015);
  camera.position.z = Math.min(600, Math.max(8, camera.position.z * factor));
  camera.updateProjectionMatrix();
  const after = cursorWorld(e);
  if (before && after) { camera.position.x += before.x - after.x; camera.position.y += before.y - after.y; }
}, { passive: false });

let dragging = false, lastX = 0, lastY = 0, dragMoved = 0;
canvas.style.cursor = 'grab';
canvas.addEventListener('pointerdown', (e) => {
  if (e.button !== 0) return;
  dragging = true; dragMoved = 0; lastX = e.clientX; lastY = e.clientY;
  canvas.style.cursor = 'grabbing';
  try { canvas.setPointerCapture(e.pointerId); } catch (_) {}
});
canvas.addEventListener('pointermove', (e) => {
  if (!dragging) return;
  const dx = e.clientX - lastX, dy = e.clientY - lastY;
  lastX = e.clientX; lastY = e.clientY; dragMoved += Math.abs(dx) + Math.abs(dy);
  const H = canvas.parentElement.clientHeight || 500;
  const worldPerPx = (2 * camera.position.z * Math.tan(FOV / 2)) / H;
  camera.position.x -= dx * worldPerPx;
  camera.position.y += dy * worldPerPx;
  if (dragMoved > 3) tooltip.style.display = 'none';
});
function endDrag(e) {
  if (!dragging) return;
  dragging = false; canvas.style.cursor = 'grab';
  try { canvas.releasePointerCapture(e.pointerId); } catch (_) {}
}
canvas.addEventListener('pointerup', endDrag);
canvas.addEventListener('pointercancel', endDrag);
canvas.addEventListener('dblclick', () => fitView());

// Frame all nodes so nothing spills off-screen, however many there are.
function fitView() {
  if (!graphNodes.length) return;
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of graphNodes) {
    const p = n.mesh.position;
    if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
    if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
  }
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  const spanX = (maxX - minX) || 1, spanY = (maxY - minY) || 1;
  const wrap = canvas.parentElement;
  const aspect = (wrap.clientWidth || 800) / (wrap.clientHeight || 500);
  const pad = 1.35;
  const distY = (spanY * pad / 2) / Math.tan(FOV / 2);
  const distX = (spanX * pad / 2) / (Math.tan(FOV / 2) * aspect);
  camera.position.set(cx, cy, Math.min(600, Math.max(14, Math.max(distX, distY) + 8)));
  camera.updateProjectionMatrix();
}

let t = 0;
function animate() {
  requestAnimationFrame(animate);
  t += 0.05;
  const wrap = canvas.parentElement, W = wrap.clientWidth, H = wrap.clientHeight;
  for (const n of graphNodes) {
    if (n.halo) { const s = 1 + Math.sin(t * 1.5) * 0.12; n.halo.scale.setScalar(s); n.halo.material.opacity = 0.12 + Math.sin(t * 1.5) * 0.06; }
    const v = n.mesh.position.clone().project(camera);
    n.labelEl.style.left = ((v.x * 0.5 + 0.5) * W) + 'px';
    n.labelEl.style.top = ((-v.y * 0.5 + 0.5) * H) + 'px';
    n.labelEl.style.display = (v.z < 1) ? 'block' : 'none';
  }
  renderer.render(scene, camera);
}
animate();

/* ───────── live console ───────── */
const consoleEl = $('console');
function logLine(level, msg) {
  const d = new Date();
  const ts = d.toTimeString().slice(0, 8);
  const line = document.createElement('div');
  line.className = 'line';
  line.innerHTML = `<span class="ts">${ts}</span><span class="lv ${level}">${level.toUpperCase()}</span><span class="msg">${msg}</span>`;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
  while (consoleEl.children.length > 200) consoleEl.removeChild(consoleEl.firstChild);
  return line;
}
logLine('info', 'DarkObscura engine ready · verification-gated · zero-false-positive');

/* ───────── global activity / busy indicator ───────── */
let __busyOps = 0;
function setBusy(on) {
  __busyOps = Math.max(0, __busyOps + (on ? 1 : -1));
  document.body.classList.toggle('busy', __busyOps > 0);
}
// activity() starts an animated "⏳ working" console line + top-bar spinner and
// returns a handle. Call .done(msg, level) when finished so nothing ever looks
// silently stuck.
function activity(label) {
  setBusy(true);
  const line = logLine('info', `⏳ ${label}`);
  const msgEl = line.querySelector('.msg');
  let dots = 0;
  const timer = setInterval(() => {
    dots = (dots + 1) % 4;
    msgEl.textContent = `⏳ ${label}${'.'.repeat(dots)}`;
  }, 400);
  let closed = false;
  return {
    step(m) { if (!closed) msgEl.textContent = `⏳ ${m}`; },
    done(m, level) {
      if (closed) return; closed = true;
      clearInterval(timer); setBusy(false);
      const lv = level || 'ok';
      line.querySelector('.lv').className = 'lv ' + lv;
      line.querySelector('.lv').textContent = lv.toUpperCase();
      if (m) msgEl.textContent = m;
      consoleEl.scrollTop = consoleEl.scrollHeight;
    },
  };
}

/* ───────── scan orchestration ───────── */
const targetEl = $('target'), authzEl = $('authz'), scanBtn = $('scan'), sweep = $('sweep');
let lastFindings = [];
let lastData = null;

let evtSource = null;
let liveConfirmed = 0;

let __streamHeartbeat = null, __lastEvent = 0;
function startHeartbeat(what) {
  __lastEvent = Date.now();
  stopHeartbeat();
  __streamHeartbeat = setInterval(() => {
    const idle = Math.round((Date.now() - __lastEvent) / 1000);
    if (idle >= 3) $('graph-meta').textContent = `${what}… (${idle}s)`;
  }, 1000);
}
function stopHeartbeat() { if (__streamHeartbeat) { clearInterval(__streamHeartbeat); __streamHeartbeat = null; } }

let __streamBusy = false;
function streamBusy(on) { if (on && !__streamBusy) { setBusy(true); __streamBusy = true; } else if (!on && __streamBusy) { setBusy(false); __streamBusy = false; } }

function endScan() {
  scanBtn.disabled = false; scanBtn.classList.remove('scanning'); sweep.classList.remove('on');
  stopHeartbeat(); streamBusy(false);
  if (evtSource) { evtSource.close(); evtSource = null; }
}

// runScan streams the scan live over Server-Sent Events: each verification stage
// appears in the console as it actually happens, not after the fact.
function runScan() {
  const url = targetEl.value.trim();
  if (!url) { logLine('warn', 'no target URL entered'); targetEl.focus(); return; }
  if (!authzEl.checked) { logLine('warn', 'authorization required — tick the "authorized" box'); return; }
  if (evtSource) evtSource.close();
  scanBtn.disabled = true; scanBtn.classList.add('scanning'); sweep.classList.add('on'); streamBusy(true);
  liveConfirmed = 0;
  $('graph-meta').textContent = 'scanning…';
  $('s-conf').textContent = '0'; $('s-crit').textContent = '0';
  logLine('info', `initiating live scan → ${url}`);
  startHeartbeat('scanning');

  evtSource = new EventSource(`/api/scan/stream?url=${encodeURIComponent(url)}&authorized=1`);
  evtSource.addEventListener('progress', (e) => { __lastEvent = Date.now(); handleProgress(JSON.parse(e.data)); });
  evtSource.addEventListener('scanerror', (e) => { logLine('warn', 'scan error: ' + (JSON.parse(e.data).error || '')); endScan(); });
  evtSource.addEventListener('done', (e) => {
    endScan(); // close the stream first so a render error can't reconnect-loop
    try { renderAll(JSON.parse(e.data)); logLine('ok', 'scan complete'); }
    catch (err) { logLine('warn', 'render error: ' + err.message); }
  });
  evtSource.onerror = () => { if (evtSource && evtSource.readyState === EventSource.CLOSED) { logLine('warn', 'stream closed'); endScan(); } };
}

/* ───────── deep scan (crawl + scan every endpoint) ───────── */
const deepBtn = $('deepscan');
function endDeep() {
  deepBtn.disabled = false; deepBtn.classList.remove('scanning');
  scanBtn.disabled = false; sweep.classList.remove('on');
  stopHeartbeat(); streamBusy(false);
  if (evtSource) { evtSource.close(); evtSource = null; }
}
function deepScan() {
  let url = targetEl.value.trim();
  if (!url) { logLine('warn', 'enter a base URL (e.g. http://site) to deep-scan'); targetEl.focus(); return; }
  if (!authzEl.checked) { logLine('warn', 'authorization required — tick the "authorized" box'); return; }
  if (evtSource) evtSource.close();
  deepBtn.disabled = true; deepBtn.classList.add('scanning'); scanBtn.disabled = true; sweep.classList.add('on'); streamBusy(true);
  liveConfirmed = 0; $('s-conf').textContent = '0'; $('s-crit').textContent = '0';
  $('graph-meta').textContent = 'crawling…';
  logLine('info', `🕸 DEEP SCAN → ${url} (crawl + scan all endpoints)`);
  startHeartbeat('crawling + scanning');
  evtSource = new EventSource(`/api/deepscan/stream?url=${encodeURIComponent(url)}&authorized=1`);
  evtSource.addEventListener('progress', (e) => { __lastEvent = Date.now(); handleProgress(JSON.parse(e.data)); });
  evtSource.addEventListener('scanerror', (e) => { logLine('warn', 'deep-scan error: ' + (JSON.parse(e.data).error || '')); endDeep(); });
  evtSource.addEventListener('done', (e) => {
    endDeep(); // close the stream FIRST so a render error can't cause a reconnect loop
    try { renderDeep(JSON.parse(e.data)); logLine('ok', 'deep scan complete'); }
    catch (err) { logLine('warn', 'render error: ' + err.message); }
  });
  evtSource.onerror = () => { if (evtSource && evtSource.readyState === EventSource.CLOSED) endDeep(); };
}
deepBtn.onclick = deepScan;

function renderDeep(data) {
  const eps = data.endpoints || [], findings = data.findings || [], s = data.summary || {};
  lastFindings = findings;
  lastData = { summary: s, params: [], findings, passive: data.passive, capture: null,
    endpoints: eps, origin: data.origin };

  $('intel-host').textContent = data.origin || s.host || 'origin';
  $('intel-meta').textContent = `deep scan · ${eps.length} endpoints · ${s.paramsFound} params · ${s.durationMs} ms`;
  $('graph-meta').textContent = `${eps.length} endpoints · ${findings.length} confirmed`;
  $('s-params').textContent = eps.length;      // show endpoint count as the headline
  $('s-probed').textContent = s.paramsProbed || 0;
  $('s-conf').textContent = s.total || 0;
  $('s-crit').textContent = s.critical || 0;
  $('find-count').textContent = findings.length;
  renderSevbar(s);

  // Multi-endpoint attack graph: origin at centre, one node per endpoint.
  layoutDeep(data.origin, eps);

  renderFindings(findings.map((f) => ({ ...f, param: `${f.param}  ·  ${pathOf(f.endpoint)}` })));
  renderPassive(data.passive || []);
  refreshModes(); // params / tactical / god

  const table = eps.map((e) => `${e.path} [${e.params.join(', ') || '—'}] → ${e.findings} finding(s)`);
  logLine('info', `discovered endpoints:`);
  table.forEach((t) => logLine(/[1-9]\d* finding/.test(t) ? 'vuln' : 'info', '  ↳ ' + t));
}

// layoutDeep draws the origin surrounded by its discovered endpoints; endpoints
// with confirmed findings glow red.
function layoutDeep(origin, eps) {
  const nodes = [{ id: 'root', type: 'endpoint', x: 0, y: 0, label: originHost(origin) }];
  const edges = [];
  const perRing = 14, ringGap = 17, baseR = 24;
  eps.forEach((e, i) => {
    const ring = Math.floor(i / perRing);
    const inRing = i % perRing;
    const countInRing = Math.min(perRing, eps.length - ring * perRing);
    const R = baseR + ring * ringGap;
    const a = (inRing / Math.max(1, countInRing)) * Math.PI * 2 - Math.PI / 2 + ring * 0.4;
    nodes.push({
      id: 'e' + i, label: e.path || '/', risk: (e.params || []).join(','),
      type: e.findings > 0 ? 'vuln' : 'param', url: e.url,
      x: Math.cos(a) * R, y: Math.sin(a) * R * 0.82,
      detail: { name: e.path, location: 'endpoint', risk: `${e.params.length} param(s)`, reasons: e.params, url: e.url },
      vuln: e.findings > 0,
    });
    edges.push(['root', 'e' + i]);
  });
  buildGraph(nodes, edges);
}
function pathOf(u) { try { return new URL(u).pathname; } catch { return u || ''; } }
function originHost(u) { try { return new URL(u).host; } catch { return (u || 'origin').replace(/^https?:\/\//, ''); } }

// handleProgress renders one live scan event.
function handleProgress(p) {
  switch (p.kind) {
    case 'scan-start': logLine('info', `engine engaged · target ${p.message}`); break;
    case 'deep': logLine('info', p.message); break;
    case 'param':
      logLine(p.severity === 'critical' || p.severity === 'high' ? 'warn' : 'info',
        `parameter «${p.param}» → ${p.message}`); break;
    case 'probe': logLine('info', `  probing «${p.param}» · ${p.class} · ${truncate(p.payload, 42)}`); break;
    case 'stage': logLine('info', `    ├─ ${p.stage}: ${p.message}`); break;
    case 'finding':
      liveConfirmed++;
      $('s-conf').textContent = liveConfirmed;
      logLine('vuln', `⚠ CONFIRMED ${p.class} on «${p.param}» — ${p.message.replace('CONFIRMED ' + p.class + ' ', '')}`);
      break;
    case 'param-done': logLine('ok', `  «${p.param}» done · ${p.message}`); break;
    case 'passive': logLine(p.severity === 'high' ? 'warn' : 'info', `passive · ${p.message} [${p.severity}]`); break;
    case 'waf': logLine(p.severity === 'warning' ? 'warn' : 'info', p.message); setWafBadge(p.message, p.severity); break;
  }
}

// setWafBadge shows a persistent WAF/block indicator in the top bar.
function setWafBadge(msg, severity) {
  let b = document.getElementById('waf-badge');
  if (!b) {
    b = document.createElement('span');
    b.id = 'waf-badge';
    const brand = document.querySelector('.brand');
    if (brand) brand.appendChild(b);
  }
  const blocked = severity === 'warning';
  b.className = 'waf-badge ' + (blocked ? 'blocked' : 'present');
  b.textContent = blocked ? '⚠ WAF BLOCKING' : '🛡 WAF';
  b.title = msg;
}
scanBtn.onclick = runScan;
targetEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') runScan(); });
function truncate(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n) + '…' : s; }

function renderAll(data) {
  const s = data.summary || {}, params = data.params || [], findings = data.findings || [];
  lastFindings = findings; lastData = data;
  const vulnSet = new Set(findings.map((f) => f.param));

  // header + stats
  $('intel-host').textContent = s.host || 'target';
  $('intel-meta').textContent = `scanned in ${s.durationMs} ms · ${s.paramsFound} params · ${s.paramsProbed} probed`;
  $('graph-meta').textContent = `${params.length} nodes · ${findings.length} confirmed`;
  $('s-params').textContent = s.paramsFound || 0;
  $('s-probed').textContent = s.paramsProbed || 0;
  $('s-conf').textContent = s.total || 0;
  $('s-crit').textContent = s.critical || 0;
  $('find-count').textContent = findings.length;

  // severity bar
  renderSevbar(s);
  layoutScan(s.host, params, vulnSet);
  renderFindings(findings);
  renderPassive(data.passive || []);
  refreshModes(); // params / tactical / god

  if (findings.length === 0) logLine('ok', '✔ 0 confirmed vulnerabilities — zero false positives by design');
}

function renderPassive(issues) {
  const el = $('passive');
  $('passive-count').textContent = issues.length;
  if (!issues.length) {
    el.innerHTML = `<div class="empty">No passive issues found in the captured response.</div>`;
    return;
  }
  const rank = { high: 0, medium: 1, low: 2, info: 3 };
  issues = issues.slice().sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  el.innerHTML = issues.map((i) => `
    <div class="pissue ${i.severity}">
      <div class="pt"><b>${esc(i.title)}</b><span class="psev">${i.severity}</span></div>
      <div class="pd">${esc(i.detail)}</div>
      ${i.evidence ? `<div class="pe">${esc(i.evidence)}</div>` : ''}
    </div>`).join('');
}

function renderSevbar(s) {
  const bar = $('sevbar'), leg = $('sevlegend');
  const parts = [['critical', s.critical], ['high', s.high], ['medium', s.medium], ['low', s.low]];
  const total = parts.reduce((a, [, n]) => a + (n || 0), 0) || 1;
  bar.innerHTML = parts.map(([k, n]) => n ? `<span style="width:${(n / total) * 100}%;background:${SEV[k]}"></span>` : '').join('');
  leg.innerHTML = parts.map(([k, n]) => `<span><i style="background:${SEV[k]}"></i>${k} ${n || 0}</span>`).join('');
}

// pipelineHTML renders the exact verification stages a finding passed as a
// horizontal green stepper — adapts to any vulnerability class.
function pipelineHTML(stages) {
  if (!stages || !stages.length) return '';
  let html = '<div class="pipeline">';
  stages.forEach((name, i) => {
    html += `<div class="pipe-stage pass"><div class="pipe-node"></div>` +
      `<div class="pipe-label">${esc(name)}</div></div>`;
    if (i < stages.length - 1) html += `<div class="pipe-line pass"></div>`;
  });
  return html + '</div>';
}

function renderFindings(findings) {
  const el = $('findings');
  if (!findings.length) {
    el.innerHTML = `<div class="empty">No confirmed vulnerabilities. Every candidate was rejected by the
      verification pipeline — zero false positives by design.</div>`;
    return;
  }
  el.innerHTML = '';
  findings.forEach((f) => {
    const div = document.createElement('div');
    div.className = 'finding';
    div.style.borderLeftColor = SEV[f.severity] || SEV.high;
    div.innerHTML =
      `<div class="f-head">
        <span class="chev">▸</span>
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="f-class">${f.class}</span>
        <span class="f-param">${f.param}</span>
      </div>
      <div class="f-body">
        <div class="kv">payload &nbsp;<code>${esc(f.payload)}</code></div>
        <div class="kv">verified via <b style="color:var(--ok)">${f.verifiedVia}</b></div>
        ${pipelineHTML(f.stages || [])}
        <div class="evidence">${(f.evidence || []).map((e) => `<div>${fmtEvidence(e)}</div>`).join('')}</div>
        ${attackable(f) ? `<button class="prove-btn">⚡ Prove exploit — extract live evidence</button>` : ''}
      </div>`;
    div.querySelector('.f-head').onclick = () => div.classList.toggle('open');
    const pb = div.querySelector('.prove-btn');
    if (pb) pb.onclick = (e) => { e.stopPropagation(); openAttack(f, pb); };
    el.appendChild(div);
  });
  findings[0] && el.firstChild.classList.add('open');
}

// refreshModes repaints the Params / Tactical / God views from lastData after
// any scan. Called by both renderAll and renderDeep.
function refreshModes() {
  renderParams();
  renderTactical();
  renderGod();
}

// buildInventory flattens lastData into a per-injection-point inventory usable
// by the Params view, aggregating findings per (endpoint, param).
function buildInventory() {
  const d = lastData; if (!d) return [];
  const findByKey = {};
  (d.findings || []).forEach((f) => {
    const ep = f.endpoint || (d.summary && d.summary.target) || '';
    const k = ep + '|' + f.param;
    findByKey[k] = (findByKey[k] || 0) + 1;
  });
  const rows = [];
  if (d.endpoints && d.endpoints.length) {              // deep scan
    d.endpoints.forEach((ep) => (ep.params || []).forEach((p) => {
      const fc = findByKey[ep.url + '|' + p] || 0;
      rows.push({ name: p, location: 'query', endpoint: ep.path, url: ep.url,
        risk: fc > 0 ? 'high' : 'low', probed: true, findings: fc, reasons: [] });
    }));
  } else {                                              // single-URL scan
    (d.params || []).forEach((p) => {
      const url = d.summary && d.summary.target;
      rows.push({ name: p.name, location: p.location, endpoint: pathOf(url), url,
        risk: p.risk, probed: p.probed, findings: findByKey[(url || '') + '|' + p.name] || 0, reasons: p.reasons || [] });
    });
  }
  return rows;
}

function renderParams() {
  const rows = buildInventory();
  const d = lastData || {};
  $('param-meta').textContent = rows.length
    ? `${(d.origin || (d.summary && d.summary.host) || '')} · ${rows.length} injection points`
    : '—';
  const body = $('param-body');
  if (!rows.length) { body.innerHTML = `<tr><td colspan="6" class="empty">Run a scan to enumerate parameters.</td></tr>`; return; }
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  rows.sort((a, b) => (b.findings - a.findings) || ((rank[a.risk] ?? 9) - (rank[b.risk] ?? 9)));
  body.innerHTML = rows.map((p) => `
    <tr class="clickable" data-url="${esc(p.url || '')}" data-name="${esc(p.name)}" data-loc="${p.location}">
      <td class="pname">${esc(p.name)}</td>
      <td class="muted">${p.location || '—'}</td>
      <td class="epcol">${esc(p.endpoint || '—')}</td>
      <td><span class="pill ${p.risk}">${p.risk}</span></td>
      <td class="findcol">${p.findings ? `<b>${p.findings} finding(s)</b>` : '<span class="muted">clean</span>'}</td>
      <td class="reasons">${(p.reasons || []).join(' · ') || (p.findings ? 'confirmed vulnerable' : '')}</td>
    </tr>`).join('');
  // Click a param → prefill the manual payload console and jump to God mode.
  body.querySelectorAll('tr.clickable').forEach((tr) => {
    tr.onclick = () => {
      $('pc-url').value = tr.dataset.url;
      $('pc-param').value = tr.dataset.name;
      $('pc-loc').value = tr.dataset.loc === 'header' || tr.dataset.loc === 'cookie' ? tr.dataset.loc : 'query';
      setMode('god');
      logLine('info', `loaded «${tr.dataset.name}» into the payload console`);
    };
  });
}

// Tactical = a live HTTP repeater. Prefills the editable request from the last
// capture (or a template for the target).
let repeatBase = '';
function renderTactical() {
  const d = lastData; if (!d) return;
  const cap = d.capture;
  const req = $('req-edit');
  if (cap && cap.request) {
    req.value = cap.request;
    repeatBase = d.origin || deriveOrigin((d.summary && d.summary.target) || '');
  } else {
    const t = (d.summary && d.summary.target) || (d.origin || '');
    try {
      const u = new URL(t);
      req.value = `GET ${u.pathname}${u.search || ''} HTTP/1.1\nHost: ${u.host}\nUser-Agent: DarkObscura/0.1\nAccept: */*`;
      repeatBase = u.origin;
    } catch { /* leave placeholder */ }
  }
}

function renderGod() {
  const d = lastData; if (!d) return;
  // Prefill the payload console with the first injection point.
  const inv = buildInventory();
  if (inv.length && !$('pc-url').value) {
    $('pc-url').value = inv[0].url || '';
    $('pc-param').value = inv[0].name || '';
  }
}

function deriveOrigin(u) { try { return new URL(u).origin; } catch { return u; } }

/* ───────── Tactical repeater ───────── */
$('repeat-send').onclick = async () => {
  const raw = $('req-edit').value.trim();
  if (!raw) { $('repeat-meta').textContent = 'nothing to send'; return; }
  $('repeat-meta').textContent = 'sending…';
  try {
    const res = await fetch('/api/repeat', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw, base: repeatBase }) });
    const d = await res.json();
    if (d.error) { $('repeat-meta').textContent = 'error: ' + d.error; $('resp').textContent = ''; return; }
    $('repeat-meta').textContent = `HTTP ${d.status} · ${d.elapsedMs} ms · ${d.length} B`;
    $('resp').innerHTML = highlightResp(esc(d.response));
    logLine('info', `repeater → HTTP ${d.status} (${d.elapsedMs}ms)`);
  } catch (err) { $('repeat-meta').textContent = 'error: ' + err.message; }
};
// Ctrl/Cmd+Enter sends the request.
$('req-edit').addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); $('repeat-send').click(); }
});
function highlightResp(s) {
  return s.replace(/(&lt;svg\/onload=[^&\s]*|&lt;script&gt;[^&]*|dobx\d+|root:.*:0:0:)/g, '<span class="hl">$1</span>');
}

/* ───────── God: manual payload console ───────── */
$('pc-send').onclick = async () => {
  const url = $('pc-url').value.trim(), param = $('pc-param').value.trim();
  const location = $('pc-loc').value, payload = $('pc-payload').value;
  if (!url || !param) { $('pc-verdict').innerHTML = '<span class="v-badge miss">enter a URL and a parameter/header name</span>'; return; }
  $('pc-verdict').innerHTML = '<span class="row">firing…</span>';
  try {
    const res = await fetch('/api/probe', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, param, location, payload }) });
    const d = await res.json();
    renderProbe(d);
    logLine('info', `payload console → ${param} [${location}] HTTP ${d.status || '?'}${d.reflected ? ' · REFLECTED' : ''}`);
  } catch (err) { $('pc-verdict').innerHTML = '<span class="v-badge miss">error: ' + esc(err.message) + '</span>'; }
};
$('pc-payload').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('pc-send').click(); });

function renderProbe(d) {
  if (d.error) { $('pc-verdict').innerHTML = `<span class="v-badge miss">error: ${esc(d.error)}</span>`; return; }
  const hit = d.reflected;
  $('pc-verdict').innerHTML =
    `<span class="v-badge ${hit ? 'hit' : 'miss'}">${hit ? '⚠ PAYLOAD REFLECTED' : '○ not reflected'}</span>` +
    `<div class="row">status <b>${d.status}</b></div>` +
    `<div class="row">time <b>${d.elapsedMs} ms</b></div>` +
    `<div class="row">length <b>${d.length} B</b></div>`;
  const body = d.body || '';
  $('god-meta').textContent = `HTTP ${d.status} · ${d.elapsedMs} ms · ${d.length} B`;
  $('god-resp').innerHTML = highlightResp(esc(body.slice(0, 6000)));
  $('god-ast').innerHTML = astOf(body);
  $('god-hex').innerHTML = hexdump(body.slice(0, 256));
}

// astOf renders the response structure: JSON tree or HTML tag frequency.
function astOf(body) {
  try {
    const j = JSON.parse(body);
    return syntaxJSON(JSON.stringify(j, null, 2).slice(0, 4000));
  } catch { /* not JSON */ }
  const tags = {};
  (body.match(/<([a-zA-Z][a-zA-Z0-9]*)/g) || []).forEach((t) => {
    const n = t.slice(1).toLowerCase(); tags[n] = (tags[n] || 0) + 1;
  });
  const entries = Object.entries(tags).sort((a, b) => b[1] - a[1]);
  return entries.map(([t, c]) => `<span class="tok-key">&lt;${t}&gt;</span> <span class="tok-num">×${c}</span>`).join('\n') || '(no structure)';
}

function exportFindings() {
  const blob = new Blob([JSON.stringify(lastFindings, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'darkobscura-findings.json'; a.click();
  logLine('ok', `exported ${lastFindings.length} finding(s) as JSON`);
}

// exportReport builds a self-contained HTML report of the last scan.
function exportReport() {
  if (!lastData) { logLine('warn', 'run a scan before exporting a report'); return; }
  const s = lastData.summary || {}, findings = lastData.findings || [], params = lastData.params || [];
  const row = (f) => `<div class="f"><span class="b ${f.severity}">${f.severity}</span>
    <b>${esc(f.class)}</b> on <code>${esc(f.param)}</code> · verified via ${esc(f.verifiedVia)}
    <div class="pl">payload: <code>${esc(f.payload)}</code></div>
    <ul>${(f.evidence || []).map((e) => `<li>${esc(e)}</li>`).join('')}</ul></div>`;
  const doc = `<!doctype html><meta charset="utf-8"><title>DarkObscura Report — ${esc(s.host || '')}</title>
<style>body{font:14px/1.6 ui-monospace,monospace;background:#0b0d17;color:#e4e8f2;max-width:900px;margin:40px auto;padding:0 20px}
h1{color:#7c5cff}code{background:#12141f;padding:2px 6px;border-radius:4px}
.grid{display:flex;gap:20px;margin:16px 0}.stat{background:#12141f;border:1px solid #232838;border-radius:10px;padding:14px 20px}
.stat b{font-size:26px;display:block}.f{background:#12141f;border:1px solid #232838;border-left:3px solid #ff2d55;border-radius:10px;padding:12px 16px;margin:10px 0}
.b{font-size:10px;text-transform:uppercase;padding:2px 8px;border-radius:20px;background:#ff2d5522;color:#ff6b85;margin-right:6px}
.b.high{background:#ff9f4322;color:#ff9f43}.pl{color:#79839c;margin:6px 0}ul{color:#79839c;font-size:12px}
table{width:100%;border-collapse:collapse;margin:10px 0}td,th{text-align:left;padding:6px 10px;border-bottom:1px solid #232838;font-size:12px}</style>
<h1>◈ DarkObscura — Security Report</h1>
<p>Target: <code>${esc(s.target || '')}</code><br>Scanned in ${s.durationMs} ms · zero-false-positive verification</p>
<div class="grid"><div class="stat"><b>${s.paramsFound || 0}</b>parameters</div>
<div class="stat"><b>${s.total || 0}</b>confirmed</div><div class="stat"><b>${s.critical || 0}</b>critical</div></div>
<h2>Confirmed findings (${findings.length})</h2>${findings.map(row).join('') || '<p>None — zero confirmed vulnerabilities.</p>'}
<h2>Parameters (${params.length})</h2><table><tr><th>name</th><th>risk</th><th>probed</th><th>reasons</th></tr>
${params.map((p) => `<tr><td>${esc(p.name)}</td><td>${p.risk}</td><td>${p.probed ? 'yes' : 'no'}</td><td>${(p.reasons || []).join('; ')}</td></tr>`).join('')}</table>
<p style="color:#565f76;margin-top:30px">Generated by DarkObscura · authorized testing only</p>`;
  const blob = new Blob([doc], { type: 'text/html' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `darkobscura-report-${(s.host || 'scan').replace(/[^a-z0-9]/gi, '_')}.html`; a.click();
  logLine('ok', `exported HTML report (${findings.length} findings)`);
}

/* ───────── crawler (attack-surface discovery) ───────── */
async function crawlTarget() {
  const url = targetEl.value.trim();
  if (!url) { logLine('warn', 'enter a target URL to crawl'); return; }
  const act = activity(`crawling ${url} — discovering attack surface`);
  try {
    const res = await fetch('/api/crawl?url=' + encodeURIComponent(url));
    if (!res.ok) { act.done('crawl error: ' + (await res.text()), 'warn'); return; }
    const data = await res.json();
    const pages = data.Pages || [], endpoints = data.Endpoints || [], forms = data.Forms || [];
    act.done(`crawl complete · ${pages.length} pages · ${endpoints.length} scannable endpoints · ${forms.length} forms`);
    endpoints.slice(0, 12).forEach((e) => logLine('info', `  ↳ endpoint: ${e}`));
    if (endpoints.length) {
      targetEl.value = endpoints[0];
      logLine('ok', `target set to first discovered endpoint — press Analyze to scan it`);
    }
  } catch (err) { act.done('crawl failed: ' + err.message, 'warn'); }
}

/* ───────── new capability menus ───────── */
function needTarget(msg) {
  const url = targetEl.value.trim();
  if (!url) { logLine('warn', msg || 'enter a target URL first'); targetEl.focus(); }
  return url;
}
async function apiJSON(path, label) {
  const res = await fetch(path);
  if (!res.ok) { logLine('warn', `${label} error: ` + (await res.text())); return null; }
  return res.json();
}
async function fingerprintTarget() {
  const url = needTarget('enter a URL to fingerprint'); if (!url) return;
  const act = activity(`fingerprinting ${url}`);
  const d = await apiJSON('/api/fingerprint?url=' + encodeURIComponent(url) + '&authorized=1', 'fingerprint');
  if (!d) { act.done('fingerprint failed', 'warn'); return; }
  act.done(`fingerprint complete · ${(d.techs || []).length} tech · ${(d.cves || []).length} CVE`);
  (d.techs || []).forEach((t) => logLine(t.Confidence === 'confirmed' ? 'ok' : 'info',
    `  [${t.Confidence}] ${t.Name}${t.Version ? ' ' + t.Version : ''} · ${t.Category}`));
  (d.cves || []).forEach((v) => logLine('vuln', `  ⚠ ${v.ID} [${v.Severity}] ${v.Tech} ${v.Version} — ${v.Title}`));
}
async function templatesTarget() {
  const url = needTarget('enter a URL to run templates against'); if (!url) return;
  const act = activity(`running Nuclei templates on ${url} (304 checks)`);
  const d = await apiJSON('/api/templates?url=' + encodeURIComponent(url) + '&authorized=1', 'templates');
  if (!d) { act.done('templates failed', 'warn'); return; }
  act.done(`templates complete · ${d.count} run · ${(d.hits || []).length} hit(s)`, (d.hits || []).length ? 'vuln' : 'ok');
  (d.hits || []).forEach((h) => logLine('vuln', `  ⚠ ${h.templateId} [${h.severity}] ${h.name} (${h.url})`));
}
async function clientsideTarget() {
  const url = needTarget('enter a URL for client-side checks'); if (!url) return;
  const act = activity(`client-side checks (CORS/cache/CSP) on ${url}`);
  const d = await apiJSON('/api/clientside?url=' + encodeURIComponent(url) + '&authorized=1', 'clientside');
  if (!d) { act.done('client-side check failed', 'warn'); return; }
  act.done(`client-side complete · ${(d.findings || []).length} finding(s)`, (d.findings || []).length ? 'vuln' : 'ok');
  (d.findings || []).forEach((f) => logLine('vuln', `  ⚠ ${f.Class} [${f.Severity}] ${f.Detail}`));
}
async function domTarget() {
  const url = needTarget('enter a URL for DOM analysis'); if (!url) return;
  const act = activity(`DOM analysis on ${url}`);
  const d = await apiJSON('/api/dom?url=' + encodeURIComponent(url) + '&authorized=1', 'dom');
  if (!d) { act.done('DOM analysis failed', 'warn'); return; }
  act.done(`DOM analysis complete · ${(d.findings || []).length} observation(s) · headless=${d.headless}`);
  (d.findings || []).forEach((f) => logLine('info', `  [${f.Confidence}] ${f.Class} ${f.Source ? f.Source + ' → ' : ''}${f.Sink || ''}`));
}
async function secretsTarget() {
  const url = needTarget('enter a URL to scan for secrets'); if (!url) return;
  const act = activity(`scanning ${url} + scripts for secrets`);
  const d = await apiJSON('/api/secrets?url=' + encodeURIComponent(url) + '&authorized=1', 'secrets');
  if (!d) { act.done('secret scan failed', 'warn'); return; }
  act.done(`secret scan complete · ${(d.secrets || []).length} match(es)`, (d.secrets || []).length ? 'vuln' : 'ok');
  (d.secrets || []).forEach((s) => logLine('vuln', `  ⚠ ${s.Type} [${s.Severity}] ${s.Redacted} (H=${(s.Entropy || 0).toFixed(2)})`));
}
async function wafTarget() {
  const url = needTarget('enter a URL for the WAF / block check'); if (!url) return;
  const act = activity(`probing ${url} for a WAF / blocking`);
  const d = await apiJSON('/api/waf?url=' + encodeURIComponent(url) + '&authorized=1', 'waf');
  if (!d) { act.done('WAF probe failed', 'warn'); return; }
  const blocking = d.BlocksAttack || (d.Baseline && d.Baseline.Blocked);
  const label = (d.Baseline && d.Baseline.Blocked) ? 'BLOCKING (fully)' : d.BlocksAttack ? 'BLOCKING attacks' : d.Present ? 'present, passive' : 'none';
  act.done(`WAF: ${d.WAF || 'none'} · ${label}`, blocking ? 'warn' : 'ok');
  (d.Evidence || []).forEach((e) => logLine(blocking ? 'warn' : 'ok', '  ' + e));
  if (d.Present) setWafBadge(`WAF: ${d.WAF || 'unknown'} · ${label}`, blocking ? 'warning' : 'info');
}
async function takeoverTarget() {
  const host = prompt('Host to check for subdomain takeover (e.g. sub.example.com):');
  if (!host) return;
  const act = activity(`subdomain takeover check on ${host}`);
  const d = await apiJSON('/api/takeover?host=' + encodeURIComponent(host.trim()) + '&authorized=1', 'takeover');
  if (!d) { act.done('takeover check failed', 'warn'); return; }
  if (d.finding) {
    act.done(`⚠ SUBDOMAIN TAKEOVER: ${d.finding.Host} → ${d.finding.CNAME} (${d.finding.Provider})`, 'vuln');
  } else { act.done(`no takeover confirmed${d.error ? ' (' + d.error + ')' : ''}`); }
}
async function grpcTarget() {
  const target = prompt('gRPC endpoint (host:port):');
  if (!target) return;
  const act = activity(`gRPC reflection fuzz on ${target}`);
  const d = await apiJSON('/api/grpc?target=' + encodeURIComponent(target.trim()) + '&authorized=1', 'grpc');
  if (!d) { act.done('gRPC probe failed', 'warn'); return; }
  act.done(`gRPC complete · ${(d.Services || []).length} service(s)`);
  (d.Services || []).forEach((s) => {
    logLine('info', `  service ${s.Name}`);
    (s.Methods || []).forEach((m) => logLine('info', `    · ${m.Name}${m.InvokeStatus ? ' → ' + m.InvokeStatus : ''}`));
  });
  (d.Findings || []).forEach((f) => logLine(f.Confidence === 'confirmed' ? 'vuln' : 'warn', `  ⚠ ${f.Class} [${f.Confidence}] ${f.Detail}`));
}

/* ───────── elite attacks (race, smuggling) ───────── */
async function raceTest(marker = 'REDEEMED') {
  const url = targetEl.value.trim();
  if (!url) { logLine('warn', 'set target to the guarded action URL (e.g. /redeem?code=X)'); return; }
  logLine('vuln', `⚔ race-condition burst on ${url} (marker "${marker}")…`);
  try {
    const res = await fetch(`/api/race?url=${encodeURIComponent(url)}&marker=${encodeURIComponent(marker)}&authorized=1`);
    if (!res.ok) { logLine('warn', 'race error: ' + (await res.text())); return; }
    const d = await res.json();
    showEliteResult('⚔ Race-condition (TOCTOU)', d.vulnerable, d.summary, d.detail,
      `${d.successes} / ${d.attempts} concurrent requests succeeded`);
    logLine(d.vulnerable ? 'vuln' : 'ok', d.summary);
  } catch (err) { logLine('warn', 'race failed: ' + err.message); }
}

async function smuggleTest() {
  const url = targetEl.value.trim();
  if (!url) { logLine('warn', 'set a target URL first'); return; }
  logLine('info', `🧬 request-smuggling desync probe on ${url}…`);
  try {
    const res = await fetch(`/api/smuggle?url=${encodeURIComponent(url)}&authorized=1`);
    if (!res.ok) { logLine('warn', 'smuggle error: ' + (await res.text())); return; }
    const d = await res.json();
    showEliteResult('🧬 HTTP request smuggling', d.vulnerable, d.summary, d.detail,
      `technique: ${d.technique} · baseline ${d.baselineMs}ms · probe ${d.probeMs}ms`);
    logLine(d.vulnerable ? 'vuln' : 'ok', d.summary);
  } catch (err) { logLine('warn', 'smuggle failed: ' + err.message); }
}

function showEliteResult(title, vulnerable, summary, detail, metric) {
  attackEl.classList.add('open');
  $('attack-title').textContent = title;
  const badge = vulnerable
    ? `<span class="proven">✔ CONFIRMED · VULNERABLE</span>`
    : `<span class="unproven">not vulnerable</span>`;
  $('attack-body').innerHTML =
    `<div class="averdict">${badge}</div>
     <div class="asum">${esc(summary || '')}</div>
     <div class="abox-data"><div class="lbl">measurement</div><div class="bigdata" style="font-size:15px">${esc(metric || '')}</div></div>
     <ul class="adetail">${(detail || []).map((d) => `<li>${esc(d)}</li>`).join('')}</ul>`;
}

/* ───────── attack mode (active exploitation for proof) ───────── */
const attackEl = $('attack');
let attackES = null;
function attackable(f) { return f.class === 'sqli-time-blind' || f.class === 'reflected-xss' || f.verifiedVia === 'out-of-band-canary'; }
function closeAttack() { attackEl.classList.remove('open'); if (attackES) { attackES.close(); attackES = null; } }
$('attack-close').onclick = closeAttack;
attackEl.addEventListener('click', (e) => { if (e.target === attackEl) closeAttack(); });

function openAttack(f, btn) {
  const url = lastData && lastData.summary && lastData.summary.target;
  if (!url) { logLine('warn', 'no scan target for attack'); return; }
  attackEl.classList.add('open');
  $('attack-title').textContent = `⚡ Exploiting ${f.class} · «${f.param}»`;
  $('attack-body').innerHTML =
    `<div class="astatus" id="a-status">engaging target · establishing timing oracle…</div>
     <div class="aextract" id="a-extract"></div>
     <div id="a-result"></div>`;
  logLine('vuln', `ATTACK MODE engaged · ${f.class} on «${f.param}»`);
  if (attackES) attackES.close();
  const qs = new URLSearchParams({ url, param: f.param, class: f.class,
    payload: f.payload || '', marker: f.marker || '', authorized: '1' });
  attackES = new EventSource('/api/attack/stream?' + qs.toString());
  attackES.addEventListener('progress', (e) => {
    const p = JSON.parse(e.data);
    if (p.kind === 'attack-char') {
      $('a-extract').innerHTML =
        `<span class="lbl">exfiltrating @@version →</span> <span class="data">${esc(p.message)}<span class="cursor">▋</span></span>`;
    } else {
      $('a-status').textContent = p.message;
      logLine('info', 'attack · ' + p.message);
    }
  });
  attackES.addEventListener('done', (e) => { renderEvidence(JSON.parse(e.data), btn); attackES.close(); attackES = null; });
  attackES.addEventListener('attackerror', (e) => {
    $('a-status').textContent = 'attack error: ' + (JSON.parse(e.data).error || ''); attackES.close(); attackES = null;
  });
  attackES.onerror = () => { if (attackES && attackES.readyState === EventSource.CLOSED) { attackES = null; } };
}

function renderEvidence(ev, btn) {
  $('a-status').textContent = ev.proven ? 'exploitation succeeded' : 'exploitation complete';
  const badge = ev.proven
    ? `<span class="proven">✔ PROVEN · TRUE POSITIVE</span>`
    : `<span class="unproven">⚠ could not fully prove</span>`;
  let html = `<div class="averdict">${badge}</div><div class="asum">${esc(ev.summary || '')}</div>`;
  if (ev.extracted && ev.kind === 'sqli-extract')
    html += `<div class="abox-data"><div class="lbl">🗄 exfiltrated from the database (@@version)</div>
      <div class="bigdata">${esc(ev.extracted)}</div></div>`;
  if (ev.extracted && ev.kind === 'xss-context')
    html += `<div class="abox-data"><div class="lbl">reflected verbatim in response</div>
      <pre class="snip">${esc(ev.extracted)}</pre></div>`;
  if (ev.poc)
    html += `<div class="apoc"><span class="lbl">click-to-run PoC:</span>
      <a href="${esc(ev.poc)}" target="_blank" rel="noopener">${esc(ev.poc)}</a></div>`;
  if (ev.queries) html += `<div class="aq">${ev.queries} oracle queries issued during exploitation</div>`;
  html += `<ul class="adetail">${(ev.detail || []).map((d) => `<li>${esc(d)}</li>`).join('')}</ul>`;
  $('a-result').innerHTML = html;
  if (btn && ev.proven) { btn.textContent = '✔ proven — true positive'; btn.classList.add('done'); }
  if (ev.proven) addLoot(lootFromEvidence(ev, { class: ev.kind, param: '', endpoint: '' }));
  logLine(ev.proven ? 'vuln' : 'warn',
    ev.proven ? `PROVEN ${ev.kind}: ${ev.extracted || ev.summary}` : 'attack inconclusive');
}

/* ───────── Armitage layer: loot, Hail Mary, node context menu ───────── */
let loot = [];
function addLoot(item) { loot.push(item); renderLoot(); }
function renderLoot() {
  $('loot-meta').textContent = loot.length ? `${loot.length} item(s) looted` : 'nothing looted yet';
  const el = $('loot-list');
  if (!loot.length) {
    el.innerHTML = `<div class="empty">Run <b>🎯 Hail Mary</b> to auto-exploit confirmed findings and collect loot.</div>`;
    return;
  }
  el.innerHTML = loot.map((l) => `
    <div class="loot">
      <div class="l-head"><span class="l-kind">${esc(l.kind)}</span><span class="l-where">${esc(l.where || '')}</span></div>
      ${l.data ? `<div class="l-data">${esc(l.data)}</div>` : ''}
      ${l.poc ? `<div class="l-poc">PoC: <a href="${esc(l.poc)}" target="_blank" rel="noopener">${esc(l.poc)}</a></div>` : ''}
    </div>`).join('');
}
$('loot-export').onclick = () => {
  const blob = new Blob([JSON.stringify(loot, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'darkobscura-loot.json'; a.click();
  logLine('ok', `exported ${loot.length} loot item(s)`);
};

const ATTACKABLE = ['sqli-time-blind', 'reflected-xss', 'path-traversal-lfi', 'path-traversal-lfi (header)'];
const KIND_LABEL = { 'sqli-extract': 'DB @@version (blind SQLi)', 'xss-context': 'Reflected XSS PoC', 'lfi-dump': 'File disclosure (LFI)' };

// exploitFinding runs Attack Mode headlessly on one finding, resolving to Evidence.
function exploitFinding(f) {
  return new Promise((resolve) => {
    const target = f.endpoint || (lastData && lastData.summary && lastData.summary.target);
    if (!target) { resolve(null); return; }
    if (!ATTACKABLE.includes(f.class)) {
      // Classes proven at detection (SSTI, open-redirect, OOB): loot their evidence.
      resolve({ kind: f.class, proven: true, summary: f.class + ' confirmed',
        extracted: (f.evidence || []).filter((e) => e.startsWith('verified') || e.startsWith('leaked') || e.includes('evaluated')).join('\n'),
        where: `${f.param} @ ${pathOf(target)}` });
      return;
    }
    const qs = new URLSearchParams({ url: target, param: f.param, class: f.class,
      payload: f.payload || '', marker: f.marker || '', authorized: '1' });
    const es = new EventSource('/api/attack/stream?' + qs.toString());
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; es.close(); resolve(v); } };
    es.addEventListener('done', (e) => { const ev = JSON.parse(e.data); ev.where = `${f.param} @ ${pathOf(target)}`; finish(ev); });
    es.addEventListener('attackerror', () => finish(null));
    es.onerror = () => { if (es.readyState === EventSource.CLOSED) finish(null); };
  });
}

function lootFromEvidence(ev, f) {
  return {
    kind: KIND_LABEL[ev.kind] || f.class,
    where: ev.where || `${f.param} @ ${pathOf(f.endpoint || '')}`,
    data: ev.extracted || ev.summary || '',
    poc: ev.poc || null,
  };
}

// dedupeAttackTargets keeps one representative per (endpoint, param, class), capped.
function dedupeAttackTargets(findings, cap) {
  const seen = new Set(), out = [];
  for (const f of findings) {
    const k = (f.endpoint || '') + '|' + f.param + '|' + f.class;
    if (seen.has(k)) continue;
    seen.add(k); out.push(f);
    if (out.length >= cap) break;
  }
  return out;
}

const hailBtn = $('hailmary');
hailBtn.onclick = () => runHailMary((lastData && lastData.findings) || []);
async function runHailMary(findings, scopeLabel) {
  if (!findings.length) { logLine('warn', 'no confirmed findings — run a scan first'); return; }
  const targets = dedupeAttackTargets(findings, 24);
  hailBtn.disabled = true; hailBtn.classList.add('running');
  logLine('vuln', `🎯 HAIL MARY${scopeLabel ? ' · ' + scopeLabel : ''} — auto-exploiting ${targets.length} target(s)…`);
  setMode('loot');
  let got = 0;
  for (const f of targets) {
    logLine('info', `  exploiting ${f.class} on «${f.param}»…`);
    const ev = await exploitFinding(f);
    if (ev && ev.proven) { addLoot(lootFromEvidence(ev, f)); got++; logLine('vuln', `  💰 looted ${KIND_LABEL[ev.kind] || f.class}`); }
  }
  hailBtn.disabled = false; hailBtn.classList.remove('running');
  logLine('ok', `🎯 Hail Mary complete · +${got} loot (${loot.length} total)`);
}

// Right-click a graph node → Armitage-style attack menu.
const ctxEl = $('ctxmenu');
canvas.addEventListener('contextmenu', (e) => {
  e.preventDefault();
  const r = canvas.getBoundingClientRect();
  mouse.x = ((e.clientX - r.left) / r.width) * 2 - 1;
  mouse.y = -((e.clientY - r.top) / r.height) * 2 + 1;
  ray.setFromCamera(mouse, camera);
  const hit = ray.intersectObjects(graphNodes.map((n) => n.mesh))[0];
  if (!hit) { ctxEl.classList.remove('open'); return; }
  showCtxMenu(e.clientX, e.clientY, hit.object.userData);
});
document.addEventListener('click', () => ctxEl.classList.remove('open'));
window.addEventListener('scroll', () => ctxEl.classList.remove('open'), true);

function nodeTarget(n) {
  if (n.id === 'root') return lastData && (lastData.origin || (lastData.summary && lastData.summary.target));
  return n.url || (n.detail && n.detail.url) || (lastData && lastData.summary && lastData.summary.target);
}
function nodeFindings(n) {
  if (!lastData || !lastData.findings) return [];
  if (n.id === 'root') return lastData.findings;
  return lastData.findings.filter((f) => pathOf(f.endpoint || '') === n.label || (f.endpoint || '').includes(n.label));
}

function showCtxMenu(x, y, n) {
  const target = nodeTarget(n);
  const fs = nodeFindings(n);
  const items = [];
  if ((n.vuln || n.type === 'vuln') && fs.length) {
    items.push({ ic: '🎯', danger: true, label: `Prove & loot ${fs.length} finding(s)`, run: () => runHailMary(fs, n.label) });
  }
  items.push({ ic: '🔍', label: 'Deep-scan / analyze this', run: () => { if (target) { targetEl.value = target; (n.id === 'root' ? deepScan() : runScan()); } } });
  items.push({ ic: '⚡', label: 'Open in payload console', run: () => { if (target) { $('pc-url').value = target; setMode('god'); } } });
  items.push({ ic: '⇄', label: 'Send to Repeater', run: () => sendToRepeater(target) });
  ctxEl.innerHTML = `<div class="ctx-title">${esc(n.id === 'root' ? (target || 'origin') : n.label)}</div>` +
    items.map((it, i) => `<div class="ctx-item ${it.danger ? 'danger' : ''}" data-i="${i}"><span class="ic">${it.ic}</span>${it.label}</div>`).join('');
  ctxEl.style.left = Math.min(x, window.innerWidth - 220) + 'px';
  ctxEl.style.top = y + 'px';
  ctxEl.classList.add('open');
  ctxEl.querySelectorAll('.ctx-item').forEach((el) => {
    el.onclick = (ev) => { ev.stopPropagation(); ctxEl.classList.remove('open'); items[+el.dataset.i].run(); };
  });
}

function sendToRepeater(target) {
  if (!target) return;
  try {
    const u = new URL(target);
    $('req-edit').value = `GET ${u.pathname}${u.search || ''} HTTP/1.1\nHost: ${u.host}\nUser-Agent: DarkObscura/0.1\nAccept: */*`;
    repeatBase = u.origin;
    setMode('tactical');
  } catch { /* ignore */ }
}

/* ───────── helpers ───────── */
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function fmtEvidence(e) {
  return esc(e).replace(/(z=[\d.]+)/g, '<b>$1</b>').replace(/(verified:)/, '<b>$1</b>')
    .replace(/(observed=[\d.]+ms)/g, '<b style="color:var(--warn)">$1</b>');
}
function syntaxJSON(s) {
  return esc(s).replace(/"([^"]+)":/g, '<span class="tok-key">"$1"</span>:')
    .replace(/: "([^"]*)"/g, ': <span class="tok-str">"$1"</span>')
    .replace(/: (\d+)/g, ': <span class="tok-num">$1</span>');
}
function hexdump(str) {
  let out = '';
  for (let i = 0; i < str.length; i += 16) {
    const chunk = str.slice(i, i + 16);
    const hex = [...chunk].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    out += `<span class="tok-com">${i.toString(16).padStart(8, '0')}</span>  ${hex.padEnd(48)}  ${esc(chunk)}\n`;
  }
  return out;
}

/* ───────── nav dropdowns + about modal ───────── */
(function () {
  function openAbout() { document.getElementById('about').classList.add('open'); }
  const actions = {
    fingerprint: fingerprintTarget, templates: templatesTarget, secrets: secretsTarget,
    clientside: clientsideTarget, dom: domTarget, waf: wafTarget, takeover: takeoverTarget, grpc: grpcTarget,
    palette: () => openP(), crawl: () => crawlTarget(),
    report: () => exportReport(), findings: () => exportFindings(),
    about: openAbout,
  };
  document.querySelectorAll('.dropdown').forEach((dd) => {
    const toggle = dd.querySelector('.dd-toggle');
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const wasOpen = dd.classList.contains('open');
      document.querySelectorAll('.dropdown').forEach((d) => d.classList.remove('open'));
      if (!wasOpen) dd.classList.add('open');
    });
    dd.querySelectorAll('.dd-menu button').forEach((btn) => {
      btn.addEventListener('click', () => {
        dd.classList.remove('open');
        const fn = actions[btn.dataset.act];
        if (fn) fn();
      });
    });
  });
  document.addEventListener('click', () => document.querySelectorAll('.dropdown').forEach((d) => d.classList.remove('open')));

  const about = document.getElementById('about');
  document.getElementById('about-close').addEventListener('click', () => about.classList.remove('open'));
  about.addEventListener('click', (e) => { if (e.target === about) about.classList.remove('open'); });
  window.addEventListener('keydown', (e) => { if (e.key === 'Escape') about.classList.remove('open'); });
})();
