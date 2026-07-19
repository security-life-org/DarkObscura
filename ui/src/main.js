// DarkObscura UI shell: mode switching, Ctrl+K command palette, and the WebGL
// attack graph. The graph renders endpoints/params/vulns as nodes; nodes the
// backend confirms as exploitable pulse red and are clickable.
//
// Backend integration: connect to cmd/core over ws://127.0.0.1:8080 and replace
// the demo data below with live flow/finding events.
import * as THREE from 'three';

/* ---------- mode switching (Progressive Disclosure) ---------- */
const views = document.querySelectorAll('.view');
document.querySelectorAll('.modes button').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.modes button').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    views.forEach((v) => v.classList.toggle('active', v.id === btn.dataset.mode));
  });
});

/* ---------- Ctrl+K command palette ---------- */
const palette = document.getElementById('palette');
const paletteInput = palette.querySelector('input');
const paletteList = palette.querySelector('ul');
const commands = [
  'Switch to Zen mode', 'Switch to Tactical mode', 'Switch to God mode',
  'Start scan', 'Toggle intercept', 'Open eBPF trace', 'Load WASM plugin', 'Export findings',
];
let sel = 0;
function renderPalette(filter = '') {
  const items = commands.filter((c) => c.toLowerCase().includes(filter.toLowerCase()));
  paletteList.innerHTML = '';
  items.forEach((c, i) => {
    const li = document.createElement('li');
    li.textContent = c;
    if (i === sel) li.classList.add('sel');
    paletteList.appendChild(li);
  });
}
window.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    palette.classList.add('open');
    paletteInput.value = '';
    sel = 0;
    renderPalette();
    paletteInput.focus();
  } else if (e.key === 'Escape') {
    palette.classList.remove('open');
  }
});
paletteInput.addEventListener('input', () => { sel = 0; renderPalette(paletteInput.value); });

/* ---------- WebGL attack graph ---------- */
const canvas = document.getElementById('graph');
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 1000);
camera.position.z = 60;
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });

function resize() {
  const w = canvas.clientWidth || canvas.parentElement.clientWidth || window.innerWidth;
  const h = canvas.clientHeight || canvas.parentElement.clientHeight || window.innerHeight;
  renderer.setSize(w, h, false);
  camera.aspect = w / h || 1;
  camera.updateProjectionMatrix();
}
new ResizeObserver(resize).observe(canvas.parentElement);
window.addEventListener('resize', resize);
// Size once layout has settled.
requestAnimationFrame(resize);

// Demo graph: replace with backend-provided nodes/edges.
const COLORS = { endpoint: 0x35d0a5, risky: 0xffcc55, vuln: 0xff4d6d };
const demo = {
  nodes: [
    { id: 'root', type: 'endpoint', x: 0, y: 0 },
    { id: '/login', type: 'endpoint', x: -22, y: 12 },
    { id: '/search?q', type: 'risky', x: 20, y: 10 },
    { id: '/fetch?url', type: 'vuln', x: 24, y: -12 },
    { id: '/user?id', type: 'vuln', x: -18, y: -14 },
  ],
  edges: [['root', '/login'], ['root', '/search?q'], ['/search?q', '/fetch?url'], ['root', '/user?id']],
};

const nodeMeshes = new Map();
const pulsing = [];
for (const n of demo.nodes) {
  const geo = new THREE.SphereGeometry(n.type === 'endpoint' ? 1.6 : 2.2, 24, 24);
  const mat = new THREE.MeshBasicMaterial({ color: COLORS[n.type] });
  const mesh = new THREE.Mesh(geo, mat);
  mesh.position.set(n.x, n.y, 0);
  mesh.userData = n;
  scene.add(mesh);
  nodeMeshes.set(n.id, mesh);
  if (n.type === 'vuln') pulsing.push(mesh);
}
for (const [a, b] of demo.edges) {
  const pa = nodeMeshes.get(a).position, pb = nodeMeshes.get(b).position;
  const g = new THREE.BufferGeometry().setFromPoints([pa, pb]);
  scene.add(new THREE.Line(g, new THREE.LineBasicMaterial({ color: 0x2a2f3d })));
}

// Click an exploitable (red) node to "exploit".
const ray = new THREE.Raycaster();
const mouse = new THREE.Vector2();
canvas.addEventListener('click', (e) => {
  const r = canvas.getBoundingClientRect();
  mouse.x = ((e.clientX - r.left) / r.width) * 2 - 1;
  mouse.y = -((e.clientY - r.top) / r.height) * 2 + 1;
  ray.setFromCamera(mouse, camera);
  const hit = ray.intersectObjects([...nodeMeshes.values()])[0];
  if (hit && hit.object.userData.type === 'vuln') {
    alert(`Exploiting confirmed node: ${hit.object.userData.id}`);
  }
});

let t = 0;
function animate() {
  requestAnimationFrame(animate);
  t += 0.05;
  for (const m of pulsing) {
    const s = 1 + Math.sin(t) * 0.15;
    m.scale.setScalar(s);
  }
  scene.rotation.y = Math.sin(t * 0.05) * 0.15;
  renderer.render(scene, camera);
}
resize();
animate();

/* ---------- Tactical demo content with smart highlighting ---------- */
const RISKY = /(user_?id|redirect|url|cmd|token|file|q)=/gi;
document.getElementById('req').textContent =
  'GET /search?q=laptop&user_id=42&theme=dark HTTP/1.1\nHost: target.example\nCookie: session=…';
const respEl = document.getElementById('resp');
const raw = 'HTTP/1.1 200 OK\n\n{"results":[…],"echo":"q=laptop","uid":42}';
respEl.innerHTML = raw.replace(RISKY, (m) => `<span class="hl">${m}</span>`);
