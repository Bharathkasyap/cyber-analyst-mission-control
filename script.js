// ===== View routing =========================================================
const views = {};
document.querySelectorAll('.view').forEach(v => (views[v.id] = v));

function showView(id) {
  Object.values(views).forEach(v => v.classList.add('hidden'));
  const el = views[id] || views['view-dashboard'];
  el.classList.remove('hidden');
  updateRelatedLinks(id);
}

// Boot to dashboard
showView('view-dashboard');

// ===== Collapsibles in left nav ============================================
document.querySelectorAll('[data-collapse]').forEach(btn => {
  btn.addEventListener('click', () => {
    const sel = btn.getAttribute('data-collapse');
    const tgt = document.querySelector(sel);
    if (tgt) tgt.classList.toggle('hidden');
  });
});

// ===== Left nav + dashboard links routing ==================================
function wireNavButtons() {
  document.querySelectorAll('.nav-item, .card-link').forEach(b => {
    b.addEventListener('click', () => {
      const tool = b.getAttribute('data-tool');
      if (!tool) return;
      showView(`view-${tool}`);
    });
  });
}
wireNavButtons();

// ===== Tabs (used by runbooks, etc.) =======================================
function wireTabs(root = document) {
  root.querySelectorAll('.tabs .tab').forEach(t => {
    t.addEventListener('click', () => {
      const group = t.parentElement;
      group.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
      t.classList.add('active');

      const container = t.closest('.p-4') || document;
      container.querySelectorAll('.tabview').forEach(v => v.classList.add('hidden'));
      const sel = t.getAttribute('data-tab');
      const pane = container.querySelector(sel);
      if (pane) pane.classList.remove('hidden');
    });
  });
}
wireTabs();

// ===== Global search filters left rail =====================================
const search = document.getElementById('globalSearch');
if (search) {
  search.addEventListener('input', () => {
    const q = search.value.trim().toLowerCase();
    document.querySelectorAll('#leftNav section').forEach(sec => {
      const body = sec.querySelector('div[id^="grp-"]');
      const items = sec.querySelectorAll('.nav-item');
      let any = false;
      items.forEach(i => {
        const hit = i.textContent.toLowerCase().includes(q);
        i.style.display = hit ? 'block' : 'none';
        if (hit) any = true;
      });
      if (!body) return;
      if (q === '') body.classList.remove('hidden');
      else body.classList.toggle('hidden', !any);
    });
  });
}

// ===== Theme toggle =========================================================
const themeBtn = document.getElementById('themeToggle');
if (themeBtn) {
  themeBtn.addEventListener('click', () => {
    document.documentElement.classList.toggle('dark');
    document.body.classList.toggle('bg-slate-900');
    document.body.classList.toggle('text-slate-100');
    toast('Theme toggled');
  });
}

// ===== Personal Quick Links with LocalStorage ===============================
const qlKey = 'mc_quicklinks';

function loadQuickLinks() {
  const list = JSON.parse(localStorage.getItem(qlKey) || '[]');
  const ul = document.getElementById('ql-list');
  if (!ul) return;
  ul.innerHTML = '';
  list.forEach((u, idx) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = u; a.target = '_blank'; a.textContent = u; a.className = 'a';
    const del = document.createElement('button');
    del.textContent = '×'; del.className = 'ml-2 btn';
    del.addEventListener('click', () => {
      const arr = JSON.parse(localStorage.getItem(qlKey) || '[]');
      arr.splice(idx, 1);
      localStorage.setItem(qlKey, JSON.stringify(arr));
      loadQuickLinks();
    });
    li.appendChild(a); li.appendChild(del); ul.appendChild(li);
  });
}

const qlAdd = document.getElementById('ql-add');
if (qlAdd) {
  qlAdd.addEventListener('click', () => {
    const inp = document.getElementById('ql-url');
    if (!inp) return;
    const url = inp.value.trim();
    if (!url) return;
    const list = JSON.parse(localStorage.getItem(qlKey) || '[]');
    list.push(url);
    localStorage.setItem(qlKey, JSON.stringify(list));
    inp.value = '';
    loadQuickLinks();
  });
}
loadQuickLinks();

// ===== Notes autosave =======================================================
const notes = document.getElementById('notes');
const notesKey = 'mc_notes';
if (notes) {
  notes.value = localStorage.getItem(notesKey) || '';
  notes.addEventListener('input', () => {
    localStorage.setItem(notesKey, notes.value);
  });
}

// ===== Related links per view (right rail) =================================
function updateRelatedLinks(viewId) {
  const map = {
    'view-base64': [
      ['MDN Base64', 'https://developer.mozilla.org/en-US/docs/Glossary/Base64'],
      ['MDN btoa', 'https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/btoa'],
      ['MDN atob', 'https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/atob']
    ],
    'view-cidr': [
      ['IANA IPv4 Special-Purpose', 'https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml'],
      ['RFC 4632 CIDR', 'https://www.rfc-editor.org/rfc/rfc4632']
    ],
    'view-goldLinks': [
      ['KQL Docs', 'https://learn.microsoft.com/en-us/kusto/query'],
      ['MITRE ATT&CK', 'https://attack.mitre.org/matrices/enterprise/'],
      ['Splunk Search Reference', 'https://docs.splunk.com/Documentation/Splunk/9.4.2/SearchReference/WhatsInThisManual'],
      ['Palo Alto Tech Docs', 'https://docs.paloaltonetworks.com/']
    ],
    'view-rb-ransomware': [
      ['CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
      ['NIST CSF', 'https://www.nist.gov/cyberframework']
    ]
  };

  const ul = document.getElementById('relatedLinks');
  if (!ul) return;
  ul.innerHTML = '';
  (map[viewId] || []).forEach(([t, u]) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = u; a.target = '_blank'; a.textContent = t; a.className = 'a';
    li.appendChild(a); ul.appendChild(li);
  });
}

// ===== Base64 (UTF-8 safe) =================================================
const b64In = document.getElementById('b64-in');
const b64Out = document.getElementById('b64-out');

function b64enc(text) {
  const bytes = new TextEncoder().encode(text);        // string → UTF-8 bytes
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b))); // bytes → binary string
  return btoa(bin);                                    // → base64
}
function b64dec(b64) {
  const bin = atob(b64);                               // base64 → binary string
  const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);              // bytes → string
}

document.getElementById('b64-encode')?.addEventListener('click', () => {
  try { b64Out.value = b64enc(b64In.value); toast('Encoded'); }
  catch (e) { b64Out.value = 'Error: ' + e.message; }
});
document.getElementById('b64-decode')?.addEventListener('click', () => {
  try { b64Out.value = b64dec(b64In.value.trim()); toast('Decoded'); }
  catch (e) { b64Out.value = 'Error: ' + e.message; }
});
document.getElementById('b64-clear')?.addEventListener('click', () => { b64In.value=''; b64Out.value=''; });
document.getElementById('b64-copy')?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(b64Out.value); toast('Copied'); }
  catch { toast('Copy failed'); }
});

// ===== Wildcard Mask Calculator ============================================
// Helpers
function parseDotted(str) {
  const parts = str.trim().split('.');
  if (parts.length !== 4) throw new Error('Use dotted IPv4 like 255.255.255.0');
  const octets = parts.map(p => {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new Error('Each octet 0..255');
    return n;
  });
  return octets;
}
function toDotted(arr) { return arr.join('.'); }
function wildcardFromMask(octets) { return octets.map(o => 255 - o); }
function maskFromPrefix(prefix) {
  const p = Number(prefix);
  if (!Number.isInteger(p) || p < 0 || p > 32) throw new Error('Prefix 0..32');
  const bits = Array(32).fill(0).map((_, i) => (i < p ? 1 : 0));
  const octets = [];
  for (let i = 0; i < 4; i++) {
    const b = bits.slice(i * 8, i * 8 + 8).join('');
    octets.push(parseInt(b.padEnd(8, '0'), 2));
  }
  return octets;
}

document.getElementById('wm-fromMask')?.addEventListener('click', () => {
  const input = document.getElementById('wm-subnet');
  const out = document.getElementById('wm-out-fromMask');
  try {
    const mask = parseDotted(input.value);
    out.value = toDotted(wildcardFromMask(mask));
    toast('Calculated');
  } catch (e) { out.value = 'Error: ' + e.message; }
});

document.getElementById('wm-fromCidr')?.addEventListener('click', () => {
  const cidr = document.getElementById('wm-cidr');
  const outMask = document.getElementById('wm-out-mask');
  const outWild = document.getElementById('wm-out-wild');
  try {
    const mask = maskFromPrefix(cidr.value);
    outMask.value = toDotted(mask);
    outWild.value = toDotted(wildcardFromMask(mask));
    toast('Calculated');
  } catch (e) {
    outMask.value = 'Error: ' + e.message;
    outWild.value = 'Error: ' + e.message;
  }
});

// ===== Hex ↔ Dec ============================================================
document.getElementById('dec-to-hex')?.addEventListener('click', () => {
  const v = document.getElementById('dec-in').value.trim();
  const out = document.getElementById('dec-hex-out');
  if (v === '') { out.value = ''; return; }
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) { out.value = 'Error: enter a non-negative number'; return; }
  out.value = '0x' + Math.floor(n).toString(16).toUpperCase();
});

document.getElementById('hex-to-dec')?.addEventListener('click', () => {
  let v = document.getElementById('hex-in').value.trim();
  const out = document.getElementById('hex-dec-out');
  if (v === '') { out.value = ''; return; }
  v = v.replace(/^0x/i, '');
  if (!/^[0-9a-f]+$/i.test(v)) { out.value = 'Error: hex only 0-9 A-F'; return; }
  out.value = String(parseInt(v, 16));
});

// ===== Timestamp converter ==================================================
function pad(n) { return n.toString().padStart(2, '0'); }
function fmtUTC(d) {
  return (
    d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' +
    pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + ' UTC'
  );
}
document.getElementById('ts-from-epoch')?.addEventListener('click', () => {
  const v = Number(document.getElementById('ts-epoch').value.trim());
  const out = document.getElementById('ts-out');
  if (!Number.isFinite(v)) { out.value = 'Error: epoch seconds number required'; return; }
  const d = new Date(v * 1000);
  out.value = 'UTC: ' + fmtUTC(d) + '\nLocal: ' + new Date(v * 1000).toString();
});
document.getElementById('ts-to-epoch')?.addEventListener('click', () => {
  const s = document.getElementById('ts-human').value.trim();
  const out = document.getElementById('ts-out');
  if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) { out.value = 'Error: use YYYY-MM-DD HH:mm:ss'; return; }
  const [date, time] = s.split(' ');
  const [Y, M, D] = date.split('-').map(Number);
  const [h, m, sec] = time.split(':').map(Number);
  const ms = Date.UTC(Y, M - 1, D, h, m, sec);
  out.value = 'Epoch (s): ' + Math.floor(ms / 1000) + '\nUTC: ' + fmtUTC(new Date(ms)) + '\nLocal: ' + new Date(ms).toString();
});

// ===== CIDR calculator (IPv4) ==============================================
function ipToInt(ip) {
  const a = ip.trim().split('.').map(x => Number(x));
  if (a.length !== 4 || a.some(x => !Number.isInteger(x) || x < 0 || x > 255)) {
    throw new Error('Enter IPv4 like 192.168.1.10');
  }
  return ((a[0] << 24) >>> 0) + (a[1] << 16) + (a[2] << 8) + a[3];
}
function intToIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
function maskFromPrefixInt(p) { if (p < 0 || p > 32) throw new Error('Prefix 0..32'); return p === 0 ? 0 : (((0xFFFFFFFF << (32 - p)) >>> 0)); }

document.getElementById('cidr-calc')?.addEventListener('click', () => {
  const ipStr = document.getElementById('cidr-ip').value.trim();
  const pfx = Number(document.getElementById('cidr-prefix').value.trim());
  const out = document.getElementById('cidr-out');
  try {
    const ip = ipToInt(ipStr);
    const mask = maskFromPrefixInt(pfx);
    const network = (ip & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;

    const firstHost = pfx === 32 ? network : ((network + 1) >>> 0);
    const lastHost  = pfx >= 31 ? broadcast : ((broadcast - 1) >>> 0);
    const hostCount = pfx === 32 ? 1 : (pfx === 31 ? 2 : Math.max(0, (broadcast - network - 1)));

    const maskArr = [(mask >>> 24) & 255, (mask >>> 16) & 255, (mask >>> 8) & 255, mask & 255];
    const wildcardArr = maskArr.map(o => 255 - o);

    out.value =
`Network:   ${intToIp(network)}/${pfx}
Broadcast: ${intToIp(broadcast)}
First host:${intToIp(firstHost)}
Last host: ${intToIp(lastHost)}
Hosts:     ${hostCount}
Mask:      ${maskArr.join('.')}
Wildcard:  ${wildcardArr.join('.')}`;
    toast('Calculated');
  } catch (e) { out.value = 'Error: ' + e.message; }
});

// ===== Tiny toast ===========================================================
function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 1200);
}
