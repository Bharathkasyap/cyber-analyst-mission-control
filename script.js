// ===== Basic view routing =====
const views = {}; // cache view elements by id
document.querySelectorAll('.view').forEach(v => { views[v.id] = v; }); // map all .view nodes

function showView(id) {
  Object.values(views).forEach(v => v.classList.add('hidden')); // hide all
  const el = views[id] || views['view-dashboard'];               // fall back to dashboard
  el.classList.remove('hidden');                                 // show target
  updateRelatedLinks(id);                                        // refresh right-rail links
}

// Boot to dashboard
showView('view-dashboard');

// ===== Collapsibles in left nav =====
document.querySelectorAll('[data-collapse]').forEach(btn => {
  btn.addEventListener('click', () => {
    const sel = btn.getAttribute('data-collapse');               // target selector
    const tgt = document.querySelector(sel);                     // section body
    if (tgt) tgt.classList.toggle('hidden');                     // toggle open close
  });
});

// ===== Left nav routing and dashboard cards =====
function wireNavButtons() {
  document.querySelectorAll('.nav-item, .card-link').forEach(b => {
    b.addEventListener('click', () => {
      const tool = b.getAttribute('data-tool');                  // tool token
      if (!tool) return;
      showView(`view-${tool}`);                                  // open matching view
    });
  });
}
wireNavButtons();

// ===== Tabs (used in runbooks and later tools) =====
function wireTabs(root=document) {
  root.querySelectorAll('.tabs .tab').forEach(t => {
    t.addEventListener('click', () => {
      const tabs = t.parentElement.querySelectorAll('.tab');     // all tabs in group
      tabs.forEach(x => x.classList.remove('active'));           // reset
      t.classList.add('active');                                 // activate current

      const container = t.closest('.p-4');                       // view container
      container.querySelectorAll('.tabview').forEach(v => v.classList.add('hidden')); // hide all panes
      const sel = t.getAttribute('data-tab');                    // pane selector
      const pane = container.querySelector(sel);
      if (pane) pane.classList.remove('hidden');                 // show selected
    });
  });
}
wireTabs();

// ===== Global search filters left rail =====
const search = document.getElementById('globalSearch');
if (search) {
  search.addEventListener('input', () => {
    const q = search.value.trim().toLowerCase();                 // user query
    document.querySelectorAll('#leftNav section').forEach(sec => {
      const body = sec.querySelector('div[id^="grp-"]');         // items wrapper
      const items = sec.querySelectorAll('.nav-item');           // all links
      let any = false;
      items.forEach(i => {
        const hit = i.textContent.toLowerCase().includes(q);     // match test
        i.style.display = hit ? 'block' : 'none';                // show or hide
        if (hit) any = true;
      });
      if (!body) return;
      if (q === '') body.classList.remove('hidden');             // reset expand
      else body.classList.toggle('hidden', !any);                // auto open when matches exist
    });
  });
}

// ===== Theme toggle =====
const themeBtn = document.getElementById('themeToggle');
if (themeBtn) {
  themeBtn.addEventListener('click', () => {
    document.documentElement.classList.toggle('dark');           // toggles html.dark
    document.body.classList.toggle('bg-slate-900');              // dark bg
    document.body.classList.toggle('text-slate-100');            // light text
    toast('Theme toggled');                                      // tiny feedback
  });
}

// ===== Personal Quick Links with LocalStorage =====
const qlKey = 'mc_quicklinks';

function loadQuickLinks() {
  const list = JSON.parse(localStorage.getItem(qlKey) || '[]');  // read saved
  const ul = document.getElementById('ql-list');
  if (!ul) return;
  ul.innerHTML = '';
  list.forEach((u, idx) => {
    const li = document.createElement('li');
    const a = document.createElement('a'); a.href = u; a.target = '_blank'; a.textContent = u; a.className = 'a';
    const del = document.createElement('button'); del.textContent = 'x'; del.className = 'ml-2 btn';
    del.addEventListener('click', () => {
      const arr = JSON.parse(localStorage.getItem(qlKey) || '[]');
      arr.splice(idx, 1); localStorage.setItem(qlKey, JSON.stringify(arr));
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
    list.push(url); localStorage.setItem(qlKey, JSON.stringify(list));
    inp.value = ''; loadQuickLinks();
  });
}
loadQuickLinks();

// ===== Notes autosave =====
const notes = document.getElementById('notes');
const notesKey = 'mc_notes';
if (notes) {
  notes.value = localStorage.getItem(notesKey) || '';            // load
  notes.addEventListener('input', () => {
    localStorage.setItem(notesKey, notes.value);                 // save on change
  });
}

// ===== Related links per view (right rail) =====
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
    const a = document.createElement('a'); a.href = u; a.target = '_blank'; a.textContent = t; a.className = 'a';
    li.appendChild(a); ul.appendChild(li);
  });
}

// ===== Base64 Encode Decode with proper UTF 8 handling =====
const b64In = document.getElementById('b64-in');
const b64Out = document.getElementById('b64-out');

function encodeBase64Utf8(text) {
  const bytes = new TextEncoder().encode(text);                  // string → UTF 8 bytes
  let bin = ''; bytes.forEach(b => { bin += String.fromCharCode(b); }); // bytes → binary string
  return btoa(bin);                                              // binary string → base64
}

function decodeBase64Utf8(b64) {
  const bin = atob(b64);                                         // base64 → binary string
  const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));      // binary string → bytes
  return new TextDecoder().decode(bytes);                        // bytes → string
}

document.getElementById('b64-encode')?.addEventListener('click', () => {
  try { b64Out.value = encodeBase64Utf8(b64In.value); toast('Encoded'); }
  catch (e) { b64Out.value = 'Error: ' + e.message; }
});

document.getElementById('b64-decode')?.addEventListener('click', () => {
  try { b64Out.value = decodeBase64Utf8(b64In.value.trim()); toast('Decoded'); }
  catch (e) { b64Out.value = 'Error: ' + e.message; }
});

document.getElementById('b64-clear')?.addEventListener('click', () => {
  b64In.value = ''; b64Out.value = '';
});

document.getElementById('b64-copy')?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(b64Out.value); toast('Copied'); }
  catch { toast('Copy failed'); }
});

// ===== Tiny toast helper =====
function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 1200);
}
