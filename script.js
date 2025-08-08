// Apply saved theme on load
(function initTheme(){                               // run early on load
  const saved = localStorage.getItem('mc_theme');    // read saved theme
  if (saved === 'dark') document.body.classList.add('dark-mode'); // set class
})();

// ===== View routing
const views = {}; document.querySelectorAll('.view').forEach(v => views[v.id] = v);
function showView(id){ Object.values(views).forEach(v=>v.classList.add('hidden')); (views[id]||views['view-dashboard']).classList.remove('hidden'); updateRelatedLinks(id); }
showView('view-dashboard');                           // default view

// ===== Collapsibles
document.querySelectorAll('[data-collapse]').forEach(b=>b.addEventListener('click',()=>{
  const t=document.querySelector(b.getAttribute('data-collapse')); if(t) t.classList.toggle('hidden');
}));

// ===== Nav & dashboard links
function wireNav(){
  document.querySelectorAll('.nav-item,.card-link').forEach(b=>{
    b.addEventListener('click',()=>{
      const tool=b.getAttribute('data-tool');         // which view to open
      if(!tool) return;
      if(tool==='runbook'){                           // runbook is dynamic
        renderRunbook(b.getAttribute('data-runbook'));
        showView('view-runbook');
        return;
      }
      showView('view-'+tool);
    });
  });
}
wireNav();

// ===== Tabs
function wireTabs(root=document){
  root.querySelectorAll('.tabs .tab').forEach(t=>t.addEventListener('click',()=>{
    const grp=t.parentElement; grp.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');                        // activate clicked tab
    const box=t.closest('.p-4')||document;           // find container
    box.querySelectorAll('.tabview').forEach(v=>v.classList.add('hidden'));
    const pane=box.querySelector(t.getAttribute('data-tab'));
    if(pane) pane.classList.remove('hidden');        // show target pane
  }));
}
wireTabs();

// ===== Global search filters left rail
const g=document.getElementById('globalSearch');
g.addEventListener('input',()=>{
  const q=g.value.trim().toLowerCase();              // normalized query
  document.querySelectorAll('#leftNav section').forEach(sec=>{
    const body=sec.querySelector('div[id^="grp-"]'); const items=sec.querySelectorAll('.nav-item'); let any=false;
    items.forEach(i=>{ const hit=i.textContent.toLowerCase().includes(q); i.style.display=hit?'block':'none'; if(hit) any=true; });
    if(!body) return; if(q==='') body.classList.remove('hidden'); else body.classList.toggle('hidden',!any);
  });
});

// ===== Theme toggle (now robust)
document.getElementById('themeToggle').addEventListener('click',()=>{
  document.body.classList.toggle('dark-mode');                                // flip class
  const mode = document.body.classList.contains('dark-mode') ? 'dark' : 'light';
  localStorage.setItem('mc_theme', mode);                                     // persist choice
  toast(`Theme: ${mode}`);                                                    // feedback
});

// ===== Quick links
const qlKey='mc_quicklinks';
function loadQL(){ const ul=document.getElementById('ql-list'); ul.innerHTML=''; const list=JSON.parse(localStorage.getItem(qlKey)||'[]');
  list.forEach((u,idx)=>{ const li=document.createElement('li'); const a=document.createElement('a'); a.href=u;a.target='_blank';a.textContent=u;a.className='a';
    const del=document.createElement('button'); del.textContent='×'; del.className='ml-2 btn';
    del.addEventListener('click',()=>{ const arr=JSON.parse(localStorage.getItem(qlKey)||'[]'); arr.splice(idx,1); localStorage.setItem(qlKey,JSON.stringify(arr)); loadQL(); });
    li.appendChild(a); li.appendChild(del); ul.appendChild(li); });
}
document.getElementById('ql-add').addEventListener('click',()=>{ const inp=document.getElementById('ql-url'); const url=inp.value.trim(); if(!url) return;
  const list=JSON.parse(localStorage.getItem(qlKey)||'[]'); list.push(url); localStorage.setItem(qlKey,JSON.stringify(list)); inp.value=''; loadQL();
});
loadQL();

// ===== Notes autosave
const notesKey='mc_notes'; const notes=document.getElementById('notes');
notes.value=localStorage.getItem(notesKey)||''; notes.addEventListener('input',()=>localStorage.setItem(notesKey,notes.value));

// ===== Related links
function updateRelatedLinks(viewId){
  const map={
    'view-base64': [
      ['MDN Base64','https://developer.mozilla.org/en-US/docs/Glossary/Base64'],
      ['MDN btoa','https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/btoa'],
      ['MDN atob','https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/atob']
    ],
    'view-cidr': [
      ['IANA IPv4 Special-Purpose','https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml'],
      ['RFC 4632 CIDR','https://www.rfc-editor.org/rfc/rfc4632']
    ],
    'view-kqlCheat': [
      ['KQL Docs','https://learn.microsoft.com/en-us/kusto/query'],
      ['Sentinel Docs','https://learn.microsoft.com/en-us/azure/sentinel']
    ],
    'view-splCheat': [
      ['Splunk Search Reference','https://docs.splunk.com/Documentation/Splunk/9.4.2/SearchReference/WhatsInThisManual']
    ],
    'view-cvss': [
      ['FIRST CVSS v3.1 Calculator','https://www.first.org/cvss/calculator/3.1'],
      ['NVD CVSS v3 Calculator','https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator']
    ],
    'view-runbook': [
      ['MITRE ATT&CK','https://attack.mitre.org/matrices/enterprise/'],
      ['CISA KEV','https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
      ['NIST CSF','https://www.nist.gov/cyberframework']
    ]
  };
  const ul=document.getElementById('relatedLinks'); ul.innerHTML='';
  (map[viewId]||[]).forEach(([t,u])=>{ const li=document.createElement('li'); const a=document.createElement('a'); a.href=u;a.target='_blank';a.textContent=t;a.className='a'; li.appendChild(a); ul.appendChild(li); });
}

// ===== Base64 (UTF-8 safe)
const b64In=document.getElementById('b64-in'), b64Out=document.getElementById('b64-out');
function b64enc(s){ const bytes=new TextEncoder().encode(s); let bin=''; bytes.forEach(b=>bin+=String.fromCharCode(b)); return btoa(bin); }
function b64dec(b){ const bin=atob(b); const bytes=Uint8Array.from(bin,c=>c.charCodeAt(0)); return new TextDecoder().decode(bytes); }
document.getElementById('b64-encode')?.addEventListener('click',()=>{ try{ b64Out.value=b64enc(b64In.value); toast('Encoded'); }catch(e){ b64Out.value='Error: '+e.message; }});
document.getElementById('b64-decode')?.addEventListener('click',()=>{ try{ b64Out.value=b64dec(b64In.value.trim()); toast('Decoded'); }catch(e){ b64Out.value='Error: '+e.message; }});
document.getElementById('b64-clear')?.addEventListener('click',()=>{ b64In.value=''; b64Out.value=''; });
document.getElementById('b64-copy')?.addEventListener('click',async()=>{ try{ await navigator.clipboard.writeText(b64Out.value); toast('Copied'); }catch{ toast('Copy failed'); }});

// ===== Wildcard mask + helpers
function parseDotted(str){ const parts=str.trim().split('.'); if(parts.length!==4) throw new Error('Use dotted IPv4 like 255.255.255.0');
  const octets=parts.map(p=>{ const n=Number(p); if(!Number.isInteger(n)||n<0||n>255) throw new Error('Each octet 0..255'); return n; }); return octets; }
function toDotted(arr){ return arr.join('.'); }
function wildcardFromMask(oct){ return oct.map(o=>255-o); }
function maskFromPrefix(pfx){ const p=Number(pfx); if(!Number.isInteger(p)||p<0||p>32) throw new Error('Prefix 0..32'); const bits=Array(32).fill(0).map((_,i)=>i<p?1:0); const o=[]; for(let i=0;i<4;i++){ const b=bits.slice(i*8,i*8+8).join(''); o.push(parseInt(b.padEnd(8,'0'),2)); } return o; }
document.getElementById('wm-fromMask')?.addEventListener('click',()=>{ const inp=document.getElementById('wm-subnet'); const out=document.getElementById('wm-out-fromMask'); try{ out.value=toDotted(wildcardFromMask(parseDotted(inp.value))); toast('Calculated'); }catch(e){ out.value='Error: '+e.message; }});
document.getElementById('wm-fromCidr')?.addEventListener('click',()=>{ const c=document.getElementById('wm-cidr'); const om=document.getElementById('wm-out-mask'); const ow=document.getElementById('wm-out-wild'); try{ const m=maskFromPrefix(c.value); om.value=toDotted(m); ow.value=toDotted(wildcardFromMask(m)); toast('Calculated'); }catch(e){ om.value=ow.value='Error: '+e.message; }});

// ===== Hex ↔ Dec
document.getElementById('dec-to-hex')?.addEventListener('click',()=>{ const v=document.getElementById('dec-in').value.trim(); const out=document.getElementById('dec-hex-out');
  if(v===''){out.value='';return;} const n=Number(v); if(!Number.isFinite(n)||n<0){ out.value='Error: enter a non-negative number'; return; } out.value='0x'+Math.floor(n).toString(16).toUpperCase();
});
document.getElementById('hex-to-dec')?.addEventListener('click',()=>{ let v=document.getElementById('hex-in').value.trim(); const out=document.getElementById('hex-dec-out');
  if(v===''){out.value='';return;} v=v.replace(/^0x/i,''); if(!/^[0-9a-f]+$/i.test(v)){ out.value='Error: hex only 0-9 A-F'; return; } out.value=String(parseInt(v,16));
});

// ===== Timestamp
function pad(n){return n.toString().padStart(2,'0');}
function fmtUTC(d){ return d.getUTCFullYear()+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())+' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds())+' UTC'; }
document.getElementById('ts-from-epoch')?.addEventListener('click',()=>{ const v=Number(document.getElementById('ts-epoch').value.trim()); const out=document.getElementById('ts-out');
  if(!Number.isFinite(v)){ out.value='Error: epoch seconds number required'; return; } const d=new Date(v*1000); out.value='UTC: '+fmtUTC(d)+'\nLocal: '+new Date(v*1000).toString();
});
document.getElementById('ts-to-epoch')?.addEventListener('click',()=>{ const s=document.getElementById('ts-human').value.trim(); const out=document.getElementById('ts-out');
  if(!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)){ out.value='Error: use YYYY-MM-DD HH:mm:ss'; return; } const [date,time]=s.split(' '); const [Y,M,D]=date.split('-').map(Number); const [h,m,sec]=time.split(':').map(Number); const ms=Date.UTC(Y,M-1,D,h,m,sec); out.value='Epoch (s): '+Math.floor(ms/1000)+'\nUTC: '+fmtUTC(new Date(ms))+'\nLocal: '+new Date(ms).toString();
});

// ===== CIDR (IPv4)
function ipToInt(ip){ const a=ip.trim().split('.').map(x=>Number(x)); if(a.length!==4||a.some(x=>!Number.isInteger(x)||x<0||x>255)) throw new Error('Enter IPv4 like 192.168.1.10'); return ((a[0]<<24)>>>0)+(a[1]<<16)+(a[2]<<8)+a[3]; }
function intToIp(n){ return [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.'); }
function maskFromPrefixInt(p){ if(p<0||p>32) throw new Error('Prefix 0..32'); return p===0?0:(((0xFFFFFFFF<<(32-p))>>>0)); }
document.getElementById('cidr-calc')?.addEventListener('click',()=>{
  const ipStr=document.getElementById('cidr-ip').value.trim(); const pfx=Number(document.getElementById('cidr-prefix').value.trim()); const out=document.getElementById('cidr-out');
  try{
    const ip=ipToInt(ipStr); const mask=maskFromPrefixInt(pfx); const network=(ip & mask)>>>0; const broadcast=(network | (~mask>>>0))>>>0;
    const firstHost = (pfx===32)? network : ((network+1)>>>0);
    const lastHost  = (pfx>=31)? broadcast : ((broadcast-1)>>>0);
    const hostCount = pfx===32? 1 : (pfx===31? 2 : Math.max(0, (broadcast - network - 1)));
    const maskArr=[(mask>>>24)&255,(mask>>>16)&255,(mask>>>8)&255,mask&255]; const wildcardArr=maskArr.map(o=>255-o);
    out.value = `Network:   ${intToIp(network)}/${pfx}
Broadcast: ${intToIp(broadcast)}
First host:${intToIp(firstHost)}
Last host: ${intToIp(lastHost)}
Hosts:     ${hostCount}
Mask:      ${maskArr.join('.')}
Wildcard:  ${wildcardArr.join('.')}`;
    toast('Calculated');
  }catch(e){ out.value='Error: '+e.message; }
});

// ===== ALE/SLE/ARO
document.getElementById('calc-ale')?.addEventListener('click',()=>{
  const av=Number(document.getElementById('av').value.trim()); const ef=Number(document.getElementById('ef').value.trim()); const aro=Number(document.getElementById('aro').value.trim());
  const out=document.getElementById('ale-out');
  if(!Number.isFinite(av)||!Number.isFinite(ef)||!Number.isFinite(aro)||ef<0||ef>1||aro<0){ out.value='Error: AV number, EF 0..1, ARO >= 0'; return; }
  const sle = av * ef; const ale = sle * aro;
  out.value = `SLE (AV × EF): ${sle.toFixed(2)}
ALE (SLE × ARO): ${ale.toFixed(2)}
Interpretation: Expected annual loss (ALE) for this risk scenario.`;
});

// ===== CVSS helper (vector only)
document.getElementById('cvss-build')?.addEventListener('click',()=>{
  const parts=[
    'CVSS:3.1',
    document.getElementById('cvss-av').value,
    document.getElementById('cvss-ac').value,
    document.getElementById('cvss-pr').value,
    document.getElementById('cvss-ui').value,
    document.getElementById('cvss-s').value,
    document.getElementById('cvss-c').value,
    document.getElementById('cvss-i').value,
    document.getElementById('cvss-a').value
  ];
  const vector=parts.join('/');
  document.getElementById('cvss-vector').value=vector;
  document.getElementById('cvss-first').href='https://www.first.org/cvss/calculator/3.1#'+encodeURIComponent(vector);
  document.getElementById('cvss-nvd').href='https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector='+encodeURIComponent(vector);
  toast('Vector built');
});

// ===== KQL & SPL cheat sheets
const kqlGroups=[
  {title:'Filter & project', items:[
    {q:"SecurityEvent | where EventID == 4625 | project TimeGenerated, Account, IpAddress", d:"Failed logons"},
    {q:"DeviceNetworkEvents | where RemoteUrl has \"example.com\"", d:"Filter by domain"}
  ]},
  {title:'Join & summarize', items:[
    {q:"SigninLogs | summarize count() by bin(TimeGenerated, 1h), ResultType", d:"Hourly sign-in outcomes"},
    {q:"SecurityEvent | where EventID in (4624,4625) | summarize count() by Account", d:"Auth events by account"}
  ]}
];
const splGroups=[
  {title:'Search & fields', items:[
    {q:"index=wineventlog EventCode=4625 | table _time, Account_Name, Source_Network_Address", d:"Failed logons"},
    {q:"index=proxy url=*example.com* | stats count by src_ip, url", d:"Hits to domain"}
  ]},
  {title:'Stats & joins', items:[
    {q:"index=edr process_name=powershell.exe | timechart span=1h count", d:"PowerShell over time"},
    {q:"index=auth (action=success OR action=failure) | stats count by user", d:"Auth counts by user"}
  ]}
];

function renderCheatSheet(rootId, groups){
  const root=document.getElementById(rootId); root.innerHTML='';
  groups.forEach(g=>{
    const card=document.createElement('div'); card.className='border rounded-md p-3';
    const h=document.createElement('h3'); h.className='font-medium'; h.textContent=g.title; card.appendChild(h);
    g.items.forEach(item=>{
      const wrap=document.createElement('div'); wrap.className='mt-2';
      const p=document.createElement('div'); p.className='text-xs text-slate-500'; p.textContent=item.d; wrap.appendChild(p);
      const ta=document.createElement('textarea'); ta.className='w-full border rounded p-2 mono mt-1'; ta.rows=2; ta.value=item.q; wrap.appendChild(ta);
      const btn=document.createElement('button'); btn.className='btn mt-1'; btn.textContent='Copy'; btn.addEventListener('click',async()=>{ try{ await navigator.clipboard.writeText(ta.value); toast('Copied'); }catch{ toast('Copy failed'); }});
      wrap.appendChild(btn); card.appendChild(wrap);
    });
    root.appendChild(card);
  });
}
renderCheatSheet('kql-body', kqlGroups);
renderCheatSheet('spl-body', splGroups);

// ===== Regex tester
document.getElementById('re-run')?.addEventListener('click',()=>{
  const pat=document.getElementById('re-pattern').value; const flags=document.getElementById('re-flags').value; const txt=document.getElementById('re-text').value; const out=document.getElementById('re-out');
  try{ const re=new RegExp(pat, flags); const matches=[...txt.matchAll(re)]; if(!matches.length){ out.value='No matches'; return; }
    out.value=matches.map(m=>`Match: ${m[0]} (index ${m.index})`+(m.length>1?`\nGroups: ${m.slice(1).join(', ')}`:'')).join('\n\n'); }
  catch(e){ out.value='Error: '+e.message; }
});

// ===== Runbooks (rendered into shared view)
const RUNBOOKS={ /* same content as before, truncated here for brevity in this comment */
  ransomware:{ title:'Ransomware suspected', quick:['Isolate affected hosts (EDR network containment/VLAN).','Disable interactive logon for suspected accounts; revoke tokens.','Block IOCs (domains/IPs/hashes) on edge/EDR.','Capture volatile data if safe (process list, netconns).','Notify IR lead, Legal, IT Ops; start incident ticket.'],
    full:['Scope: enumerate hosts/users/timeline; identify initial vector.','Collect: EDR timeline, Sysmon, WinSec (4624/4625/4769/4672), firewall, proxy, backups integrity.','Contain: segment networks, disable SMB where feasible, reset creds, rotate keys/secrets.','Eradicate: remove persistence, patch exploited vuln, cleanup artifacts.','Recover: reimage from gold images, restore clean backups, validate business apps.','Lessons: update detections, table-top, report to stakeholders.']},
  unauth:{ title:'Unauthorized access', quick:['Force password reset + revoke sessions for impacted accounts.','Enable sign-in risk policies/MFA if not enforced.','Search for suspicious sign-ins (impossible travel, unfamiliar IPs).','Check mail-forwarding rules/BEC indicators.','Notify affected user and SOC lead.'],
    full:['Scope all logins for user (successful/failed), token issuance, device registrations.','Collect logs: IdP/AAD SigninLogs, ADFS, VPN, email audit, endpoint auth.','Contain: block risky IPs, conditional access, reset API tokens/app passwords.','Eradicate: remove malicious rules/apps, reset recovery factors.','Harden: enforce MFA, conditional access, impossible travel.','Post: user awareness, update detections.']},
  phishing:{ title:'Phishing wave', quick:['Block sender domains/URLs; submit samples to sandbox.','Create transport rules to quarantine similar mail.','Notify users with screenshot + “Report Phish” steps.','Hunt for clicks/credential posts.','Open incident and track campaign ID.'],
    full:['Identify lures/TTPs; gather headers and URLs; host intel via urlscan/VT.','Collect: mail logs, proxy/DNS, EDR URL events, OAuth app consent.','Contain: purge messages, block URLs/domains, disable compromised accounts.','Eradicate: remove OAuth grants, reset creds, rotate tokens.','Awareness: targeted training for impacted groups.']},
  exfil:{ title:'Active data exfiltration', quick:['Throttle/deny egress for suspected hosts/accounts.','Snapshot volatile state: active connections, processes.','Preserve logs and start chain of custody.','Notify IR lead and Data Protection/Legal.'],
    full:['Scope: classify data at risk; map sources/destinations; timeframe.','Collect: DLP logs, proxy/firewall, CASB, storage access, EDR net events.','Contain: block destinations, token revoke, quarantine devices.','Eradicate: remove tools/tunnels, rotate keys.','Review: breach notification obligations.']},
  lateral:{ title:'Lateral movement', quick:['Disable suspected accounts; block SMB/RDP from affected segments.','Contain endpoints; stop PsExec/WMI/RemoteService use.','Hunt for credential dumping and admin token misuse.'],
    full:['Review auth logs (4769/4624/4672), admin groups changes (4732/4728).','Collect: Sysmon 1/3/7/10/11, EDR process graph, firewall east-west.','Contain: segment, enforce LAPS/LSA protection, disable legacy protocols.','Eradicate: remove persistence (scheduled tasks, run keys, services).','Harden: tiered admin, JIT/JEA.']},
  webshell:{ title:'Web shell suspected', quick:['Isolate web server; preserve webroot; stop external access if possible.','Capture memory dump and running processes.','Block suspicious IPs/URIs at WAF.'],
    full:['Collect: web server logs, config, file integrity, WAF logs.','Identify upload vectors; enumerate backdoors.','Contain/eradicate: remove shell, patch vuln, rotate credentials.','Recover: redeploy clean image, restore content, add WAF rules.','Monitor: detections for re-hit.']},
  ddos:{ title:'DDoS / edge exploitation', quick:['Engage ISP/WAF provider for mitigation.','Enable rate limiting/geo blocks; move to CDN shield.','Increase autoscaling thresholds as safe.'],
    full:['Classify attack type (volumetric/protocol/app).','Collect: edge device logs, WAF metrics, NetFlow.','Harden: TLS offload, caching, connection limits, patch edge devices.','Review: vendor runbook and post-mortem.']},
  insider:{ title:'Insider data mishandling', quick:['Suspend access to sensitive repositories.','Preserve endpoints and storage audit trails.','Notify HR/Legal; start evidence handling.'],
    full:['Scope data touched; identify exfil methods (USB/cloud/email).','Collect: DLP, storage, CASB, EDR file events.','Contain: revoke access, disable sharing links, rotate tokens.','Eradicate: remove local copies; require attestation.','Post: least-privilege review, monitoring.']},
  lostdevice:{ title:'Lost/Stolen device', quick:['Issue remote wipe/lock; revoke auth tokens.','Mark device as compromised in MDM/EDR.','Notify user, security, and IT.'],
    full:['Verify last seen, user activity, sensitive data presence.','Collect: MDM, EDR, IdP sessions, VPN connections.','Contain: block device certs, rotate passwords/keys.','Replace device; user re-onboarding; report if required.']}
};

function renderRunbook(key){
  const rb=RUNBOOKS[key]||{title:'Runbook',quick:[],full:[]};
  document.getElementById('rb-title').textContent='Runbook: '+rb.title;
  const q=document.getElementById('rb-quick'); q.innerHTML='';
  const f=document.getElementById('rb-full'); f.innerHTML='';
  const ql=document.createElement('ol'); ql.className='list-decimal ml-5 text-sm space-y-2'; rb.quick.forEach(i=>{const li=document.createElement('li'); li.textContent=i; ql.appendChild(li);}); q.appendChild(ql);
  const fl=document.createElement('ul'); fl.className='list-disc ml-5 text-sm space-y-2'; rb.full.forEach(i=>{const li=document.createElement('li'); li.textContent=i; fl.appendChild(li);}); f.appendChild(fl);
  wireTabs(document.getElementById('view-runbook')); // rewire tabs in this view
}

// ===== Toast helper
function toast(msg){ const t=document.createElement('div'); t.className='toast'; t.textContent=msg; document.body.appendChild(t); setTimeout(()=>t.remove(),1200); }
