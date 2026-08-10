'use strict';

let DATA = [];
let DNS_DOMAINS = [];
let TLS_DOMAINS = [];
let ATI_DOMAINS = new Set();

const DNS_SID = 6000000;
const TLS_SID = 6000001;

async function load() {
  const r = await fetch('./db/index.json');
  DATA = await r.json();

  const total = DATA.length;
  const urls = DATA.filter(x => x.protocol === 'http' || x.protocol === 'https').length;
  let domains_count = 0;
  let ati_count = 0;

  const dnsEntry = DATA.find(x => x.sid === DNS_SID);
  if (dnsEntry) {
    if (dnsEntry.domains_count) domains_count = dnsEntry.domains_count;
    if (dnsEntry.ati_count) ati_count = dnsEntry.ati_count;
  }

  if (domains_count === 0) {
    const dnsRule = DATA.find(x => x.protocol === 'dns' || x.protocol === 'tls');
    if (dnsRule) {
      try {
        const res = await fetch(`./db/sid/${dnsRule.sid}.json`);
        const detail = await res.json();
        if (detail.dns_feed) {
          if (detail.dns_feed.domains_count) domains_count = detail.dns_feed.domains_count;
          if (detail.dns_feed.ati_count) ati_count = detail.dns_feed.ati_count;
        }
      } catch (_) { }
    }
  }

  const malicious_vectors = urls + domains_count;

  const statsEl = document.getElementById('stats-widget');
  if (statsEl) {
    const atiOrbHtml = ati_count > 0 ? `
      <div class="visualizer-orb" style="border-color: rgba(0, 229, 255, 0.4);">
        <span class="v-value" style="color: #00f0ff; text-shadow: 0 0 15px #00f0ff;">${ati_count}</span>
        <span class="v-label">NRD Intel - ATI (Antiphishing Threat Intel)</span>
      </div>
    ` : '';

    statsEl.innerHTML = `
      <div class="visualizer-orb">
        <span class="v-value">${total}</span>
        <span class="v-label">Total Signatures</span>
      </div>
      <div class="visualizer-orb" style="border-color: rgba(255, 170, 0, 0.3);">
        <span class="v-value" style="color: #ffaa00; text-shadow: 0 0 15px #ffaa00;">${urls}</span>
        <span class="v-label">Malicious URLs</span>
      </div>
      <div class="visualizer-orb" style="border-color: rgba(0, 255, 128, 0.3);">
        <span class="v-value" style="color: #00ff80; text-shadow: 0 0 15px #00ff80;">${domains_count}</span>
        <span class="v-label">TLS SNI / DNS domanins</span>
      </div>
      ${atiOrbHtml}
      <div class="visualizer-orb" style="border-color: rgba(138, 43, 226, 0.5);">
        <span class="v-value" style="color: #b050ff; text-shadow: 0 0 15px #b050ff;">${malicious_vectors}</span>
        <span class="v-label">Malicious Vectors</span>
      </div>
    `;
  }
}

async function loadFeedDomains() {
  try {
    const [dRes, tRes] = await Promise.all([
      fetch(`./db/sid/${DNS_SID}.json`),
      fetch(`./db/sid/${TLS_SID}.json`),
    ]);
    const dData = await dRes.json();
    const tData = await tRes.json();
    DNS_DOMAINS = (dData.dns_feed && dData.dns_feed.domains) || [];
    TLS_DOMAINS = (tData.dns_feed && tData.dns_feed.domains) || [];

    const dAti = (dData.dns_feed && dData.dns_feed.ati_domains) || [];
    const tAti = (tData.dns_feed && tData.dns_feed.ati_domains) || [];
    ATI_DOMAINS = new Set([...dAti, ...tAti].map(x => String(x).toLowerCase()));
  } catch (_) { }
}

function protocolBadge(protocol) {
  const MAP = {
    dns: { label: 'DNS', color: 'var(--neon-pink)', bg: 'rgba(255,0,85,0.1)' },
    tls: { label: 'TLS', color: '#00ff80', bg: 'rgba(0,255,128,0.07)' },
    http: { label: 'HTTP', color: 'var(--cyan)', bg: 'rgba(0,229,255,0.1)' },
    https: { label: 'HTTPS', color: 'var(--cyan)', bg: 'rgba(0,229,255,0.1)' },
  };
  const s = MAP[protocol] || { label: (protocol || '').toUpperCase(), color: 'var(--cyan)', bg: 'rgba(0,229,255,0.1)' };
  return `<span class="badge" style="border-color:${s.color};color:${s.color};background:${s.bg};font-size:0.7em;">${s.label}</span>`;
}

function renderCards(rows) {
  const el = document.getElementById('cards');
  if (rows.length === 0) {
    el.innerHTML = `<div class="card" style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 40px;">[ NO MATCHING RECORDS ]</div>`;
    return;
  }
  el.innerHTML = rows.map(x => {
    const staleTag = x.is_stale ? '<span class="badge stale" style="margin-left: 8px;">STALE</span>' : '';
    const atiTag = x.is_ati ? '<span class="badge ati" style="margin-left: 8px;" title="Antiphishing Threat Intelligence">ATI</span>' : '';
    const severityClass = (x.severity || '').toLowerCase() === 'high' ? 'high' : '';
    const proto = protocolBadge(x.protocol);
    const label = x.domain ? x.domain : x.name;
    const href = x.domain
      ? `signature.html?sid=${x.sid}&domain=${encodeURIComponent(x.domain)}`
      : `signature.html?sid=${x.sid}`;
    return `
      <div class="card glow" onclick="location='${href}'">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
           <h3 style="margin: 0; color: var(--cyan); font-size: 1.1em;">SID ${x.sid}</h3>
           <div>
             ${proto}
             ${atiTag}
             ${staleTag}
           </div>
        </div>
        <p style="font-size: 0.9em; color: var(--text-muted); margin: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${label}</p>
      </div>
    `;
  }).join('');
}

let _feedLoaded = false;

document.getElementById('search').oninput = async (e) => {
  const q = e.target.value.trim().toLowerCase();
  const statsWidget = document.getElementById('stats-widget');
  const cardsWidget = document.getElementById('cards');

  if (!q) {
    statsWidget.style.display = 'grid';
    cardsWidget.style.display = 'none';
    return;
  }

  statsWidget.style.display = 'none';
  cardsWidget.style.display = 'grid';

  if (!_feedLoaded) {
    await loadFeedDomains();
    _feedLoaded = true;
  }

  const results = [];

  const ruleMatches = DATA.filter(x =>
    x.protocol !== 'dns' && x.protocol !== 'tls' &&
    (String(x.sid).includes(q) || (x.name || '').toLowerCase().includes(q))
  );
  for (const r of ruleMatches.slice(0, 50)) results.push(r);

  const dnsDomains = DNS_DOMAINS.filter(d => d.toLowerCase().includes(q));
  for (const d of dnsDomains.slice(0, 25)) {
    const isAti = ATI_DOMAINS.has(d.toLowerCase());
    results.push({ sid: DNS_SID, name: 'DNS feed', protocol: 'dns', severity: 'high', domain: d, is_ati: isAti });
  }

  const tlsDomains = TLS_DOMAINS.filter(d => d.toLowerCase().includes(q));
  for (const d of tlsDomains.slice(0, 25)) {
    const isAti = ATI_DOMAINS.has(d.toLowerCase());
    results.push({ sid: TLS_SID, name: 'TLS feed', protocol: 'tls', severity: 'high', domain: d, is_ati: isAti });
  }

  renderCards(results.slice(0, 50));
};

load();

setTimeout(() => {
  if (document.cookie.split('; ').some(row => row.startsWith('donateBannerShown='))) return;
  document.cookie = 'donateBannerShown=true; max-age=28800; path=/';

  const banner = document.createElement('div');
  banner.innerHTML = `
        <div style="position:fixed; bottom:20px; right:20px; background:rgba(20,20,20,0.95); border:1px solid var(--cyan); border-radius:8px; padding:20px; box-shadow:0 0 20px rgba(0,229,255,0.2); z-index:9999; max-width:350px; color:var(--text); font-family:'Orbitron', sans-serif;">
            <button onclick="this.parentElement.remove()" style="position:absolute; top:10px; right:10px; background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:20px; padding:0; line-height:1;">&times;</button>
            <h3 style="margin-top:0; color:var(--neon-pink); font-size:1.1em; display:flex; align-items:center; gap:8px;">
                &#x26A0; Too many requests
            </h3>
            <p style="font-size:0.9em; line-height:1.4; color:var(--text-muted); margin-bottom:15px;">
                This is what we get when we try to list detailed information of the vectors. We can solve this by paying for APIs that meet our demand.
            </p>
            <a href="https://github.com/sponsors/julioliraup" target="_blank" style="display:inline-block; background:rgba(0,229,255,0.1); border:1px solid var(--cyan); color:var(--cyan); padding:8px 15px; text-decoration:none; border-radius:4px; font-size:0.85em; transition:0.3s; text-transform:uppercase; letter-spacing:1px;" onmouseover="this.style.background='var(--cyan)'; this.style.color='#000';" onmouseout="this.style.background='rgba(0,229,255,0.1)'; this.style.color='var(--cyan)';">
                Contribute
            </a>
        </div>
    `;
  document.body.appendChild(banner.firstElementChild);
}, 5000);
