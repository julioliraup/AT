let DATA = [];

async function load() {
  const r = await fetch('./db/index.json');
  DATA = await r.json();
  
  const total = DATA.length;
  const urls = DATA.filter(x => x.protocol === 'http' || x.protocol === 'https').length;
  let domains_count = 0;
  for(let row of DATA) {
      if(row.domains_count) {
          domains_count = row.domains_count;
          break;
      }
  }
  
  if (domains_count === 0) {
      const dnsRule = DATA.find(x => x.protocol === 'dns' || x.protocol === 'tls');
      if (dnsRule) {
          try {
              const res = await fetch(`./db/sid/${dnsRule.sid}.json`);
              const detail = await res.json();
              if (detail.dns_feed && detail.dns_feed.domains_count) {
                  domains_count = detail.dns_feed.domains_count;
              }
          } catch(e){}
      }
  }

  const malicious_vectors = urls + domains_count;

  const statsEl = document.getElementById('stats-widget');
  if(statsEl) {
    statsEl.innerHTML = `
      <div class="visualizer-orb">
        <span class="v-value">${total}</span>
        <span class="v-label">Total Signatures</span>
      </div>
      <div class="visualizer-orb" style="border-color: rgba(255, 170, 0, 0.3);">
        <span class="v-value" style="color: #ffaa00; text-shadow: 0 0 15px #ffaa00;">${urls}</span>
        <span class="v-label">Malicious URLs</span>
      </div>
      <div class="visualizer-orb" style="border-color: rgba(255, 0, 85, 0.3);">
        <span class="v-value" style="color: var(--neon-pink); text-shadow: 0 0 15px var(--neon-pink);">${domains_count}</span>
        <span class="v-label">DNS Domains</span>
      </div>
      <div class="visualizer-orb" style="border-color: rgba(0, 255, 128, 0.3);">
        <span class="v-value" style="color: #00ff80; text-shadow: 0 0 15px #00ff80;">${domains_count}</span>
        <span class="v-label">TLS SNI</span>
      </div>
      <div class="visualizer-orb" style="border-color: rgba(138, 43, 226, 0.5);">
        <span class="v-value" style="color: #b050ff; text-shadow: 0 0 15px #b050ff;">${malicious_vectors}</span>
        <span class="v-label">Malicious Vectors</span>
      </div>
    `;
  }
}

function render(rows) {
  const el = document.getElementById('cards');
  if(rows.length === 0) {
    el.innerHTML = `<div class="card" style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 40px;">[ NO MATCHING RECORDS ]</div>`;
    return;
  }
  el.innerHTML = rows.map(x => {
    const staleTag = x.is_stale ? '<span class="badge stale" style="margin-left: 8px;">STALE</span>' : '';
    return `
      <div class="card glow" onclick="go(${x.sid})">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
           <h3 style="margin: 0; color: var(--cyan); font-size: 1.1em;">SID ${x.sid}</h3>
           <div>
             <span class="badge ${x.severity?.toLowerCase() === 'high' ? 'high' : ''}" style="font-size: 0.7em;">${x.protocol}</span>
             ${staleTag}
           </div>
        </div>
        <p style="font-size: 0.9em; color: var(--text-muted); margin: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${x.name}</p>
      </div>
    `;
  }).join('');
}

function go(sid){
  location = 'signature.html?sid=' + sid;
}

document.getElementById('search').oninput = (e) => {
  const q = e.target.value.trim().toLowerCase();
  const statsWidget = document.getElementById('stats-widget');
  const cardsWidget = document.getElementById('cards');
  
  if(!q) {
     statsWidget.style.display = 'grid';
     cardsWidget.style.display = 'none';
     return;
  }
  
  statsWidget.style.display = 'none';
  cardsWidget.style.display = 'grid';
  
  const filtered = DATA.filter(x => String(x.sid).includes(q) || x.name.toLowerCase().includes(q));
  render(filtered.slice(0, 50));
}

load();

// Banner logic: Show "Too many requests" after 5 seconds, only once.
setTimeout(() => {
    if (localStorage.getItem('donateBannerShown')) return;
    localStorage.setItem('donateBannerShown', 'true');
    
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
            <a href="https://github.com/julioliraup/AT/#how-to-donate" target="_blank" style="display:inline-block; background:rgba(0,229,255,0.1); border:1px solid var(--cyan); color:var(--cyan); padding:8px 15px; text-decoration:none; border-radius:4px; font-size:0.85em; transition:0.3s; text-transform:uppercase; letter-spacing:1px;" onmouseover="this.style.background='var(--cyan)'; this.style.color='#000';" onmouseout="this.style.background='rgba(0,229,255,0.1)'; this.style.color='var(--cyan)';">
                Contribute
            </a>
        </div>
    `;
    document.body.appendChild(banner.firstElementChild);
}, 5000);
