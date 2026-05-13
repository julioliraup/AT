async function load() {
    const sid = new URLSearchParams(location.search).get('sid');
    const el = document.getElementById('detail');

    if (!sid) {
        el.innerHTML = '<h1 style="color: var(--neon-pink)">[ ERROR: SID NOT SPECIFIED ]</h1>';
        return;
    }

    try {
        const r = await fetch(`./db/sid/${sid}.json`);
        if (!r.ok) throw new Error('Not found');
        const d = await r.json();

        document.title = `SID ${d.sid} - Antiphishing`;

        const severityClass = d.severity?.toLowerCase() === 'high' ? 'high' : '';
        const actionClass = d.action?.toLowerCase() === 'alert' ? 'alert' : '';

        // PhishStats block
        let psHtml = '';
        if (d.phishstats) {
            const ps = d.phishstats;
            
            let mapHtml = '';
            if (ps.latitude && ps.longitude) {
                const lat = parseFloat(ps.latitude);
                const lon = parseFloat(ps.longitude);
                const bbox = `${lon - 0.05},${lat - 0.05},${lon + 0.05},${lat + 0.05}`;
                mapHtml = `
                <div class="data-group" style="margin-top: 25px; border-top: 1px dashed rgba(255,255,255,0.1); padding-top: 20px;">
                    <span class="data-label">Origin Map Overlay</span>
                    <div style="border: 1px solid var(--cyan); border-radius: 8px; overflow: hidden; height: 250px; box-shadow: 0 0 15px rgba(0, 229, 255, 0.1); background: #000; position: relative;">
                        <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; background: rgba(0, 229, 255, 0.05); z-index: 10;"></div>
                        <iframe width="100%" height="100%" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" 
                            src="https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&amp;layer=mapnik&amp;marker=${lat}%2C${lon}" 
                            style="filter: invert(100%) hue-rotate(180deg) brightness(85%) contrast(120%) sepia(30%) hue-rotate(150deg); width: 100%; height: 100%;">
                        </iframe>
                    </div>
                </div>`;
            }
            psHtml = `
            <h2 class="section-title">PHISHSTATS INTELLIGENCE</h2>
            <div class="card">
                <div class="grid-2">
                    <div class="data-group">
                        <span class="data-label">IP Address</span>
                        <span class="data-value">${ps.ip || 'N/A'}</span>
                    </div>
                    <div class="data-group">
                        <span class="data-label">Location</span>
                        <span class="data-value">${[ps.city, ps.countryname].filter(Boolean).join(', ') || 'N/A'}</span>
                    </div>
                    <div class="data-group">
                        <span class="data-label">ISP / ASN</span>
                        <span class="data-value">${ps.isp || 'N/A'} (${ps.asn || 'N/A'})</span>
                    </div>
                    <div class="data-group">
                        <span class="data-label">Date Seen</span>
                        <span class="data-value">${ps.date ? new Date(ps.date).toLocaleString() : 'N/A'}</span>
                    </div>
                    <div class="data-group">
                        <span class="data-label">HTTP Code / Server</span>
                        <span class="data-value">${ps.http_code || '?'} / ${ps.http_server || 'N/A'}</span>
                    </div>
                    <div class="data-group">
                        <span class="data-label">Risk Score</span>
                        <span class="data-value" style="color: ${ps.score > 5 ? 'var(--neon-pink)' : 'var(--cyan)'}">${ps.score || 'N/A'} / 10</span>
                    </div>
                </div>
                <div class="data-group" style="margin-top: 15px;">
                    <span class="data-label">Full URL</span>
                    <span class="data-value" style="font-size: 0.85em; color: var(--text-muted);">${ps.url || 'N/A'}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">Vulnerabilities</span>
                    <span class="data-value">${ps.vulns || 'None detected'}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">SHA-256 Hash</span>
                    <span class="data-value" style="font-size: 0.8em; color: var(--cyan);">${ps.hash || 'N/A'}</span>
                </div>
                ${mapHtml}
            </div>`;
        } else {
            psHtml = `
            <h2 class="section-title">PHISHSTATS INTELLIGENCE</h2>
            <div class="card" style="text-align: center; color: var(--text-muted); padding: 40px;">
                <p>[ NO INTELLIGENCE DATA AVAILABLE ]</p>
            </div>`;
        }

        const refsHtml = (d.references && d.references.length > 0) 
            ? `<ul class="ref-list">${d.references.map(r => `<li>${r}</li>`).join('')}</ul>` 
            : '<span class="data-value">No references</span>';

        el.innerHTML = 
        `<div class="card glow" style="border-top: 4px solid var(--neon-pink);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px; margin-bottom: 20px;">
                <h1 style="margin: 0; font-size: 2.5em; color: var(--text);">SID <span style="color: var(--cyan);">${d.sid}</span></h1>
                <div>
                    <span class="badge ${severityClass}">${d.severity || 'Unknown'} Severity</span>
                    <span class="badge ${actionClass}">${d.action || 'Unknown'}</span>
                </div>
            </div>
            
            <h2 style="color: var(--text-muted); font-size: 1.2em; margin-bottom: 30px;">${d.msg || 'No description'}</h2>
            
            <h2 class="section-title">SIGNATURE METADATA</h2>
            <div class="grid-2">
                <div class="data-group">
                    <span class="data-label">Protocol</span>
                    <span class="data-value" style="text-transform: uppercase;">${d.protocol || 'N/A'}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">Class Type</span>
                    <span class="data-value">${d.classtype || 'N/A'}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">Revision</span>
                    <span class="data-value">${d.rev || 'N/A'}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">Risk Score</span>
                    <span class="data-value">${d.risk_score || 'N/A'}</span>
                </div>
            </div>

            <div class="data-group" style="margin-top: 20px;">
                <span class="data-label">Raw Rule</span>
                <pre class="code-block">${d.rule_raw || 'Rule unavailable'}</pre>
            </div>

            <div class="data-group" style="margin-top: 20px;">
                <span class="data-label">References</span>
                ${refsHtml}
            </div>
        </div>
        ${psHtml}`;

    } catch (e) {
        console.error(e);
        el.innerHTML = `
        <div class="card" style="border-color: var(--neon-pink); text-align: center; padding: 50px;">
            <h1 style="color: var(--neon-pink);">[ DATA_CORRUPTED // NOT_FOUND ]</h1>
            <p>The signature data could not be retrieved from the database.</p>
        </div>`;
    }
}

load();