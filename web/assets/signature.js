// SPDX-License-Identifier: GPL-3.0-or-later
//
// signature.js -- Signature detail view for the Antiphishing dashboard.
//
// Copyright (C) 2024  Julio Lira <https://julioliraup.github.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

'use strict';

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/**
 * Return *value* as a string, or *fallback* when the value is null/undefined/empty.
 *
 * @param {*} value
 * @param {string} [fallback='N/A']
 * @returns {string}
 */
const val = (value, fallback = 'N/A') =>
    (value === null || value === undefined || value === '')
        ? fallback
        : String(value);

/**
 * Format an ISO timestamp for locale display, or return *fallback*.
 *
 * @param {string|null|undefined} iso
 * @param {string} [fallback='N/A']
 * @returns {string}
 */
const fmtDate = (iso, fallback = 'N/A') => {
    if (!iso) return fallback;
    try { return new Date(iso).toLocaleString(); } catch (_) { return fallback; }
};

/**
 * Derive a CSS colour expression for an HTTP status code.
 * 2xx → cyan, 3xx → amber, 4xx/5xx → neon-pink, unknown → muted.
 *
 * @param {number|null|undefined} code
 * @returns {string}
 */
const httpCodeColour = (code) => {
    if (!code) return 'var(--text-muted)';
    if (code >= 200 && code < 300) return 'var(--cyan)';
    if (code >= 300 && code < 400) return '#ffaa00';
    if (code >= 400)               return 'var(--neon-pink)';
    return 'var(--text-muted)';
};

/**
 * Derive a CSS colour for a TLP (Traffic Light Protocol) classification.
 *
 * @param {string|null|undefined} tlp
 * @returns {string}
 */
const tlpColour = (tlp) => {
    const map = { WHITE: '#cccccc', GREEN: '#00ff80', AMBER: '#ffaa00', RED: 'var(--neon-pink)' };
    return map[(tlp || '').toUpperCase()] || 'var(--text-muted)';
};

// ---------------------------------------------------------------------------
// HTML fragment builders
// ---------------------------------------------------------------------------

/**
 * Build the OpenStreetMap overlay fragment.
 *
 * @param {number} lat
 * @param {number} lon
 * @returns {string}
 */
const buildMapHtml = (lat, lon) => {
    const bbox = `${lon - 0.05},${lat - 0.05},${lon + 0.05},${lat + 0.05}`;
    const src  = `https://www.openstreetmap.org/export/embed.html`
               + `?bbox=${bbox}&layer=mapnik&marker=${lat}%2C${lon}`;
    return `
    <div class="data-group" style="margin-top:25px;border-top:1px dashed rgba(255,255,255,0.1);padding-top:20px;">
        <span class="data-label">Origin Map Overlay</span>
        <div style="border:1px solid var(--cyan);border-radius:8px;overflow:hidden;
                    height:250px;box-shadow:0 0 15px rgba(0,229,255,0.1);background:#000;position:relative;">
            <div style="position:absolute;top:0;left:0;width:100%;height:100%;
                        pointer-events:none;background:rgba(0,229,255,0.05);z-index:10;"></div>
            <iframe width="100%" height="100%" frameborder="0" scrolling="no"
                    marginheight="0" marginwidth="0" src="${src}"
                    style="filter:invert(100%) hue-rotate(180deg) brightness(85%)
                           contrast(120%) sepia(30%) hue-rotate(150deg);width:100%;height:100%;">
            </iframe>
        </div>
    </div>`;
};

/**
 * Build the Google Safe Browsing threat section.
 * Returns an empty string when no hits are present.
 *
 * @param {Array<{threat_type:string, platform_type:string, cache_duration:string}>} hits
 * @returns {string}
 */
const buildSafeBrowsingHtml = (hits) => {
    if (!hits || hits.length === 0) return '';

    const THREAT_COLOUR = {
        MALWARE:             'var(--neon-pink)',
        SOCIAL_ENGINEERING:  '#ffaa00',
        UNWANTED_SOFTWARE:   '#ff6600',
        POTENTIALLY_HARMFUL: '#ff6600',
    };

    const rows = hits.map(h => {
        const threat  = val(h.threat_type, 'UNKNOWN');
        const colour  = THREAT_COLOUR[threat] || 'var(--neon-pink)';
        const ttl     = h.cache_duration ? ` · TTL: ${h.cache_duration}` : '';
        return `
        <div style="background:rgba(255,0,85,0.07);border:1px solid ${colour};
                    border-radius:6px;padding:10px 14px;margin-bottom:8px;">
            <span class="badge" style="border-color:${colour};color:${colour};
                                       background:rgba(255,0,85,0.1);font-size:0.7em;">
                ${threat}
            </span>
            <span style="margin-left:8px;font-size:0.85em;color:var(--text-muted);">
                Platform: <strong style="color:var(--text);">${val(h.platform_type)}</strong>${ttl}
            </span>
        </div>`;
    }).join('');

    return `
    <div class="data-group" style="margin-top:20px;border-top:1px dashed rgba(255,0,85,0.25);padding-top:20px;">
        <span class="data-label" style="color:var(--neon-pink);">
            &#x26A0; Google Safe Browsing Hits (${hits.length})
        </span>
        <div style="margin-top:10px;">${rows}</div>
    </div>`;
};

/**
 * Build the TLS certificate analysis section.
 * Returns an empty string when *cert* is absent.
 *
 * Key CTI signals: free-CA issuers (Let's Encrypt) are common in phishing;
 * wildcard SANs, short validity windows, and self-signed certs are red flags.
 *
 * @param {object|null} cert
 * @returns {string}
 */
const buildCertHtml = (cert) => {
    if (!cert) return '';

    const selfSigned  = (cert.is_self_signed || 'no') !== 'no';
    const expired     = cert.is_expired === true;
    const certColour  = (selfSigned || expired) ? 'var(--neon-pink)' : 'var(--cyan)';
    const sanList     = (cert.subject_alt_names || []).join(', ') || 'N/A';
    const hasWildcard = (cert.subject_alt_names || []).some(s => s.startsWith('*.'));

    const fp256 = cert.fingerprint_sha256
        ? `<div class="data-group">
               <span class="data-label">Fingerprint SHA-256</span>
               <pre class="code-block" style="font-size:0.7em;margin:0;border-left-color:var(--cyan);word-break:break-all;">${cert.fingerprint_sha256}</pre>
           </div>`
        : '';

    return `
    <div style="margin-top:20px;border-top:1px dashed rgba(0,229,255,0.2);padding-top:20px;">
        <span class="data-label" style="color:${certColour};display:block;margin-bottom:12px;">
            TLS Certificate Analysis
            ${selfSigned ? '<span class="badge high" style="font-size:0.65em;margin-left:8px;">SELF-SIGNED</span>' : ''}
            ${expired    ? '<span class="badge high" style="font-size:0.65em;margin-left:8px;">EXPIRED</span>'     : ''}
            ${hasWildcard? '<span class="badge" style="font-size:0.65em;margin-left:8px;border-color:#ffaa00;color:#ffaa00;">WILDCARD SAN</span>' : ''}
        </span>
        <div class="grid-2">
            <div class="data-group">
                <span class="data-label">Subject CN</span>
                <span class="data-value" style="color:${certColour};">${val(cert.subject_cn)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Issuer</span>
                <span class="data-value">${val(cert.issuer_org)} (${val(cert.issuer_cn)})</span>
            </div>
            <div class="data-group">
                <span class="data-label">Valid From</span>
                <span class="data-value">${fmtDate(cert.not_valid_before)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Valid Until</span>
                <span class="data-value" style="color:${expired ? 'var(--neon-pink)' : 'inherit'};">
                    ${fmtDate(cert.not_valid_after)}
                </span>
            </div>
            <div class="data-group">
                <span class="data-label">Signature Algorithm</span>
                <span class="data-value">${val(cert.signature_algorithm)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">x509 Version</span>
                <span class="data-value">${val(cert.x509_version)}</span>
            </div>
        </div>
        <div class="data-group">
            <span class="data-label">Subject Alt Names (SAN)</span>
            <span class="data-value" style="font-size:0.85em;color:${hasWildcard ? '#ffaa00' : 'var(--text-muted)'};">
                ${sanList}
            </span>
        </div>
        ${fp256}
    </div>`;
};

/**
 * Build the HTTP infrastructure section from response headers.
 * Returns an empty string when *httpResp* is absent.
 *
 * CDN detection: presence of CF-RAY or SERVER=cloudflare indicates
 * the site uses Cloudflare, which is frequently abused for phishing.
 *
 * @param {object|null} httpResp
 * @returns {string}
 */
const buildInfraHtml = (httpResp) => {
    if (!httpResp) return '';
    if (!Object.values(httpResp).some(Boolean)) return '';

    const isCF = !!(httpResp.cf_ray || (httpResp.server || '').toLowerCase().includes('cloudflare'));
    const cfBadge = isCF
        ? `<span class="badge" style="border-color:#f48024;color:#f48024;
                                      background:rgba(244,128,36,0.1);font-size:0.65em;margin-left:8px;">
               CLOUDFLARE FRONTED
           </span>`
        : '';

    return `
    <div style="margin-top:20px;border-top:1px dashed rgba(0,229,255,0.2);padding-top:20px;">
        <span class="data-label" style="color:var(--cyan);display:block;margin-bottom:12px;">
            HTTP Infrastructure ${cfBadge}
        </span>
        <div class="grid-2">
            <div class="data-group">
                <span class="data-label">Server</span>
                <span class="data-value">${val(httpResp.server)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Content-Type</span>
                <span class="data-value">${val(httpResp.content_type)}</span>
            </div>
            ${httpResp.cf_ray ? `
            <div class="data-group">
                <span class="data-label">Cloudflare Ray ID</span>
                <span class="data-value" style="color:#f48024;">${httpResp.cf_ray}</span>
            </div>
            <div class="data-group">
                <span class="data-label">CF Cache Status</span>
                <span class="data-value">${val(httpResp.cf_cache_status)}</span>
            </div>` : ''}
            ${httpResp.alt_svc ? `
            <div class="data-group">
                <span class="data-label">Alt-Svc (HTTP/3)</span>
                <span class="data-value" style="font-size:0.85em;color:var(--text-muted);">${httpResp.alt_svc}</span>
            </div>` : ''}
        </div>
    </div>`;
};

/**
 * Build the file analysis section (hashes + magic type).
 * Returns an empty string when no file data is present.
 *
 * @param {object} otx - Normalised intel.alienvault object.
 * @returns {string}
 */
const buildFileAnalysisHtml = (otx) => {
    if (!otx.sha256 && !otx.md5 && !otx.filetype) return '';

    const hashRow = (label, hash) => hash
        ? `<div class="data-group">
               <span class="data-label">${label}</span>
               <pre class="code-block" style="font-size:0.75em;margin:0;
                    border-left-color:var(--cyan);word-break:break-all;">${hash}</pre>
           </div>`
        : '';

    return `
    <div style="margin-top:20px;border-top:1px dashed rgba(0,229,255,0.2);padding-top:20px;">
        <span class="data-label" style="color:var(--cyan);display:block;margin-bottom:12px;">
            File Analysis
        </span>
        <div class="grid-2">
            <div class="data-group">
                <span class="data-label">File Type</span>
                <span class="data-value">${val(otx.filetype)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">File Magic</span>
                <span class="data-value" style="color:var(--text-muted);font-size:0.9em;">${val(otx.filemagic)}</span>
            </div>
        </div>
        ${hashRow('SHA-256', otx.sha256)}
        ${hashRow('MD5', otx.md5)}
    </div>`;
};

/**
 * Build the complete AlienVault OTX intelligence card.
 *
 * @param {object|null} otx    - Content of intel.alienvault, or null.
 * @param {object|null} ipinfo - Content of intel.ipinfo, used as a geo fallback.
 * @returns {string}
 */
const buildOtxHtml = (otx, ipinfo) => {
    if (!otx) {
        return `
        <h2 class="section-title">ALIENVAULT OTX INTELLIGENCE</h2>
        <div class="card" style="text-align:center;color:var(--text-muted);padding:40px;">
            <p>[ NO OTX DATA AVAILABLE ]</p>
        </div>`;
    }

    const geoStr    = [otx.city, otx.country_name].filter(Boolean).join(', ') || null;
    const geoLine   = geoStr
        ? `${geoStr}${otx.flag ? ' ' + otx.flag : ''}${otx.continent_code ? ' [' + otx.continent_code + ']' : ''}`
        : null;

    const tlpStr    = (otx.tlp || '').toUpperCase();
    const tlpBadge  = tlpStr
        ? `<span class="badge" style="border-color:${tlpColour(tlpStr)};color:${tlpColour(tlpStr)};
                                      background:rgba(0,0,0,0.2);font-size:0.7em;">
               TLP:${tlpStr}
           </span>`
        : '';

    const deepBadge = otx.deep_analysis
        ? `<span class="badge" style="border-color:#00ff80;color:#00ff80;
                                      background:rgba(0,255,128,0.07);font-size:0.7em;">
               DEEP ANALYSIS
           </span>`
        : '';

    const sbCount   = (otx.safebrowsing || []).length;
    const sbBadge   = sbCount
        ? `<span class="badge high" style="font-size:0.7em;">
               &#x26A0; ${sbCount} GSB HIT${sbCount !== 1 ? 'S' : ''}
           </span>`
        : '';

    const isCF = otx.http_response && (
        otx.http_response.cf_ray
        || (otx.http_response.server || '').toLowerCase().includes('cloudflare')
    );
    const cfBadge = isCF
        ? `<span class="badge" style="border-color:#f48024;color:#f48024;
                                      background:rgba(244,128,36,0.1);font-size:0.7em;">
               CLOUDFLARE
           </span>`
        : '';

    // Resolve map coordinates: prefer OTX ip_geo; fall back to ipinfo.loc
    // ("lat,lon" string) when OTX did not return geographic data.
    let mapLat = otx.latitude  ? parseFloat(otx.latitude)  : null;
    let mapLon = otx.longitude ? parseFloat(otx.longitude) : null;
    if ((!mapLat || !mapLon) && ipinfo && ipinfo.loc) {
        const parts = ipinfo.loc.split(',');
        if (parts.length === 2) {
            const parsedLat = parseFloat(parts[0]);
            const parsedLon = parseFloat(parts[1]);
            if (!isNaN(parsedLat) && !isNaN(parsedLon)) {
                mapLat = parsedLat;
                mapLon = parsedLon;
            }
        }
    }
    const mapHtml = (mapLat && mapLon) ? buildMapHtml(mapLat, mapLon) : '';

    return `
    <h2 class="section-title">ALIENVAULT OTX INTELLIGENCE</h2>
    <div class="card">
        <!-- Header badges -->
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:20px;">
            <span class="badge" style="border-color:#ff6600;color:#ff6600;
                                       background:rgba(255,102,0,0.1);font-size:0.7em;">
                OTX // ALIENVAULT
            </span>
            <span class="badge" style="font-size:0.7em;">
                ${otx.url_count || 0} URL${(otx.url_count || 0) !== 1 ? 'S' : ''} INDEXED
            </span>
            ${tlpBadge}${deepBadge}${sbBadge}${cfBadge}
        </div>

        <!-- Network & geolocation -->
        <div class="grid-2">
            <div class="data-group">
                <span class="data-label">IP Address</span>
                <span class="data-value">${val(otx.ip)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">HTTP Status</span>
                <span class="data-value" style="color:${httpCodeColour(otx.http_code)};">
                    ${val(otx.http_code)}
                </span>
            </div>
            <div class="data-group">
                <span class="data-label">Domain (net_loc)</span>
                <span class="data-value" style="color:var(--cyan);">${val(otx.domain)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">First Seen</span>
                <span class="data-value">${fmtDate(otx.first_seen)}</span>
            </div>
            ${geoLine ? `
            <div class="data-group">
                <span class="data-label">Location</span>
                <span class="data-value">${geoLine}</span>
            </div>` : ''}
            ${otx.country_code ? `
            <div class="data-group">
                <span class="data-label">Country Code</span>
                <span class="data-value" style="letter-spacing:3px;">${otx.country_code}</span>
            </div>` : ''}
        </div>

        <!-- Full URL -->
        <div class="data-group" style="margin-top:15px;">
            <span class="data-label">Full URL</span>
            <span class="data-value" style="font-size:0.82em;color:var(--text-muted);word-break:break-all;">
                ${val(otx.url)}
            </span>
        </div>

        <!-- Google Safe Browsing -->
        ${buildSafeBrowsingHtml(otx.safebrowsing)}

        <!-- TLS certificate -->
        ${buildCertHtml(otx.cert)}

        <!-- HTTP infrastructure -->
        ${buildInfraHtml(otx.http_response)}

        <!-- File analysis -->
        ${buildFileAnalysisHtml(otx)}

        <!-- Geographic map -->
        ${mapHtml}
    </div>`;
};

// ---------------------------------------------------------------------------
// Main loader
// ---------------------------------------------------------------------------

/**
 * Fetch the SID JSON record and render the full detail view.
 */
async function load() {
    const sid = new URLSearchParams(location.search).get('sid');
    const el  = document.getElementById('detail');

    if (!sid) {
        el.innerHTML = `<h1 style="color:var(--neon-pink);">[ ERROR: SID NOT SPECIFIED ]</h1>`;
        return;
    }

    try {
        const resp = await fetch(`./db/sid/${sid}.json`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const d = await resp.json();

        document.title = `SID ${d.sid} - Antiphishing`;

        const severityClass = d.severity?.toLowerCase() === 'high' ? 'high' : '';
        const actionClass   = d.action?.toLowerCase()   === 'alert' ? 'alert' : '';

        const refs = Array.isArray(d.references) && d.references.length > 0;
        const refsHtml = refs
            ? `<ul class="ref-list">${d.references.map(r => `<li>${r}</li>`).join('')}</ul>`
            : `<span class="data-value">No references</span>`;

        el.innerHTML = `
        <div class="card glow" style="border-top:4px solid var(--neon-pink);">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;
                        flex-wrap:wrap;gap:15px;margin-bottom:20px;">
                <h1 style="margin:0;font-size:2.5em;color:var(--text);">
                    SID <span style="color:var(--cyan);">${d.sid}</span>
                </h1>
                <div>
                    <span class="badge ${severityClass}">${val(d.severity, 'Unknown')} Severity</span>
                    <span class="badge ${actionClass}">${val(d.action, 'Unknown')}</span>
                </div>
            </div>

            <h2 style="color:var(--text-muted);font-size:1.2em;margin-bottom:30px;">
                ${val(d.msg, 'No description')}
            </h2>

            <h2 class="section-title">SIGNATURE METADATA</h2>
            <div class="grid-2">
                <div class="data-group">
                    <span class="data-label">Protocol</span>
                    <span class="data-value" style="text-transform:uppercase;">${val(d.protocol)}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">Class Type</span>
                    <span class="data-value">${val(d.classtype)}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">Revision</span>
                    <span class="data-value">${val(d.rev)}</span>
                </div>
                <div class="data-group">
                    <span class="data-label">Risk Score</span>
                    <span class="data-value">${val(d.risk_score)}</span>
                </div>
            </div>

            <div class="data-group" style="margin-top:20px;">
                <span class="data-label">Raw Rule</span>
                <pre class="code-block">${val(d.rule_raw, 'Rule unavailable')}</pre>
            </div>

            <div class="data-group" style="margin-top:20px;">
                <span class="data-label">References</span>
                ${refsHtml}
            </div>
        </div>

        ${buildOtxHtml(d.intel && d.intel.alienvault, d.intel && d.intel.ipinfo)}`;  

    } catch (err) {
        console.error('[signature]', err);
        el.innerHTML = `
        <div class="card" style="border-color:var(--neon-pink);text-align:center;padding:50px;">
            <h1 style="color:var(--neon-pink);">[ DATA_CORRUPTED // NOT_FOUND ]</h1>
            <p>The signature data could not be retrieved from the database.</p>
            <p style="color:var(--text-muted);font-size:0.85em;">${err.message}</p>
        </div>`;
    }
}

load();