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
const escapeHTML = (str) => {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    };
    return String(str).replace(/[&<>"']/g, (c) => map[c]);
};

/**
 * Format an ISO timestamp for locale display, or return fallback.
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
    if (code >= 400) return 'var(--neon-pink)';
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
 * Build a global map section using the best available geographic data.
 * Falls back to text-based search (Google Maps) if coordinates are missing.
 *
 * @param {object} d The signature detail data object.
 * @returns {string}
 */
const buildGlobalMapHtml = (d) => {
    let lat = null, lon = null, query = null;
    const otx = d.intel?.alienvault;
    if (otx && otx.latitude && otx.longitude) {
        lat = parseFloat(otx.latitude);
        lon = parseFloat(otx.longitude);
    }

    const ipinfo = d.intel?.ipinfo || d.intel?.phishdestroy?.infrastructure?.ipinfo;
    if ((lat === null || lon === null || isNaN(lat) || isNaN(lon)) && ipinfo) {
        if (ipinfo.loc) {
            const parts = ipinfo.loc.split(',');
            if (parts.length === 2) {
                lat = parseFloat(parts[0]);
                lon = parseFloat(parts[1]);
            }
        }
        if (lat === null || lon === null || isNaN(lat) || isNaN(lon)) {
            query = [ipinfo.city, ipinfo.region, ipinfo.country].filter(Boolean).join(', ');
        }
    }

    if ((lat === null || lon === null) && !query && otx) {
        const q = [otx.city, otx.country_name].filter(Boolean).join(', ');
        if (q) query = q;
    }

    let src = '';
    if (lat !== null && lon !== null && !isNaN(lat) && !isNaN(lon)) {
        const bbox = `${lon - 0.05},${lat - 0.05},${lon + 0.05},${lat + 0.05}`;
        src = `https://www.openstreetmap.org/export/embed.html`
            + `?bbox=${bbox}&layer=mapnik&marker=${lat}%2C${lon}`;
    } else if (query) {
        src = `https://maps.google.com/maps?q=${encodeURIComponent(query)}&t=&z=10&ie=UTF8&iwloc=&output=embed`;
    } else {
        return '';
    }

    return `
    <h2 class="section-title" style="margin-top:40px;">GEOGRAPHIC LOCATION</h2>
    <div class="card" style="padding:0;overflow:hidden;border-color:var(--cyan);">
        <div style="height:350px;background:#000;position:relative;">
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
        MALWARE: 'var(--neon-pink)',
        SOCIAL_ENGINEERING: '#ffaa00',
        UNWANTED_SOFTWARE: '#ff6600',
        POTENTIALLY_HARMFUL: '#ff6600',
    };

    const rows = hits.map(h => {
        const threat = val(h.threat_type, 'UNKNOWN');
        const colour = THREAT_COLOUR[threat] || 'var(--neon-pink)';
        const ttl = h.cache_duration ? ` · TTL: ${h.cache_duration}` : '';
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

    const selfSigned = (cert.is_self_signed || 'no') !== 'no';
    const expired = cert.is_expired === true;
    const certColour = (selfSigned || expired) ? 'var(--neon-pink)' : 'var(--cyan)';
    const sanList = (cert.subject_alt_names || []).join(', ') || 'N/A';
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
            ${expired ? '<span class="badge high" style="font-size:0.65em;margin-left:8px;">EXPIRED</span>' : ''}
            ${hasWildcard ? '<span class="badge" style="font-size:0.65em;margin-left:8px;border-color:#ffaa00;color:#ffaa00;">WILDCARD SAN</span>' : ''}
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

    const geoStr = [otx.city, otx.country_name].filter(Boolean).join(', ') || null;
    const geoLine = geoStr
        ? `${geoStr}${otx.flag ? ' ' + otx.flag : ''}${otx.continent_code ? ' [' + otx.continent_code + ']' : ''}`
        : null;

    const tlpStr = (otx.tlp || '').toUpperCase();
    const tlpBadge = tlpStr
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

    const sbCount = (otx.safebrowsing || []).length;
    const sbBadge = sbCount
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
    </div>`;
};

/**
 * Build the PhishDestroy intelligence card.
 *
 * @param {object|null} pd - Content of intel.phishdestroy, or null.
 * @returns {string}
 */
const buildPhishDestroyHtml = (pd) => {
    if (!pd) return '';

    const vt = pd.intel?.virustotal || {};
    const us = pd.intel?.urlscan || {};
    const infra = pd.infrastructure || {};
    const ipinfo = infra.ipinfo || {};

    const geoLine = [ipinfo.city, ipinfo.region, ipinfo.country].filter(Boolean).join(', ') || null;

    const vtBadge = vt.total
        ? `<span class="badge ${vt.malicious > 0 ? 'high' : ''}" style="font-size:0.7em;">
               VT: ${vt.malicious}/${vt.total}
           </span>`
        : '';

    const usBadge = us.score !== undefined
        ? `<span class="badge ${us.malicious ? 'high' : ''}" style="font-size:0.7em;">
               URLSCAN: ${us.score}
           </span>`
        : '';

    let screenshotHtml = '';
    if (us.screenshot) {
        screenshotHtml = `
        <div class="data-group" style="margin-top:20px;">
            <span class="data-label">Screenshot</span>
            <div style="border:1px solid var(--cyan);border-radius:8px;overflow:hidden;
                        max-width:100%;box-shadow:0 0 15px rgba(0,229,255,0.1);">
                <img src="${us.screenshot}" style="width:100%;display:block;filter:brightness(90%);" alt="URLScan Screenshot"/>
            </div>
        </div>`;
    }

    const detectionsHtml = (pd.detections && pd.detections.length > 0)
        ? `<div class="data-group" style="margin-top:20px;border-top:1px dashed rgba(255,0,85,0.25);padding-top:20px;">
               <span class="data-label" style="color:var(--neon-pink);">&#x26A0; Threat Detections (${pd.detections.length})</span>
               <div style="margin-top:10px; display:flex; flex-wrap:wrap; gap:8px;">
                   ${pd.detections.map(d => `
                   <div style="background:rgba(255,0,85,0.07);border:1px solid var(--neon-pink);border-radius:6px;padding:6px 10px;display:flex;align-items:center;gap:8px;">
                       <span style="font-size:0.85em;color:var(--text-muted);">
                           <strong style="color:var(--text);">${val(d.source)}</strong>
                       </span>
                       <span class="badge" style="border-color:var(--neon-pink);color:var(--neon-pink);background:rgba(255,0,85,0.1);font-size:0.65em;padding:2px 6px;">
                           ${val(d.type).toUpperCase()}
                       </span>
                   </div>`).join('')}
               </div>
           </div>`
        : '';

    const dnsA = (infra.dns?.A || []).join(', ') || 'N/A';
    const dnsAAAA = (infra.dns?.AAAA || []).join(', ') || 'N/A';

    return `
    <h2 class="section-title" style="margin-top:40px;">PHISHDESTROY INTELLIGENCE</h2>
    <div class="card">
        <!-- Header badges -->
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:20px;">
            <span class="badge" style="border-color:#ff6600;color:#ff6600;
                                       background:rgba(255,102,0,0.1);font-size:0.7em;">
                PHISHDESTROY
            </span>
            ${vtBadge}${usBadge}
        </div>

        <div class="grid-2">
            <div class="data-group">
                <span class="data-label">Defanged Domain</span>
                <span class="data-value" style="color:var(--neon-pink);">${val(pd.domain_defanged)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Analyzed At</span>
                <span class="data-value">${fmtDate(pd.analyzed_at)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Domain Age (Days)</span>
                <span class="data-value">${val(pd.domain_info?.age_days)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">IP Address</span>
                <span class="data-value">${val(infra.ip)}</span>
            </div>
            ${geoLine ? `
            <div class="data-group">
                <span class="data-label">Location</span>
                <span class="data-value">${geoLine}</span>
            </div>` : ''}
            <div class="data-group">
                <span class="data-label">Organization</span>
                <span class="data-value">${val(ipinfo.org)}</span>
            </div>
        </div>

        <div class="data-group" style="margin-top:15px;">
            <span class="data-label">DNS A Records</span>
            <span class="data-value" style="font-size:0.82em;color:var(--text-muted);word-break:break-all;">${dnsA}</span>
        </div>
        <div class="data-group" style="margin-top:15px;">
            <span class="data-label">DNS AAAA Records</span>
            <span class="data-value" style="font-size:0.82em;color:var(--text-muted);word-break:break-all;">${dnsAAAA}</span>
        </div>

        ${detectionsHtml}
        ${screenshotHtml}
    </div>`;
};

// ---------------------------------------------------------------------------
// Main loader
// ---------------------------------------------------------------------------

/**
 * Build the IP feed table for the bare SID 6000002 page.
 * Each row links to ?sid=6000002&ip=<ip> for a detail view.
 *
 * @param {object} ipFeed - Content of ip_feed from the SID JSON.
 * @returns {string}
 */
const buildIpFeedHtml = (ipFeed) => {
    if (!ipFeed || !ipFeed.ips || ipFeed.ips.length === 0) return '';
    const ps = { color: '#ffaa00' };
    const rows = ipFeed.ips.map(ip =>
        `<div style="display:flex;justify-content:space-between;align-items:center;
                     padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
            <span style="color:var(--text);font-family:monospace;font-size:0.9em;">${escapeHTML(ip)}</span>
            <a href="?sid=6000002&ip=${encodeURIComponent(ip)}"
               style="color:${ps.color};font-size:0.75em;text-decoration:none;border:1px solid ${ps.color};
                      padding:2px 8px;border-radius:3px;transition:0.2s;
                      background:rgba(255,170,0,0.07);white-space:nowrap;"
               onmouseover="this.style.background='rgba(255,170,0,0.2)';"
               onmouseout="this.style.background='rgba(255,170,0,0.07);'">
                [ VIEW DETAIL ]
            </a>
         </div>`
    ).join('');

    return `
    <h2 class="section-title" style="margin-top:40px;">IP FEED — ${ipFeed.ips_count.toLocaleString()} ENTRIES</h2>
    <div class="card" style="padding:15px 20px;border-color:${ps.color};">
        ${rows}
    </div>`;
};

const PROTO_STYLE = {
    dns:   { label: 'DNS',   color: 'var(--neon-pink)', bg: 'rgba(255,0,85,0.12)' },
    tls:   { label: 'TLS',   color: '#00ff80',          bg: 'rgba(0,255,128,0.08)' },
    ip:    { label: 'IP',    color: '#ffaa00',           bg: 'rgba(255,170,0,0.10)' },
    http:  { label: 'HTTP',  color: 'var(--cyan)',       bg: 'rgba(0,229,255,0.1)' },
    https: { label: 'HTTPS', color: 'var(--cyan)',       bg: 'rgba(0,229,255,0.1)' },
};

function protocolBadge(proto) {
    const s = PROTO_STYLE[proto] || { label: (proto || '').toUpperCase(), color: 'var(--cyan)', bg: 'rgba(0,229,255,0.1)' };
    return `<span class="badge" style="border-color:${s.color};color:${s.color};background:${s.bg};font-size:0.75em;letter-spacing:2px;">${s.label}</span>`;
}

function renderDomainView(el, d, domain) {
    const proto = d.protocol || 'dns';
    const ps = PROTO_STYLE[proto] || PROTO_STYLE.dns;
    const tld = domain.includes('.') ? domain.split('.').pop().toLowerCase() : 'unknown';
    const feed = d.dns_feed || {};
    const topTlds = feed.top_tlds || [];
    const atiDomains = (feed.ati_domains || []).map(x => String(x).toLowerCase());
    const isAti = atiDomains.includes(domain.toLowerCase());

    const refs = Array.isArray(d.references) && d.references.length > 0;
    const refsHtml = refs
        ? `<ul class="ref-list">${d.references.map(r => `<li>${r}</li>`).join('')}</ul>`
        : `<span class="data-value">No references</span>`;

    const tldRows = topTlds.map(t =>
        `<div style="display:flex;justify-content:space-between;align-items:center;
                     padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
            <span style="color:${t.tld === tld ? ps.color : 'var(--text)'};font-weight:${t.tld === tld ? 'bold' : 'normal'};">
                .${t.tld}${t.tld === tld ? ' \u2190 this domain' : ''}
            </span>
            <span class="badge" style="font-size:0.65em;">${t.count.toLocaleString()}</span>
         </div>`
    ).join('');

    el.innerHTML = `
    <div class="card glow" style="border-top:4px solid ${ps.color};">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:15px;margin-bottom:20px;">
            <h1 style="margin:0;font-size:2em;color:var(--text);word-break:break-all;">
                ${escapeHTML(domain)}
            </h1>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">

                ${protocolBadge(proto)}
                ${isAti ? '<span class="badge ati" style="font-size:0.7em;" title="Antiphishing Threat Intel">NRD - Antiphishing Threat Intel</span>' : ''}
                <span class="badge high" style="font-size:0.7em;">${val(d.severity, 'high')} severity</span>
            </div>
        </div>

        <h2 style="color:var(--text-muted);font-size:1.1em;margin-bottom:30px;">${val(d.msg)}</h2>

        <h2 class="section-title">FEED ENTRY</h2>
        <div class="grid-2">
            <div class="data-group">
                <span class="data-label">Detection Protocol</span>
                <span class="data-value" style="color:${ps.color};text-transform:uppercase;">${proto}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Threat Intel Source</span>
                <span class="data-value">${isAti ? '<span class="badge ati" style="font-size:0.75em;">ATI // NRD EXTRACT</span>' : 'Standard Feed Vector'}</span>
            </div>
            <div class="data-group">
                <span class="data-label">SID</span>
                <span class="data-value" style="color:var(--cyan);">${d.sid}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Domain</span>
                <span class="data-value" style="word-break:break-all;">${escapeHTML(domain)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">TLD</span>
                <span class="data-value">.${tld}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Class Type</span>
                <span class="data-value">${val(d.classtype)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Risk Score</span>
                <span class="data-value">${val(d.risk_score)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Feed Size</span>
                <span class="data-value">${(feed.domains_count || 0).toLocaleString()} domains</span>
            </div>
            <div class="data-group">
                <span class="data-label">Updated At</span>
                <span class="data-value" style="font-size:0.85em;color:var(--text-muted);">${fmtDate(d.updated_at)}</span>
            </div>
        </div>

        <div class="data-group" style="margin-top:20px;">
            <span class="data-label">References</span>
            ${refsHtml}
        </div>

        ${isAti ? `
        <h2 class="section-title" style="margin-top:40px;">
            🛡️ AUTOMATED NRD THREAT DETECTION & VERIFICATION PIPELINE
        </h2>
        <div class="card" style="border-left: 4px solid var(--cyan); background: rgba(10, 20, 35, 0.85);">
            <p style="color: var(--text); font-size: 0.95em; line-height: 1.6; margin-top: 0;">
                All incoming domains undergo real-time analysis through our automated
                <strong style="color: var(--cyan);">Newly Registered Domains (NRD) Ingestion &amp; Heuristic Verification Pipeline</strong>:
            </p>
            <ul style="list-style: none; padding: 0; margin: 15px 0 20px 0; display: flex; flex-direction: column; gap: 12px;">
                <li style="padding-left: 20px; position: relative; font-size: 0.9em; line-height: 1.5; color: var(--text);">
                    <span style="position: absolute; left: 0; color: var(--cyan); font-weight: bold;">▪</span>
                    <strong style="color: var(--cyan);">Ingestion &amp; Active Traffic Validation:</strong>
                    Ingests daily Newly Registered Domains (NRDs) filtered against active DNS telemetry to eliminate unresolvable noise.
                </li>
                <li style="padding-left: 20px; position: relative; font-size: 0.9em; line-height: 1.5; color: var(--text);">
                    <span style="position: absolute; left: 0; color: var(--cyan); font-weight: bold;">▪</span>
                    <strong style="color: var(--cyan);">Lexical &amp; Structural Analysis:</strong>
                    Uses <code style="color: var(--neon-pink); background: rgba(0,0,0,0.4); padding: 2px 5px; border-radius: 3px;">tldextract</code> for accurate Public Suffix / Apex Domain isolation across complex international TLDs (<code style="color: var(--text-muted); font-size: 0.85em;">.co.uk</code>, <code style="color: var(--text-muted); font-size: 0.85em;">.com.br</code>, <code style="color: var(--text-muted); font-size: 0.85em;">.gov.br</code>).
                </li>
                <li style="padding-left: 20px; position: relative; font-size: 0.9em; line-height: 1.5; color: var(--text);">
                    <span style="position: absolute; left: 0; color: var(--cyan); font-weight: bold;">▪</span>
                    <strong style="color: var(--cyan);">Algorithmic Permutation Fuzzing (<code style="color: var(--neon-pink); background: rgba(0,0,0,0.4); padding: 2px 5px; border-radius: 3px;">dnstwist</code>):</strong>
                    Cross-references domain structures against <strong style="color: #ffaa00;">&gt;130,000 algorithmic permutations</strong> (Homoglyphs, Bitquatting, Transposition, Omission, Insertion) derived from protected global brand targets (Banking, Crypto, E-commerce, SaaS).
                </li>
                <li style="padding-left: 20px; position: relative; font-size: 0.9em; line-height: 1.5; color: var(--text);">
                    <span style="position: absolute; left: 0; color: var(--cyan); font-weight: bold;">▪</span>
                    <strong style="color: var(--cyan);">Multi-Language Social Engineering Heuristics:</strong>
                    Evaluates lexical patterns against multi-language credential harvesting and phishing indicators across English, Portuguese, Spanish, German, and French.
                </li>
                <li style="padding-left: 20px; position: relative; font-size: 0.9em; line-height: 1.5; color: var(--text);">
                    <span style="position: absolute; left: 0; color: var(--cyan); font-weight: bold;">▪</span>
                    <strong style="color: var(--cyan);">Deduplication &amp; False-Positive Controls:</strong>
                    Employs an in-memory deduplication index (<code style="color: var(--neon-pink); background: rgba(0,0,0,0.4); padding: 2px 5px; border-radius: 3px;">nrd_suspicious_domains.txt</code>) to audit detections, prevent redundant rule injection, and enable rapid false-positive suppression before Base64 dataset serialization for Suricata IDS/IPS rulesets (<code style="color: var(--text-muted); font-size: 0.85em;">sid:6000000</code>/<code style="color: var(--text-muted); font-size: 0.85em;">sid:6000001</code>).
                </li>
            </ul>
            <div style="margin-top: 25px; padding-top: 15px; border-top: 1px dashed rgba(0, 229, 255, 0.2); display: flex; justify-content: space-between; align-items: center; gap: 15px; flex-wrap: wrap;">
                <span style="font-size: 0.85em; color: var(--text-muted);">
                    Legitimate domain or false positive? Report it directly to our threat response team:
                </span>
                <a href="https://github.com/julioliraup/Antiphishing/issues/new"
                   target="_blank"
                   class="fp-btn">
                    [ 🚩 REPORT FALSE POSITIVE ]
                </a>
            </div>
        </div>` : ''}

        ${topTlds.length > 0 ? `
        <h2 class="section-title" style="margin-top:40px;">TOP TLDs IN FEED</h2>
        <div class="card" style="padding:15px 20px;">
            ${tldRows}
        </div>` : ''}
    </div>`;
}

/**
 * Render the IP-feed detail view for a specific IP address.
 * Mirrors renderDomainView() — same card structure, amber colour scheme.
 *
 * @param {HTMLElement} el
 * @param {object} d      - SID JSON data (6000002.json)
 * @param {string} ip     - The IP address from the URL param
 */
function renderIpView(el, d, ip) {
    const ps = PROTO_STYLE.ip;
    const feed = d.ip_feed || {};
    const refs = Array.isArray(d.references) && d.references.length > 0;
    const refsHtml = refs
        ? `<ul class="ref-list">${d.references.map(r => `<li>${r}</li>`).join('')}</ul>`
        : `<span class="data-value">No references</span>`;

    el.innerHTML = `
    <div class="card glow" style="border-top:4px solid ${ps.color};">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:15px;margin-bottom:20px;">
            <h1 style="margin:0;font-size:2em;color:var(--text);word-break:break-all;font-family:'Orbitron',sans-serif;">
                ${escapeHTML(ip)}
            </h1>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                ${protocolBadge('ip')}
                <span class="badge high" style="font-size:0.7em;">${val(d.severity, 'high')} severity</span>
            </div>
        </div>

        <h2 style="color:var(--text-muted);font-size:1.1em;margin-bottom:30px;">${val(d.msg)}</h2>

        <h2 class="section-title">FEED ENTRY</h2>
        <div class="grid-2">
            <div class="data-group">
                <span class="data-label">Detection Layer</span>
                <span class="data-value" style="color:${ps.color};text-transform:uppercase;">IP</span>
            </div>
            <div class="data-group">
                <span class="data-label">Threat Intel Source</span>
                <span class="data-value">Phishing IP Feed</span>
            </div>
            <div class="data-group">
                <span class="data-label">SID</span>
                <span class="data-value" style="color:var(--cyan);">${d.sid}</span>
            </div>
            <div class="data-group">
                <span class="data-label">IP Address</span>
                <span class="data-value" style="color:${ps.color};word-break:break-all;">${escapeHTML(ip)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Class Type</span>
                <span class="data-value">${val(d.classtype)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Feed Size</span>
                <span class="data-value">${(feed.ips_count || 0).toLocaleString()} IPs</span>
            </div>
            <div class="data-group">
                <span class="data-label">Risk Score</span>
                <span class="data-value">${val(d.risk_score)}</span>
            </div>
            <div class="data-group">
                <span class="data-label">Updated At</span>
                <span class="data-value" style="font-size:0.85em;color:var(--text-muted);">${fmtDate(d.updated_at)}</span>
            </div>
        </div>

        <div class="data-group" style="margin-top:20px;">
            <span class="data-label">References</span>
            ${refsHtml}
        </div>
    </div>`;

    // Dynamically fetch IP geolocation via ipinfo.io
    const loaderId = 'ip-loader-' + Date.now();
    el.insertAdjacentHTML('beforeend',
        `<div id="${loaderId}" style="text-align:center;margin-top:40px;color:${ps.color};font-family:'Orbitron',sans-serif;">[ FETCHING IP INTELLIGENCE... ]</div>`);

    fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`)
        .then(r => { if (!r.ok) throw new Error('ipinfo error'); return r.json(); })
        .then(info => {
            document.getElementById(loaderId)?.remove();
            const geoLine = [info.city, info.region, info.country].filter(Boolean).join(', ') || null;
            const mapHtml = buildGlobalMapHtml({ intel: { ipinfo: info } });
            const infoHtml = `
            <h2 class="section-title" style="margin-top:40px;">IP GEOLOCATION & NETWORK</h2>
            <div class="card" style="border-color:${ps.color};">
                <div class="grid-2">
                    <div class="data-group">
                        <span class="data-label">Organization</span>
                        <span class="data-value">${val(info.org)}</span>
                    </div>
                    <div class="data-group">
                        <span class="data-label">Hostname</span>
                        <span class="data-value" style="font-size:0.9em;color:var(--text-muted);">${val(info.hostname)}</span>
                    </div>
                    ${geoLine ? `<div class="data-group">
                        <span class="data-label">Location</span>
                        <span class="data-value">${escapeHTML(geoLine)}</span>
                    </div>` : ''}
                    ${info.country ? `<div class="data-group">
                        <span class="data-label">Country</span>
                        <span class="data-value" style="letter-spacing:3px;">${escapeHTML(info.country)}</span>
                    </div>` : ''}
                    ${info.postal ? `<div class="data-group">
                        <span class="data-label">Postal</span>
                        <span class="data-value">${escapeHTML(info.postal)}</span>
                    </div>` : ''}
                    ${info.timezone ? `<div class="data-group">
                        <span class="data-label">Timezone</span>
                        <span class="data-value">${escapeHTML(info.timezone)}</span>
                    </div>` : ''}
                </div>
            </div>${mapHtml}`;
            const wrapper = document.createElement('div');
            wrapper.innerHTML = infoHtml;
            el.appendChild(wrapper);
        })
        .catch(err => {
            console.error('[ipinfo] fetch error:', err);
            const loader = document.getElementById(loaderId);
            if (loader) loader.innerHTML = `<span style="color:var(--text-muted);font-size:0.85em;">[ IP INTEL UNAVAILABLE ]</span>`;
        });
}

const params = new URLSearchParams(window.location.search);
const sid = params.get('sid');
const domain = params.get('domain');
const el = document.getElementById('detail');
(async () => {

if (!sid) {
    el.innerHTML = `<h1 style="color:var(--neon-pink);">[ ERROR: SID NOT SPECIFIED ]</h1>`;
    return;
}

try {
    const resp = await fetch(`./db/sid/${sid}.json`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const d = await resp.json();

    const ip = params.get('ip');

    if (ip) {
        // IP detail view (SID 6000002)
        const ipExists = Array.isArray(d.ip_feed?.ips) && d.ip_feed.ips.includes(ip);
        if (!ipExists) {
            el.innerHTML = `
                <div class="card" style="border-color:var(--neon-pink);text-align:center;padding:40px;">
                    <h1 style="color:var(--neon-pink);">[ ERROR: IP NOT FOUND ]</h1>
                    <p style="color:var(--text-muted);font-size:0.9em;">The IP "${escapeHTML(ip)}" does not exist in this feed.</p>
                </div>`;
            return;
        }
        document.title = `${escapeHTML(ip)} - SID ${d.sid} - Antiphishing`;
        renderIpView(el, d, ip);
        return;
    }

    if (domain) {
        // Verify that the requested domain exists in the signature data
        const inDomains = Array.isArray(d.dns_feed?.domains) && d.dns_feed.domains.some(dom => dom.toLowerCase() === (domain || '').toLowerCase());
        const inAti = Array.isArray(d.dns_feed?.ati_domains) && d.dns_feed.ati_domains.some(dom => dom.toLowerCase() === (domain || '').toLowerCase());
        
        if (!inDomains && !inAti) {
            el.innerHTML = `
                <div class="card" style="border-color:var(--neon-pink);text-align:center;padding:40px;">
                    <h1 style="color:var(--neon-pink);">[ ERROR: DOMAIN NOT FOUND ]</h1>
                    <p style="color:var(--text-muted);font-size:0.9em;">The domain "${escapeHTML(domain)}" does not exist in this signature.</p>
                </div>`;
            return;
        }
        document.title = `${escapeHTML(domain)} - SID ${d.sid} - Antiphishing`;
        renderDomainView(el, d, domain);

        const loaderId = 'pd-loader-' + Date.now();
        el.insertAdjacentHTML('beforeend', `<div id="${loaderId}" style="text-align:center;margin-top:40px;color:var(--cyan);font-family:'Orbitron',sans-serif;">[ FETCHING DYNAMIC THREAT INTEL... ]</div>`);

        fetch(`https://analyze.destroy.tools/v1/analyze?domain=${escapeHTML(domain)}`)
            .then(r => { if (!r.ok) throw new Error('API Error'); return r.json(); })
            .then(pdData => {
                document.getElementById(loaderId)?.remove();
                const pdHtml = buildPhishDestroyHtml(pdData);
                const mapHtml = buildGlobalMapHtml({ intel: { phishdestroy: pdData } });
                if (pdHtml || mapHtml) {
                    const wrapper = document.createElement('div');
                    wrapper.innerHTML = pdHtml + mapHtml;
                    el.appendChild(wrapper);
                }
            })
            .catch(err => {
                console.error('[phishdestroy] dynamic fetch error:', err);
                const loader = document.getElementById(loaderId);
                if (loader) loader.innerHTML = `<span style="color:var(--text-muted);font-size:0.85em;">[ LIVE INTEL UNAVAILABLE ]</span>`;
            });

        return;
    }

    document.title = `SID ${d.sid} - Antiphishing`;

    const severityClass = d.severity?.toLowerCase() === 'high' ? 'high' : '';
    const actionClass = d.action?.toLowerCase() === 'alert' ? 'alert' : '';

    const refs = Array.isArray(d.references) && d.references.length > 0;
    const refsHtml = refs
        ? `<ul class="ref-list">${d.references.map(r => `<li>${r}</li>`).join('')}</ul>`
        : `<span class="data-value">No references</span>`;

    const staleBadge = d.rule_status === 'stale'
        ? '<span class="badge stale" style="margin-left:8px;">STALE</span>'
        : '';

    const probeHtml = d.probe ? `
            <div class="data-group" style="margin-top:20px;">
                <span class="data-label">Rule Health</span>
                <span class="data-value" style="color:var(--neon-pink);">
                    DNS: ${d.probe.dns === true ? 'responsive' : d.probe.dns === false ? 'unresponsive' : 'unknown'}
                    &#x2022;
                    WHOIS: ${d.probe.whois === true ? 'responsive' : d.probe.whois === false ? 'unresponsive' : 'unavailable'}
                </span>
            </div>
            ${d.rule_status === 'stale' ? `
            <div class="data-group stale-note">
                <span class="data-label">Status</span>
                <span class="data-value">This signature is probably stale: DNS + WHOIS probes are unresponsive.</span>
            </div>` : ''}
        ` : '';

    const proto = d.protocol || '';
    const protoBadgeHtml = (proto === 'dns' || proto === 'tls' || proto === 'ip')
        ? protocolBadge(proto)
        : '';

    const pdData = d.intel?.phishdestroy;
    const ipinfoFallback = d.intel?.ipinfo || pdData?.infrastructure?.ipinfo;

    el.innerHTML = `
        <div class="card glow" style="border-top:4px solid var(--neon-pink);">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;
                        flex-wrap:wrap;gap:15px;margin-bottom:20px;">
                <h1 style="margin:0;font-size:2.5em;color:var(--text);">
                    SID <span style="color:var(--cyan);">${d.sid}</span>
                </h1>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                    ${protoBadgeHtml}
                    <span class="badge ${severityClass}">${val(d.severity, 'Unknown')} Severity</span>
                    <span class="badge ${actionClass}">${val(d.action, 'Unknown')}</span>
                    ${staleBadge}
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
            ${probeHtml}

            <div class="data-group" style="margin-top:20px;">
                <span class="data-label">References</span>
                ${refsHtml}
            </div>
        </div>

        ${buildOtxHtml(d.intel?.alienvault, ipinfoFallback)}
        ${buildPhishDestroyHtml(pdData)}
        ${buildGlobalMapHtml(d)}
        ${d.ip_feed ? buildIpFeedHtml(d.ip_feed) : ''}`;

} catch (err) {
    console.error('[signature]', err);
    el.innerHTML = `
        <div class="card" style="border-color:var(--neon-pink);text-align:center;padding:50px;">
            <h1 style="color:var(--neon-pink);">[ DATA_CORRUPTED // NOT_FOUND ]</h1>
            <p>The signature data could not be retrieved from the database.</p>
            <p style="color:var(--text-muted);font-size:0.85em;">${err.message}</p>
        </div>`;
}

})();
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
            <a href="https://github.com/julioliraup/Antiphishing/blob/main/FUNDING.md" target="_blank" style="display:inline-block; background:rgba(0,229,255,0.1); border:1px solid var(--cyan); color:var(--cyan); padding:8px 15px; text-decoration:none; border-radius:4px; font-size:0.85em; transition:0.3s; text-transform:uppercase; letter-spacing:1px;" onmouseover="this.style.background='var(--cyan)'; this.style.color='#000';" onmouseout="this.style.background='rgba(0,229,255,0.1)'; this.style.color='var(--cyan)';">
                Contribute
            </a>
        </div>
    `;
    document.body.appendChild(banner.firstElementChild);
}, 5000);
