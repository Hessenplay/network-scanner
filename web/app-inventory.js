function dashboard() {
  const data = state.data.dashboard || {};
  const counts = data.counts || {};
  const categories = data.category_counts || {};
  const enrichment = state.data.enrichment || {};
  const total = Number(counts.devices || 0);
  const quality = [
    ["MAC", enrichment.with_mac], ["Hostname", enrichment.with_hostname],
    ["HTTP", enrichment.with_http], ["TLS", enrichment.with_tls],
    ["SSH", enrichment.with_ssh], ["Fingerprints", enrichment.with_fingerprints],
  ];

  return `${pageHeader("Dashboard", "Netzwerkinventar, Scanstatus und Erkennungsqualität auf einen Blick.", '<button class="secondary" data-action="refresh">↻ Aktualisieren</button>')}
    <div class="metric-grid">
      ${metricCard("Geräte gesamt", counts.devices || 0, `${counts.present_devices || 0} aktuell sichtbar`)}
      ${metricCard("Subnet-Jobs", counts.scan_jobs || 0, "fortlaufend rotierend")}
      ${metricCard("Laufende Scans", counts.running_scans || 0, "aktive Scan-Tasks")}
      ${metricCard("Offene Findings", counts.findings_open || 0, "prüfbare Hinweise")}
    </div>
    <div class="layout-2 dashboard-layout">
      <section class="panel">${sectionHead("Gerätekategorien", '<button class="link-button" data-action="navigate" data-view="devices">Alle Geräte →</button>')}
        ${categoryChart(categories, total)}
      </section>
      <section class="panel">${sectionHead("Erkennungsqualität", '<button class="link-button" data-action="navigate" data-view="identity">Quellen →</button>')}
        <div class="quality-bars">${quality.map(([label, count]) => {
          const pct = total ? Math.round(Number(count || 0) / total * 100) : 0;
          return `<div class="quality-row"><span>${h(label)}</span><div class="quality-track"><i style="width:${pct}%"></i></div><strong>${h(count || 0)}</strong></div>`;
        }).join("")}</div>
      </section>
    </div>
    <section class="panel">${sectionHead("Zuletzt erkannte Geräte", '<button class="link-button" data-action="navigate" data-view="devices">Alle →</button>')}${deviceList(data.recent_devices || data.recent_assets || [], 8)}</section>
    <section class="panel">${sectionHead("Letzte Scans", '<button class="link-button" data-action="navigate" data-view="scans">Scanner →</button>')}${scanCompactTable(data.recent_scans || [])}</section>`;
}

function categoryChart(categories, total) {
  const rows = Object.entries(categories).filter(([, count]) => Number(count) > 0).sort((a, b) => b[1] - a[1]);
  if (!rows.length) return emptyState("📊", "Keine Daten", "Nach dem ersten Scan werden Kategorien angezeigt.");
  const palette = ["#2563eb", "#10b981", "#f59e0b", "#8b5cf6", "#ef4444", "#06b6d4", "#f97316", "#ec4899", "#84cc16", "#6366f1", "#14b8a6", "#94a3b8"];
  const sum = rows.reduce((value, [, count]) => value + Number(count || 0), 0) || 1;
  let cursor = 0;
  const segments = rows.slice(0, 12).map(([, count], index) => {
    const start = cursor;
    cursor += Number(count || 0) / sum * 100;
    return `${palette[index % palette.length]} ${start.toFixed(2)}% ${cursor.toFixed(2)}%`;
  });
  if (cursor < 100) segments.push(`#e2e8f0 ${cursor.toFixed(2)}% 100%`);
  return `<div class="category-summary"><div class="donut" style="background:conic-gradient(${segments.join(",")})"><strong>${h(total)}</strong><span>Geräte</span></div><div class="category-legend">
    ${rows.slice(0, 12).map(([key, count], index) => `<button data-action="category-filter" data-category="${h(key)}"><span><i class="legend-dot" style="background:${palette[index % palette.length]}"></i>${CATEGORY_ICONS[key] || "📦"} ${h(lbl(key))}</span><strong>${h(count)}</strong></button>`).join("")}
  </div></div>`;
}

function devices() {
  const allRows = state.data.devices || [];
  const categories = [...new Set(allRows.map((row) => row.category || "unknown"))].sort();
  const rows = state.categoryFilter ? allRows.filter((row) => (row.category || "unknown") === state.categoryFilter) : allRows;
  return `${pageHeader("Geräte", "Stabile Geräteidentität mit IP-Verlauf, Services und Fingerprints.", '<button class="secondary" data-action="refresh">↻ Aktualisieren</button>')}
    <div class="toolbar"><input id="deviceSearch" value="${h(state.deviceQuery)}" placeholder="IP, MAC, Hostname, Hersteller oder Port suchen"><button data-action="device-search">Suchen</button></div>
    <div class="category-tabs"><button class="${state.categoryFilter ? "" : "active"}" data-action="category-filter" data-category="">Alle <sup>${allRows.length}</sup></button>
      ${categories.map((category) => `<button class="${state.categoryFilter === category ? "active" : ""}" data-action="category-filter" data-category="${h(category)}">${CATEGORY_ICONS[category] || "📦"} ${h(lbl(category))} <sup>${allRows.filter((row) => (row.category || "unknown") === category).length}</sup></button>`).join("")}
    </div>
    ${deviceTable(rows)}`;
}

function deviceList(rows, max = rows.length) {
  if (!rows.length) return emptyState("📭", "Keine Geräte", "Der Scanner hat noch keine Geräte gefunden.");
  return `<div class="device-list">${rows.slice(0, max).map((row) => `<article class="device-row" data-action="open-device" data-device="${h(row.device_id || row.id)}">
    <div><div class="device-name">${h(row.display_name || row.hostname || firstIp(row) || "Unbenannt")}</div><div class="device-meta"><code>${h(firstIp(row))}</code><span>${h(row.mac_address || "")}</span></div></div>
    <div>${categoryBadge(row.category)}</div>
    <div>${h([vendor(row), model(row)].filter(Boolean).join(" ") || "—")}</div>
    <div>${chips((row.services || []).map((service) => service.port), "chip port")}</div>
    <div class="muted">${h(displayTime(row.last_seen_at))}</div>
  </article>`).join("")}</div>`;
}

function deviceTable(rows) {
  if (!rows.length) return emptyState("🔍", "Keine Treffer", "Suche oder Kategorienfilter anpassen.");
  return `<div class="table-wrap"><table class="table devices-table"><thead><tr><th>Gerät</th><th>IP / MAC</th><th>Kategorie</th><th>Hersteller / Modell</th><th>Ports</th><th>Zuletzt</th></tr></thead><tbody>
    ${rows.map((row) => `<tr class="clickable" data-action="open-device" data-device="${h(row.device_id || row.id)}"><td><strong>${h(row.display_name || row.hostname || firstIp(row) || "Unbenannt")}</strong></td><td><code>${h(firstIp(row))}</code><small>${h(row.mac_address || "")}</small></td><td>${categoryBadge(row.category)}</td><td>${h([vendor(row), model(row)].filter(Boolean).join(" ") || "—")}</td><td>${chips((row.services || []).map((service) => service.port), "chip port")}</td><td class="muted">${h(displayTime(row.last_seen_at))}</td></tr>`).join("")}
  </tbody></table></div>`;
}

function deviceDetail() {
  const device = state.data.device || {};
  const tab = state.deviceTab || "overview";
  const title = device.display_name || device.hostname || device.identifiers?.hostnames?.[0] || firstIp(device) || device.device_id || "Gerät";
  const tabs = [["overview", "Übersicht"], ["edit", "Bearbeiten"], ["identity", "Identität"], ["services", "Services"], ["timeline", "Verlauf"], ["raw", "Rohdaten"]];
  return `<button class="link-button" data-action="back-devices">← Zurück zu Geräte</button>
    <div class="device-hero"><div><h1>${h(title)}</h1><p><code>${h(device.device_id || "")}</code></p></div>${categoryBadge(device.category)}</div>
    <div class="tabs">${tabs.map(([id, label]) => `<button class="${tab === id ? "active" : ""}" data-action="device-tab" data-tab="${id}">${h(label)}</button>`).join("")}</div>
    ${tab === "overview" ? deviceOverview(device) : ""}
    ${tab === "edit" ? deviceEdit(device) : ""}
    ${tab === "identity" ? deviceIdentity(device) : ""}
    ${tab === "services" ? deviceServices(device) : ""}
    ${tab === "timeline" ? deviceTimeline(device) : ""}
    ${tab === "raw" ? `<pre class="raw">${h(JSON.stringify(device, null, 2))}</pre>` : ""}`;
}

function deviceOverview(device) {
  const ips = uniq([...(device.current_ips || []), ...(device.ip_history || []).map((row) => row.ip)]);
  return `<div class="metric-grid compact">${metricCard("IP-Adressen", ips.length, ips.slice(0, 3).join(", "))}${metricCard("Services", (device.services || []).length, compact((device.services || []).map((service) => service.port)).join(", "))}${metricCard("Findings", (device.findings || []).length, "offen oder historisch")}${metricCard("Zuletzt gesehen", displayTime(device.last_seen_at), "Europe/Berlin")}</div>
    <div class="layout-2"><section class="panel"><h2>Profil</h2><dl class="details"><dt>Hersteller</dt><dd>${h(vendor(device) || "—")}</dd><dt>Modell</dt><dd>${h(model(device) || "—")}</dd><dt>MAC</dt><dd><code>${h(device.mac_address || "—")}</code></dd><dt>Tags</dt><dd>${chips(device.tags || [])}</dd><dt>Notizen</dt><dd>${h(device.notes || "—")}</dd></dl></section><section class="panel"><h2>Findings</h2>${findingCards(device.findings || [])}</section></div>`;
}

function deviceEdit(device) {
  const categories = Object.keys(CATEGORY_ICONS);
  return `<section class="panel"><h2>Gerätestammdaten bearbeiten</h2><div class="form-grid">
    <label>Kategorie<select id="deviceCategory">${categories.map((category) => `<option value="${h(category)}" ${selected(device.category || "unknown", category)}>${h(lbl(category))}</option>`).join("")}</select></label>
    <label>Hersteller überschreiben<input id="deviceVendor" value="${h(vendor(device))}"></label>
    <label>Modell überschreiben<input id="deviceModel" value="${h(model(device))}"></label>
    <label>Tags<input id="deviceTags" value="${h((device.tags || []).join(", "))}" placeholder="server, produktiv"></label>
    <label class="wide">Notizen<textarea id="deviceNotes">${h(device.notes || "")}</textarea></label>
    <div class="form-action"><button data-action="save-device">Speichern</button></div>
  </div></section>`;
}

function deviceIdentity(device) {
  const identifiers = device.identifiers || {};
  const hostnames = identifiers.hostnames || (device.hostname ? [device.hostname] : []);
  const ips = uniq([...(device.current_ips || []), ...(device.ip_history || []).map((row) => row.ip)]);
  const identifierFingerprints = identifiers.fingerprints || [];
  return `<div class="layout-2"><section class="panel"><h2>Identitätsmerkmale</h2><dl class="details"><dt>Hostnames</dt><dd>${chips(hostnames)}</dd><dt>IP-Adressen</dt><dd>${chips(ips, "chip mono")}</dd><dt>Fingerprints</dt><dd>${chips(identifierFingerprints, "chip mono")}</dd><dt>Kategorie</dt><dd>${categoryBadge(device.category)}</dd></dl></section><section class="panel"><h2>Erkannte Fingerprints</h2><div class="fingerprint-grid">${Object.entries(device.fingerprints || {}).map(([name, content]) => `<article class="mini-card"><strong>${h(name)}</strong><pre>${h(JSON.stringify(content, null, 2))}</pre></article>`).join("") || emptyState("🔬", "Noch leer", "Deep-Enrichment oder Quellen-Sync ergänzen diese Daten.")}</div></section></div>`;
}

function deviceServices(device) {
  const rows = device.services || [];
  if (!rows.length) return emptyState("🔌", "Keine Services", "Noch keine offenen Services erfasst.");
  return `<div class="table-wrap"><table class="table"><thead><tr><th>Port</th><th>Service</th><th>Produkt</th><th>Version</th><th>Merkmale</th></tr></thead><tbody>${rows.map((service) => `<tr><td><span class="chip port">${h(service.protocol || "tcp")}/${h(service.port)}</span></td><td>${h(service.service_name || "—")}</td><td>${h(service.product || "—")}</td><td>${h(service.version || "—")}</td><td>${chips([service.http?.title, service.http?.server, service.http?.favicon_sha256, service.tls?.sha256, service.ssh?.banner, service.banner], "chip mono")}</td></tr>`).join("")}</tbody></table></div>`;
}

function deviceTimeline(device) {
  const observations = device.timeline || device.recent_observations || [];
  return `<div class="layout-2"><section class="panel"><h2>IP-Verlauf</h2><div class="timeline">${(device.ip_history || []).map((row) => `<div><time>${h(displayTime(row.observed_at))}</time><strong>${h(row.ip || "—")}</strong><span>${h(row.source || "scan")}</span></div>`).join("") || emptyState("📜", "Keine IP-Historie", "Noch keine IP-Wechsel aufgezeichnet.")}</div></section><section class="panel"><h2>Events</h2><div class="timeline">${observations.map((row) => `<div><time>${h(displayTime(row.observed_at))}</time><strong>${h((row.events || [row.type]).filter(Boolean).join(", ") || "Beobachtung")}</strong><span>${h([row.ip, row.hostname, row.source].filter(Boolean).join(" · "))}</span></div>`).join("") || emptyState("📜", "Keine Events", "Noch keine Timeline-Events vorhanden.")}</div></section></div>`;
}

