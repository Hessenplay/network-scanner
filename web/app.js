const state = {
  token: localStorage.getItem("networkScannerToken") || "",
  view: location.pathname.replace(/^\//, "") || "dashboard",
  selectedDevice: "",
  deviceTab: "overview",
  data: {},
  error: "",
  refreshTimer: null,
};

const api = async (path, options = {}) => {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
  return res.json();
};

const h = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const firstIp = (r) => r.primary_ip || (r.current_ips || [])[0] || "";
const vendor = (r) => r.override_vendor || r.detected_vendor || r.detected?.vendor || "";
const model = (r) => r.override_model || r.detected_model || r.detected?.model || "";
const uniq = (items) => [...new Set((items || []).filter(Boolean))];
const compact = (items, max = 4) => {
  const values = uniq(items);
  if (values.length <= max) return values;
  return [...values.slice(0, max), `+${values.length - max}`];
};
const displayTime = (value) => {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("de-DE", { timeZone: "Europe/Berlin", dateStyle: "short", timeStyle: "short" });
};
const labels = {
  dashboard: "Dashboard", devices: "Geräte", device: "Gerät", scans: "Scans", networks: "Zielnetze", profiles: "Profile",
  identity: "Quellen", credentials: "Zugangsdaten", users: "Benutzer", system: "System", setup: "Setup", findings: "Findings", audit: "Audit",
  present_devices: "Aktiv", scan_jobs: "Subnet-Jobs", running_scans: "Laufende Scans", findings_open: "Offene Findings",
  web_device: "Web-Gerät", "web-device": "Web-Gerät", windows_host: "Windows-Host", "windows-host": "Windows-Host", switch: "Switch",
  printer: "Drucker", appliance: "Appliance", server: "Server", unknown: "Unbekannt", energy_device: "Energie", "energy-device": "Energie",
  discovery: "Discovery", service: "Service-Erkennung", deep: "Deep-Enrichment", vulnerability: "Vulnerability", auth_audit: "Auth-Audit",
  exploit: "Exploit-Validierung", bruteforce: "Bruteforce-Audit", queued: "Wartet", running: "Läuft", finished: "Fertig", failed: "Fehler",
  cancelled: "Abgebrochen", paused: "Pausiert", low: "Niedrig", medium: "Mittel", high: "Hoch", critical: "Kritisch", info: "Info",
};
const label = (value) => labels[value] || String(value || "").replaceAll("_", " ");
const boolLabel = (value) => value ? "Aktiv" : "Inaktiv";
const statusClass = (value) => `status ${String(value || "").toLowerCase()}`;
const categoryClass = (value) => `badge category-${String(value || "unknown").replace(/[^a-z0-9-]/gi, "-").toLowerCase()}`;

async function load() {
  state.error = "";
  try {
    if (!state.token) return render();
    if (state.view === "dashboard") {
      state.data.dashboard = await api("/api/v1/dashboard");
      state.data.enrichment = await api("/api/v1/enrichment/summary").catch(() => ({}));
    }
    if (state.view === "devices") state.data.devices = await api(`/api/v1/devices?q=${encodeURIComponent(document.querySelector("#deviceSearch")?.value || "")}`);
    if (state.view === "device" && state.selectedDevice) state.data.device = await api(`/api/v1/devices/${encodeURIComponent(state.selectedDevice)}`);
    if (state.view === "scans") {
      state.data.scans = await api("/api/v1/scans");
      state.data.scanJobs = await api("/api/v1/scan-jobs");
      state.data.networks = await api("/api/v1/networks").catch(() => []);
    }
    if (state.view === "networks") state.data.networks = await api("/api/v1/networks");
    if (state.view === "profiles") {
      state.data.portProfiles = await api("/api/v1/port-profiles");
      state.data.scanProfiles = await api("/api/v1/scan-profiles");
    }
    if (state.view === "identity") {
      state.data.identitySources = await api("/api/v1/identity-sources");
      state.data.credentials = await api("/api/v1/credentials").catch(() => []);
    }
    if (state.view === "credentials") state.data.credentials = await api("/api/v1/credentials");
    if (state.view === "users") state.data.users = await api("/api/v1/users");
    if (state.view === "system") state.data.system = await api("/api/v1/system/settings");
    if (state.view === "setup") state.data.setup = await api("/api/v1/setup/status");
    if (state.view === "findings") state.data.findings = await api("/api/v1/findings");
    if (state.view === "audit") state.data.audit = await api("/api/v1/audit-events");
  } catch (err) {
    state.error = err.message;
    if (err.message.includes("Invalid token") || err.message.includes("Missing bearer")) {
      state.token = "";
      localStorage.removeItem("networkScannerToken");
    }
  }
  render();
}

function nav() {
  const groups = [
    ["Inventar", [["dashboard", "Dashboard"], ["devices", "Geräte"], ["findings", "Findings"]]],
    ["Scanning", [["scans", "Scans"], ["networks", "Zielnetze"], ["profiles", "Profile"], ["identity", "Quellen"]]],
    ["Verwaltung", [["credentials", "Zugangsdaten"], ["users", "Benutzer"], ["system", "System"], ["setup", "Setup"], ["audit", "Audit"]]],
  ];
  return `<aside class="sidebar"><div class="brand"><span class="brand-mark">NI</span><span>Network Inventory</span></div>${groups.map(([title, items]) => `<div class="nav-group"><div class="nav-title">${h(title)}</div><nav class="nav">${items.map(([id, title]) => `<a class="${state.view === id ? "active" : ""}" href="/${id}" data-view="${id}">${h(title)}</a>`).join("")}</nav></div>`).join("")}<div class="sidebar-footer"><button class="secondary" id="logout">Abmelden</button></div></aside>`;
}

function pageIntro(title, text, action = "") {
  return `<div class="page-intro"><div><h1>${h(title)}</h1>${text ? `<p>${h(text)}</p>` : ""}</div>${action ? `<div class="page-actions">${action}</div>` : ""}</div>`;
}

function emptyState(title, text) {
  return `<div class="empty"><strong>${h(title)}</strong><span>${h(text)}</span></div>`;
}

function metricCard(title, value, detail = "") {
  return `<div class="metric-card"><div class="metric-label">${h(title)}</div><div class="metric-value">${h(value ?? 0)}</div>${detail ? `<div class="metric-detail">${h(detail)}</div>` : ""}</div>`;
}

function chips(items, cls = "chip") {
  const values = compact(items, 5);
  return values.length ? `<div class="chips">${values.map((x) => `<span class="${cls}">${h(x)}</span>`).join("")}</div>` : `<span class="muted">-</span>`;
}
const selected = (a, b) => String(a ?? "") === String(b ?? "") ? "selected" : "";
const checked = (value) => value ? "checked" : "";
const rowValue = (id, field) => document.querySelector(`[data-id="${CSS.escape(id)}"][data-field="${field}"]`)?.value ?? "";
const rowChecked = (id, field) => Boolean(document.querySelector(`[data-id="${CSS.escape(id)}"][data-field="${field}"]`)?.checked);
const splitList = (value) => String(value || "").split(",").map((s) => s.trim()).filter(Boolean);

function dashboard() {
  const d = state.data.dashboard || { counts: {}, recent_devices: [], recent_scans: [] };
  const e = state.data.enrichment || {};
  const counts = d.counts || {};
  const enrichmentCards = [
    ["MAC erkannt", e.with_mac], ["Hostname", e.with_hostname], ["HTTP", e.with_http], ["TLS", e.with_tls], ["SSH", e.with_ssh], ["Fingerprints", e.with_fingerprints],
  ];
  return `${pageIntro("Dashboard", "Inventarstatus, neue Geräte und aktuelle Scanner-Aktivität auf einen Blick.")}
  <div class="metric-grid">
    ${metricCard("Geräte gesamt", counts.devices, `${counts.present_devices || 0} aktuell sichtbar`)}
    ${metricCard("Subnet-Jobs", counts.scan_jobs, "fortlaufende Rotation")}
    ${metricCard("Laufende Scans", counts.running_scans || 0, "Discovery und Deep-Scans")}
    ${metricCard("Offene Findings", counts.findings_open || 0, "prüfbare Hinweise")}
  </div>
  <div class="layout-2">
    <section class="panel"><div class="section-head"><h2>Neue Geräteaktivität</h2><a href="/devices" data-view="devices">Alle Geräte</a></div>${deviceCards(d.recent_devices || d.recent_assets || [])}</section>
    <section class="panel"><div class="section-head"><h2>Erkennungsqualität</h2><a href="/credentials" data-view="credentials">Zugangsdaten</a></div><div class="quality-grid">${enrichmentCards.map(([k, v]) => `<div><span>${h(k)}</span><strong>${h(v ?? 0)}</strong></div>`).join("")}</div></section>
  </div>
  <section class="panel"><div class="section-head"><h2>Letzte Scans</h2><a href="/scans" data-view="scans">Scan-Verwaltung</a></div>${scanList(d.recent_scans || [])}</section>`;
}

function deviceCards(rows) {
  if (!rows.length) return emptyState("Keine Geräte", "Der Scanner hat für diese Ansicht noch keine Geräte geliefert.");
  return `<div class="device-list">${rows.map((r) => {
    const servicePorts = (r.services || []).map((s) => s.port ? `${s.port}` : "");
    return `<article class="device-row" data-device="${h(r.device_id)}">
      <div class="device-main"><div class="device-name">${h(r.display_name || r.hostname || firstIp(r) || "Unbenanntes Gerät")}</div><div class="device-meta"><code>${h(firstIp(r))}</code><span>${h(displayTime(r.last_seen_at))}</span></div></div>
      <div>${chips([r.mac_address || r.device_id], "chip mono")}</div>
      <div><span class="${categoryClass(r.category)}">${h(label(r.category || "unknown"))}</span></div>
      <div>${h([vendor(r), model(r)].filter(Boolean).join(" ") || "-")}</div>
      <div>${chips(servicePorts, "chip port")}</div>
    </article>`;
  }).join("")}</div>`;
}

function deviceTable(rows) {
  if (!rows.length) return emptyState("Keine Treffer", "Passe die Suche an oder starte einen Discovery-Scan.");
  return `<div class="table-wrap"><table class="table devices-table"><thead><tr><th>Gerät</th><th>Adresse</th><th>Kategorie</th><th>Hersteller</th><th>Services</th><th>Zuletzt</th></tr></thead><tbody>
  ${rows.map((r) => `<tr class="clickable" data-device="${h(r.device_id)}"><td><strong>${h(r.display_name || r.hostname || firstIp(r) || "Unbenannt")}</strong><small><code>${h(r.mac_address || r.device_id)}</code></small></td><td>${chips([firstIp(r), ...(r.current_ips || [])], "chip mono")}</td><td><span class="${categoryClass(r.category)}">${h(label(r.category || "unknown"))}</span></td><td>${h([vendor(r), model(r)].filter(Boolean).join(" ") || "-")}</td><td>${chips((r.services || []).map((s) => s.port), "chip port")}</td><td>${h(displayTime(r.last_seen_at))}</td></tr>`).join("")}
  </tbody></table></div>`;
}

function scanList(rows) {
  if (!rows.length) return emptyState("Keine Scans", "Es sind noch keine Scanläufe gespeichert.");
  return `<div class="table-wrap"><table class="table scan-table"><thead><tr><th>Scan</th><th>Ziel</th><th>Modus</th><th>Status</th><th>Fortschritt</th><th>Meldung</th><th>Aktionen</th></tr></thead><tbody>${rows.map((r) => `<tr><td><strong>${h(r.short_id || String(r.id || "").slice(-8))}</strong><small><code>${h(r.id)}</code></small></td><td><strong>${h(r.target_label || r.cidr || r.network_cidr || "Alle aktiven Zielnetze")}</strong>${r.network_name ? `<small>${h(r.network_name)}</small>` : ""}</td><td>${h(label(r.mode))}</td><td><span class="${statusClass(r.status)}">${h(label(r.status))}</span></td><td><div class="progress"><span style="width:${Math.max(0, Math.min(100, Number(r.progress || 0)))}%"></span></div><small>${h(r.progress || 0)}%</small></td><td>${h(r.message || "-")}</td><td><div class="row-actions"><button class="secondary small" data-rerun-scan="${h(r.id)}">Neu starten</button>${["running", "queued", "paused"].includes(r.status) ? `<button class="secondary small" data-cancel-scan="${h(r.id)}">Abbrechen</button>` : ""}</div></td></tr>`).join("")}</tbody></table></div>`;
}

function scanJobsList(rows) {
  if (!rows.length) return emptyState("Keine /24-Jobs", "Für die aktiven Zielnetze wurden noch keine Subnet-Jobs angelegt.");
  const active = rows.filter((r) => r.status === "running").length;
  const failed = rows.filter((r) => r.status === "failed").length;
  return `<div class="job-summary"><span>${h(rows.length)} Subnetze</span><span>${h(active)} laufen</span><span>${h(failed)} mit Fehler</span></div><div class="table-wrap"><table class="table scan-job-table"><thead><tr><th>/24</th><th>Netz</th><th>Status</th><th>Fortschritt</th><th>Letzte Geräte</th><th>Letzter Lauf</th><th>Nächster Lauf</th><th>Meldung</th></tr></thead><tbody>${rows.map((r) => `<tr><td><strong>${h(r.cidr)}</strong></td><td>${h(r.network_name || r.network_cidr || "-")}</td><td><span class="${statusClass(r.status || "queued")}">${h(label(r.status || "queued"))}</span></td><td><div class="progress"><span style="width:${Math.max(0, Math.min(100, Number(r.progress || 0)))}%"></span></div><small>${h(r.progress || 0)}%</small></td><td>${h(r.last_result_count ?? 0)}</td><td>${h(displayTime(r.last_started_at || r.started_at))}</td><td>${h(displayTime(r.next_due_at))}</td><td>${h(r.message || r.last_error || "-")}</td></tr>`).join("")}</tbody></table></div>`;
}

function devices() {
  return `${pageIntro("Geräte", "Inventar mit stabiler Geräteidentität, IP-Verlauf und Fingerprints.", `<button id="refreshView" class="secondary">Aktualisieren</button>`)}
  <div class="toolbar"><input id="deviceSearch" placeholder="Suche nach IP, MAC, Hostname, Hersteller, Modell, Tag oder Service"><button id="deviceSearchBtn">Suchen</button></div>
  ${deviceTable(state.data.devices || [])}`;
}

function deviceDetail() {
  const d = state.data.device || {};
  const activeTab = state.deviceTab || "overview";
  const tabs = [["overview", "Übersicht"], ["identity", "Identität"], ["services", "Services"], ["timeline", "Verlauf"], ["raw", "Rohdaten"]];
  const ips = uniq([...(d.current_ips || []), ...((d.ip_history || []).map((o) => o.ip))]);
  const hostnames = d.identifiers?.hostnames || (d.hostname ? [d.hostname] : []);
  const title = d.display_name || hostnames[0] || firstIp(d) || d.device_id || "Gerät";
  return `<button class="link-button" id="backToDevices">Zurück zur Geräteliste</button>
  <div class="device-hero"><div><h1>${h(title)}</h1><p><code>${h(d.device_id)}</code></p></div><span class="${categoryClass(d.category)}">${h(label(d.category || "unknown"))}</span></div>
  <div class="tabs">${tabs.map(([id, title]) => `<button class="${activeTab === id ? "active" : ""}" data-device-tab="${id}">${h(title)}</button>`).join("")}</div>
  ${activeTab === "overview" ? deviceOverview(d, ips) : ""}
  ${activeTab === "identity" ? deviceIdentity(d, hostnames) : ""}
  ${activeTab === "services" ? deviceServices(d) : ""}
  ${activeTab === "timeline" ? deviceTimeline(d) : ""}
  ${activeTab === "raw" ? `<pre class="raw">${h(JSON.stringify(d, null, 2))}</pre>` : ""}`;
}

function deviceOverview(d, ips) {
  return `<div class="metric-grid compact">
    ${metricCard("Aktuelle IPs", ips.length || "-", ips.slice(0, 3).join(", "))}
    ${metricCard("Services", (d.services || []).length, compact((d.services || []).map((s) => s.port), 6).join(", "))}
    ${metricCard("Findings", (d.findings || []).length, "offen oder historisch")}
    ${metricCard("Zuletzt gesehen", displayTime(d.last_seen_at), "Europe/Berlin")}
  </div>
  <div class="layout-2"><section class="panel"><h2>Profil</h2><dl class="details"><dt>Hersteller</dt><dd>${h(vendor(d) || "-")}</dd><dt>Modell</dt><dd>${h(model(d) || "-")}</dd><dt>MAC</dt><dd><code>${h(d.mac_address || "-")}</code></dd><dt>Tags</dt><dd>${chips(d.tags || [])}</dd><dt>Notizen</dt><dd>${h(d.notes || "-")}</dd></dl></section><section class="panel"><h2>Offene Hinweise</h2>${findingCards(d.findings || [])}</section></div>`;
}

function findingCards(rows) {
  if (!rows.length) return emptyState("Keine Findings", "Für dieses Gerät liegen keine offenen Hinweise vor.");
  return `<div class="finding-list">${rows.map((f) => `<div class="finding"><span class="severity ${h(f.severity || "info")}">${h(label(f.severity || "info"))}</span><strong>${h(f.title)}</strong><small>${h(f.status || "open")} · ${h(displayTime(f.last_seen_at))}</small></div>`).join("")}</div>`;
}

function deviceIdentity(d, hostnames) {
  const fingerprints = d.identifiers?.fingerprints || [];
  return `<div class="layout-2"><section class="panel"><h2>Identitätsmerkmale</h2><dl class="details"><dt>Hostnames</dt><dd>${chips(hostnames)}</dd><dt>IPs</dt><dd>${chips(uniq([...(d.current_ips || []), ...((d.ip_history || []).map((o) => o.ip))]), "chip mono")}</dd><dt>Fingerprints</dt><dd>${chips(fingerprints, "chip mono")}</dd><dt>Kategorie</dt><dd><span class="${categoryClass(d.category)}">${h(label(d.category || "unknown"))}</span></dd></dl></section><section class="panel"><h2>Erkannte Rohmerkmale</h2><div class="fingerprint-grid">${Object.entries(d.fingerprints || {}).map(([key, value]) => `<div class="mini-card"><strong>${h(key)}</strong><pre>${h(JSON.stringify(value, null, 2))}</pre></div>`).join("") || emptyState("Noch leer", "Deep-Enrichment oder Quellen-Sync ergänzen diese Daten.")}</div></section></div>`;
}

function deviceServices(d) {
  const rows = d.services || [];
  if (!rows.length) return emptyState("Keine Services", "Für dieses Gerät wurden noch keine offenen Services erfasst.");
  return `<div class="table-wrap"><table class="table"><thead><tr><th>Port</th><th>Service</th><th>Produkt</th><th>Version</th><th>Merkmale</th></tr></thead><tbody>${rows.map((s) => `<tr><td><span class="chip port">${h(s.protocol || "tcp")}/${h(s.port)}</span></td><td>${h(s.service_name || "-")}</td><td>${h(s.product || "-")}</td><td>${h(s.version || "-")}</td><td>${chips([s.http?.title, s.http?.server, s.http?.favicon_sha256, s.tls?.sha256, s.ssh?.banner, s.banner], "chip mono")}</td></tr>`).join("")}</tbody></table></div>`;
}

function deviceTimeline(d) {
  const obs = d.timeline || d.recent_observations || [];
  return `<div class="layout-2"><section class="panel"><h2>IP-Verlauf</h2><div class="timeline">${(d.ip_history || []).map((o) => `<div><time>${h(displayTime(o.observed_at))}</time><strong>${h(o.ip)}</strong><span>${h(o.source || "scan")}</span></div>`).join("") || emptyState("Keine IP-Historie", "Noch keine historischen IP-Wechsel gespeichert.")}</div></section><section class="panel"><h2>Timeline</h2><div class="timeline">${obs.map((o) => `<div><time>${h(displayTime(o.observed_at))}</time><strong>${h((o.events || [o.type]).join(", "))}</strong><span>${h([o.ip, o.hostname, o.source].filter(Boolean).join(" · "))}</span></div>`).join("") || emptyState("Keine Events", "Noch keine Timeline-Events vorhanden.")}</div></section></div>`;
}

function scans() {
  const networks = state.data.networks || [];
  const options = `<option value="">Alle aktiven Zielnetze</option>${networks.map((n) => `<option value="${h(n.id)}">${h(n.name || n.cidr)} (${h(n.cidr)})</option>`).join("")}`;
  return `${pageIntro("Scans", "Discovery, Service-Erkennung und freigegebene Security-Profile getrennt steuern.")}
  <section class="panel"><h2>Scan starten</h2><div class="form-row scan-start"><select id="scanNetwork">${options}</select><select id="scanMode"><option value="discovery">Discovery</option><option value="service">Service-Erkennung</option><option value="deep">Deep-Enrichment</option><option value="vulnerability">Vulnerability</option><option value="auth_audit">Auth-Audit</option><option value="exploit">Exploit-Validierung</option><option value="bruteforce">Bruteforce-Audit</option></select><button id="startScan">Scan starten</button></div></section>
  <section class="panel"><div class="section-head"><h2>Live /24-Status</h2><button class="secondary small" id="refreshView">Aktualisieren</button></div>${scanJobsList(state.data.scanJobs || [])}</section>
  <section class="panel"><h2>Scanläufe</h2>${scanList(state.data.scans || [])}</section>`;
}

function networks() {
  const rows = state.data.networks || [];
  return `${pageIntro("Zielnetze", "Aktive Netze werden in Subnet-Jobs aufgeteilt und fortlaufend rotiert.")}
  <section class="panel"><h2>Netz anlegen</h2><div class="form-grid"><label>Name<input id="networkName" value="192.168.0.0/16"></label><label>CIDR<input id="networkCidr" value="192.168.0.0/16"></label><label>Discovery-Intervall<input id="networkInterval" type="number" value="120"></label><button id="createNetwork">Anlegen</button></div></section>
  <section class="panel"><h2>Zielnetze verwalten</h2><div class="settings-list">${rows.map((r) => `<article class="settings-row"><div class="form-grid"><label>Name<input data-kind="network" data-id="${h(r.id)}" data-field="name" value="${h(r.name || "")}"></label><label>CIDR<input data-kind="network" data-id="${h(r.id)}" data-field="cidr" value="${h(r.cidr || "")}"></label><label>Discovery Sekunden<input type="number" data-kind="network" data-id="${h(r.id)}" data-field="discovery_interval_seconds" value="${h(r.discovery_interval_seconds || 120)}"></label><label>Rate Limit/min<input type="number" data-kind="network" data-id="${h(r.id)}" data-field="rate_limit_per_minute" value="${h(r.rate_limit_per_minute || 600)}"></label><label>Aktiv<input type="checkbox" data-kind="network" data-id="${h(r.id)}" data-field="is_active" ${checked(r.is_active)}></label><div class="row-actions"><button class="small" data-save-network="${h(r.id)}">Speichern</button><button class="secondary small" data-delete-network="${h(r.id)}">Löschen</button></div></div></article>`).join("") || emptyState("Keine Zielnetze", "Lege mindestens ein Zielnetz an.")}</div></section>`;
}

function profiles() {
  const portRows = state.data.portProfiles || [];
  const scanRows = state.data.scanProfiles || [];
  return `${pageIntro("Profile", "Portlisten und Scanarten zentral verwalten.")}
  <div class="layout-2"><section class="panel"><h2>Portprofile</h2><div class="settings-list">${portRows.map((r) => `<article class="settings-row"><label>Name<input data-id="${h(r.id)}" data-field="port_name" value="${h(r.name || "")}"></label><label>Beschreibung<input data-id="${h(r.id)}" data-field="port_description" value="${h(r.description || "")}"></label><label>Ports<textarea data-id="${h(r.id)}" data-field="port_ports">${h((r.ports || []).join(", "))}</textarea></label><label>Default<input type="checkbox" data-id="${h(r.id)}" data-field="port_default" ${checked(r.is_default)}></label><div class="row-actions"><button class="small" data-save-port-profile="${h(r.id)}">Speichern</button><button class="secondary small" data-delete-port-profile="${h(r.id)}">Löschen</button></div></article>`).join("")}</div></section>
  <section class="panel"><h2>Scanprofile</h2><div class="settings-list">${scanRows.map((r) => `<article class="settings-row"><label>Name<input data-id="${h(r.id)}" data-field="scan_name" value="${h(r.name || "")}"></label><label>Typ<input data-id="${h(r.id)}" data-field="scan_kind" value="${h(r.kind || "")}"></label><label>Aktiv<input type="checkbox" data-id="${h(r.id)}" data-field="scan_enabled" ${checked(r.is_enabled)}></label><label>Freigabe nötig<input type="checkbox" data-id="${h(r.id)}" data-field="scan_approval" ${checked(r.requires_manual_approval)}></label><div class="row-actions"><button class="small" data-save-scan-profile="${h(r.id)}">Speichern</button><button class="secondary small" data-delete-scan-profile="${h(r.id)}">Löschen</button></div></article>`).join("")}</div></section></div>`;
}

function identity() {
  const credentials = state.data.credentials || [];
  const optionsFor = (current) => `<option value="">Keine Zugangsdaten</option>${credentials.map((c) => `<option value="${h(c.id)}" ${selected(current, c.id)}>${h(c.name)} (${h(c.type)})</option>`).join("")}`;
  return `${pageIntro("Quellen", "DHCP, ARP, DNS und Switch-Informationen verbessern die Gerätezuordnung.")}
  <section class="panel"><h2>Quelle hinzufügen</h2><div class="form-grid"><label>Name<input id="sourceName" value="Core Switch SNMP"></label><label>Typ<select id="sourceType"><option value="snmp">SNMP read-only</option><option value="arp">ARP</option><option value="dhcp">DHCP</option><option value="dns">DNS</option><option value="file">Dateiimport</option><option value="ssdp">SSDP</option><option value="mdns">mDNS</option></select></label><label>Host oder Pfad<input id="sourceHost" placeholder="192.168.1.1"></label><label>Zugangsdaten<select id="sourceCredential">${optionsFor("")}</select></label><button id="createSource">Quelle speichern</button></div></section>
  <section class="panel"><h2>Quellen verwalten</h2><div class="settings-list">${(state.data.identitySources || []).map((r) => `<article class="settings-row"><div class="form-grid"><label>Name<input data-id="${h(r.id)}" data-field="source_name" value="${h(r.name || "")}"></label><label>Typ<select data-id="${h(r.id)}" data-field="source_type"><option value="snmp" ${selected(r.type,"snmp")}>SNMP</option><option value="arp" ${selected(r.type,"arp")}>ARP</option><option value="dhcp" ${selected(r.type,"dhcp")}>DHCP</option><option value="dns" ${selected(r.type,"dns")}>DNS</option><option value="file" ${selected(r.type,"file")}>Datei</option><option value="ssdp" ${selected(r.type,"ssdp")}>SSDP</option><option value="mdns" ${selected(r.type,"mdns")}>mDNS</option></select></label><label>Host/Pfad<input data-id="${h(r.id)}" data-field="source_host" value="${h((r.config || {}).host || (r.config || {}).path || "")}"></label><label>Zugangsdaten<select data-id="${h(r.id)}" data-field="source_credential">${optionsFor(r.credential_id || (r.config || {}).credential_id)}</select></label><label>Aktiv<input type="checkbox" data-id="${h(r.id)}" data-field="source_active" ${checked(r.is_active)}></label><div class="row-actions"><button class="small" data-save-source="${h(r.id)}">Speichern</button><button class="secondary small" data-sync-source="${h(r.id)}">Sync</button><button class="secondary small" data-delete-source="${h(r.id)}">Löschen</button></div></div></article>`).join("") || emptyState("Keine Quellen", "Lege Quellen für bessere Geräteidentität an.")}</div></section>`;
}

function credentials() {
  const rows = state.data.credentials || [];
  return `${pageIntro("Zugangsdaten", "Wenige zentrale Profile reichen meist: Switch-SNMP, Linux-SSH, Windows-WinRM und Geräte-HTTP.")}
  <section class="panel"><h2>Profil anlegen</h2><div class="form-grid credentials-form"><label>Name<input id="credName" value="Switch SNMP read-only"></label><label>Typ<select id="credType"><option value="snmp">SNMP read-only</option><option value="ssh">SSH</option><option value="winrm">WinRM</option><option value="api_token">API Token</option><option value="basic_auth">HTTP Basic</option></select></label><label>Benutzer<input id="credUsername" placeholder="optional"></label><label>Passwort / Token<input id="credPassword" type="password" placeholder="optional"></label><label>SNMP Community<input id="credCommunity" type="password" placeholder="read-only Community"></label><label>Zielmuster<input id="credTargets" placeholder="192.168.1.0/24, switch"></label><button id="createCredential">Profil speichern</button></div></section>
  <section class="panel"><h2>Zugangsdaten verwalten</h2><div class="settings-list">${rows.map((r) => `<article class="settings-row"><div class="form-grid"><label>Name<input data-id="${h(r.id)}" data-field="cred_name" value="${h(r.name || "")}"></label><label>Typ<select data-id="${h(r.id)}" data-field="cred_type"><option value="snmp" ${selected(r.type,"snmp")}>SNMP</option><option value="ssh" ${selected(r.type,"ssh")}>SSH</option><option value="winrm" ${selected(r.type,"winrm")}>WinRM</option><option value="api_token" ${selected(r.type,"api_token")}>API Token</option><option value="basic_auth" ${selected(r.type,"basic_auth")}>HTTP Basic</option></select></label><label>Benutzer<input data-id="${h(r.id)}" data-field="cred_username" value="${h(r.username || "")}"></label><label>Zielmuster<input data-id="${h(r.id)}" data-field="cred_targets" value="${h((r.target_patterns || []).join(", "))}"></label><label>Aktiv<input type="checkbox" data-id="${h(r.id)}" data-field="cred_active" ${checked(r.is_active)}></label><div class="row-actions"><button class="small" data-save-credential="${h(r.id)}">Speichern</button><button class="secondary small" data-test-credential="${h(r.id)}">Test</button><button class="secondary small" data-delete-credential="${h(r.id)}">Deaktivieren</button></div></div><small>Gespeicherte Secrets: ${h((r.has_secret_fields || []).join(", ") || "keine")}</small></article>`).join("") || emptyState("Keine Zugangsdaten", "Speichere zentrale Profile für Quellen und Deep-Enrichment.")}</div></section>`;
}

function users() {
  const rows = state.data.users || [];
  return `${pageIntro("Benutzer", "Rollen und Scopes für UI-Zugriff und API-Nutzung verwalten.")}
  <section class="panel"><h2>Benutzer anlegen</h2><div class="form-grid"><label>E-Mail<input id="userEmail"></label><label>Name<input id="userName"></label><label>Passwort<input id="userPassword" type="password"></label><label>Rolle<select id="userRole"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option><option value="owner">Owner</option></select></label><label>Scopes<input id="userScopes" placeholder="optional, kommagetrennt"></label><button id="createUser">Speichern</button></div></section>
  <section class="panel"><h2>Konten verwalten</h2><div class="settings-list">${rows.map((r) => `<article class="settings-row"><div class="form-grid"><label>E-Mail<input data-id="${h(r.id)}" data-field="user_email" value="${h(r.email || "")}"></label><label>Name<input data-id="${h(r.id)}" data-field="user_name" value="${h(r.name || "")}"></label><label>Neues Passwort<input type="password" data-id="${h(r.id)}" data-field="user_password" placeholder="leer lassen"></label><label>Rolle<select data-id="${h(r.id)}" data-field="user_role"><option value="viewer" ${selected(r.role,"viewer")}>Viewer</option><option value="operator" ${selected(r.role,"operator")}>Operator</option><option value="admin" ${selected(r.role,"admin")}>Admin</option><option value="owner" ${selected(r.role,"owner")}>Owner</option></select></label><label>Scopes<input data-id="${h(r.id)}" data-field="user_scopes" value="${h((r.scopes || []).join(", "))}"></label><label>Aktiv<input type="checkbox" data-id="${h(r.id)}" data-field="user_active" ${checked(r.is_active)}></label><div class="row-actions"><button class="small" data-save-user="${h(r.id)}">Speichern</button><button class="secondary small" data-delete-user="${h(r.id)}">Deaktivieren</button></div></div></article>`).join("")}</div></section>`;
}

function system() {
  const s = state.data.system || {};
  return `${pageIntro("System", "Globale Einstellungen für Oberfläche, Zeitzone und Aufbewahrung.")}
  <section class="panel"><div class="form-grid"><label>App-Name<input id="systemAppName" value="${h(s.app_name || "")}"></label><label>Zeitzone<input id="systemTimezone" value="${h(s.timezone || "Europe/Berlin")}"></label><label>Aufbewahrung in Tagen<input id="systemRetention" type="number" value="${h(s.retention_days || "")}"></label><label>Setup-Status<select id="systemSetup"><option value="false" ${!s.setup_completed ? "selected" : ""}>Offen</option><option value="true" ${s.setup_completed ? "selected" : ""}>Abgeschlossen</option></select></label><button id="saveSystem">Speichern</button></div></section>`;
}

function setup() {
  const s = state.data.setup || {};
  return `${pageIntro("Setup", "Initialisierung und Basisnetz für neue Installationen.")}
  <section class="panel"><div class="form-grid"><label>Setup Token<input id="setupToken" type="password"></label><label>Owner E-Mail<input id="setupEmail"></label><label>Owner Name<input id="setupName" value="Owner"></label><label>Owner Passwort<input id="setupPassword" type="password"></label><label>Default-Netz<input id="setupNetwork" value="192.168.0.0/16"></label><button id="runSetup">Setup ausführen</button></div></section>
  <section class="panel"><h2>Status</h2><dl class="details"><dt>Admin vorhanden</dt><dd>${h(s.has_admin ? "Ja" : "Nein")}</dd><dt>Token erforderlich</dt><dd>${h(s.requires_token ? "Ja" : "Nein")}</dd><dt>Setup abgeschlossen</dt><dd>${h(s.setup_completed ? "Ja" : "Nein")}</dd></dl></section>`;
}

function findings() {
  const rows = state.data.findings || [];
  return `${pageIntro("Findings", "Hinweise aus Service-Erkennung und freigegebenen Security-Profilen.")}
  <section class="panel"><div class="finding-list">${rows.map((r) => `<div class="finding"><span class="severity ${h(r.severity || "info")}">${h(label(r.severity || "info"))}</span><strong>${h(r.title)}</strong><small>${h(r.status)} · ${h(r.device_id)} · ${h(displayTime(r.last_seen_at))}</small></div>`).join("") || emptyState("Keine Findings", "Aktuell sind keine Findings vorhanden.")}</div></section>`;
}

function audit() {
  const rows = state.data.audit || [];
  return `${pageIntro("Audit", "Änderungen, Logins und administrative Aktionen.")}
  <section class="panel"><div class="table-wrap"><table class="table"><thead><tr><th>Zeit</th><th>Actor</th><th>Aktion</th><th>Ressource</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${h(displayTime(r.created_at))}</td><td>${h(r.actor_type)}:${h(r.actor_id)}</td><td>${h(r.action)}</td><td>${h(r.resource_type)} ${h(r.resource_id)}</td></tr>`).join("")}</tbody></table></div></section>`;
}

function login() {
  return `<section class="login"><div class="login-card"><div class="brand login-brand"><span class="brand-mark">NI</span><span>Network Inventory</span></div><h1>Anmelden</h1><label>E-Mail<input id="email" value="admin@example.local"></label><label>Passwort<input id="password" type="password"></label><button id="loginBtn">Anmelden</button>${state.error ? `<div class="error">${h(state.error)}</div>` : ""}</div></section>`;
}

function scheduleLiveRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
  if (state.token && state.view === "scans") {
    state.refreshTimer = setInterval(() => {
      if (state.view === "scans") load();
    }, 15000);
  }
}

function render() {
  scheduleLiveRefresh();
  const root = document.querySelector("#app");
  if (!state.token) {
    root.innerHTML = login();
    document.querySelector("#loginBtn")?.addEventListener("click", doLogin);
    return;
  }
  const views = { dashboard, devices, device: deviceDetail, scans, networks, profiles, identity, credentials, users, system, setup, findings, audit };
  root.innerHTML = `<div class="shell">${nav()}<main class="content">${state.error ? `<div class="error">${h(state.error)}</div>` : ""}${(views[state.view] || dashboard)()}</main></div>`;
  bindEvents();
}

function bindEvents() {
  document.querySelectorAll("[data-view]").forEach((btn) => btn.addEventListener("click", (event) => { event.preventDefault(); state.view = btn.dataset.view; state.selectedDevice = ""; state.deviceTab = "overview"; history.pushState({}, "", `/${state.view}`); load(); }));
  document.querySelectorAll("[data-device]").forEach((row) => row.addEventListener("click", () => { state.selectedDevice = row.dataset.device; state.view = "device"; state.deviceTab = "overview"; load(); }));
  document.querySelectorAll("[data-device-tab]").forEach((btn) => btn.addEventListener("click", () => { state.deviceTab = btn.dataset.deviceTab; render(); }));
  document.querySelector("#backToDevices")?.addEventListener("click", () => { state.view = "devices"; state.selectedDevice = ""; history.pushState({}, "", "/devices"); load(); });
  document.querySelector("#refreshView")?.addEventListener("click", load);
  document.querySelector("#logout")?.addEventListener("click", () => { state.token = ""; localStorage.removeItem("networkScannerToken"); render(); });
  document.querySelector("#deviceSearchBtn")?.addEventListener("click", load);
  document.querySelector("#deviceSearch")?.addEventListener("keydown", (event) => { if (event.key === "Enter") load(); });
  document.querySelector("#startScan")?.addEventListener("click", async () => {
    await api("/api/v1/scans", { method: "POST", body: JSON.stringify({ mode: document.querySelector("#scanMode").value, network_id: document.querySelector("#scanNetwork")?.value || null }) });
    await load();
  });
  document.querySelectorAll("[data-rerun-scan]").forEach((btn) => btn.addEventListener("click", async () => { await api(`/api/v1/scans/${btn.dataset.rerunScan}/rerun`, { method: "POST", body: JSON.stringify({}) }); await load(); }));
  document.querySelectorAll("[data-cancel-scan]").forEach((btn) => btn.addEventListener("click", async () => { await api(`/api/v1/scans/${btn.dataset.cancelScan}/cancel`, { method: "POST", body: JSON.stringify({}) }); await load(); }));
  document.querySelector("#createNetwork")?.addEventListener("click", async () => {
    await api("/api/v1/networks", { method: "POST", body: JSON.stringify({ name: document.querySelector("#networkName").value, cidr: document.querySelector("#networkCidr").value, discovery_interval_seconds: Number(document.querySelector("#networkInterval").value), is_active: true, excludes: [] }) });
    await load();
  });
  document.querySelectorAll("[data-save-network]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = btn.dataset.saveNetwork;
    await api(`/api/v1/networks/${id}`, { method: "PATCH", body: JSON.stringify({ name: rowValue(id, "name"), cidr: rowValue(id, "cidr"), discovery_interval_seconds: Number(rowValue(id, "discovery_interval_seconds") || 120), rate_limit_per_minute: Number(rowValue(id, "rate_limit_per_minute") || 600), is_active: rowChecked(id, "is_active"), excludes: [] }) });
    await load();
  }));
  document.querySelectorAll("[data-delete-network]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("Zielnetz wirklich löschen? Die zugehörigen Scan-Jobs werden entfernt.")) return;
    await api(`/api/v1/networks/${btn.dataset.deleteNetwork}`, { method: "DELETE" });
    await load();
  }));
  document.querySelectorAll("[data-save-port-profile]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = btn.dataset.savePortProfile;
    await api(`/api/v1/port-profiles/${id}`, { method: "PATCH", body: JSON.stringify({ name: rowValue(id, "port_name"), description: rowValue(id, "port_description") || null, ports: splitList(rowValue(id, "port_ports")).map(Number).filter(Boolean), is_default: rowChecked(id, "port_default") }) });
    await load();
  }));
  document.querySelectorAll("[data-delete-port-profile]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("Portprofil wirklich löschen?")) return;
    await api(`/api/v1/port-profiles/${btn.dataset.deletePortProfile}`, { method: "DELETE" });
    await load();
  }));
  document.querySelectorAll("[data-save-scan-profile]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = btn.dataset.saveScanProfile;
    await api(`/api/v1/scan-profiles/${id}`, { method: "PATCH", body: JSON.stringify({ name: rowValue(id, "scan_name"), kind: rowValue(id, "scan_kind"), is_enabled: rowChecked(id, "scan_enabled"), requires_manual_approval: rowChecked(id, "scan_approval"), config: {} }) });
    await load();
  }));
  document.querySelectorAll("[data-delete-scan-profile]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("Scanprofil wirklich löschen?")) return;
    await api(`/api/v1/scan-profiles/${btn.dataset.deleteScanProfile}`, { method: "DELETE" });
    await load();
  }));
  document.querySelector("#createSource")?.addEventListener("click", async () => {
    const host = document.querySelector("#sourceHost")?.value.trim();
    const credentialId = document.querySelector("#sourceCredential")?.value || null;
    const config = { ...(host ? { host } : {}), ...(credentialId ? { credential_id: credentialId } : {}) };
    await api("/api/v1/identity-sources", { method: "POST", body: JSON.stringify({ name: document.querySelector("#sourceName").value, type: document.querySelector("#sourceType").value, config, credential_id: credentialId, is_active: true }) });
    await load();
  });
  document.querySelectorAll("[data-sync-source]").forEach((btn) => btn.addEventListener("click", async () => { await api(`/api/v1/identity-sources/${btn.dataset.syncSource}/sync`, { method: "POST", body: JSON.stringify({}) }); await load(); }));
  document.querySelectorAll("[data-save-source]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = btn.dataset.saveSource;
    const type = rowValue(id, "source_type");
    const hostOrPath = rowValue(id, "source_host");
    const credentialId = rowValue(id, "source_credential") || null;
    const config = { ...(hostOrPath ? (type === "file" || type === "dhcp" ? { path: hostOrPath } : { host: hostOrPath }) : {}), ...(credentialId ? { credential_id: credentialId } : {}) };
    await api(`/api/v1/identity-sources/${id}`, { method: "PATCH", body: JSON.stringify({ name: rowValue(id, "source_name"), type, config, credential_id: credentialId, is_active: rowChecked(id, "source_active") }) });
    await load();
  }));
  document.querySelectorAll("[data-delete-source]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("Quelle wirklich löschen?")) return;
    await api(`/api/v1/identity-sources/${btn.dataset.deleteSource}`, { method: "DELETE" });
    await load();
  }));
  document.querySelector("#createCredential")?.addEventListener("click", async () => {
    const type = document.querySelector("#credType").value;
    const password = document.querySelector("#credPassword")?.value || "";
    const community = document.querySelector("#credCommunity")?.value || "";
    const secret_fields = {};
    if (type === "snmp" && community) secret_fields.community = community;
    if (["ssh", "winrm", "basic_auth"].includes(type) && password) secret_fields.password = password;
    if (type === "api_token" && password) secret_fields.token = password;
    const target_patterns = (document.querySelector("#credTargets")?.value || "").split(",").map((s) => s.trim()).filter(Boolean);
    await api("/api/v1/credentials", { method: "POST", body: JSON.stringify({ name: document.querySelector("#credName").value, type, username: document.querySelector("#credUsername").value || null, secret_fields, config: {}, target_patterns, tags: [], is_active: true }) });
    await load();
  });
  document.querySelectorAll("[data-save-credential]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = btn.dataset.saveCredential;
    await api(`/api/v1/credentials/${id}`, { method: "PATCH", body: JSON.stringify({ name: rowValue(id, "cred_name"), type: rowValue(id, "cred_type"), username: rowValue(id, "cred_username") || null, target_patterns: splitList(rowValue(id, "cred_targets")), is_active: rowChecked(id, "cred_active") }) });
    await load();
  }));
  document.querySelectorAll("[data-delete-credential]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("Zugangsdaten deaktivieren?")) return;
    await api(`/api/v1/credentials/${btn.dataset.deleteCredential}`, { method: "DELETE" });
    await load();
  }));
  document.querySelectorAll("[data-test-credential]").forEach((btn) => btn.addEventListener("click", async () => { const result = await api(`/api/v1/credentials/${btn.dataset.testCredential}/test`, { method: "POST", body: JSON.stringify({}) }); alert(`${result.ok ? "OK" : "Fehler"}: ${result.message}`); }));
  document.querySelector("#createUser")?.addEventListener("click", async () => {
    const scopes = (document.querySelector("#userScopes").value || "").split(",").map((s) => s.trim()).filter(Boolean);
    await api("/api/v1/users", { method: "POST", body: JSON.stringify({ email: document.querySelector("#userEmail").value, name: document.querySelector("#userName").value, password: document.querySelector("#userPassword").value || null, role: document.querySelector("#userRole").value, scopes, is_active: true }) });
    await load();
  });
  document.querySelectorAll("[data-save-user]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = btn.dataset.saveUser;
    await api(`/api/v1/users/${id}`, { method: "PATCH", body: JSON.stringify({ email: rowValue(id, "user_email"), name: rowValue(id, "user_name"), password: rowValue(id, "user_password") || null, role: rowValue(id, "user_role"), scopes: splitList(rowValue(id, "user_scopes")), is_active: rowChecked(id, "user_active") }) });
    await load();
  }));
  document.querySelectorAll("[data-delete-user]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("Benutzer deaktivieren?")) return;
    await api(`/api/v1/users/${btn.dataset.deleteUser}`, { method: "DELETE" });
    await load();
  }));
  document.querySelector("#saveSystem")?.addEventListener("click", async () => {
    await api("/api/v1/system/settings", { method: "PATCH", body: JSON.stringify({ app_name: document.querySelector("#systemAppName").value, timezone: document.querySelector("#systemTimezone").value, retention_days: Number(document.querySelector("#systemRetention").value || 0) || null, setup_completed: document.querySelector("#systemSetup").value === "true" }) });
    await load();
  });
  document.querySelector("#runSetup")?.addEventListener("click", async () => {
    await api("/api/v1/setup/bootstrap", { method: "POST", body: JSON.stringify({ token: document.querySelector("#setupToken").value || null, email: document.querySelector("#setupEmail").value || null, name: document.querySelector("#setupName").value || "Owner", password: document.querySelector("#setupPassword").value || null, default_network: document.querySelector("#setupNetwork").value || null }) });
    await load();
  });
}

async function doLogin() {
  try {
    const res = await api("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email: document.querySelector("#email").value, password: document.querySelector("#password").value }) });
    state.token = res.token;
    localStorage.setItem("networkScannerToken", state.token);
    state.view = "dashboard";
    history.pushState({}, "", "/dashboard");
    await load();
  } catch (err) {
    state.error = err.message;
    render();
  }
}

load();
window.addEventListener("popstate", () => { state.view = location.pathname.replace(/^\//, "") || "dashboard"; state.selectedDevice = ""; load(); });
