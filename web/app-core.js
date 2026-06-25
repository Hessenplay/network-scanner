const VIEWS = new Set([
  "dashboard", "devices", "scans", "networks", "profiles", "identity",
  "credentials", "users", "system", "setup", "findings", "audit",
]);

const state = {
  token: localStorage.getItem("networkScannerToken") || "",
  view: normalizeView(location.pathname),
  selectedDevice: "",
  deviceTab: "overview",
  deviceQuery: "",
  categoryFilter: "",
  data: {},
  error: "",
  notice: "",
  loading: false,
  requestSerial: 0,
  refreshTimer: null,
  logPollTimer: null,
  activeScanId: null,
  scanLogs: [],
  showScanOptions: false,
  showInitialSetup: false,
  lastApiToken: "",
  scanOptions: {
    discovery_timeout_s: 12,
    tcp_timeout_ms: 750,
    retry_count: 1,
    rate_limit: 600,
  },
};

const LABELS = {
  dashboard: "Dashboard", devices: "Geräte", scans: "Scanner", networks: "Zielnetze",
  profiles: "Profile", identity: "Quellen", credentials: "Zugangsdaten", users: "Benutzer",
  system: "System", setup: "Setup", findings: "Findings", audit: "Audit",
  discovery: "Discovery", service: "Service-Erkennung", deep: "Deep-Enrichment",
  vulnerability: "Vulnerability", auth_audit: "Auth-Audit", exploit: "Exploit-Validierung",
  bruteforce: "Bruteforce-Audit", queued: "Wartet", running: "Läuft", finished: "Fertig",
  failed: "Fehler", cancelled: "Abgebrochen", paused: "Pausiert", idle: "Bereit",
  skipped: "Übersprungen", low: "Niedrig", medium: "Mittel", high: "Hoch",
  critical: "Kritisch", info: "Info", open: "Offen", closed: "Geschlossen",
  server: "Server", "windows-host": "Windows", printer: "Drucker", camera: "Kamera",
  switch: "Switch", "router-firewall": "Router/Firewall", "access-point": "Access Point",
  nas: "NAS", hypervisor: "Hypervisor", database: "Datenbank", "energy-device": "Energie",
  "network-device": "Netzwerkgerät", "web-device": "Web-Gerät", appliance: "Appliance",
  unknown: "Unbekannt",
};

const CATEGORY_ICONS = {
  server: "🖥", "windows-host": "🪟", printer: "🖨", camera: "📷", switch: "🔀",
  "router-firewall": "🛡", "access-point": "📡", nas: "💾", hypervisor: "⚡",
  database: "🗃", "energy-device": "⚡", "network-device": "🔌", "web-device": "🌐",
  appliance: "📦", unknown: "❓",
};

function normalizeView(pathname) {
  const value = String(pathname || "").replace(/^\/+|\/+$/g, "");
  return VIEWS?.has?.(value) ? value : "dashboard";
}

function h(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function lbl(value) {
  return LABELS[value] || String(value || "").replaceAll("_", " ");
}

function selected(a, b) {
  return String(a ?? "") === String(b ?? "") ? "selected" : "";
}

function checked(value) {
  return value ? "checked" : "";
}

function uniq(values) {
  return [...new Set((values || []).filter(Boolean))];
}

function compact(values, max = 5) {
  const items = uniq(values);
  return items.length <= max ? items : [...items.slice(0, max), `+${items.length - max}`];
}

function splitList(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function firstIp(row) {
  return row?.primary_ip || row?.current_ips?.[0] || "";
}

function vendor(row) {
  return row?.override_vendor || row?.detected_vendor || row?.overrides?.vendor || row?.detected?.vendor || "";
}

function model(row) {
  return row?.override_model || row?.detected_model || row?.overrides?.model || row?.detected?.model || "";
}

function displayTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("de-DE", {
    timeZone: "Europe/Berlin",
    dateStyle: "short",
    timeStyle: "short",
  });
}

function parseJson(value, fallback = {}) {
  const text = String(value || "").trim();
  if (!text) return fallback;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Das JSON-Feld enthält ungültiges JSON.");
  }
}

function field(id, fieldName) {
  const escapedId = CSS.escape(String(id));
  const escapedField = CSS.escape(String(fieldName));
  return document.querySelector(`[data-id="${escapedId}"][data-field="${escapedField}"]`);
}

function value(id, fieldName) {
  return field(id, fieldName)?.value ?? "";
}

function isChecked(id, fieldName) {
  return Boolean(field(id, fieldName)?.checked);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  if (options.body !== undefined && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const text = await response.text();
  let body = null;
  if (text) {
    try { body = JSON.parse(text); } catch { body = text; }
  }

  if (!response.ok) {
    const detail = body && typeof body === "object" ? body.detail : body;
    const error = new Error(detail || response.statusText || `HTTP ${response.status}`);
    error.status = response.status;
    if (response.status === 401) clearSession(false);
    throw error;
  }
  return body;
}

function clearSession(renderNow = true) {
  state.token = "";
  localStorage.removeItem("networkScannerToken");
  stopLogPoll();
  stopRefresh();
  if (renderNow) render();
}

function setNotice(message) {
  state.notice = message;
  state.error = "";
}

function setError(error) {
  state.error = error instanceof Error ? error.message : String(error || "Unbekannter Fehler");
  state.notice = "";
}

async function load(options = {}) {
  const serial = ++state.requestSerial;
  if (!options.silent) state.loading = true;
  state.error = "";

  try {
    if (!state.token) {
      state.data.setup = await api("/api/v1/setup/status").catch(() => ({}));
      if (serial === state.requestSerial) render();
      return;
    }

    switch (state.view) {
      case "dashboard": {
        const [dashboardData, enrichment] = await Promise.all([
          api("/api/v1/dashboard"),
          api("/api/v1/enrichment/summary").catch(() => ({})),
        ]);
        state.data.dashboard = dashboardData;
        state.data.enrichment = enrichment;
        break;
      }
      case "devices": {
        const query = encodeURIComponent(state.deviceQuery.trim());
        state.data.devices = await api(`/api/v1/devices?q=${query}`);
        break;
      }
      case "scans": {
        const [scansData, jobs, networksData, profilesData] = await Promise.all([
          api("/api/v1/scans"),
          api("/api/v1/scan-jobs"),
          api("/api/v1/networks").catch(() => []),
          api("/api/v1/scan-profiles").catch(() => []),
        ]);
        state.data.scans = scansData;
        state.data.scanJobs = jobs;
        state.data.networks = networksData;
        state.data.scanProfiles = profilesData;
        break;
      }
      case "networks":
        state.data.networks = await api("/api/v1/networks");
        break;
      case "profiles": {
        const [portProfiles, scanProfiles] = await Promise.all([
          api("/api/v1/port-profiles"),
          api("/api/v1/scan-profiles"),
        ]);
        state.data.portProfiles = portProfiles;
        state.data.scanProfiles = scanProfiles;
        break;
      }
      case "identity": {
        const [sources, credentials] = await Promise.all([
          api("/api/v1/identity-sources"),
          api("/api/v1/credentials").catch(() => []),
        ]);
        state.data.identitySources = sources;
        state.data.credentials = credentials;
        break;
      }
      case "credentials":
        state.data.credentials = await api("/api/v1/credentials");
        break;
      case "users": {
        const [usersData, clients] = await Promise.all([
          api("/api/v1/users"),
          api("/api/v1/api-clients").catch(() => []),
        ]);
        state.data.users = usersData;
        state.data.apiClients = clients;
        break;
      }
      case "system": {
        const [settings, health] = await Promise.all([
          api("/api/v1/system/settings"),
          api("/health").catch(() => ({})),
        ]);
        state.data.system = settings;
        state.data.health = health;
        break;
      }
      case "setup":
        state.data.setup = await api("/api/v1/setup/status");
        break;
      case "findings": {
        const q = encodeURIComponent(state.data.findingQuery || "");
        state.data.findings = await api(`/api/v1/findings?q=${q}`);
        break;
      }
      case "audit":
        state.data.audit = await api("/api/v1/audit-events");
        break;
      default:
        break;
    }

    if (state.view === "device" && state.selectedDevice) {
      state.data.device = await api(`/api/v1/devices/${encodeURIComponent(state.selectedDevice)}`);
    }
  } catch (error) {
    setError(error);
  } finally {
    if (serial === state.requestSerial) {
      state.loading = false;
      render();
      scheduleRefresh();
    }
  }
}

function navigate(view) {
  const next = VIEWS.has(view) ? view : "dashboard";
  if (next !== "scans") stopLogPoll();
  state.view = next;
  state.selectedDevice = "";
  state.deviceTab = "overview";
  state.error = "";
  history.pushState({}, "", `/${next}`);
  load();
}

function openDevice(deviceId) {
  stopLogPoll();
  state.selectedDevice = deviceId;
  state.view = "device";
  state.deviceTab = "overview";
  state.error = "";
  load();
}

function stopRefresh() {
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  state.refreshTimer = null;
}

function scheduleRefresh() {
  stopRefresh();
  if (state.token && state.view === "scans") {
    state.refreshTimer = setInterval(() => {
      if (state.view === "scans") load({ silent: true });
    }, 20000);
  }
}

function stopLogPoll() {
  if (state.logPollTimer) clearInterval(state.logPollTimer);
  state.logPollTimer = null;
}

function startLogPoll(scanId) {
  stopLogPoll();
  state.activeScanId = scanId;
  state.scanLogs = [];

  const poll = async () => {
    if (!state.activeScanId || state.view !== "scans") return;
    try {
      const result = await api(`/api/v1/scans/${encodeURIComponent(state.activeScanId)}/logs`);
      state.scanLogs = result.logs || [];
      const logBody = document.querySelector("#logBody");
      if (logBody) {
        logBody.innerHTML = state.scanLogs.length
          ? state.scanLogs.map((line) => `<div class="log-line">${h(line)}</div>`).join("")
          : '<div class="log-empty">Warte auf Logs…</div>';
        logBody.scrollTop = logBody.scrollHeight;
      }
      const progress = document.querySelector(`#scanProg_${CSS.escape(String(state.activeScanId))}`);
      if (progress) progress.style.width = `${Math.max(0, Math.min(100, result.progress || 0))}%`;
      if (result.status && !["running", "queued", "paused"].includes(result.status)) {
        stopLogPoll();
        await load({ silent: true });
      }
    } catch (error) {
      if (error.status === 404) stopLogPoll();
    }
  };

  poll();
  state.logPollTimer = setInterval(poll, 2000);
  render();
}

function render() {
  const root = document.querySelector("#app");
  if (!root) return;

  if (!state.token) {
    root.innerHTML = loginPage();
    return;
  }

  const views = {
    dashboard, devices, scans, networks, profiles, identity, credentials,
    users, system, setup, findings, audit,
  };
  const content = state.view === "device" ? deviceDetail() : (views[state.view] || dashboard)();
  root.innerHTML = `<div class="shell">${nav()}<main class="content">
    ${state.loading ? '<div class="loading-bar"><span></span></div>' : ""}
    ${state.error ? `<div class="error">${h(state.error)}</div>` : ""}
    ${state.notice ? `<div class="notice">${h(state.notice)}</div>` : ""}
    ${content}
  </main></div>`;
}

function nav() {
  const groups = [
    ["Inventar", [["dashboard", "Dashboard", "◈"], ["devices", "Geräte", "⬡"], ["findings", "Findings", "◉"]]],
    ["Scanner", [["scans", "Scanner", "⚡"], ["networks", "Zielnetze", "◫"], ["profiles", "Profile", "⊞"], ["identity", "Quellen", "⊛"]]],
    ["Verwaltung", [["credentials", "Zugangsdaten", "⊕"], ["users", "Benutzer", "⊙"], ["system", "System", "⊗"], ["setup", "Setup", "⊜"], ["audit", "Audit", "≡"]]],
  ];
  return `<aside class="sidebar">
    <div class="brand"><span class="brand-mark">NI</span><div><div>Network</div><small>Inventory</small></div></div>
    ${groups.map(([title, items]) => `<div class="nav-group"><div class="nav-title">${h(title)}</div><nav class="nav">
      ${items.map(([id, text, icon]) => `<a href="/${id}" data-action="navigate" data-view="${id}" class="${state.view === id ? "active" : ""}"><span class="nav-icon">${icon}</span>${h(text)}</a>`).join("")}
    </nav></div>`).join("")}
    <div class="sidebar-footer"><button class="secondary" data-action="logout">Abmelden</button></div>
  </aside>`;
}

function pageHeader(title, subtitle, actions = "") {
  return `<div class="page-intro"><div><h1>${h(title)}</h1>${subtitle ? `<p>${h(subtitle)}</p>` : ""}</div>${actions ? `<div class="page-actions">${actions}</div>` : ""}</div>`;
}

function sectionHead(title, actions = "") {
  return `<div class="section-head"><h2>${h(title)}</h2>${actions ? `<div class="row-actions">${actions}</div>` : ""}</div>`;
}

function emptyState(icon, title, text) {
  return `<div class="empty"><strong>${icon} ${h(title)}</strong><span>${h(text)}</span></div>`;
}

function metricCard(label, value, detail = "", extra = "") {
  return `<article class="metric-card ${h(extra)}"><div class="metric-label">${h(label)}</div><div class="metric-value">${h(value ?? 0)}</div>${detail ? `<div class="metric-detail">${h(detail)}</div>` : ""}</article>`;
}

function chips(values, className = "chip") {
  const items = compact(values, 6);
  return items.length ? `<div class="chips">${items.map((item) => `<span class="${h(className)}">${h(item)}</span>`).join("")}</div>` : '<span class="muted">—</span>';
}

function statusBadge(status) {
  return `<span class="status ${h(status || "idle")}">${h(lbl(status || "idle"))}</span>`;
}

function categoryBadge(category) {
  const value = category || "unknown";
  const safe = String(value).replace(/[^a-z0-9-]/gi, "-").toLowerCase();
  return `<span class="badge category-${safe}">${CATEGORY_ICONS[value] || "📦"} ${h(lbl(value))}</span>`;
}

function severityBadge(severity) {
  return `<span class="severity ${h(severity || "info")}">${h(lbl(severity || "info"))}</span>`;
}

function progressBar(percent, id = "") {
  const value = Math.max(0, Math.min(100, Number(percent || 0)));
  return `<div class="progress"><span ${id ? `id="${h(id)}"` : ""} style="width:${value}%"></span></div>`;
}

