function scans() {
  const networksData = state.data.networks || [];
  const profilesData = state.data.scanProfiles || [];
  const scanRows = state.data.scans || [];
  const jobs = state.data.scanJobs || [];
  const enabledSecurityProfiles = profilesData.filter((profile) => profile.is_enabled);
  const failed = jobs.filter((job) => job.status === "failed").length;
  const active = scanRows.filter((row) => ["running", "queued", "paused"].includes(row.status));
  return `${pageHeader("Scanner", "Subnetz-Erkennung, Live-Logs, Jobsteuerung und Security-Profile.", '<button class="secondary" data-action="refresh">↻ Aktualisieren</button>')}
    <section class="panel">${sectionHead("Scan starten", `<button class="secondary small" data-action="toggle-scan-options">${state.showScanOptions ? "Optionen ausblenden" : "Optionen anzeigen"}</button>`)}
      <div class="scan-start"><select id="scanNetwork"><option value="">Alle aktiven Zielnetze</option>${networksData.map((network) => `<option value="${h(network.id)}">${h(network.name || network.cidr)} (${h(network.cidr)})</option>`).join("")}</select><select id="scanMode"><option value="discovery">Discovery</option><option value="service">Service-Erkennung</option><option value="deep">Deep-Enrichment</option><option value="vulnerability">Vulnerability</option><option value="auth_audit">Auth-Audit</option><option value="exploit">Exploit-Validierung</option><option value="bruteforce">Bruteforce-Audit</option></select><select id="scanProfile"><option value="">Kein Security-Profil</option>${enabledSecurityProfiles.map((profile) => `<option value="${h(profile.id)}">${h(profile.name)} (${h(lbl(profile.kind))})</option>`).join("")}</select><input id="scanCidr" class="mono" placeholder="CIDR überschreiben (optional)"><button data-action="start-scan">▶ Starten</button></div>
      ${state.showScanOptions ? scanOptions() : ""}
    </section>
    <section class="panel">${sectionHead(`Live-Log${state.activeScanId ? ` · ${String(state.activeScanId).slice(-8)}` : ""}`, `${active.length ? `<span class="live-indicator">● ${active.length} aktiv</span>` : ""}<button class="secondary small" data-action="clear-logs">Leeren</button>`)}<div id="logBody" class="log-body">${state.scanLogs.length ? state.scanLogs.map((line) => `<div class="log-line">${h(line)}</div>`).join("") : '<div class="log-empty">Laufenden Scan auswählen oder einen neuen Scan starten.</div>'}</div></section>
    <section class="panel">${sectionHead(`Subnet-Status (${jobs.length} Jobs)`, `${failed ? `<button class="danger small" data-action="reset-failed-jobs">${failed} Fehler zurücksetzen</button>` : ""}`)}${subnetGrid(jobs)}</section>
    <section class="panel">${sectionHead("Scan-Verlauf")}${scanTable(scanRows)}</section>`;
}

function scanOptions() {
  const options = state.scanOptions;
  return `<div class="scan-options"><label>Discovery-Timeout<select data-scan-option="discovery_timeout_s"><option value="5" ${selected(options.discovery_timeout_s, 5)}>5 s</option><option value="10" ${selected(options.discovery_timeout_s, 10)}>10 s</option><option value="12" ${selected(options.discovery_timeout_s, 12)}>12 s – Standard</option><option value="20" ${selected(options.discovery_timeout_s, 20)}>20 s</option><option value="30" ${selected(options.discovery_timeout_s, 30)}>30 s</option></select><small>Maximale Wartezeit pro Host.</small></label><label>TCP-Timeout<select data-scan-option="tcp_timeout_ms"><option value="300" ${selected(options.tcp_timeout_ms, 300)}>300 ms</option><option value="500" ${selected(options.tcp_timeout_ms, 500)}>500 ms</option><option value="750" ${selected(options.tcp_timeout_ms, 750)}>750 ms – Standard</option><option value="1500" ${selected(options.tcp_timeout_ms, 1500)}>1500 ms</option><option value="3000" ${selected(options.tcp_timeout_ms, 3000)}>3000 ms</option></select><small>Fallback TCP-Verbindungszeit.</small></label><label>Wiederholungen<select data-scan-option="retry_count"><option value="0" ${selected(options.retry_count, 0)}>0</option><option value="1" ${selected(options.retry_count, 1)}>1 – Standard</option><option value="2" ${selected(options.retry_count, 2)}>2</option><option value="3" ${selected(options.retry_count, 3)}>3</option></select><small>Retries bei Fehlern oder leeren Ergebnissen.</small></label><label>Rate-Limit<select data-scan-option="rate_limit"><option value="60" ${selected(options.rate_limit, 60)}>60/min</option><option value="300" ${selected(options.rate_limit, 300)}>300/min</option><option value="600" ${selected(options.rate_limit, 600)}>600/min – Standard</option><option value="1200" ${selected(options.rate_limit, 1200)}>1200/min</option></select><small>Für den Scanlauf protokollierter Zielwert.</small></label></div>`;
}

function subnetGrid(jobs) {
  if (!jobs.length) return emptyState("📡", "Keine Subnet-Jobs", "Lege zuerst ein aktives Zielnetz an.");
  return `<div class="subnet-grid">${jobs.map((job) => {
    const status = job.status || "idle";
    const label = String(job.cidr || "").replace(/\.0\/24$/, ".x");
    return `<article class="subnet-cell ${h(status)}"><div class="subnet-main"><strong>${h(label)}</strong><span>${h(job.last_result_count || 0)} Geräte</span></div><div class="subnet-meta">${statusBadge(status)}<small>${h(job.message || displayTime(job.next_due_at))}</small></div>${status === "running" ? progressBar(job.progress || job.current_scan?.progress || 0) : ""}<div class="row-actions"><button class="secondary small" data-action="trigger-job" data-id="${h(job.id)}">Jetzt</button>${status === "failed" ? `<button class="danger small" data-action="reset-job" data-id="${h(job.id)}">Reset</button>` : ""}</div></article>`;
  }).join("")}</div>`;
}

function scanTable(rows) {
  if (!rows.length) return emptyState("📋", "Keine Scanläufe", "Noch kein Scan gestartet.");
  return `<div class="table-wrap"><table class="table scan-table"><thead><tr><th>ID</th><th>Ziel</th><th>Modus</th><th>Status</th><th>Fortschritt</th><th>Meldung</th><th>Zeit</th><th>Aktionen</th></tr></thead><tbody>${rows.map((row) => {
    const active = ["running", "queued", "paused"].includes(row.status);
    return `<tr><td><code>${h(row.short_id || String(row.id || "").slice(-8))}</code></td><td><strong>${h(row.target_label || row.cidr || "Alle Zielnetze")}</strong><small>${h(row.network_name || "")}</small></td><td>${h(lbl(row.mode))}</td><td>${statusBadge(row.status)}</td><td>${progressBar(row.progress, `scanProg_${row.id}`)}<small>${h(row.progress || 0)} %</small></td><td class="muted">${h(row.message || "—")}</td><td class="muted">${h(displayTime(row.created_at))}</td><td><div class="row-actions">${active ? `<button class="secondary small" data-action="watch-scan" data-id="${h(row.id)}">Log</button>${row.status === "running" ? `<button class="secondary small" data-action="pause-scan" data-id="${h(row.id)}">Pause</button>` : ""}${row.status === "paused" ? `<button class="secondary small" data-action="resume-scan" data-id="${h(row.id)}">Fortsetzen</button>` : ""}<button class="danger small" data-action="cancel-scan" data-id="${h(row.id)}">Abbruch</button>` : `<button class="secondary small" data-action="rerun-scan" data-id="${h(row.id)}">Wiederholen</button>`}</div></td></tr>`;
  }).join("")}</tbody></table></div>`;
}

function scanCompactTable(rows) {
  if (!rows.length) return emptyState("📋", "Keine Scans", "Noch keine Scanläufe vorhanden.");
  return `<div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Ziel</th><th>Modus</th><th>Status</th><th>Fortschritt</th><th>Zeit</th></tr></thead><tbody>${rows.slice(0, 8).map((row) => `<tr><td><code>${h(row.short_id || String(row.id || "").slice(-8))}</code></td><td>${h(row.target_label || row.cidr || "Alle")}</td><td>${h(lbl(row.mode))}</td><td>${statusBadge(row.status)}</td><td>${progressBar(row.progress)}</td><td class="muted">${h(displayTime(row.created_at))}</td></tr>`).join("")}</tbody></table></div>`;
}

