async function perform(action, successMessage = "Gespeichert.") {
  state.error = "";
  state.notice = "";
  try {
    const result = await action();
    if (successMessage) setNotice(successMessage);
    return result;
  } catch (error) {
    setError(error);
    render();
    throw error;
  }
}

async function login() {
  const email = document.querySelector("#loginEmail")?.value.trim();
  const password = document.querySelector("#loginPassword")?.value || "";
  const result = await api("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  state.token = result.token;
  localStorage.setItem("networkScannerToken", result.token);
  state.view = "dashboard";
  history.replaceState({}, "", "/dashboard");
  await load();
}

async function runSetup(prefix = "setup") {
  const id = (name) => document.querySelector(`#${prefix}${name}`)?.value?.trim() || null;
  const payload = {
    token: id("Token"),
    email: id("Email"),
    name: id("Name") || "Owner",
    password: document.querySelector(`#${prefix}Password`)?.value || null,
    default_network: id("Network"),
  };
  await api("/api/v1/setup/bootstrap", { method: "POST", body: JSON.stringify(payload) });
  setNotice("Setup abgeschlossen. Du kannst dich jetzt anmelden.");
  state.showInitialSetup = false;
  state.data.setup = await api("/api/v1/setup/status");
  render();
}

async function handleAction(button) {
  const action = button.dataset.action;
  const id = button.dataset.id;

  if (action === "navigate") return navigate(button.dataset.view);
  if (action === "logout") return clearSession();
  if (action === "refresh") return load();
  if (action === "open-device") return openDevice(button.dataset.device);
  if (action === "back-devices") return navigate("devices");
  if (action === "device-tab") { state.deviceTab = button.dataset.tab; return render(); }
  if (action === "toggle-scan-options") { state.showScanOptions = !state.showScanOptions; return render(); }
  if (action === "clear-logs") { state.scanLogs = []; state.activeScanId = null; stopLogPoll(); return render(); }
  if (action === "watch-scan") return startLogPoll(id);
  if (action === "toggle-login-setup") { state.showInitialSetup = !state.showInitialSetup; state.error = ""; return render(); }
  if (action === "copy-api-token") {
    await navigator.clipboard.writeText(state.lastApiToken);
    setNotice("Token in die Zwischenablage kopiert.");
    return render();
  }
  if (action === "category-filter") {
    state.categoryFilter = button.dataset.category || "";
    if (state.view !== "devices") {
      state.view = "devices";
      history.pushState({}, "", "/devices");
      await load();
    } else render();
    return;
  }

  button.disabled = true;
  try {
    switch (action) {
      case "login":
        await perform(login, "");
        break;
      case "login-run-setup":
        await perform(() => runSetup("loginSetup"), "");
        break;
      case "run-setup":
        await perform(() => runSetup("setup"), "");
        break;
      case "device-search":
        state.deviceQuery = document.querySelector("#deviceSearch")?.value || "";
        await load();
        break;
      case "save-device":
        await perform(() => api(`/api/v1/devices/${encodeURIComponent(state.selectedDevice)}`, { method: "PATCH", body: JSON.stringify({ category: document.querySelector("#deviceCategory").value, override_vendor: document.querySelector("#deviceVendor").value.trim(), override_model: document.querySelector("#deviceModel").value.trim(), tags: splitList(document.querySelector("#deviceTags").value), notes: document.querySelector("#deviceNotes").value.trim() }) }));
        await load();
        break;
      case "start-scan": {
        const mode = document.querySelector("#scanMode").value;
        const security = ["exploit", "bruteforce", "vulnerability", "auth_audit"].includes(mode);
        const profileId = document.querySelector("#scanProfile").value || null;
        if (security && !profileId) throw new Error("Für diesen Scanmodus muss ein aktiviertes Security-Profil gewählt werden.");
        const scan = await perform(() => api("/api/v1/scans", { method: "POST", body: JSON.stringify({ mode, network_id: document.querySelector("#scanNetwork").value || null, profile_id: profileId, cidr: document.querySelector("#scanCidr").value.trim() || null, ...state.scanOptions }) }), "Scan gestartet.");
        await load({ silent: true });
        startLogPoll(scan.id);
        break;
      }
      case "pause-scan":
      case "resume-scan":
      case "cancel-scan":
      case "rerun-scan": {
        const verb = action.replace("-scan", "");
        const result = await perform(() => api(`/api/v1/scans/${encodeURIComponent(id)}/${verb}`, { method: "POST", body: "{}" }), "Scanstatus aktualisiert.");
        await load({ silent: true });
        if (action === "rerun-scan" && result?.id) startLogPoll(result.id);
        break;
      }
      case "trigger-job": {
        const result = await perform(() => api(`/api/v1/scan-jobs/${encodeURIComponent(id)}/trigger-now`, { method: "POST", body: "{}" }), "Subnet-Job gestartet.");
        await load({ silent: true });
        const scanId = result?.current_scan_id;
        if (scanId) startLogPoll(scanId);
        break;
      }
      case "reset-job":
        await perform(() => api(`/api/v1/scan-jobs/${encodeURIComponent(id)}/reset`, { method: "POST", body: "{}" }), "Job zurückgesetzt.");
        await load();
        break;
      case "reset-failed-jobs":
        await perform(() => api("/api/v1/scan-jobs/reset-failed", { method: "POST", body: "{}" }), "Fehlgeschlagene Jobs zurückgesetzt.");
        await load();
        break;
      case "create-network":
        await perform(() => api("/api/v1/networks", { method: "POST", body: JSON.stringify({ name: document.querySelector("#networkName").value.trim(), cidr: document.querySelector("#networkCidr").value.trim(), is_active: true, excludes: splitList(document.querySelector("#networkExcludes").value), discovery_interval_seconds: Number(document.querySelector("#networkInterval").value || 120), deep_scan_interval_minutes: Number(document.querySelector("#networkDeepInterval").value || 360), rate_limit_per_minute: Number(document.querySelector("#networkRate").value || 600), scan_window: document.querySelector("#networkWindow").value.trim() || null }) }), "Zielnetz angelegt.");
        await load();
        break;
      case "save-network":
        await perform(() => api(`/api/v1/networks/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name: value(id, "network_name"), cidr: value(id, "network_cidr"), is_active: isChecked(id, "network_active"), excludes: splitList(value(id, "network_excludes")), discovery_interval_seconds: Number(value(id, "network_interval") || 120), deep_scan_interval_minutes: Number(value(id, "network_deep") || 360), rate_limit_per_minute: Number(value(id, "network_rate") || 600), scan_window: value(id, "network_window") || null }) }), "Zielnetz gespeichert.");
        await load();
        break;
      case "delete-network":
        if (confirm("Zielnetz und zugehörige Scan-Jobs wirklich löschen?")) {
          await perform(() => api(`/api/v1/networks/${encodeURIComponent(id)}`, { method: "DELETE" }), "Zielnetz gelöscht.");
          await load();
        }
        break;
      case "create-port-profile":
        await perform(() => api("/api/v1/port-profiles", { method: "POST", body: JSON.stringify({ name: document.querySelector("#newPortName").value.trim(), description: document.querySelector("#newPortDescription").value.trim() || null, ports: splitList(document.querySelector("#newPortPorts").value).map(Number).filter(Number.isInteger), is_default: document.querySelector("#newPortDefault").checked }) }), "Portprofil angelegt.");
        await load();
        break;
      case "save-port-profile":
        await perform(() => api(`/api/v1/port-profiles/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name: value(id, "port_name"), description: value(id, "port_description") || null, ports: splitList(value(id, "port_ports")).map(Number).filter(Number.isInteger), is_default: isChecked(id, "port_default") }) }), "Portprofil gespeichert.");
        await load();
        break;
      case "delete-port-profile":
        if (confirm("Portprofil wirklich löschen?")) {
          await perform(() => api(`/api/v1/port-profiles/${encodeURIComponent(id)}`, { method: "DELETE" }), "Portprofil gelöscht.");
          await load();
        }
        break;
      case "save-scan-profile":
        await perform(() => api(`/api/v1/scan-profiles/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name: value(id, "scan_name"), kind: value(id, "scan_kind"), is_enabled: isChecked(id, "scan_enabled"), requires_manual_approval: isChecked(id, "scan_approval"), config: parseJson(value(id, "scan_config"), {}) }) }), "Scanprofil gespeichert.");
        await load();
        break;
      case "delete-scan-profile":
        if (confirm("Scanprofil wirklich löschen?")) {
          await perform(() => api(`/api/v1/scan-profiles/${encodeURIComponent(id)}`, { method: "DELETE" }), "Scanprofil gelöscht.");
          await load();
        }
        break;
      case "create-source": {
        const type = document.querySelector("#sourceType").value;
        const target = document.querySelector("#sourceHost").value.trim();
        const credentialId = document.querySelector("#sourceCredential").value || null;
        const config = target ? (["file", "dhcp"].includes(type) ? { path: target } : { host: target }) : {};
        await perform(() => api("/api/v1/identity-sources", { method: "POST", body: JSON.stringify({ name: document.querySelector("#sourceName").value.trim(), type, config, credential_id: credentialId, is_active: true }) }), "Quelle angelegt.");
        await load();
        break;
      }
      case "save-source": {
        const type = value(id, "source_type");
        const target = value(id, "source_target").trim();
        const credentialId = value(id, "source_credential") || null;
        const config = target ? (["file", "dhcp"].includes(type) ? { path: target } : { host: target }) : {};
        await perform(() => api(`/api/v1/identity-sources/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name: value(id, "source_name"), type, config, credential_id: credentialId, is_active: isChecked(id, "source_active") }) }), "Quelle gespeichert.");
        await load();
        break;
      }
      case "test-source": {
        const result = await perform(() => api(`/api/v1/identity-sources/${encodeURIComponent(id)}/test`, { method: "POST", body: "{}" }), "");
        setNotice(result.message || (result.ok ? "Quellentest erfolgreich." : "Quellentest fehlgeschlagen."));
        render();
        break;
      }
      case "sync-source":
        await perform(() => api(`/api/v1/identity-sources/${encodeURIComponent(id)}/sync`, { method: "POST", body: "{}" }), "Quelle synchronisiert.");
        await load();
        break;
      case "delete-source":
        if (confirm("Quelle wirklich löschen?")) {
          await perform(() => api(`/api/v1/identity-sources/${encodeURIComponent(id)}`, { method: "DELETE" }), "Quelle gelöscht.");
          await load();
        }
        break;
      case "create-credential": {
        const type = document.querySelector("#credType").value;
        const secret = document.querySelector("#credSecret").value;
        const community = document.querySelector("#credCommunity").value;
        const secretFields = {};
        if (type === "snmp" && community) secretFields.community = community;
        if (["ssh", "winrm", "basic_auth"].includes(type) && secret) secretFields.password = secret;
        if (type === "api_token" && secret) secretFields.token = secret;
        await perform(() => api("/api/v1/credentials", { method: "POST", body: JSON.stringify({ name: document.querySelector("#credName").value.trim(), type, username: document.querySelector("#credUsername").value.trim() || null, secret_fields: secretFields, config: document.querySelector("#credHost").value.trim() ? { host: document.querySelector("#credHost").value.trim() } : {}, target_patterns: splitList(document.querySelector("#credTargets").value), tags: [], is_active: true }) }), "Zugangsdatenprofil angelegt.");
        await load();
        break;
      }
      case "save-credential": {
        const type = value(id, "cred_type");
        const secret = value(id, "cred_secret");
        const payload = { name: value(id, "cred_name"), type, username: value(id, "cred_username") || null, config: value(id, "cred_host") ? { host: value(id, "cred_host") } : {}, target_patterns: splitList(value(id, "cred_targets")), is_active: isChecked(id, "cred_active") };
        if (secret) payload.secret_fields = type === "api_token" ? { token: secret } : type === "snmp" ? { community: secret } : { password: secret };
        await perform(() => api(`/api/v1/credentials/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) }), "Zugangsdatenprofil gespeichert.");
        await load();
        break;
      }
      case "test-credential": {
        const result = await perform(() => api(`/api/v1/credentials/${encodeURIComponent(id)}/test`, { method: "POST", body: "{}" }), "");
        setNotice(result.message || (result.ok ? "Test erfolgreich." : "Test fehlgeschlagen."));
        render();
        break;
      }
      case "delete-credential":
        if (confirm("Zugangsdatenprofil deaktivieren?")) {
          await perform(() => api(`/api/v1/credentials/${encodeURIComponent(id)}`, { method: "DELETE" }), "Zugangsdatenprofil deaktiviert.");
          await load();
        }
        break;
      case "create-user":
        await perform(() => api("/api/v1/users", { method: "POST", body: JSON.stringify({ email: document.querySelector("#userEmail").value.trim(), name: document.querySelector("#userName").value.trim(), password: document.querySelector("#userPassword").value || null, role: document.querySelector("#userRole").value, scopes: splitList(document.querySelector("#userScopes").value), is_active: true }) }), "Benutzer angelegt.");
        await load();
        break;
      case "save-user":
        await perform(() => api(`/api/v1/users/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ email: value(id, "user_email"), name: value(id, "user_name"), password: value(id, "user_password") || null, role: value(id, "user_role"), scopes: splitList(value(id, "user_scopes")), is_active: isChecked(id, "user_active") }) }), "Benutzer gespeichert.");
        await load();
        break;
      case "delete-user":
        if (confirm("Benutzer deaktivieren?")) {
          await perform(() => api(`/api/v1/users/${encodeURIComponent(id)}`, { method: "DELETE" }), "Benutzer deaktiviert.");
          await load();
        }
        break;
      case "create-api-client": {
        const result = await perform(() => api("/api/v1/api-clients", { method: "POST", body: JSON.stringify({ name: document.querySelector("#apiClientName").value.trim(), scopes: splitList(document.querySelector("#apiClientScopes").value) }) }), "API-Client angelegt.");
        state.lastApiToken = result.token || "";
        await load();
        break;
      }
      case "save-system":
        await perform(() => api("/api/v1/system/settings", { method: "PATCH", body: JSON.stringify({ app_name: document.querySelector("#systemAppName").value.trim(), timezone: document.querySelector("#systemTimezone").value.trim(), retention_days: Number(document.querySelector("#systemRetention").value || 0) || null, default_scan_mode: document.querySelector("#systemScanMode").value.trim() || null, setup_completed: document.querySelector("#systemSetup").value === "true", ui_defaults: parseJson(document.querySelector("#systemUiDefaults").value, {}) }) }), "Systemeinstellungen gespeichert.");
        await load();
        break;
      case "finding-search":
        state.data.findingQuery = document.querySelector("#findingSearch").value.trim();
        await load();
        break;
      case "save-finding":
        await perform(() => api(`/api/v1/findings/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ title: value(id, "finding_title"), severity: value(id, "finding_severity"), status: value(id, "finding_status") }) }), "Finding gespeichert.");
        await load();
        break;
      default:
        break;
    }
  } catch (error) {
    // perform() rendered API errors already. Local validation errors are handled here.
    if (!state.error) {
      setError(error);
      render();
    }
  } finally {
    if (button.isConnected) button.disabled = false;
  }
}

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  if (target.tagName === "A") event.preventDefault();
  handleAction(target);
});

document.addEventListener("change", (event) => {
  const option = event.target.closest("[data-scan-option]");
  if (option) state.scanOptions[option.dataset.scanOption] = Number(option.value);
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  if (event.target.matches("#loginEmail, #loginPassword")) {
    event.preventDefault();
    document.querySelector('[data-action="login"]')?.click();
  }
  if (event.target.matches("#deviceSearch")) {
    event.preventDefault();
    document.querySelector('[data-action="device-search"]')?.click();
  }
  if (event.target.matches("#findingSearch")) {
    event.preventDefault();
    document.querySelector('[data-action="finding-search"]')?.click();
  }
});

window.addEventListener("popstate", () => {
  state.view = normalizeView(location.pathname);
  if (state.view !== "scans") stopLogPoll();
  state.selectedDevice = "";
  state.deviceTab = "overview";
  load();
});

load();
