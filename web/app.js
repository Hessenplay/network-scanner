const scripts = [
  "/static/app-core.js?v=20260625-8",
  "/static/app-inventory.js?v=20260625-8",
  "/static/app-scanner.js?v=20260625-8",
  "/static/app-config.js?v=20260625-8",
  "/static/app-management.js?v=20260625-8",
  "/static/app-actions.js?v=20260625-8",
];
for (const src of scripts) {
  await new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.onload = resolve;
    script.onerror = () => reject(new Error(`Frontend-Modul konnte nicht geladen werden: ${src}`));
    document.head.appendChild(script);
  });
}
