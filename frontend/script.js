const API_BASE = "http://localhost:5000";
document.getElementById("urlInput")
  .addEventListener("keydown", e => { if (e.key === "Enter") scanURL(); });
window.addEventListener("DOMContentLoaded", () => {
  loadStats();
  loadHistory();
  document.getElementById("clearHistoryBtn").addEventListener("click", clearHistory);
});
async function scanURL() {
  const input = document.getElementById("urlInput");
  const url = input.value.trim();
  const btn = document.getElementById("scanBtn");
  const label = document.getElementById("btnLabel");
  const spinner = document.getElementById("btnSpinner");
  const panel = document.getElementById("resultPanel");
  if (!url) {
    shakeInput();
    return;
  }
  btn.disabled = true;
  label.textContent = "Scanning...";
  spinner.classList.remove("hidden");
  panel.classList.add("hidden");
  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, fetch_html: true })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    renderResult(data);
    loadStats();
    loadHistory();
  } catch (err) {
    renderError(err.message);
  } finally {
    btn.disabled = false;
    label.textContent = "Scan";
    spinner.classList.add("hidden");
  }
}
function renderResult(data) {
  const panel = document.getElementById("resultPanel");
  const labelEl = document.getElementById("resultLabel");
  const meterFill = document.getElementById("meterFill");
  const riskPct = document.getElementById("riskPct");
  const confVal = document.getElementById("confValue");
  const flagsGrid = document.getElementById("flagsGrid");
  const scannedUrl = document.getElementById("scannedUrl");
  const isPhish = data.is_phishing;
  const risk = data.risk_score;
  labelEl.className = "result-label " + (isPhish ? "phishing" : "safe");
  labelEl.innerHTML = isPhish
    ? `<span>⚠</span>  PHISHING DETECTED`
    : `<span>✔</span>  LEGITIMATE WEBSITE`;
  meterFill.style.width = "0%";
  riskPct.textContent = "0%";
  setTimeout(() => {
    meterFill.style.width = `${risk}%`;
    animateNumber(riskPct, 0, risk, 1000, v => `${v.toFixed(1)}%`);
  }, 60);
  confVal.textContent = `${data.confidence.toFixed(2)}%`;
  confVal.style.color = isPhish ? "var(--danger)" : "var(--safe)";
  const flags = data.features || {};
  const flagDefs = [
    { key: "uses_https", label: "HTTPS", good: true },
    { key: "has_at_symbol", label: "@ Symbol", good: false },
    { key: "has_ip", label: "IP in URL", good: false },
    { key: "uses_shortener", label: "URL Shortener", good: false },
    { key: "has_prefix_suffix", label: "Prefix/Suffix (–)", good: false },
    { key: "domain_age_suspicious", label: "New Domain", good: false },
  ];
  flagsGrid.innerHTML = "";
  flagDefs.forEach(def => {
    const val = flags[def.key];
    const isOk = def.good ? val === true : val === false;
    const item = document.createElement("div");
    item.className = `flag-item ${isOk ? "flag-ok" : "flag-bad"}`;
    item.innerHTML = `<span class="flag-icon"></span><span>${def.label}</span>`;
    flagsGrid.appendChild(item);
  });
  scannedUrl.textContent = `Scanned: ${data.url}`;
  panel.classList.remove("hidden");
}
function renderError(msg) {
  const panel = document.getElementById("resultPanel");
  const labelEl = document.getElementById("resultLabel");
  const meterFill = document.getElementById("meterFill");
  const riskPct = document.getElementById("riskPct");
  const confVal = document.getElementById("confValue");
  const flagsGrid = document.getElementById("flagsGrid");
  const scannedUrl = document.getElementById("scannedUrl");
  labelEl.className = "result-label";
  labelEl.style.color = "var(--warn)";
  labelEl.innerHTML = `⚡ Error — ${msg}`;
  meterFill.style.width = "0%";
  riskPct.textContent = "—";
  confVal.textContent = "—";
  flagsGrid.innerHTML = "";
  scannedUrl.textContent = "Could not complete scan. Is the Flask server running?";
  panel.classList.remove("hidden");
}
async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    const data = await res.json();
    setText("statTotal", data.total_scans);
    setText("statPhish", data.phishing_detected);
    setText("statLeg", data.legitimate);
    setText("statRate", `${data.phishing_rate}%`);
  } catch (_) {
    ["statTotal", "statPhish", "statLeg", "statRate"].forEach(id => setText(id, "—"));
  }
}
async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    const rows = await res.json();
    const tbody = document.getElementById("historyBody");
    if (!rows.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="6">No scans yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map((r, i) => `
      <tr>
        <td>${r.id}</td>
        <td class="url-cell" title="${r.url}">${r.url}</td>
        <td>
          <span class="badge ${r.label === 'PHISHING' ? 'badge-phish' : 'badge-safe'}">
            ${r.label}
          </span>
        </td>
        <td>${r.risk_score.toFixed(1)}%</td>
        <td>${r.confidence.toFixed(1)}%</td>
        <td>${formatDate(r.scanned_at)}</td>
      </tr>
    `).join("");
  } catch (_) { }
}
async function clearHistory() {
  if (!confirm("Are you sure you want to clear all scan history?")) return;
  try {
    const res = await fetch(`${API_BASE}/api/history`, { method: "DELETE" });
    if (res.ok) {
      loadStats();
      loadHistory();

      // Reset the result panel as well if it's currently showing an old scan
      document.getElementById("resultPanel").classList.add("hidden");
    }
  } catch (err) {
    console.error("Failed to clear history:", err);
  }
}

function animateNumber(el, from, to, duration, format) {
  const start = performance.now();
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const val = from + (to - from) * easeOut(t);
    el.textContent = format(val);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}
function easeOut(t) { return 1 - Math.pow(1 - t, 3); }
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function formatDate(iso) {
  try {
    const d = new Date(iso + "Z");
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return iso; }
}
function shakeInput() {
  const el = document.getElementById("urlInput");
  el.style.animation = "none";
  el.offsetHeight;
  el.style.borderColor = "var(--danger)";
  setTimeout(() => { el.style.borderColor = ""; }, 1200);
}
