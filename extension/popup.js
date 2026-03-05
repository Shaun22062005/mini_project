const API_BASE = "http://localhost:5000";

let currentUrl = "";


document.addEventListener("DOMContentLoaded", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentUrl = tab.url || "";
    document.getElementById("currentUrl").textContent = currentUrl || "No URL detected";
  } catch (err) {
    document.getElementById("currentUrl").textContent = "Could not read tab URL";
  }

  loadHistory();
});


async function scanCurrentTab() {
  if (!currentUrl || currentUrl.startsWith("chrome://") || currentUrl.startsWith("about:")) {
    showError("Cannot scan browser internal pages.");
    return;
  }

  const btn = document.getElementById("scanBtn");
  const errorBox = document.getElementById("errorMsg");
  const resultBox = document.getElementById("resultBox");

  btn.disabled = true;
  btn.textContent = "Scanning...";
  errorBox.classList.remove("visible");
  resultBox.classList.remove("visible");

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl, fetch_html: false })  // fast mode for extension
    });

    if (!res.ok) throw new Error(`Server error: ${res.status}`);

    const data = await res.json();
    if (data.error) throw new Error(data.error);

    renderResult(data);
    saveToLocalHistory(data);
    loadHistory();

  } catch (err) {
    showError(`Scan failed: ${err.message}. Is PhishGuard server running on port 5000?`);
  } finally {
    btn.disabled = false;
    btn.textContent = "🔍 Scan This Page";
  }
}


function renderResult(data) {
  const resultBox    = document.getElementById("resultBox");
  const resultHeader = document.getElementById("resultHeader");
  const riskVal      = document.getElementById("riskVal");
  const confVal      = document.getElementById("confVal");
  const meterFill    = document.getElementById("meterFill");

  const isPhish = data.is_phishing;

  resultHeader.textContent  = isPhish ? "⚠  PHISHING DETECTED" : "✔  LEGITIMATE WEBSITE";
  resultHeader.className    = "result-header " + (isPhish ? "phishing" : "safe");

  riskVal.textContent = `${data.risk_score.toFixed(1)}%`;
  riskVal.style.color = isPhish ? "var(--danger)" : "var(--safe)";

  confVal.textContent = `${data.confidence.toFixed(1)}%`;
  confVal.style.color = "var(--text)";


  meterFill.style.width = "0%";
  setTimeout(() => { meterFill.style.width = `${data.risk_score}%`; }, 50);

  resultBox.classList.add("visible");
}

function showError(msg) {
  const errorBox = document.getElementById("errorMsg");
  errorBox.textContent = msg;
  errorBox.classList.add("visible");
}


function saveToLocalHistory(data) {
  chrome.storage.local.get(["scanHistory"], result => {
    const history = result.scanHistory || [];
    history.unshift({
      url:       data.url,
      label:     data.label,
      risk:      data.risk_score,
      timestamp: new Date().toISOString()
    });

    chrome.storage.local.set({ scanHistory: history.slice(0, 20) });
  });
}

function loadHistory() {
  chrome.storage.local.get(["scanHistory"], result => {
    const history = result.scanHistory || [];
    const list    = document.getElementById("historyList");

    if (!history.length) {
      list.innerHTML = `<div style="color:var(--muted);font-size:11px;">No scans yet.</div>`;
      return;
    }

    list.innerHTML = history.slice(0, 5).map(item => `
      <div class="history-item">
        <span class="h-url" title="${item.url}">${item.url}</span>
        <span class="h-badge ${item.label === 'PHISHING' ? 'ph' : 'ok'}">${item.label}</span>
      </div>
    `).join("");
  });
}
