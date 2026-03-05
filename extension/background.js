// background.js — Service worker for PhishGuard Chrome Extension
// Listens for tab updates and can badge-warn on high-risk URLs

const API_BASE = "http://localhost:5000";

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only run when the tab finishes loading a real URL
  if (changeInfo.status !== "complete") return;
  if (!tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("about:")) return;

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url, fetch_html: false })
    });

    if (!res.ok) return;
    const data = await res.json();
    if (data.error) return;

    if (data.is_phishing) {
      // Set a red badge on the extension icon
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
    } else {
      // Clear badge for safe pages
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  } catch (_) {
    // Server not running — silently fail
  }
});
