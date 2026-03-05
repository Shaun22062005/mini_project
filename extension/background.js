
const API_BASE = "http://localhost:5000";

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
 
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

      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
    } else {
    
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  } catch (_) {
   
  }
});
