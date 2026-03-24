const params = new URLSearchParams(window.location.search);
const url = params.get("url") || "Unknown URL";
const risk = parseFloat(params.get("risk") || "0");
const conf = parseFloat(params.get("conf") || "0");

document.getElementById("blockedUrl").textContent = url;
document.getElementById("riskVal").textContent = risk.toFixed(1) + "%";
document.getElementById("confVal").textContent = conf.toFixed(1) + "%";

setTimeout(() => {
    document.getElementById("meterFill").style.width = risk + "%";
}, 100);

document.getElementById("btnBack").addEventListener("click", () => {
    chrome.tabs.update({ url: "chrome://newtab" });
});

document.getElementById("btnProceed").addEventListener("click", () => {
    const safe = params.get("original") || url;
    window.location.href = safe;
});
