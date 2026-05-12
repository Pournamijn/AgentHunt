const THREAT_BACKEND_URL = "http://127.0.0.1:5000";
const MAX_HISTORY = 50;


async function saveToHistory(scanResult) {
  return new Promise(resolve => {
    chrome.storage.local.get(["scanHistory"], (data) => {
      const history = data.scanHistory || [];
      
      history.push(scanResult);
      
      if (history.length > MAX_HISTORY) {
        history.shift();
      }
      
      chrome.storage.local.set({
        scanHistory: history,
        lastResult: scanResult
      }, resolve);
    });
  });
}


chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  
  if (msg.type === "ANALYZE_EMAIL") {
    (async () => {
      try {
        const res = await fetch(`${THREAT_BACKEND_URL}/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(msg.payload),
        });
        
        const json = await res.json();
        const analysis = json.result;
        
        await saveToHistory(analysis);
        
        sendResponse({ result: analysis });
        
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    
    return true;
  }

  if (msg.type === "SCAN_URL") {
    (async () => {
      try {
        const res = await fetch(`${THREAT_BACKEND_URL}/scan-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: msg.url }),
        });
        
        const json = await res.json();
        
        sendResponse({ result: json.result });
        
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    
    return true;
  }
});


chrome.runtime.onInstalled.addListener(async () => {
  
  chrome.contextMenus.create({
    id: "threatguard-scan-link",
    title: " AgentHunt: Scan this link",
    contexts: ["link"]
  });
  
  try {
    const res = await fetch(`${THREAT_BACKEND_URL}/health`);
    const data = await res.json();
    console.log("[AgentHunt] Server healthy:", data);
    
  } catch (err) {
    console.warn("[AgentHunt] Server offline — run: python server.py");
  }
});


chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  
  if (info.menuItemId !== "threatguard-scan-link") return;
  
  const targetUrl = info.linkUrl;
  if (!targetUrl) return;
  
  try {
    const res = await fetch(`${THREAT_BACKEND_URL}/scan-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl })
    });
    
    const json = await res.json();
    const result = json.result || {};
    const score = result.risk_score || 0;
    const verdict = result.verdict || "Unknown";
    
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: showToastResult,
      args: [score, verdict, targetUrl, result.reasoning || ""]
    });
    
  } catch (err) {
    console.error("[AgentHunt] Scan failed:", err);
  }
});


function showToastResult(score, verdict, url, reasoning) {
  const color = score >= 70 ? "#f5c400" : score >= 40 ? "#ffa726" : "#66bb6a";
  
  const toast = document.createElement("div");
  toast.innerHTML = `
    <div style="
      position:fixed;top:20px;right:20px;z-index:2147483647;
      background:#0d1b2a;border:2px solid ${color};border-radius:10px;
      padding:14px 18px;font-family:sans-serif;font-size:.9rem;
      color:#c8d8f0;max-width:320px;box-shadow:0 4px 24px rgba(0,0,0,.6)">
      
      <div style="font-family:monospace;color:${color};letter-spacing:3px;margin-bottom:8px">ThreatGuard</div>
      
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span style="font-size:2rem;font-weight:700;color:${color};font-family:monospace">${score}</span>
        <span style="color:${color};font-weight:700;font-size:1rem;letter-spacing:1px">${verdict.toUpperCase()}</span>
      </div>
      
      <div style="font-size:.78rem;color:#a0b4c8;word-break:break-all;margin-bottom:6px">
        ${url.slice(0,60)}${url.length>60?"…":""}
      </div>
      
      <div style="font-size:.8rem;color:#c8d8f0">${reasoning}</div>
      
      <div style="color:#334e6e;font-size:.7rem;margin-top:8px">Auto-closes in 6s</div>
    </div>`;
  
  document.body.appendChild(toast);
  
  setTimeout(() => toast.remove(), 6000);
}