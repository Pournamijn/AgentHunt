const THREAT_SCAN_BTN_ID = "threatguard-scan-btn";
const THREAT_RESULT_BADGE_ID = "threatguard-badge";

const IS_GMAIL = location.hostname === "mail.google.com";
const IS_OUTLOOK = location.hostname.includes("outlook");

const GMAIL_SELECTORS = {
  subject: ["h2[data-thread-perm-id]",".hP","h1.ha","[data-legacy-thread-id] h2",".nH h2","h2"],
  body: [".a3s.aiL",".a3s","[data-message-id] .a3s",".ii.gt div",".Am.Al.editable",".adn.ads","[data-message-id]"],
  sender: [".gD[email]","[email].go",".go span[email]","[data-hovercard-id]",".yW span[email]",".zA .zF","span[email]"]
};

const OUTLOOK_SELECTORS = {
  subject: ['[aria-label*="subject" i]','.allowTextSelection.VR.tI','span[class*="Subject"]','.ReadingPaneContents [role="heading"]','h1[role="heading"]'],
  body: ['[aria-label*="message body" i]','.ReadingPaneContents .XbIp4','[role="document"]','div[class*="readingPane"]','.ItemBody'],
  sender: ['[aria-label*="From" i] .allowTextSelection','.lpc-hoverTarget','[aria-label*="From" i] span']
};

function findFirst(selectors) {
  for (const sel of selectors) {
    try { const el = document.querySelector(sel); if (el) return el; } catch(e) {}
  }
  return null;
}

function extractGmailData() {
  const data = { sender: "", subject: "", body: "", urls: [] };
  const subjectEl = findFirst(GMAIL_SELECTORS.subject);
  if (subjectEl) data.subject = subjectEl.innerText.trim();
  const bodyEl = findFirst(GMAIL_SELECTORS.body);
  if (bodyEl) {
    data.body = bodyEl.innerText.trim().slice(0, 5000);
    bodyEl.querySelectorAll("a[href]").forEach(a => {
      const href = a.href;
      if (href && href.startsWith("http") && !href.includes("mail.google.com")) data.urls.push(href);
    });
  }
  for (const sel of GMAIL_SELECTORS.sender) {
    try {
      const el = document.querySelector(sel);
      if (el) {
        const attr = el.getAttribute("email") || el.getAttribute("data-hovercard-id");
        if (attr && attr.includes("@")) { data.sender = attr; break; }
        const txt = el.innerText.trim();
        if (txt.includes("@")) { data.sender = txt; break; }
      }
    } catch(e) {}
  }
  if (!data.sender) {
    for (const el of document.querySelectorAll("span,div,a")) {
      const e = el.getAttribute("email");
      if (e && e.includes("@")) { data.sender = e; break; }
    }
  }
  console.log("[AgentHunt] Gmail extracted:", { subject: data.subject?.slice(0,50), sender: data.sender, bodyLen: data.body.length });
  return data;
}

function extractOutlookData() {
  const data = { sender: "", subject: "", body: "", urls: [] };
  const subjectEl = findFirst(OUTLOOK_SELECTORS.subject);
  if (subjectEl) data.subject = subjectEl.innerText.trim();
  const bodyEl = findFirst(OUTLOOK_SELECTORS.body);
  if (bodyEl) {
    data.body = bodyEl.innerText.trim().slice(0, 5000);
    bodyEl.querySelectorAll("a[href]").forEach(a => {
      const href = a.href;
      if (href && href.startsWith("http")) data.urls.push(href);
    });
  }
  const senderEl = findFirst(OUTLOOK_SELECTORS.sender);
  if (senderEl) data.sender = senderEl.innerText.trim();
  return data;
}

function getCurrentEmail() {
  return IS_GMAIL ? extractGmailData() : extractOutlookData();
}

function isEmailOpenInView() {
  if (IS_GMAIL) {
    return !!(document.querySelector(".a3s.aiL") || document.querySelector(".a3s") || document.querySelector("[data-message-id] .ii"));
  }
  if (IS_OUTLOOK) {
    return !!(document.querySelector('[aria-label*="message body" i]') || document.querySelector('[role="document"]') || document.querySelector(".ReadingPaneContents"));
  }
  return false;
}

function getRiskColorFromScore(score) {
  if (score >= 70) return "#ef5350";
  if (score >= 40) return "#ffa726";
  return "#66bb6a";
}

function getActionColorFromAction(action) {
  if (!action) return "#ffa726";
  const a = action.toLowerCase();
  if (a.includes("block") || a.includes("phishing")) return "#ef5350";
  if (a.includes("quarantine") || a.includes("report")) return "#ffa726";
  return "#66bb6a";
}

function removeOverlay(overlayId) {
  const el = document.getElementById(overlayId);
  if (el) el.remove();
}

function showScanningOverlay() {
  removeOverlay("threatguard-overlay");
  const el = document.createElement("div");
  el.id = "threatguard-overlay";
  el.innerHTML = `<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,14,26,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;font-family:monospace;"><div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:12px;padding:36px 48px;text-align:center;box-shadow:0 0 40px rgba(79,195,247,.15);"><div style="font-size:2.5rem">🛡️</div><div style="color:#4fc3f7;font-size:1.1rem;letter-spacing:3px;margin-top:12px">SCANNING MESSAGE...</div><div style="color:#7a9fc4;font-size:.85rem;margin-top:8px">Running AI + ML + threat intelligence checks</div><div style="margin-top:16px"><div style="width:200px;height:3px;background:#1e3a5f;border-radius:2px;overflow:hidden;"><div id="pg-progress" style="height:100%;width:0;background:#4fc3f7;border-radius:2px;transition:width 3s linear;"></div></div></div></div></div>`;
  document.body.appendChild(el);
  setTimeout(() => { const bar = document.getElementById("pg-progress"); if (bar) bar.style.width = "90%"; }, 100);
}

function hideScanningOverlay() { removeOverlay("threatguard-overlay"); }

function showErrorPopup(msg) {
  removeOverlay("threatguard-result");
  const el = document.createElement("div");
  el.id = "threatguard-result";
  el.innerHTML = `<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,14,26,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;font-family:sans-serif;" onclick="this.parentElement.remove()"><div style="background:#0d1b2a;border:1px solid #ef5350;border-radius:12px;padding:28px;max-width:480px;box-shadow:0 0 30px rgba(239,83,80,.2);"><div style="color:#ef9a9a;font-size:1.1rem;font-weight:700">⚠ Analysis Error</div><div style="color:#c8d8f0;margin-top:8px;font-size:.9rem">${msg}</div><div style="color:#7a9fc4;margin-top:12px;font-size:.8rem">Make sure server is running: <code style="color:#f5c400">python server.py</code></div><div style="color:#4fc3f7;margin-top:16px;font-size:.8rem;cursor:pointer">Click anywhere to close</div></div></div>`;
  document.body.appendChild(el);
}

function displayResultOverlay(result) {
  removeOverlay("threatguard-result");
  const ai = result.ai_analysis || {};
  const ml = result.ml_summary || {};
  const score = result.final_score || 0;
  const riskColor = getRiskColorFromScore(score);
  const flags = (ai.red_flags || result.heuristic?.flags || []).slice(0, 6);
  const ti = result.threat_intel || {};
  const tiFlags = (ti.flags || []).slice(0, 3);
  const mlSignals = (ml.top_signals || []).slice(0, 4);

  const flagsHtml = flags.length
    ? flags.map(f => `<span style="display:inline-block;background:rgba(239,83,80,.15);border:1px solid rgba(239,83,80,.4);color:#ef9a9a;font-size:.75rem;padding:2px 8px;border-radius:20px;margin:2px;">${f}</span>`).join("")
    : '<span style="color:#66bb6a;font-size:.85rem"> No red flags</span>';

  const tiHtml = tiFlags.length
    ? tiFlags.map(f => `<div style="color:#ffcc80;font-size:.8rem;margin:2px 0"> ${f}</div>`).join("")
    : '<div style="color:#66bb6a;font-size:.8rem"> No threat intel hits</div>';

  const urlAnalysis = ml.url_analysis || {};
  const urlResults  = (urlAnalysis.results || []).slice(0, 5);
  const urlRowsHtml = urlResults.length ? urlResults.map(r => {
    const uc = r.score >= 70 ? "#ef5350" : r.score >= 40 ? "#ffa726" : "#66bb6a";
    const shortUrl = r.url.length > 52 ? r.url.slice(0, 49) + "\u2026" : r.url;
    const flags = (r.top_flags || []).slice(0, 2).join(", ");
    return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;background:#0a1222;border:1px solid #1e3a5f;border-radius:5px;padding:5px 8px;">
      <div style="font-family:monospace;font-size:1rem;font-weight:700;color:${uc};min-width:32px;text-align:center;">${r.score}</div>
      <div style="flex:1;min-width:0;">
        <div style="font-size:.7rem;color:#a0b4c8;word-break:break-all;">${shortUrl}</div>
        ${flags ? `<div style="font-size:.63rem;color:#ffcc80;margin-top:1px;">\u25a0 ${flags}</div>` : ""}
      </div>
      <div style="font-size:.62rem;font-weight:700;color:${uc};border:1px solid ${uc};border-radius:4px;padding:1px 5px;white-space:nowrap;">${r.verdict}</div>
    </div>`;
  }).join("") : '<div style="color:#66bb6a;font-size:.78rem;padding:4px 0;"> No malicious URLs detected</div>';

  const mlHtml = (ml.ml_available || ml.nlp_score > 0 || urlResults.length > 0) ? `
    <div style="background:#111d30;border:1px solid #1e3a5f;border-radius:8px;padding:12px 14px;margin-bottom:14px;">
      <div style="color:#7a9fc4;font-size:.75rem;letter-spacing:2px;margin-bottom:8px">\u2699 ML + NLP ANALYSIS</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:10px;">
        <div style="text-align:center;background:#0d1b2a;border:1px solid #1e3a5f;border-radius:6px;padding:8px;">
          <div style="font-family:monospace;font-size:1.3rem;font-weight:700;color:${ml.ml_score >= 0 ? getRiskColorFromScore(ml.ml_score) : "#7a9fc4"}">${ml.ml_score >= 0 ? ml.ml_score : "N/A"}</div>
          <div style="font-size:.6rem;color:#7a9fc4;letter-spacing:1px;">ML SCORE</div>
        </div>
        <div style="text-align:center;background:#0d1b2a;border:1px solid #1e3a5f;border-radius:6px;padding:8px;">
          <div style="font-family:monospace;font-size:1.3rem;font-weight:700;color:${getRiskColorFromScore(ml.nlp_score || 0)}">${ml.nlp_score || 0}</div>
          <div style="font-size:.6rem;color:#7a9fc4;letter-spacing:1px;">NLP SCORE</div>
        </div>
        <div style="text-align:center;background:#0d1b2a;border:1px solid #1e3a5f;border-radius:6px;padding:8px;">
          <div style="font-family:monospace;font-size:1.3rem;font-weight:700;color:${getRiskColorFromScore(ml.urgency_score || 0)}">${ml.urgency_score || 0}</div>
          <div style="font-size:.6rem;color:#7a9fc4;letter-spacing:1px;">URGENCY</div>
        </div>
      </div>
      ${mlSignals.length ? mlSignals.map(s => `<div style="background:rgba(79,195,247,.08);border:1px solid rgba(79,195,247,.25);color:#81d4fa;font-size:.75rem;padding:3px 8px;border-radius:4px;margin-bottom:3px;"> ${s}</div>`).join("") : ""}
      <div style="color:#7a9fc4;font-size:.68rem;letter-spacing:2px;margin:10px 0 5px;">URL ML SCANNER \u2014 ${urlAnalysis.url_count || 0} URLs \u00b7 ${urlAnalysis.malicious_count || 0} MALICIOUS \u00b7 ${urlAnalysis.suspicious_count || 0} SUSPICIOUS</div>
      ${urlRowsHtml}
    </div>` : "";

  const actionColor = getActionColorFromAction(ai.suggested_action);
  const acRgb = actionColor === "#ef5350" ? "239,83,80" : actionColor === "#ffa726" ? "255,167,38" : "102,187,106";

  const el = document.createElement("div");
  el.id = "threatguard-result";
  el.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,14,26,0.88);z-index:99999;display:flex;align-items:center;justify-content:center;font-family:sans-serif;overflow-y:auto;">
      <div style="background:#0d1b2a;border:1px solid #1e3a5f;border-radius:14px;padding:28px 32px;width:540px;max-width:95vw;max-height:90vh;overflow-y:auto;box-shadow:0 0 50px rgba(79,195,247,.1);">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
          <div style="font-family:monospace;color:#4fc3f7;font-size:1.05rem;letter-spacing:3px">🛡 AgentHunt</div>
          <button id="pg-close" style="background:none;border:none;color:#7a9fc4;font-size:1.2rem;cursor:pointer;padding:0 4px;">✕</button>
        </div>
        <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px">
          <div style="text-align:center;min-width:80px">
            <div style="font-family:monospace;font-size:2.8rem;font-weight:700;color:${riskColor};line-height:1">${score}</div>
            <div style="color:#7a9fc4;font-size:.7rem;letter-spacing:2px">RISK SCORE</div>
          </div>
          <div style="flex:1">
            <div style="background:rgba(${score >= 70 ? "239,83,80" : score >= 40 ? "255,167,38" : "102,187,106"},.15);border:1px solid ${riskColor};border-radius:8px;padding:10px 14px;font-size:1rem;font-weight:700;color:${riskColor};letter-spacing:1px;"> ${(ai.verdict || result.final_verdict || "Unknown").toUpperCase()}</div>
            <div style="color:#7a9fc4;font-size:.8rem;margin-top:6px">Attack: <span style="color:#c8d8f0">${ai.attack_type || "Unknown"}</span> &nbsp;·&nbsp; Confidence: <span style="color:#4fc3f7">${ai.confidence || "N/A"}</span></div>
          </div>
        </div>
        <div style="background:#111d30;border:1px solid #1e3a5f;border-radius:8px;padding:12px 14px;font-size:.88rem;color:#c8d8f0;line-height:1.6;margin-bottom:14px;">${ai.reasoning || "No reasoning available."}</div>
        ${mlHtml}
        <div style="margin-bottom:14px">
          <div style="color:#7a9fc4;font-size:.75rem;letter-spacing:2px;margin-bottom:6px">RED FLAGS</div>
          <div>${flagsHtml}</div>
        </div>
        <div style="background:#111d30;border:1px solid #1e3a5f;border-radius:8px;padding:12px 14px;margin-bottom:14px;">
          <div style="color:#7a9fc4;font-size:.75rem;letter-spacing:2px;margin-bottom:6px">THREAT INTEL</div>
          ${tiHtml}
          ${ti.domain_age_days != null ? `<div style="color:#a0b4c8;font-size:.8rem;margin-top:4px">Domain age: ${ti.domain_age_days} days</div>` : ""}
        </div>
        <div style="background:rgba(${acRgb},.12);border:1px solid ${actionColor};border-radius:8px;padding:10px 14px;font-size:.9rem;font-weight:700;color:${actionColor};letter-spacing:1px;"> ${ai.suggested_action || "Manual Review"}</div>
        <div style="color:#334e6e;font-size:.72rem;text-align:center;margin-top:14px;letter-spacing:1px">Click ✕ to close · AgentHunt v2.0</div>
      </div>
    </div>`;

  document.body.appendChild(el);
  document.getElementById("pg-close").addEventListener("click", () => removeOverlay("threatguard-result"));
}

function updateResultBadge(score) {
  const btn = document.getElementById(THREAT_SCAN_BTN_ID);
  if (!btn) return;
  let badge = document.getElementById(THREAT_RESULT_BADGE_ID);
  if (!badge) {
    badge = document.createElement("span");
    badge.id = THREAT_RESULT_BADGE_ID;
    Object.assign(badge.style, { marginLeft:"8px",fontWeight:"bold",color:"#fff",padding:"0 6px",borderRadius:"10px",fontSize:"0.9rem",verticalAlign:"middle",userSelect:"none" });
    btn.appendChild(badge);
  }
  badge.textContent = score;
  badge.style.backgroundColor = getRiskColorFromScore(score);
}

function injectScanButton() {
  if (document.getElementById(THREAT_SCAN_BTN_ID)) return;
  const btn = document.createElement("button");
  btn.id = THREAT_SCAN_BTN_ID;
  btn.innerHTML = "🛡 AgentHunt";
  Object.assign(btn.style, {
    position:"fixed", top:"120px", right:"20px", zIndex:"999999",
    background:"linear-gradient(135deg,#1565c0,#0d47a1)", color:"white",
    border:"2px solid #4fc3f7", padding:"10px 16px", borderRadius:"8px",
    cursor:"pointer", fontWeight:"700", fontSize:"13px", fontFamily:"Arial,sans-serif",
    boxShadow:"0 4px 16px rgba(79,195,247,0.3)", letterSpacing:"0.5px",
  });
  btn.onmouseenter = () => btn.style.boxShadow = "0 4px 24px rgba(79,195,247,0.6)";
  btn.onmouseleave = () => btn.style.boxShadow = "0 4px 16px rgba(79,195,247,0.3)";
  btn.onclick = () => startEmailScan();
  document.body.appendChild(btn);
  console.log("[AgentHunt] Scan button injected.");
}

function startEmailScan() {
  showScanningOverlay();
  const emailData = getCurrentEmail();
  console.log("[AgentHunt] Sending for analysis:", emailData);
  fetch("http://127.0.0.1:5000/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(emailData),
  })
    .then(r => r.json())
    .then(data => {
      hideScanningOverlay();
      if (data && data.result) {
        displayResultOverlay(data.result);
        updateResultBadge(data.result.final_score || 0);
        chrome.runtime.sendMessage({ type: "SAVE_RESULT", payload: data.result });
      } else {
        showErrorPopup(data.error || "Invalid response from backend.");
      }
    })
    .catch(err => {
      hideScanningOverlay();
      console.error("[AgentHunt]", err);
      showErrorPopup("Cannot reach backend. Is <b>python server.py</b> running on port 5000?");
    });
}

let lastSeenSubject = "";
let debounceTimerId = null;

const emailViewObserver = new MutationObserver(() => {
  injectScanButton();
  const subjectEl = IS_GMAIL
    ? findFirst(GMAIL_SELECTORS.subject)
    : findFirst(OUTLOOK_SELECTORS.subject);
  if (!subjectEl) return;
  const subject = subjectEl.innerText.trim();
  if (!subject || subject === lastSeenSubject) return;
  lastSeenSubject = subject;
  clearTimeout(debounceTimerId);
  debounceTimerId = setTimeout(() => {
    if (isEmailOpenInView()) {
      console.log("[AgentHunt] New email detected:", subject.slice(0, 60));
      startEmailScan();
    }
  }, 1500);
});

emailViewObserver.observe(document.body, { childList: true, subtree: true });

injectScanButton();
if (isEmailOpenInView()) {
  setTimeout(() => startEmailScan(), 2000);
}