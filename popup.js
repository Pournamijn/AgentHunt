const THREAT_BACKEND_URL = "http://127.0.0.1:5000";
const MAX_HISTORY_ITEMS = 50;


function getColorForScore(score) {
  if (score >= 70) return "#f5c400";
  if (score >= 40) return "#ffa726";
  return "#66bb6a";
}

function getScoreCssClass(score) {
  if (score >= 70) return "score-phishing";
  if (score >= 40) return "score-suspicious";
  return "score-safe";
}

function getVerdictCssClass(verdict) {
  if (!verdict) return "verdict-suspicious";
  
  const v = verdict.toLowerCase();
  if (v === "phishing") return "verdict-phishing";
  if (v === "suspicious") return "verdict-suspicious";
  return "verdict-legitimate";
}

function getActionCssClass(action) {
  if (!action) return "action-report";
  
  const a = action.toLowerCase();
  if (a.includes("block")) return "action-block";
  if (a.includes("quarantine") || a.includes("report")) return "action-report";
  return "action-ignore";
}

function getHistoryVerdictClass(verdict) {
  const v = (verdict || "").toLowerCase();
  if (v === "phishing") return "hv-phishing";
  if (v === "suspicious") return "hv-suspicious";
  return "hv-legitimate";
}


function renderScanResult(result) {
  const ai = result.ai_analysis || result;
  const score = result.final_score ?? ai.risk_score ?? 0;
  const riskColor = getColorForScore(score);
  const ti = result.threat_intel || {};
  const flags = (ai.red_flags || result.heuristic?.flags || []).slice(0, 5);

  const flagsHtml = flags.length
    ? flags.map(f => `<span class="flag-chip">⚑ ${f}</span>`).join("")
    : '<span class="safe-chip"> No red flags detected</span>';

  const tiRows = [];
  
  if (ti.is_domain_blacklisted) {
    tiRows.push(`<div class="ti-row ti-bad">🚨 Domain blacklisted</div>`);
  }
  if (ti.domain_age_days != null && ti.domain_age_days < 30) {
    tiRows.push(`<div class="ti-row ti-bad"> Domain only ${ti.domain_age_days} days old</div>`);
  }
  if (ti.vt_detections > 2) {
    tiRows.push(`<div class="ti-row ti-bad"> VirusTotal: ${ti.vt_detections} engines flagged</div>`);
  }
  if (ti.abuseipdb_reports > 0) {
    tiRows.push(`<div class="ti-row ti-warn"> AbuseIPDB: ${ti.abuseipdb_reports} reports</div>`);
  }
  if (!tiRows.length) {
    tiRows.push(`<div class="ti-row ti-ok"> No threat intel hits</div>`);
  }
  if (ti.domain_age_days != null) {
    tiRows.push(`<div class="ti-row" style="color:#a0b4c8;font-size:.75rem">Domain age: ${ti.domain_age_days} days</div>`);
  }

  const panel = document.getElementById("result-panel");
  panel.innerHTML = `
    <div class="score-row">
      <div>
        <div class="score-num ${getScoreCssClass(score)}">${score}</div>
        <div class="score-label">RISK SCORE</div>
      </div>
      <div style="flex:1">
        <div class="verdict-box ${getVerdictCssClass(ai.verdict || result.final_verdict)}">
          ⚡ ${(ai.verdict || result.final_verdict || "UNKNOWN").toUpperCase()}
        </div>
        <div style="color:#7a9fc4;font-size:.72rem;margin-top:5px">
          ${ai.attack_type ? ai.attack_type + " · " : ""}${ai.confidence || ""}
        </div>
      </div>
    </div>

    ${result.sender ? `
    <div class="card">
      <div class="card-label">FROM</div>
      <div class="sender-text">${result.sender}</div>
    </div>` : ""}

    <div class="card">
      <div class="card-label">AI ANALYSIS</div>
      <div class="card-text">${ai.reasoning || "No analysis available."}</div>
    </div>

    <div class="card">
      <div class="card-label">RED FLAGS</div>
      <div>${flagsHtml}</div>
    </div>

    <div class="card">
      <div class="card-label">THREAT INTEL</div>
      ${tiRows.join("")}
    </div>

    <div class="action-box ${getActionCssClass(ai.suggested_action)}">
       ${ai.suggested_action || "Manual Review"}
    </div>
  `;

  document.getElementById("empty-state").style.display = "none";
  panel.style.display = "block";

  renderMlNlpPanel(result);
}


function formatTimeAgo(timestamp) {
  const diff = Date.now() - new Date(timestamp).getTime();
  const mins = Math.floor(diff / 60000);
  
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  
  return `${Math.floor(hours / 24)}d ago`;
}


function renderHistory(history) {
  const listEl = document.getElementById("hist-list");
  const emptyEl = document.getElementById("hist-empty");
  const clearBtn = document.getElementById("hist-clear");

  listEl.innerHTML = "";

  if (!history || !history.length) {
    emptyEl.style.display = "block";
    clearBtn.style.display = "none";
    return;
  }

  emptyEl.style.display = "none";
  clearBtn.style.display = "block";

  history.slice().reverse().forEach((item, idx) => {
    const ai = item.ai_analysis || {};
    const score = item.final_score ?? ai.risk_score ?? 0;
    const verdict = ai.verdict || item.final_verdict || "Unknown";
    const color = getColorForScore(score);

    const div = document.createElement("div");
    div.className = "hist-item";
    div.innerHTML = `
      <div class="hist-score" style="color:${color}">${score}</div>
      <div class="hist-info">
        <div class="hist-subject">${item.subject || "(no subject)"}</div>
        <div class="hist-sender">${item.sender || "Unknown sender"}</div>
        <div class="hist-time">${formatTimeAgo(item.timestamp)}</div>
      </div>
      <div class="hist-verdict ${getHistoryVerdictClass(verdict)}">${verdict.toUpperCase()}</div>
    `;
    
    div.addEventListener("click", () => {
      switchTab("scan");
      renderScanResult(item);
    });
    
    listEl.appendChild(div);
  });
}


function renderStats(history) {
  const total = history.length;
  const threatCount = history.filter(h => (h.ai_analysis?.verdict || h.final_verdict || "").toLowerCase() === "phishing").length;
  const suspCount = history.filter(h => (h.ai_analysis?.verdict || h.final_verdict || "").toLowerCase() === "suspicious").length;
  const safeCount = total - threatCount - suspCount;
  const avgScore = total
    ? Math.round(history.reduce((sum, h) => sum + (h.final_score ?? h.ai_analysis?.risk_score ?? 0), 0) / total)
    : 0;

  document.getElementById("st-total").textContent = total;
  document.getElementById("st-phishing").textContent = threatCount;
  document.getElementById("st-suspicious").textContent = suspCount;
  document.getElementById("st-safe").textContent = safeCount;
  document.getElementById("st-avg").textContent = total ? avgScore : "—";

  const pctThreat = total ? Math.round(threatCount / total * 100) : 0;
  const pctSusp = total ? Math.round(suspCount / total * 100) : 0;
  const pctSafe = total ? Math.round(safeCount / total * 100) : 0;

  document.getElementById("pct-phishing").textContent = pctThreat + "%";
  document.getElementById("pct-suspicious").textContent = pctSusp + "%";
  document.getElementById("pct-safe").textContent = pctSafe + "%";
  
  document.getElementById("bar-phishing").style.width = pctThreat + "%";
  document.getElementById("bar-suspicious").style.width = pctSusp + "%";
  document.getElementById("bar-safe").style.width = pctSafe + "%";
}


function switchTab(tabName) {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.classList.toggle("active", tab.dataset.tab === tabName);
  });
  
  document.querySelectorAll(".tab-panel").forEach(panel => {
    panel.classList.toggle("active", panel.id === `tab-${tabName}`);
  });
}

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
});

document.getElementById("hist-clear").addEventListener("click", () => {
  chrome.storage.local.set({ scanHistory: [] }, () => {
    renderHistory([]);
    renderStats([]);
  });
});


async function checkServerHealth() {
  const dot = document.getElementById("status-dot");
  const statusEl = document.getElementById("server-status");
  
  try {
    const res = await fetch(`${THREAT_BACKEND_URL}/health`, {
      signal: AbortSignal.timeout(2000)
    });
    
    if (res.ok) {
      dot.classList.remove("offline");
      statusEl.textContent = " Server online — ready to scan";
      statusEl.style.color = "#66bb6a";
    } else {
      throw new Error("Server error");
    }
    
  } catch (err) {
    dot.classList.add("offline");
    statusEl.innerHTML = ' Server offline — run: <code style="color:#f5c400">python server.py</code>';
    statusEl.style.color = "#ef9a9a";
  }
}


chrome.storage.local.get(["lastResult", "scanHistory"], (data) => {
  if (data.lastResult) {
    renderScanResult(data.lastResult);
  }
  
  const history = data.scanHistory || [];
  renderHistory(history);
  renderStats(history);
});

checkServerHealth();

// ── ML + NLP Panel Renderer ──────────────────────────────────────────────────
function renderMlNlpPanel(result) {
  const ml = result.ml_summary || {};
  const panel = document.getElementById("ml-nlp-panel");
  if (!panel) return;

  if (!ml || (ml.ml_score === undefined && !ml.nlp_score)) {
    panel.style.display = "none";
    return;
  }

  panel.style.display = "block";

  const mlScore = ml.ml_score >= 0 ? ml.ml_score : "N/A";
  const mlEl = document.getElementById("ml-score-val");
  if (mlEl) {
    mlEl.textContent = mlScore;
    mlEl.style.color = typeof mlScore === "number" ? getColorForScore(mlScore) : "#7a9fc4";
  }

  const nlpScore = ml.nlp_score || 0;
  const nlpEl = document.getElementById("nlp-score-val");
  if (nlpEl) {
    nlpEl.textContent = nlpScore;
    nlpEl.style.color = getColorForScore(nlpScore);
  }

  const setBar = (pctId, barId, val) => {
    const pct = document.getElementById(pctId);
    const bar = document.getElementById(barId);
    if (pct) pct.textContent = val + "%";
    if (bar) bar.style.width = val + "%";
  };
  setBar("nlp-urgency-pct", "nlp-urgency-bar", ml.urgency_score || 0);
  setBar("nlp-deception-pct", "nlp-deception-bar", ml.deception_score || 0);
  setBar("nlp-impersonation-pct", "nlp-impersonation-bar", ml.impersonation_score || 0);

  const signalsContainer = document.getElementById("nlp-signal-list");
  if (signalsContainer) {
    const signals = ml.top_signals || [];
    signalsContainer.innerHTML = signals.length
      ? signals.map(s => `<span class="signal-chip"> ${s}</span>`).join("")
      : '<span class="signal-chip" style="color:#66bb6a"> No ML/NLP anomalies detected</span>';
  }
}