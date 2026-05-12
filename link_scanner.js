const THREAT_BACKEND_URL = "http://127.0.0.1:5000";
const SCAN_CACHE = {};

const TRUSTED_DOMAINS = [
  "google.com", "microsoft.com", "github.com",
  "linkedin.com", "apple.com", "amazon.com",
  "youtube.com", "wikipedia.org", "stackoverflow.com"
];



function isTrustedDomain(urlToCheck) {
  try {
    const parsed = new URL(urlToCheck);
    const host = parsed.hostname.replace(/^www\./, "");
    
    return TRUSTED_DOMAINS.some(trusted =>
      host === trusted || host.endsWith("." + trusted)
    );
  } catch {
    return false;
  }
}


function getRiskColors(riskScore) {
  if (riskScore >= 70) {
    return { bg: "#ef5350", glow: "rgba(239,83,80,.5)" };
  }
  if (riskScore >= 40) {
    return { bg: "#ffa726", glow: "rgba(255,167,38,.4)" };
  }
  return { bg: "#66bb6a", glow: "rgba(102,187,106,.4)" };
}


function attachBadgeToLink(link) {
  if (link.dataset.threatguardBadge) return;
  link.dataset.threatguardBadge = "1";

  const href = link.href;
  
  if (!href || !href.startsWith("http") || isTrustedDomain(href)) {
    return;
  }

  const badge = document.createElement("span");
  badge.className = "tg-link-badge";
  badge.title = "AgentHunt: click to scan this link";
  badge.textContent = "🛡";
  
  Object.assign(badge.style, {
    display: "inline-block",
    marginLeft: "3px",
    cursor: "pointer",
    fontSize: "0.75em",
    verticalAlign: "middle",
    opacity: "0.7",
    transition: "opacity .15s",
    position: "relative",
    zIndex: "9999"
  });

  badge.addEventListener("mouseenter", () => { badge.style.opacity = "1"; });
  badge.addEventListener("mouseleave", () => { badge.style.opacity = "0.7"; });

  badge.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();

    if (SCAN_CACHE[href]) {
      showTooltip(badge, SCAN_CACHE[href]);
      return;
    }

    badge.textContent = "⏳";
    
    try {
      const res = await fetch(`${THREAT_BACKEND_URL}/scan-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: href })
      });
      
      const data = await res.json();
      const result = data.result || {};
      
      SCAN_CACHE[href] = result;

      const score = result.risk_score || 0;
      const colors = getRiskColors(score);
      
      if (score >= 70) {
        badge.textContent = "🚨";
      } else if (score >= 40) {
        badge.textContent = "⚠️";
      } else {
        badge.textContent = "✅";
      }
      
      badge.style.filter = `drop-shadow(0 0 4px ${colors.glow})`;

      showTooltip(badge, result);
      
    } catch (err) {
      badge.textContent = "⚠";
      showErrorToast("AgentHunt server not running (python server.py)");
    }
  });

  if (link.nextSibling) {
    link.parentNode.insertBefore(badge, link.nextSibling);
  } else {
    link.parentNode.appendChild(badge);
  }
}


function showTooltip(badgeEl, result) {
  document.querySelectorAll(".tg-tooltip").forEach(t => t.remove());

  const score = result.risk_score || 0;
  const colors = getRiskColors(score);
  const verdict = (result.verdict || "Unknown").toUpperCase();
  const flags = (result.flags || []).slice(0, 3);
  const ti = result.threat_intel || {};

  const tooltip = document.createElement("div");
  tooltip.className = "tg-tooltip";

  const flagsHtml = flags.length
    ? flags.map(f => `<div style="color:#ffcc80;font-size:.78rem;margin:2px 0">⚑ ${f}</div>`).join("")
    : '<div style="color:#66bb6a;font-size:.78rem"> No flags detected</div>';

  const tiHtml = ti.is_domain_blacklisted
    ? `<div style="color:#ef9a9a;font-size:.78rem;margin-top:4px">🚨 Domain blacklisted</div>`
    : ti.vt_detections > 0
    ? `<div style="color:#ffcc80;font-size:.78rem;margin-top:4px">⚠ VirusTotal: ${ti.vt_detections} detections</div>`
    : "";

  tooltip.innerHTML = `
    <div style="
      position:fixed;z-index:2147483647;
      background:#0d1b2a;border:1px solid ${colors.bg};
      border-radius:10px;padding:14px 16px;
      font-family:sans-serif;font-size:.85rem;
      color:#c8d8f0;width:290px;
      box-shadow:0 4px 24px ${colors.glow};">
      
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
        <span style="font-family:monospace;color:#4fc3f7;font-size:.8rem;letter-spacing:2px">AgentHunt</span>
        <button class="tg-tip-close" style="background:none;border:none;color:#7a9fc4;cursor:pointer;font-size:1rem">✕</button>
      </div>
      
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <div style="font-family:monospace;font-size:2rem;font-weight:700;color:${colors.bg};line-height:1">${score}</div>
        <div style="background:rgba(255,255,255,.05);border:1px solid ${colors.bg};border-radius:6px;
                    padding:6px 10px;font-weight:700;color:${colors.bg};font-size:.85rem;letter-spacing:1px">
          ${verdict}
        </div>
      </div>
      
      <div style="font-size:.8rem;color:#a0b4c8;margin-bottom:8px;word-break:break-all;
                  background:#0a1222;border-radius:4px;padding:4px 6px">
        ${result.url ? result.url.slice(0, 60) + (result.url.length > 60 ? "…" : "") : ""}
      </div>
      
      <div style="font-size:.8rem;color:#c8d8f0;line-height:1.5;margin-bottom:8px">
        ${result.reasoning || ""}
      </div>
      
      ${flagsHtml}
      
      ${tiHtml}
      
      <div style="color:#334e6e;font-size:.7rem;margin-top:10px;text-align:center">Click ✕ or outside to close</div>
    </div>
  `;

  document.body.appendChild(tooltip);

  const pos = badgeEl.getBoundingClientRect();
  const tipBox = tooltip.firstElementChild;
  
  let top = pos.bottom + window.scrollY + 6;
  let left = pos.left + window.scrollX;
  
  if (left + 290 > window.innerWidth) {
    left = window.innerWidth - 300;
  }
  
  tipBox.style.top = top + "px";
  tipBox.style.left = left + "px";

  tooltip.querySelector(".tg-tip-close").addEventListener("click", () => {
    tooltip.remove();
  });

  setTimeout(() => {
    document.addEventListener("click", function handler(e) {
      if (!tooltip.contains(e.target)) {
        tooltip.remove();
        document.removeEventListener("click", handler);
      }
    });
  }, 100);
}


function showErrorToast(msg) {
  const toast = document.createElement("div");
  toast.textContent = msg;
  
  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: "#1a2a4a",
    color: "#ef9a9a",
    border: "1px solid #ef5350",
    borderRadius: "8px",
    padding: "10px 16px",
    zIndex: "2147483647",
    fontFamily: "sans-serif",
    fontSize: ".85rem",
    boxShadow: "0 4px 16px rgba(0,0,0,.4)"
  });
  
  document.body.appendChild(toast);
  
  setTimeout(() => toast.remove(), 4000);
}


function scanAndBadgeAllLinks() {
  const allLinks = document.querySelectorAll("a[href]");
  allLinks.forEach(link => attachBadgeToLink(link));
}

scanAndBadgeAllLinks();

const linkObserver = new MutationObserver(() => {
  scanAndBadgeAllLinks();
});

linkObserver.observe(document.body, {
  childList: true,
  subtree: true
});