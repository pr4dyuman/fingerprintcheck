const apiKeyInput = document.getElementById("apiKey");
const regionInput = document.getElementById("region");
const backendUrlInput = document.getElementById("backendUrl");
const linkedIdInput = document.getElementById("linkedId");
const runCheckButton = document.getElementById("runCheck");

const summary = document.getElementById("summary");
const signalList = document.getElementById("signalList");
const fpResultView = document.getElementById("fpResultView");
const payloadView = document.getElementById("payloadView");
const responseView = document.getElementById("responseView");
const riskAlert = document.getElementById("riskAlert");
const riskScoreView = document.getElementById("riskScore");
const userStatusView = document.getElementById("userStatus");
const decisionStatusView = document.getElementById("decisionStatus");

const STORAGE_KEYS = {
  apiKey: "fp_api_key",
  region: "fp_region",
  backendUrl: "fp_backend_url",
  linkedId: "fp_linked_id",
};

const pretty = (value) => JSON.stringify(value, null, 2);

function getClientSignals() {
  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    languages: navigator.languages,
    platform: navigator.userAgentData?.platform || navigator.platform,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: {
      width: window.screen.width,
      height: window.screen.height,
      pixelRatio: window.devicePixelRatio,
    },
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    timestamp: new Date().toISOString(),
  };
}

function setSummary(text, status = "neutral") {
  summary.textContent = text;
  summary.style.borderColor =
    status === "ok" ? "#14532d" : status === "warn" ? "#78350f" : "#334155";
}

function setRiskAlert(level, text) {
  riskAlert.className = "risk-alert";
  if (level === "high") {
    riskAlert.classList.add("risk-high");
  } else if (level === "medium") {
    riskAlert.classList.add("risk-medium");
  } else if (level === "low") {
    riskAlert.classList.add("risk-low");
  } else {
    riskAlert.classList.add("risk-neutral");
  }
  riskAlert.textContent = text;
}

function updateDecisionMetrics(responseJson) {
  const score = Number(responseJson?.riskScore);
  const scoreText = Number.isFinite(score) ? String(score) : "-";
  const userStatus = responseJson?.isNewUser ? "NEW USER" : "RETURNING";
  const decision = responseJson?.decision || "-";

  riskScoreView.textContent = scoreText;
  userStatusView.textContent = responseJson?.ok ? userStatus : "-";
  decisionStatusView.textContent = responseJson?.ok ? decision.toUpperCase() : "-";
}

function renderBackendDecision(responseJson) {
  updateDecisionMetrics(responseJson);

  if (!responseJson?.ok) {
    setRiskAlert("neutral", "No backend decision yet.");
    return;
  }

  const reasons = Array.isArray(responseJson.reasons) ? responseJson.reasons : [];
  const reasonText = reasons.length ? ` | reasons: ${reasons.join(", ")}` : "";

  if (responseJson.isFraudSuspected) {
    setRiskAlert(
      "high",
      `ALERT: Fraud suspected. Decision: ${responseJson.decision}.${reasonText}`,
    );
    return;
  }

  if (responseJson.isNewUser) {
    setRiskAlert("medium", `New user detected. Decision: ${responseJson.decision}.${reasonText}`);
    return;
  }

  setRiskAlert("low", `Returning user recognized. Decision: ${responseJson.decision}.${reasonText}`);
}

function persistSettings() {
  localStorage.setItem(STORAGE_KEYS.apiKey, apiKeyInput.value.trim());
  localStorage.setItem(STORAGE_KEYS.region, regionInput.value);
  localStorage.setItem(STORAGE_KEYS.backendUrl, backendUrlInput.value.trim());
  localStorage.setItem(STORAGE_KEYS.linkedId, linkedIdInput.value.trim());
}

function loadSettings() {
  const apiKey = localStorage.getItem(STORAGE_KEYS.apiKey);
  const region = localStorage.getItem(STORAGE_KEYS.region);
  const backendUrl = localStorage.getItem(STORAGE_KEYS.backendUrl);
  const linkedId = localStorage.getItem(STORAGE_KEYS.linkedId);

  if (apiKey) {
    apiKeyInput.value = apiKey;
  }
  if (region) {
    regionInput.value = region;
  }
  if (backendUrl) {
    backendUrlInput.value = backendUrl;
  }
  if (linkedId) {
    linkedIdInput.value = linkedId;
  }
}

function toText(value) {
  if (value === undefined || value === null || value === "") {
    return "unknown";
  }
  if (typeof value === "boolean") {
    return value ? "yes" : "no";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function getFlag(fpResult, keyCandidates) {
  for (const key of keyCandidates) {
    if (fpResult && Object.prototype.hasOwnProperty.call(fpResult, key)) {
      return fpResult[key];
    }
  }
  return undefined;
}

function renderSignals(fpResult) {
  const items = [
    ["Visitor ID", fpResult?.visitorId],
    ["Request ID", fpResult?.requestId],
    ["Confidence", fpResult?.confidence?.score],
    ["Incognito", getFlag(fpResult, ["incognito", "incognitoMode"])],
    ["VPN", getFlag(fpResult, ["vpn", "isVPN"])],
    ["Proxy", getFlag(fpResult, ["proxy", "isProxy"])],
    ["Tor", getFlag(fpResult, ["tor", "isTor"])],
    ["Bot", getFlag(fpResult, ["bot", "isBot"])],
    ["Browser", fpResult?.browserName],
    ["OS", fpResult?.os],
    ["IP", fpResult?.ip],
    ["Country", fpResult?.ipLocation?.country?.name],
  ];

  signalList.innerHTML = items
    .map(
      ([label, value]) =>
        `<div class="signal-item"><span class="signal-key">${label}:</span><span>${toText(value)}</span></div>`,
    )
    .join("");
}

async function loadFingerprintAgent(apiKey, region) {
  const FingerprintJS = await import(`https://fpjscdn.net/v3/${encodeURIComponent(apiKey)}`);
  return FingerprintJS.load({ region });
}

async function runCheck() {
  const apiKey = apiKeyInput.value.trim();
  const region = regionInput.value;
  const backendUrl = backendUrlInput.value.trim();
  const linkedId = linkedIdInput.value.trim();

  persistSettings();

  if (!apiKey) {
    setSummary("Enter your FingerprintJS Pro API key first.", "warn");
    return;
  }

  runCheckButton.disabled = true;
  setSummary("Running FingerprintJS Pro check...");

  try {
    const fp = await loadFingerprintAgent(apiKey, region);

    const fpResult = await fp.get({
      extendedResult: true,
      linkedId: linkedId || undefined,
      tag: {
        source: "manual-check-ui",
      },
    });

    fpResultView.textContent = pretty(fpResult);
    renderSignals(fpResult);

    const payload = {
      fpResult,
      clientSignals: getClientSignals(),
    };

    payloadView.textContent = pretty(payload);

    if (!backendUrl) {
      setSummary("Fingerprint check complete. Add backend URL to save and score risk.", "ok");
      responseView.textContent = pretty({
        info: "No backend URL provided. Only frontend result is shown.",
      });
      renderBackendDecision({ ok: false });
      return;
    }

    const response = await fetch(backendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const responseJson = await response.json();
    responseView.textContent = pretty(responseJson);

    if (!response.ok) {
      setSummary(`Backend returned ${response.status}. Check response below.`, "warn");
      renderBackendDecision({ ok: false });
      return;
    }

    const userStatus = responseJson.isNewUser ? "NEW" : "RETURNING";
    const risk = responseJson.riskLabel || "unknown";
    setSummary(`Check complete: ${userStatus} user | risk: ${risk}`, "ok");
    renderBackendDecision(responseJson);
  } catch (error) {
    fpResultView.textContent = pretty({
      error: error.message,
    });
    responseView.textContent = pretty({
      error: error.message,
    });
    setSummary(`Failed to run check: ${error.message}`, "warn");
    renderBackendDecision({ ok: false });
  } finally {
    runCheckButton.disabled = false;
  }
}

runCheckButton.addEventListener("click", runCheck);

apiKeyInput.addEventListener("change", persistSettings);
regionInput.addEventListener("change", persistSettings);
backendUrlInput.addEventListener("change", persistSettings);
linkedIdInput.addEventListener("change", persistSettings);

loadSettings();

if (apiKeyInput.value.trim() && backendUrlInput.value.trim()) {
  setSummary("Auto-checking this visit...");
  runCheck();
}
