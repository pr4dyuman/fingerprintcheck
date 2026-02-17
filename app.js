const apiKeyInput = document.getElementById("apiKey");
const regionInput = document.getElementById("region");
const backendUrlInput = document.getElementById("backendUrl");
const linkedIdInput = document.getElementById("linkedId");
const runCheckButton = document.getElementById("runCheck");
const runCheckLabel = document.getElementById("runCheckLabel");
const configStatus = document.getElementById("configStatus");

const summary = document.getElementById("summary");
const signalList = document.getElementById("signalList");
const fpResultView = document.getElementById("fpResultView");
const payloadView = document.getElementById("payloadView");
const responseView = document.getElementById("responseView");
const backendFpResultView = document.getElementById("backendFpResultView");
const riskAlert = document.getElementById("riskAlert");
const isNewUserView = document.getElementById("isNewUser");
const isLegitUserView = document.getElementById("isLegitUser");
const legitimacyScoreView = document.getElementById("legitimacyScore");
const riskScoreView = document.getElementById("riskScore");

const STORAGE_KEYS = {
  region: "fp_region",
  backendUrl: "fp_backend_url",
  linkedId: "fp_linked_id",
};

const OPERATION_TIMEOUT_MS = 15000;

const pretty = (value) => JSON.stringify(value, null, 2);

function setConfigStatus(text, status = "neutral") {
  configStatus.textContent = text;
  configStatus.className = `config-status config-status-${status}`;
}

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

function setLoadingState(isLoading) {
  runCheckButton.disabled = isLoading;
  runCheckButton.classList.toggle("is-loading", isLoading);
  runCheckLabel.textContent = isLoading ? "Checking..." : "Run check";
}

async function withTimeout(promise, label) {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`${label} timed out after ${OPERATION_TIMEOUT_MS / 1000}s`));
    }, OPERATION_TIMEOUT_MS);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    clearTimeout(timeoutId);
  }
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
  if (!responseJson?.ok) {
    isNewUserView.textContent = "-";
    isLegitUserView.textContent = "-";
    legitimacyScoreView.textContent = "-";
    riskScoreView.textContent = "-";
    return;
  }

  const riskScore = Number(responseJson?.riskScore);
  const safeRisk = Number.isFinite(riskScore) ? Math.max(0, Math.min(riskScore, 100)) : 100;
  const legitimacyScore = Math.max(0, 100 - safeRisk);
  const isNewUser = Boolean(responseJson?.isNewUser);
  const isLegitUser = !Boolean(responseJson?.isFraudSuspected) && responseJson?.decision === "allow";

  isNewUserView.textContent = isNewUser ? "YES" : "NO";
  isLegitUserView.textContent = isLegitUser ? "YES" : "NO";
  legitimacyScoreView.textContent = `${legitimacyScore}/100`;
  riskScoreView.textContent = `${safeRisk}/100`;
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
      `ALERT: Fraud suspected. Is legit: NO.${reasonText}`,
    );
    return;
  }

  if (responseJson.isNewUser) {
    setRiskAlert("medium", `New user detected. Verify once. Is legit: review.${reasonText}`);
    return;
  }

  setRiskAlert("low", `Returning user recognized. Is legit: YES.${reasonText}`);
}

function persistSettings() {
  localStorage.setItem(STORAGE_KEYS.region, regionInput.value);
  localStorage.setItem(STORAGE_KEYS.backendUrl, backendUrlInput.value.trim());
  localStorage.setItem(STORAGE_KEYS.linkedId, linkedIdInput.value.trim());
}

function loadSettings() {
  const region = localStorage.getItem(STORAGE_KEYS.region);
  const backendUrl = localStorage.getItem(STORAGE_KEYS.backendUrl);
  const linkedId = localStorage.getItem(STORAGE_KEYS.linkedId);

  if (region) {
    regionInput.value = region;
  }
  if (backendUrl) {
    backendUrlInput.value = backendUrl;
  } else {
    backendUrlInput.value = `${window.location.origin}/api/track-visitor`;
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

async function loadBackendPublicConfig() {
  try {
    const response = await fetch(`${window.location.origin}/api/public-config`);
    if (!response.ok) {
      setConfigStatus("Could not load server config. Enter backend URL and check deployment env.", "warn");
      return;
    }

    const configJson = await response.json();
    const apiKey = String(configJson?.fingerprintPublicApiKey || "").trim();
    const region = String(configJson?.fingerprintRegion || "").trim();

    if (apiKey) {
      apiKeyInput.value = apiKey;
      setConfigStatus("Fingerprint public key loaded from backend environment.", "ok");
    } else {
      setConfigStatus("Missing FINGERPRINT_PUBLIC_API_KEY in backend env.", "warn");
    }

    if (region) {
      regionInput.value = region;
    }
  } catch {
    setConfigStatus("Could not fetch backend config. Check API URL and CORS settings.", "warn");
  }
}

async function runCheck() {
  if (runCheckButton.disabled) {
    return;
  }

  const apiKey = apiKeyInput.value.trim();
  const region = regionInput.value;
  const backendUrl = backendUrlInput.value.trim();
  const linkedId = linkedIdInput.value.trim();

  persistSettings();

  if (!apiKey) {
    setSummary("Fingerprint key not loaded. Set FINGERPRINT_PUBLIC_API_KEY in backend env.", "warn");
    return;
  }

  setLoadingState(true);
  setSummary("Running FingerprintJS Pro check...");

  try {
    const fp = await withTimeout(loadFingerprintAgent(apiKey, region), "Fingerprint agent load");

    const fpResult = await withTimeout(
      fp.get({
        extendedResult: true,
        linkedId: linkedId || undefined,
        tag: {
          source: "manual-check-ui",
        },
      }),
      "Fingerprint identify request",
    );

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
      if (backendFpResultView) {
        backendFpResultView.textContent = pretty({
          info: "No backend response. Enable backend URL to see stored JSON.",
        });
      }
      renderBackendDecision({ ok: false });
      return;
    }

    const abortController = new AbortController();
    const abortTimer = setTimeout(() => abortController.abort(), OPERATION_TIMEOUT_MS);
    let response;

    try {
      response = await fetch(backendUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
        signal: abortController.signal,
      });
    } finally {
      clearTimeout(abortTimer);
    }

    const responseJson = await response.json();
    responseView.textContent = pretty(responseJson);

    if (backendFpResultView) {
      backendFpResultView.textContent = pretty(
        responseJson?.rawFpResult || {
          info: "rawFpResult not included. Set RETURN_RAW_FP_RESULT=true on the backend.",
        },
      );
    }

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
    if (backendFpResultView) {
      backendFpResultView.textContent = pretty({
        error: error.message,
      });
    }
    setSummary(`Failed to run check: ${error.message}`, "warn");
    renderBackendDecision({ ok: false });
  } finally {
    setLoadingState(false);
  }
}

runCheckButton.addEventListener("click", runCheck);

apiKeyInput.addEventListener("change", persistSettings);
regionInput.addEventListener("change", persistSettings);
backendUrlInput.addEventListener("change", persistSettings);
linkedIdInput.addEventListener("change", persistSettings);

loadSettings();
loadBackendPublicConfig();
