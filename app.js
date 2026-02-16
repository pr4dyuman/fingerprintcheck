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
      return;
    }

    const userStatus = responseJson.isNewUser ? "NEW" : "RETURNING";
    const risk = responseJson.riskLabel || "unknown";
    setSummary(`Check complete: ${userStatus} user | risk: ${risk}`, "ok");
  } catch (error) {
    fpResultView.textContent = pretty({
      error: error.message,
    });
    responseView.textContent = pretty({
      error: error.message,
    });
    setSummary(`Failed to run check: ${error.message}`, "warn");
  } finally {
    runCheckButton.disabled = false;
  }
}

runCheckButton.addEventListener("click", runCheck);
