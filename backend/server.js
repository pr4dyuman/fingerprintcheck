import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import path from "path";
import { fileURLToPath } from "url";
import { existsSync } from "fs";

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3000);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendRoot = path.resolve(__dirname, "..");
const frontendIndexPath = path.join(frontendRoot, "index.html");
const hasFrontendAssets = existsSync(frontendIndexPath);

function normalizeOrigin(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\/+$/, "");
}

const configuredOrigins = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((item) => normalizeOrigin(item))
  .filter(Boolean);

const renderExternalUrl = normalizeOrigin(process.env.RENDER_EXTERNAL_URL);
if (renderExternalUrl && !configuredOrigins.includes(renderExternalUrl)) {
  configuredOrigins.push(renderExternalUrl);
}

const allowAllOrigins = configuredOrigins.includes("*");
const allowedOrigins = new Set(configuredOrigins.filter((origin) => origin !== "*"));
const PROFILE_MATCH_THRESHOLD = 70;
const RECENT_PROFILE_LOOKUP_LIMIT = 300;
const fingerprintPublicApiKey = process.env.FINGERPRINT_PUBLIC_API_KEY || "";
const fingerprintRegion = process.env.FINGERPRINT_REGION || "ap";
const fingerprintServerApiKey = process.env.FINGERPRINT_SERVER_API_KEY || "";
const returnRawFpResult = String(process.env.RETURN_RAW_FP_RESULT || "").toLowerCase() === "true";

const REGION_API_BASE = {
  us: "https://api.fpjs.io",
  eu: "https://eu.api.fpjs.io",
  ap: "https://ap.api.fpjs.io",
};

async function fetchServerEvent(requestId) {
  if (!fingerprintServerApiKey) {
    return { error: "FINGERPRINT_SERVER_API_KEY not set" };
  }
  const base = REGION_API_BASE[fingerprintRegion] || REGION_API_BASE.us;
  const url = `${base}/events/${encodeURIComponent(requestId)}`;
  try {
    const resp = await fetch(url, {
      headers: { "Auth-API-Key": fingerprintServerApiKey },
    });
    if (!resp.ok) {
      const text = await resp.text();
      return { error: `Server API ${resp.status}`, detail: text };
    }
    return await resp.json();
  } catch (err) {
    return { error: err.message };
  }
}

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowAllOrigins) {
        callback(null, true);
        return;
      }

      const normalizedRequestOrigin = normalizeOrigin(origin);
      if (allowedOrigins.has(normalizedRequestOrigin)) {
        callback(null, true);
        return;
      }

      callback(null, false);
    },
  }),
);
app.use(express.json({ limit: "1mb" }));

if (hasFrontendAssets) {
  app.use(express.static(frontendRoot));
}

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase =
  supabaseUrl && supabaseServiceRoleKey
    ? createClient(supabaseUrl, supabaseServiceRoleKey, {
        auth: { persistSession: false },
      })
    : null;

const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
if (hasDatabaseUrl && !supabase) {
  console.warn(
    "DATABASE_URL is set, but this service uses SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY by default.",
  );
}

if (!supabase) {
  console.warn("Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.");
}

function toBool(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (value && typeof value === "object") {
    if (typeof value.result === "boolean") {
      return value.result;
    }
    if (typeof value.value === "boolean") {
      return value.value;
    }
  }
  return false;
}

function calcSignalMatchScore(currentSignals, storedSignals, currentIp, storedIp, currentUserAgent, storedUserAgent) {
  let score = 0;

  const currentScreen = currentSignals?.screen || {};
  const storedScreen = storedSignals?.screen || {};

  if (currentUserAgent && storedUserAgent && currentUserAgent === storedUserAgent) {
    score += 40;
  }
  if (currentSignals?.platform && storedSignals?.platform && currentSignals.platform === storedSignals.platform) {
    score += 10;
  }
  if (currentSignals?.language && storedSignals?.language && currentSignals.language === storedSignals.language) {
    score += 8;
  }
  if (currentSignals?.timezone && storedSignals?.timezone && currentSignals.timezone === storedSignals.timezone) {
    score += 12;
  }
  if (currentScreen?.width && storedScreen?.width && currentScreen.width === storedScreen.width) {
    score += 8;
  }
  if (currentScreen?.height && storedScreen?.height && currentScreen.height === storedScreen.height) {
    score += 8;
  }
  if (
    currentSignals?.hardwareConcurrency &&
    storedSignals?.hardwareConcurrency &&
    currentSignals.hardwareConcurrency === storedSignals.hardwareConcurrency
  ) {
    score += 7;
  }
  if (currentSignals?.deviceMemory && storedSignals?.deviceMemory && currentSignals.deviceMemory === storedSignals.deviceMemory) {
    score += 7;
  }
  if (currentIp && storedIp && currentIp === storedIp) {
    score += 15;
  }

  return Math.min(100, score);
}

function extractSmartSignals(serverEvent) {
  if (!serverEvent || serverEvent.error) return {};
  const p = serverEvent.products || {};
  return {
    vpn: p.vpn?.data,
    proxy: p.proxy?.data,
    tor: p.tor?.data,
    ipBlocklist: p.ipBlocklist?.data,
    bot: p.botd?.data?.bot,
    tampering: p.tampering?.data,
    virtualMachine: p.virtualMachine?.data,
    highActivity: p.highActivity?.data,
    locationSpoofing: p.locationSpoofing?.data,
    suspectScore: p.suspectScore?.data,
    remoteControl: p.remoteControl?.data,
    velocity: p.velocity?.data,
    developerTools: p.developerTools?.data,
    rawDeviceAttributes: p.rawDeviceAttributes?.data,
    clonedApp: p.clonedApp?.data,
    factoryReset: p.factoryReset?.data,
    jailbroken: p.jailbroken?.data,
    frida: p.frida?.data,
    privacySettings: p.privacySettings?.data,
    ipInfo: p.ipInfo?.data,
    identification: p.identification?.data,
  };
}

function calcRiskLabel(payload, existing, context = {}) {
  const fpResult = payload.fpResult || {};
  const smart = payload.smartSignals || {};
  const clientSignals = payload.clientSignals || {};
  const confidenceScore = Number(fpResult?.confidence?.score || 0);
  const isIncognito = toBool(fpResult.incognito);
  const isVpn = toBool(smart.vpn?.result ?? fpResult.vpn);
  const isProxy = toBool(smart.proxy?.result ?? fpResult.proxy);
  const isTor = toBool(smart.tor?.result ?? fpResult.tor);
  const isBot = toBool(smart.bot?.result ?? fpResult.bot);

  let score = 0;
  const reasons = [];

  if (isBot) {
    score += 55;
    reasons.push("bot_detected");
  }
  if (isTor) {
    score += 35;
    reasons.push("tor_detected");
  }
  if (isVpn) {
    score += 20;
    reasons.push("vpn_detected");
  }
  if (isProxy) {
    score += 15;
    reasons.push("proxy_detected");
  }
  if (isIncognito) {
    score += 10;
    reasons.push("incognito_mode");
  }

  // Smart Signal: tampering
  if (toBool(smart.tampering?.result)) {
    score += 25;
    reasons.push("tampering_detected");
  }
  // Smart Signal: virtual machine
  if (toBool(smart.virtualMachine?.result)) {
    score += 20;
    reasons.push("virtual_machine_detected");
  }
  // Smart Signal: high activity device
  if (smart.highActivity?.result === true || Number(smart.highActivity?.dailyRequests) > 100) {
    score += 20;
    reasons.push("high_activity_device");
  }
  // Smart Signal: location spoofing
  if (toBool(smart.locationSpoofing?.result)) {
    score += 20;
    reasons.push("location_spoofing_detected");
  }
  // Smart Signal: remote control
  if (toBool(smart.remoteControl?.result)) {
    score += 25;
    reasons.push("remote_control_detected");
  }
  // Smart Signal: suspect score
  if (Number(smart.suspectScore?.result) >= 50) {
    score += 20;
    reasons.push("high_suspect_score");
  }
  // Smart Signal: developer tools open
  if (toBool(smart.developerTools?.result)) {
    score += 5;
    reasons.push("developer_tools_open");
  }
  // Smart Signal: IP blocklist
  if (toBool(smart.ipBlocklist?.result)) {
    score += 25;
    reasons.push("ip_blocklist");
  }
  // Smart Signal: jailbroken/rooted
  if (toBool(smart.jailbroken?.result)) {
    score += 20;
    reasons.push("jailbroken_device");
  }
  // Smart Signal: frida instrumentation
  if (toBool(smart.frida?.result)) {
    score += 30;
    reasons.push("frida_detected");
  }
  // Smart Signal: cloned app
  if (toBool(smart.clonedApp?.result)) {
    score += 25;
    reasons.push("cloned_app_detected");
  }
  // Smart Signal: factory reset
  if (smart.factoryReset?.timestamp) {
    const daysSinceReset = (Date.now() - new Date(smart.factoryReset.timestamp).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceReset < 7) {
      score += 15;
      reasons.push("recent_factory_reset");
    }
  }

  if (confidenceScore > 0 && confidenceScore < 0.9) {
    score += 15;
    reasons.push("low_confidence");
  }
  if (confidenceScore > 0 && confidenceScore < 0.75) {
    score += 15;
    reasons.push("very_low_confidence");
  }

  if (existing) {
    score += 35;
    reasons.push("previously_seen_profile");
  }

  if (context?.matchedBy && context.matchedBy !== "visitor_id") {
    score += 18;
    reasons.push(`matched_by_${context.matchedBy}`);
  }

  if (Number(context?.sameIpRecentCount || 0) >= 3) {
    score += 25;
    reasons.push("ip_velocity_high");
  } else if (Number(context?.sameIpRecentCount || 0) >= 2) {
    score += 12;
    reasons.push("ip_velocity_medium");
  }

  const lastIp = existing?.last_ip || null;
  const lastUserAgent = existing?.last_user_agent || null;
  const currentIp = fpResult?.ip || null;
  const currentUserAgent = clientSignals?.userAgent || null;

  if (existing) {
    if (lastIp && currentIp && lastIp !== currentIp) {
      score += 10;
      reasons.push("ip_changed_from_last_visit");
    }

    if (lastUserAgent && currentUserAgent && lastUserAgent !== currentUserAgent) {
      score += 12;
      reasons.push("user_agent_changed_from_last_visit");
    }

    if (existing?.risk_label === "high" || Number(existing?.risk_score || 0) >= 60) {
      score += 20;
      reasons.push("prior_high_risk_history");
    }
  }

  const noHardRiskFlags = !isBot && !isTor && !isVpn && !isProxy && !isIncognito;
  if (existing && confidenceScore >= 0.98 && noHardRiskFlags && Number(context?.sameIpRecentCount || 0) <= 1) {
    score = Math.max(0, score - 5);
    reasons.push("stable_returning_profile");
  }

  score = Math.max(0, Math.min(score, 100));

  const riskLabel = score >= 45 ? "high" : score >= 20 ? "medium" : "low";
  const isFraudSuspected = riskLabel === "high";
  const isReferralEligible = !existing && riskLabel === "low";
  const decision = isReferralEligible ? "allow" : isFraudSuspected ? "deny_referral" : "review";
  const legitimacyScore = Math.max(0, 100 - score);

  return {
    riskScore: score,
    legitimacyScore,
    riskLabel,
    reasons,
    confidenceScore,
    isFraudSuspected,
    decision,
    isReferralEligible,
  };
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "fingerprint-check-backend",
    supabaseConfigured: Boolean(supabase),
    fingerprintConfigPresent: Boolean(fingerprintPublicApiKey),
  });
});

app.get("/api/public-config", (_req, res) => {
  res.json({
    ok: true,
    fingerprintPublicApiKey,
    fingerprintRegion,
  });
});

app.get("/", (_req, res) => {
  if (hasFrontendAssets) {
    res.sendFile(frontendIndexPath);
    return;
  }

  res.json({
    ok: true,
    service: "fingerprint-check-backend",
    message: "Backend is running",
    endpoints: {
      health: "/health",
      trackVisitor: "/api/track-visitor",
    },
  });
});

app.post("/api/track-visitor", async (req, res) => {
  try {
    if (!supabase) {
      res.status(500).json({
        error: "Supabase is not configured",
        message: "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY",
      });
      return;
    }

    const { fpResult, clientSignals } = req.body || {};
    const visitorId = fpResult?.visitorId;
    const linkedId = fpResult?.linkedId || null;
    const currentIp = fpResult?.ip || null;
    const currentUserAgent = clientSignals?.userAgent || null;

    if (!visitorId || typeof visitorId !== "string") {
      res.status(400).json({
        error: "Invalid payload",
        message: "fpResult.visitorId is required",
      });
      return;
    }

    let matchedBy = "visitor_id";

    const { data: byVisitor, error: selectError } = await supabase
      .from("visitor_profiles")
      .select("visitor_id, visit_count, last_ip, last_user_agent, risk_label, risk_score, linked_id, raw_client_signals")
      .eq("visitor_id", visitorId)
      .maybeSingle();

    if (selectError) {
      throw selectError;
    }

    let existing = byVisitor;

    if (!existing && linkedId) {
      const { data: byLinkedId, error: linkedError } = await supabase
        .from("visitor_profiles")
        .select("visitor_id, visit_count, last_ip, last_user_agent, risk_label, risk_score, linked_id, raw_client_signals")
        .eq("linked_id", linkedId)
        .order("last_seen_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (linkedError) {
        throw linkedError;
      }

      if (byLinkedId) {
        existing = byLinkedId;
        matchedBy = "linked_id";
      }
    }

    if (!existing) {
      const { data: recentProfiles, error: recentError } = await supabase
        .from("visitor_profiles")
        .select("visitor_id, visit_count, last_ip, last_user_agent, risk_label, risk_score, linked_id, raw_client_signals")
        .order("last_seen_at", { ascending: false })
        .limit(RECENT_PROFILE_LOOKUP_LIMIT);

      if (recentError) {
        throw recentError;
      }

      let bestMatch = null;
      let bestScore = 0;

      for (const row of recentProfiles || []) {
        const rowSignals = row?.raw_client_signals || {};
        const score = calcSignalMatchScore(
          clientSignals,
          rowSignals,
          currentIp,
          row?.last_ip || null,
          currentUserAgent,
          row?.last_user_agent || null,
        );

        if (score > bestScore) {
          bestScore = score;
          bestMatch = row;
        }
      }

      if (bestMatch && bestScore >= PROFILE_MATCH_THRESHOLD) {
        existing = bestMatch;
        matchedBy = `signal_similarity_${bestScore}`;
      }
    }

    let sameIpRecentCount = 0;
    if (currentIp) {
      const sinceIso = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const { count, error: countError } = await supabase
        .from("visitor_profiles")
        .select("visitor_id", { count: "exact", head: true })
        .eq("last_ip", currentIp)
        .gte("last_seen_at", sinceIso);

      if (countError) {
        throw countError;
      }

      sameIpRecentCount = Number(count || 0);
    }

    const isNewUser = !existing;
    const nextCount = existing ? Number(existing.visit_count || 0) + 1 : 1;
    const storageVisitorId = existing ? existing.visitor_id : visitorId;

    // Fetch full Smart Signals from Fingerprint Server API
    let serverEvent = {};
    let smartSignals = {};
    if (fingerprintServerApiKey && fpResult?.requestId) {
      serverEvent = await fetchServerEvent(fpResult.requestId);
      smartSignals = extractSmartSignals(serverEvent);
    }

    const {
      riskLabel,
      riskScore,
      legitimacyScore,
      reasons,
      confidenceScore,
      isFraudSuspected,
      decision,
      isReferralEligible,
    } = calcRiskLabel(
      {
        fpResult,
        clientSignals,
        smartSignals,
      },
      existing,
      {
        matchedBy,
        sameIpRecentCount,
      },
    );

    const upsertRow = {
      visitor_id: storageVisitorId,
      first_seen_at: existing ? undefined : new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      visit_count: nextCount,
      linked_id: linkedId,
      last_ip: currentIp,
      last_user_agent: clientSignals?.userAgent || null,
      risk_label: riskLabel,
      risk_score: riskScore,
      confidence_score: confidenceScore || null,
      last_request_id: fpResult?.requestId || null,
      updated_at: new Date().toISOString(),
      raw_fp_result: fpResult,
      raw_client_signals: clientSignals || {},
      raw_server_event: serverEvent || {},
    };

    const { error: upsertError } = await supabase.from("visitor_profiles").upsert(upsertRow, {
      onConflict: "visitor_id",
    });

    if (upsertError) {
      throw upsertError;
    }

    res.json({
      ok: true,
      isNewUser,
      visitorId: storageVisitorId,
      detectedVisitorId: visitorId,
      matchedBy,
      riskLabel,
      riskScore,
      legitimacyScore,
      isFraudSuspected,
      decision,
      isReferralEligible,
      reasons,
      visitCount: nextCount,
      smartSignals: Object.keys(smartSignals).length ? smartSignals : undefined,
      serverEvent: returnRawFpResult ? serverEvent : undefined,
      rawFpResult: returnRawFpResult ? fpResult : undefined,
    });
  } catch (error) {
    res.status(500).json({
      error: "Internal server error",
      message: error.message,
    });
  }
});

app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});
