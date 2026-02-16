import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3000);

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Origin not allowed by CORS"));
    },
  }),
);
app.use(express.json({ limit: "1mb" }));

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

function calcRiskLabel(payload, existing) {
  const fpResult = payload.fpResult || {};
  const clientSignals = payload.clientSignals || {};
  const confidenceScore = Number(fpResult?.confidence?.score || 0);
  const isIncognito = toBool(fpResult.incognito);
  const isVpn = toBool(fpResult.vpn);
  const isProxy = toBool(fpResult.proxy);
  const isTor = toBool(fpResult.tor);
  const isBot = toBool(fpResult.bot);

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
  if (confidenceScore > 0 && confidenceScore < 0.8) {
    score += 10;
    reasons.push("low_confidence");
  }

  const lastIp = existing?.last_ip || null;
  const lastUserAgent = existing?.last_user_agent || null;
  const currentIp = fpResult?.ip || null;
  const currentUserAgent = clientSignals?.userAgent || null;

  if (existing) {
    if (lastIp && currentIp && lastIp !== currentIp) {
      score += 6;
      reasons.push("ip_changed_from_last_visit");
    }

    if (lastUserAgent && currentUserAgent && lastUserAgent !== currentUserAgent) {
      score += 8;
      reasons.push("user_agent_changed_from_last_visit");
    }

    if (existing?.risk_label === "high" || Number(existing?.risk_score || 0) >= 60) {
      score += 20;
      reasons.push("prior_high_risk_history");
    }
  }

  const noHardRiskFlags = !isBot && !isTor && !isVpn && !isProxy && !isIncognito;
  if (existing && confidenceScore >= 0.95 && noHardRiskFlags) {
    score = Math.max(0, score - 8);
    reasons.push("stable_returning_profile");
  }

  score = Math.max(0, Math.min(score, 100));

  const riskLabel = score >= 60 ? "high" : score >= 25 ? "medium" : "low";
  const isFraudSuspected = riskLabel === "high";
  const decision = isFraudSuspected ? "block_or_review" : riskLabel === "medium" ? "review" : "allow";
  return { riskScore: score, riskLabel, reasons, confidenceScore, isFraudSuspected, decision };
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "fingerprint-check-backend",
    supabaseConfigured: Boolean(supabase),
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

    if (!visitorId || typeof visitorId !== "string") {
      res.status(400).json({
        error: "Invalid payload",
        message: "fpResult.visitorId is required",
      });
      return;
    }

    const { data: existing, error: selectError } = await supabase
      .from("visitor_profiles")
      .select("visitor_id, visit_count, last_ip, last_user_agent, risk_label, risk_score")
      .eq("visitor_id", visitorId)
      .maybeSingle();

    if (selectError) {
      throw selectError;
    }

    const isNewUser = !existing;
    const nextCount = existing ? Number(existing.visit_count || 0) + 1 : 1;

    const { riskLabel, riskScore, reasons, confidenceScore, isFraudSuspected, decision } = calcRiskLabel(
      {
        fpResult,
        clientSignals,
      },
      existing,
    );

    const upsertRow = {
      visitor_id: visitorId,
      first_seen_at: existing ? undefined : new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      visit_count: nextCount,
      linked_id: fpResult?.linkedId || null,
      last_ip: fpResult?.ip || null,
      last_user_agent: clientSignals?.userAgent || null,
      risk_label: riskLabel,
      risk_score: riskScore,
      confidence_score: confidenceScore || null,
      last_request_id: fpResult?.requestId || null,
      updated_at: new Date().toISOString(),
      raw_fp_result: fpResult,
      raw_client_signals: clientSignals || {},
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
      visitorId,
      riskLabel,
      riskScore,
      isFraudSuspected,
      decision,
      reasons,
      visitCount: nextCount,
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
