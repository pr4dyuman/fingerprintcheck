# FingerprintJS Pro Frontend (Render + Supabase flow)

## Setup order (do this first)

1. Configure Supabase and run [backend/supabase.sql](backend/supabase.sql).
2. Configure and deploy backend on Render.
3. Connect frontend to deployed backend URL.

This order avoids backend errors from missing tables/keys.

This frontend collects:
- FingerprintJS Pro `extendedResult`
- Browser/device signals (`userAgent`, timezone, screen, language, etc.)

Then sends everything to your backend endpoint (`/api/track-visitor`).

## 1) What this frontend does

The UI in [index.html](index.html) + [app.js](app.js):
1. Loads FingerprintJS Pro using your **public API key**.
2. Calls `fp.get({ extendedResult: true })`.
3. Adds extra client signals.
4. Sends a JSON payload to your backend.
5. Shows backend result (e.g., `isNewUser`, `riskLabel`, `riskScore`, `isFraudSuspected`).
6. Auto-runs check on page load when API key + backend URL are present.
7. Shows a prominent alert banner: fraud suspected / new user / returning user.

> Security: Keep your Supabase service role key and Fingerprint Server API key in backend only.

## 2) JavaScript integration (CDN, step-by-step)

This project now uses the Fingerprint CDN style from docs:
- agent script is loaded via `https://fpjscdn.net/v3/<public_api_key>`
- region is configured as `ap`

Implementation path:
1. Open [index.html](index.html) and confirm API key + region are set.
2. Open [app.js](app.js) and check `loadFingerprintAgent()` uses:
  - `import(https://fpjscdn.net/v3/<key>)`
  - `FingerprintJS.load({ region: "ap" })`
3. `runCheck()` calls `fp.get({ extendedResult: true })`.
4. Results are shown in UI:
  - summary panel
  - Fingerprint Signals panel
  - Fingerprint Raw Result panel

Important while testing:
- Disable ad blocker.
- Wait a few minutes after creating/changing API key for propagation.

## 3) Local run

Because the app uses ES modules, run a simple static server:

```powershell
cd d:\fingerprintjs
python -m http.server 5500
```

Open:
- `http://localhost:5500`

Run backend locally (new terminal):

```powershell
cd d:\fingerprintjs\backend
npm install
copy .env.example .env
npm run dev
```

API base URL (local):
- `http://localhost:3000`

If port 3000 is already in use:

```powershell
$env:PORT=3100
npm run dev
```

## 4) Verify it works

1. Click **Run check**.
2. Confirm `visitorId` appears in **Fingerprint Signals**.
3. Confirm **Fingerprint Raw Result** contains JSON with `visitorId` and `requestId`.
4. If you have backend running, confirm **Backend response** shows `isNewUser` and `riskLabel`.
5. Run check twice with same browser, second response should return `isNewUser: false` and increased `visitCount`.
6. If risky signals are present (bot/tor/vpn/proxy/incognito), verify **Live Decision** shows fraud alert and high score.

Troubleshooting:
- If blocked or empty result, disable ad blocker and try again.
- If key error appears, verify key and region (`ap`).
- If new key was just created, wait a few minutes and retest.

## 5) FingerprintJS Pro setup

1. Create FingerprintJS Pro account and project.
2. Copy your **Public API key** and paste it in UI.
3. Set region in UI (`us`, `eu`, `ap`) based on your Fingerprint project.

## 6) Backend you need next (Render)

Create endpoint: `POST /api/track-visitor`

Expected request body:
- `fpResult` (from Fingerprint)
- `clientSignals` (from browser)

Backend should:
1. Verify request shape.
2. Optionally call Fingerprint Server API using `requestId` for deeper checks.
3. Upsert in Supabase by `visitorId`.
4. Return JSON like:

```json
{
  "isNewUser": false,
  "riskLabel": "low",
  "reasons": ["known_visitor", "stable_device"]
}
```

This repo already includes a ready backend in [backend/server.js](backend/server.js).

## 7) Supabase table (example)

Use SQL from [backend/supabase.sql](backend/supabase.sql) in Supabase SQL editor.

Upsert logic:
- if new `visitor_id`: insert with `visit_count = 1`
- if existing: update `last_seen_at`, increment `visit_count`

## 8) Deployment suggestion

- Frontend: Vercel (simple static hosting)
- Backend API: Render web service
- DB: Supabase

This split is usually easiest and stable for your use case.

Render deploy steps for backend:
1. Push this repo to GitHub.
2. In Render, create **Web Service** from repo.
3. Set Root Directory to `backend` (or use [backend/render.yaml](backend/render.yaml)).
4. Add env vars:
  - `SUPABASE_URL`
  - `SUPABASE_SERVICE_ROLE_KEY`
  - `ALLOWED_ORIGINS` (your frontend URL)
  - (optional) `FINGERPRINT_SERVER_API_KEY`
5. Deploy and test `GET /health`.
6. Put deployed URL in frontend Backend endpoint field.

## 9) Legal/compliance

Before collecting fingerprint data:
- Add privacy policy disclosure.
- Add consent where required by local law (GDPR/ePrivacy etc.).
- Define retention period for fingerprint-related records.

## 10) Security checklist

- Rotate any previously exposed DB passwords or service keys.
- Never put `SUPABASE_SERVICE_ROLE_KEY` in frontend.
- Keep only Fingerprint public key in frontend; keep server key in backend env.
