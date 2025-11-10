import http from "k6/http";
import { check, sleep, group } from "k6";
import { Trend } from "k6/metrics";
import { randomString } from "https://jslib.k6.io/k6-utils/1.2.0/index.js";

http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

// const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:5000";
const BASE_URL = "https://backend-1055266214449.europe-west1.run.app";;


const TEST_VUS = Number(__ENV.TEST_VUS) || 10;
const TEST_DURATION = __ENV.TEST_DURATION || "20s";
const USER_PREFIX = __ENV.USER_PREFIX || "k6user";
const REGISTERED_USER_EMAIL = __ENV.REGISTERED_USER_EMAIL || ""; // optional: test against existing user
const REGISTERED_USER_PASSWORD = __ENV.REGISTERED_USER_PASSWORD || "password123"; // if using existing user
const SKIP_APPLY_IF_NO_JOBS = (__ENV.SKIP_APPLY_IF_NO_JOBS || "false") === "true";

// Custom metrics
const reqTrend = new Trend("req_duration_ms");

export let options = {
  vus: TEST_VUS,
  duration: TEST_DURATION,
  // you can override with stages in env by providing RAMP_STAGES as "10:30s,20:1m,5:30s" etc.
  // The script will switch to staged mode if RAMP_STAGES is provided.
  thresholds: {
    "http_req_duration": ["p(95)<1000"], // adjust to your SLA
  }
};

// if user provided stages string, convert and override options
if (__ENV.RAMP_STAGES) {
  // expected format "10:30s,50:1m,10:30s" -> vus:duration pairs
  const stages = __ENV.RAMP_STAGES.split(",").map(pair => {
    const [v,d] = pair.split(":");
    return { duration: d.trim(), target: Number(v.trim()) };
  });
  options = { ...options, stages };
}

// --- helper functions ---
function jsonHeaders(token) {
  const h = { "Content-Type": "application/json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

function randomEmail() {
  return `${USER_PREFIX}.${randomString(6)}@example.local`;
}

// Attempt to register a new user. If REGISTERED_USER_EMAIL is specified, skip register and use provided creds.
export function setup() {
  if (REGISTERED_USER_EMAIL) {
    // Use provided credentials (external user)
    const creds = { email: REGISTERED_USER_EMAIL, password: REGISTERED_USER_PASSWORD };
    const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify(creds), { headers: jsonHeaders() });
    if (loginRes.status !== 200) {
      console.error("Provided credential login failed:", loginRes.status, loginRes.body);
      return { token: null, jobId: null };
    }
    const token = loginRes.json("access_token");
    // get a job id if present
    const jobsRes = http.get(`${BASE_URL}/jobs?page=1&per_page=5`, { headers: jsonHeaders() });
    let jobId = null;
    if (jobsRes.status === 200) {
      const items = jobsRes.json("items");
      if (items && items.length > 0) jobId = items[0].id;
    }
    return { token, jobId };
  }

  // Register fresh user
  const email = randomEmail();
  const pw = "P@ssw0rd!k6";
  const regPayload = { email: email, password: pw, role: "user" };
  const regRes = http.post(`${BASE_URL}/auth/register`, JSON.stringify(regPayload), { headers: jsonHeaders() });

  if (regRes.status !== 201 && regRes.status !== 200) {
    // Could already exist or registration blocked; try login
    console.warn("Register returned", regRes.status, regRes.body);
    const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify({ email, password: pw }), { headers: jsonHeaders() });
    if (loginRes.status !== 200) {
      console.error("Register/login failed in setup; continuing without token.");
      return { token: null, jobId: null };
    }
    const token = loginRes.json("access_token");
    // find a job
    const jobsRes = http.get(`${BASE_URL}/jobs?page=1&per_page=5`, { headers: jsonHeaders() });
    let jobId = null;
    if (jobsRes.status === 200) {
      const items = jobsRes.json("items");
      if (items && items.length > 0) jobId = items[0].id;
    }
    return { token, jobId };
  }

  // registration success: extract tokens
  const token = regRes.json("access_token");
  const jobsRes = http.get(`${BASE_URL}/jobs?page=1&per_page=5`, { headers: jsonHeaders() });
  let jobId = null;
  if (jobsRes.status === 200) {
    const items = jobsRes.json("items");
    if (items && items.length > 0) jobId = items[0].id;
  }
  return { token, jobId };
}

export default function (data) {
  // data from setup(): token, jobId
  const token = data.token;
  const jobId = data.jobId;

  group("public endpoints", function () {
    let res = http.get(`${BASE_URL}/`, { headers: jsonHeaders() });
    reqTrend.add(res.timings.duration);
    check(res, { "root: status 200": (r) => r.status === 200 });

    res = http.get(`${BASE_URL}/about`, { headers: jsonHeaders() });
    reqTrend.add(res.timings.duration);
    check(res, { "about: status 200": (r) => r.status === 200 });

    res = http.get(`${BASE_URL}/jobs?page=1&per_page=10`, { headers: jsonHeaders() });
    reqTrend.add(res.timings.duration);
    check(res, { "jobs list: status 200": (r) => r.status === 200 });
  });

  group("job detail & optional apply", function () {
    // if we didn't get a jobId in setup(), attempt to fetch jobs now
    let localJobId = jobId;
    if (!localJobId) {
      const j = http.get(`${BASE_URL}/jobs?page=1&per_page=5`, { headers: jsonHeaders() });
      if (j.status === 200) {
        const items = j.json("items");
        if (items && items.length > 0) localJobId = items[0].id;
      }
    }

    if (localJobId) {
      const res = http.get(`${BASE_URL}/job/${localJobId}`, { headers: jsonHeaders() });
      reqTrend.add(res.timings.duration);
      check(res, { "job detail: 200": (r) => r.status === 200 });

      // attempt apply if we have auth token and not skipping
      if (token && !SKIP_APPLY_IF_NO_JOBS) {
        const applyPayload = { cover_letter: "k6 load test apply", resume_url: "https://example.local/resume.pdf" };
        const applyRes = http.post(`${BASE_URL}/job/${localJobId}/apply`, JSON.stringify(applyPayload), { headers: jsonHeaders(token) });
        reqTrend.add(applyRes.timings.duration);
        // 201 created or 409 duplicate if run many times; accept both as success
        check(applyRes, {
          "apply: status 201 or 409 or 200": (r) => r.status === 201 || r.status === 409 || r.status === 200
        });
      }
    } else {
      // no jobs available
      // optionally call /dev/create-admin to create data, but that mutates state and requires admin account
      // so we just record the fact
    }
  });

  group("auth flows (login refresh)", function () {
    if (token) {
      // call /me (optional=true)
      const me = http.get(`${BASE_URL}/me`, { headers: jsonHeaders(token) });
      reqTrend.add(me.timings.duration);
      check(me, { "me: ok": (r) => r.status === 200 });

      // try refresh: only if refresh token flow used in setup; but we didn't save refresh_token separately.
      // we'll skip refresh to avoid extra complexity.
    } else {
      // if no token present try a quick register/login cycle inline
      const email = randomEmail();
      const pw = "P@ssw0rd!k6";
      const r = http.post(`${BASE_URL}/auth/register`, JSON.stringify({ email, password: pw }), { headers: jsonHeaders() });
      reqTrend.add(r.timings.duration);
      check(r, { "inline register ok": (res) => res.status === 201 || res.status === 200 || res.status === 409 });

      const l = http.post(`${BASE_URL}/auth/login`, JSON.stringify({ email, password: pw }), { headers: jsonHeaders() });
      reqTrend.add(l.timings.duration);
      check(l, { "inline login ok": (res) => res.status === 200 });
    }
  });

  // polite pacing
  sleep(Math.random() * 2 + 0.5);
}
