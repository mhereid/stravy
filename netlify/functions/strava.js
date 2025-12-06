const crypto = require("crypto");

const STRAVA_AUTH_URL = "https://www.strava.com/oauth/authorize";
const STRAVA_TOKEN_URL = "https://www.strava.com/oauth/token";
const STRAVA_API_BASE = "https://www.strava.com/api/v3";
const COOKIE_NAME = "strava_session";

// ---------- helpers: cookies & sessions ----------

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    out[key] = val;
  });
  return out;
}

function b64urlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64").toString();
}

function signSession(payload) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    throw new Error("SESSION_SECRET is not set");
  }
  const data = b64urlEncode(JSON.stringify(payload));
  const sig = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64");
  const sigUrl = sig
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${data}.${sigUrl}`;
}

function verifySession(token) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) return null;
  const [data, sig] = token.split(".");
  if (!data || !sig) return null;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  if (expected !== sig) return null;
  try {
    const json = b64urlDecode(data);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function buildCookie(payload) {
  const token = signSession(payload);
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=31536000"
  ];
  if (process.env.NODE_ENV === "production") {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function getSessionFromEvent(event) {
  const cookies =
    parseCookies(event.headers.cookie || event.headers.Cookie || "");
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  return verifySession(token);
}

// ---------- helpers: Strava API ----------

async function stravaToken(body) {
  const res = await fetch(STRAVA_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.STRAVA_CLIENT_ID,
      client_secret: process.env.STRAVA_CLIENT_SECRET,
      ...body
    })
  });

  if (!res.ok) {
    const text = await res.text();
    console.error("Strava token error:", text);
    throw new Error("Strava token exchange failed");
  }
  return res.json();
}

async function refreshAccessToken(refreshToken) {
  return stravaToken({
    grant_type: "refresh_token",
    refresh_token: refreshToken
  });
}

async function fetchActivities(accessToken, pages = 3, perPage = 100) {
  const all = [];
  for (let page = 1; page <= pages; page++) {
    const res = await fetch(
      `${STRAVA_API_BASE}/athlete/activities?per_page=${perPage}&page=${page}`,
      {
        headers: { Authorization: `Bearer ${accessToken}` }
      }
    );
    if (!res.ok) {
      const text = await res.text();
      console.error("Strava activities error:", text);
      break;
    }
    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) break;
    all.push(...data);
  }
  return all;
}

function computeWrappedStats(activities) {
  const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
  const cutoff = Date.now() - ONE_YEAR_MS;

  const recent = activities.filter((a) => {
    const t = Date.parse(a.start_date);
    return Number.isFinite(t) && t >= cutoff;
  });

  let totalDistance = 0;
  let totalMovingTime = 0;

  let fastestRun = null;
  let fastestPace = Infinity;
  let longestRun = null;
  let longestRide = null;
  let highestElev = null;

  const monthTotals = new Map();

  for (const a of recent) {
    const dist = a.distance || 0;
    const move = a.moving_time || 0;
    totalDistance += dist;
    totalMovingTime += move;

    const date = new Date(a.start_date);
    const key = `${date.getFullYear()}-${String(
      date.getMonth() + 1
    ).padStart(2, "0")}`;
    monthTotals.set(key, (monthTotals.get(key) || 0) + dist);

    if (a.type === "Run") {
      if (!longestRun || dist > longestRun.distance) {
        longestRun = a;
      }
      const km = dist / 1000;
      if (km >= 3) {
        const pace = move / km; // seconds per km
        if (pace < fastestPace) {
          fastestPace = pace;
          fastestRun = a;
        }
      }
    }

    if (a.type === "Ride") {
      if (!longestRide || dist > longestRide.distance) {
        longestRide = a;
      }
    }

    if (
      typeof a.total_elevation_gain === "number" &&
      (!highestElev ||
        a.total_elevation_gain > highestElev.total_elevation_gain)
    ) {
      highestElev = a;
    }
  }

  let peakMonth = null;
  let peakDistance = 0;
  for (const [month, dist] of monthTotals.entries()) {
    if (dist > peakDistance) {
      peakDistance = dist;
      peakMonth = month;
    }
  }

  return {
    totalDistance,
    totalMovingTime,
    fastestRun,
    fastestPace: fastestPace === Infinity ? null : fastestPace,
    longestRun,
    longestRide,
    highestElev,
    peakMonth,
    peakDistance
  };
}

// ---------- handler ----------

exports.handler = async (event) => {
  const mode =
    (event.queryStringParameters &&
      event.queryStringParameters.mode) ||
    "stats";

  if (!process.env.STRAVA_CLIENT_ID || !process.env.STRAVA_CLIENT_SECRET) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error:
          "Strava API is not configured. Set STRAVA_CLIENT_ID and STRAVA_CLIENT_SECRET in Netlify."
      })
    };
  }

  // mode=auth: redirect to Strava OAuth
  if (mode === "auth") {
    const host = event.headers.host;
    const proto =
      event.headers["x-forwarded-proto"] ||
      event.headers["X-Forwarded-Proto"] ||
      "https";
    const origin = `${proto}://${host}`;
    const redirectUri = `${origin}/.netlify/functions/strava?mode=callback`;

    const params = new URLSearchParams({
      client_id: process.env.STRAVA_CLIENT_ID,
      response_type: "code",
      redirect_uri: redirectUri,
      scope:
        "read,read_all,profile:read_all,activity:read_all",
      approval_prompt: "auto"
    });

    const url = `${STRAVA_AUTH_URL}?${params.toString()}`;

    return {
      statusCode: 302,
      headers: {
        Location: url
      }
    };
  }

  // mode=callback: handle Strava redirect, set cookie, go home
  if (mode === "callback") {
    const params = event.queryStringParameters || {};
    const code = params.code;
    const error = params.error;

    if (error || !code) {
      return {
        statusCode: 302,
        headers: {
          Location: "/?error=strava_auth_failed"
        }
      };
    }

    try {
      const tokenData = await stravaToken({
        grant_type: "authorization_code",
        code
      });

      const athlete = tokenData.athlete || {};
      const sessionPayload = {
        athleteId: athlete.id,
        athleteName: `${athlete.firstname || ""} ${
          athlete.lastname || ""
        }`.trim() || "Athlete",
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        expiresAt: tokenData.expires_at
      };

      const cookie = buildCookie(sessionPayload);

      return {
        statusCode: 302,
        headers: {
          "Set-Cookie": cookie,
          Location: "/"
        }
      };
    } catch (e) {
      console.error("Callback error", e);
      return {
        statusCode: 302,
        headers: {
          Location: "/?error=strava_auth_failed"
        }
      };
    }
  }

  // default / mode=stats: return Wrapped stats for last 12 months
  if (mode === "stats") {
    let session = getSessionFromEvent(event);
    if (!session) {
      return {
        statusCode: 401,
        body: JSON.stringify({ error: "Not authenticated" })
      };
    }

    let { accessToken, refreshToken: rToken, expiresAt } = session;
    const nowSec = Math.floor(Date.now() / 1000);
    let newCookie = null;

    // refresh if needed
    if (expiresAt && expiresAt <= nowSec + 60 && rToken) {
      try {
        const refreshed = await refreshAccessToken(rToken);
        accessToken = refreshed.access_token;
        rToken = refreshed.refresh_token;
        expiresAt = refreshed.expires_at;

        session = {
          ...session,
          accessToken,
          refreshToken: rToken,
          expiresAt
        };
        newCookie = buildCookie(session);
      } catch (e) {
        console.error("Token refresh failed", e);
        return {
          statusCode: 401,
          body: JSON.stringify({ error: "Auth expired" })
        };
      }
    }

    try {
      const activities = await fetchActivities(accessToken);
      const stats = computeWrappedStats(activities);

      const body = JSON.stringify({
        athleteName: session.athleteName || "Athlete",
        stats
      });

      const headers = {
        "Content-Type": "application/json"
      };
      if (newCookie) {
        headers["Set-Cookie"] = newCookie;
      }

      return {
        statusCode: 200,
        headers,
        body
      };
    } catch (e) {
      console.error("Stats error", e);
      return {
        statusCode: 500,
        body: JSON.stringify({
          error: "Failed to load stats from Strava"
        })
      };
    }
  }

  return {
    statusCode: 400,
    body: JSON.stringify({ error: "Unknown mode" })
  };
};