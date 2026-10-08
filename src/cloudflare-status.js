const ENDPOINT = "https://www.cloudflarestatus.com/api/v2/status.json";
const PUBLIC_STATUS = "https://www.cloudflarestatus.com";
const MAX_STATUS_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const STATES = new Map([
  ["none", "OPERATIONAL"], ["minor", "MINOR_INCIDENT"],
  ["major", "MAJOR_INCIDENT"], ["critical", "CRITICAL_INCIDENT"],
]);
export function unknownCloudflareStatus() {
  return {
    source:"cloudflare_public_statuspage",
    scope:"global_cloudflare_platform_not_account_or_worker",
    state:"UNKNOWN", indicator:null, description:null, reason:"PUBLIC_STATUS_UNAVAILABLE",
    observed_at:null, url:PUBLIC_STATUS,
    worker_runtime:"UNKNOWN", relay_connection:"NOT_MEASURED",
  };
}
export function normalizeCloudflareStatus(payload, now = Date.now()) {
  const indicator = payload?.status?.indicator;
  if (!STATES.has(indicator) ||
      typeof payload?.status?.description !== "string" ||
      !payload.status.description.trim() ||
      payload.status.description.length > 180 ||
      payload?.page?.id !== "yh6f0r4529hb" ||
      typeof payload?.page?.updated_at !== "string" ||
      !Number.isFinite(Date.parse(payload.page.updated_at)) ||
      !Number.isFinite(now)) {
    throw new Error("CLOUDFLARE_PUBLIC_STATUS_INVALID");
  }
  // Statuspage's updated_at is a publisher change time, not retrieval time.
  // Even an HTTP 200 cannot certify that an old outage/healthy label is current.
  const age = now - Date.parse(payload.page.updated_at);
  if (age > MAX_STATUS_AGE_MS || age < -MAX_FUTURE_SKEW_MS) {
    return {
      ...unknownCloudflareStatus(),
      observed_at: payload.page.updated_at,
      reason: age > MAX_STATUS_AGE_MS ? "PUBLIC_STATUS_STALE" : "PUBLIC_STATUS_FUTURE_TIMESTAMP",
    };
  }
  return {
    source:"cloudflare_public_statuspage",
    scope:"global_cloudflare_platform_not_account_or_worker",
    state:STATES.get(indicator),indicator, reason:null,
    description:payload.status.description,
    observed_at:payload.page.updated_at,
    url:PUBLIC_STATUS,
    worker_runtime:"UNKNOWN",
    relay_connection:"NOT_MEASURED",
  };
}
export async function cloudflarePublicStatus() {
  const response = await fetch(ENDPOINT, {
    headers:{Accept:"application/json", "User-Agent":"BKE-Command-Center/0.1 (+https://cc.jl-bke.com/)"},
    signal:AbortSignal.timeout(2500),
  });
  if (!response.ok) throw new Error("CLOUDFLARE_PUBLIC_STATUS_HTTP_UNAVAILABLE");
  return normalizeCloudflareStatus(await response.json());
}
