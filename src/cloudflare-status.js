const ENDPOINT = "https://www.cloudflarestatus.com/api/v2/status.json";
const PUBLIC_STATUS = "https://www.cloudflarestatus.com";
const STATES = new Map([
  ["none", "OPERATIONAL"], ["minor", "MINOR_INCIDENT"],
  ["major", "MAJOR_INCIDENT"], ["critical", "CRITICAL_INCIDENT"],
]);
export function unknownCloudflareStatus() {
  return {
    source:"cloudflare_public_statuspage",
    scope:"global_cloudflare_platform_not_account_or_worker",
    state:"UNKNOWN", indicator:null, description:null,
    observed_at:null, url:PUBLIC_STATUS,
    worker_runtime:"UNKNOWN", relay_connection:"NOT_MEASURED",
  };
}
export function normalizeCloudflareStatus(payload) {
  const indicator = payload?.status?.indicator;
  if (!STATES.has(indicator) ||
      typeof payload?.status?.description !== "string" ||
      !payload.status.description.trim() ||
      payload.status.description.length > 180 ||
      payload?.page?.id !== "yh6f0r4529hb" ||
      typeof payload?.page?.updated_at !== "string" ||
      !Number.isFinite(Date.parse(payload.page.updated_at))) {
    throw new Error("CLOUDFLARE_PUBLIC_STATUS_INVALID");
  }
  return {
    source:"cloudflare_public_statuspage",
    scope:"global_cloudflare_platform_not_account_or_worker",
    state:STATES.get(indicator),indicator,
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
