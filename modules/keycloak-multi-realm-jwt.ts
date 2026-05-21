import {
  ZuploContext,
  ZuploRequest,
  ZoneCache,
  HttpProblems,
} from "@zuplo/runtime";
import * as jose from "jose";

// Populated at deploy time via env var — e.g. "https://kc.example.com/realms/"
// All issuer values must start with this prefix.
const TRUSTED_ISSUER_PREFIX =
  typeof process !== "undefined"
    ? (process.env.KEYCLOAK_ISSUER_PREFIX ?? "")
    : "";

const JWKS_CACHE_TTL_SECONDS = 600; // 10 min positive TTL
const NEGATIVE_CACHE_TTL_SECONDS = 30; // 30 s negative TTL

// In-memory Map for intra-isolate hits (avoids ZoneCache round-trip on warm
// isolates). Keyed by issuer; values are [KeyLike[], fetchedAtMs].
const inProcessCache = new Map<string, [jose.JSONWebKeySet, number]>();
const IN_PROCESS_TTL_MS = JWKS_CACHE_TTL_SECONDS * 1000;

// Dedup concurrent fetches for the same issuer within one isolate.
const inflightFetches = new Map<string, Promise<jose.JSONWebKeySet | null>>();

function isTrustedIssuer(iss: string): boolean {
  if (!TRUSTED_ISSUER_PREFIX) {
    // No prefix configured — block everything so misconfiguration is loud.
    return false;
  }
  return (
    iss.startsWith(TRUSTED_ISSUER_PREFIX) &&
    // Prevent prefix itself being used as an issuer.
    iss.length > TRUSTED_ISSUER_PREFIX.length
  );
}

async function fetchJwks(
  issuer: string,
  context: ZuploContext
): Promise<jose.JSONWebKeySet | null> {
  const jwksUrl = `${issuer}/protocol/openid-connect/certs`;
  try {
    const res = await fetch(jwksUrl);
    if (!res.ok) {
      context.log.warn(`JWKS fetch failed for ${issuer}: ${res.status}`);
      return null;
    }
    return (await res.json()) as jose.JSONWebKeySet;
  } catch (e) {
    context.log.error(`JWKS fetch error for ${issuer}`, e);
    return null;
  }
}

async function getJwks(
  issuer: string,
  context: ZuploContext
): Promise<jose.JSONWebKeySet | null> {
  // 1. In-process cache.
  const cached = inProcessCache.get(issuer);
  if (cached && Date.now() - cached[1] < IN_PROCESS_TTL_MS) {
    return cached[0];
  }

  // 2. ZoneCache (shared across isolates).
  const zoneCache = new ZoneCache<jose.JSONWebKeySet | "NOT_FOUND">(
    "keycloak-jwks-v1",
    context
  );
  const zoned = await zoneCache.get(issuer);
  if (zoned !== undefined) {
    if (zoned === "NOT_FOUND") return null;
    inProcessCache.set(issuer, [zoned, Date.now()]);
    return zoned;
  }

  // 3. Deduplicate concurrent fetches for the same issuer.
  let inflight = inflightFetches.get(issuer);
  if (!inflight) {
    inflight = fetchJwks(issuer, context).then(async (jwks) => {
      if (jwks) {
        inProcessCache.set(issuer, [jwks, Date.now()]);
        await zoneCache
          .put(issuer, jwks, JWKS_CACHE_TTL_SECONDS)
          .catch((e) => context.log.error("ZoneCache put error", e));
      } else {
        await zoneCache
          .put(issuer, "NOT_FOUND", NEGATIVE_CACHE_TTL_SECONDS)
          .catch((e) => context.log.error("ZoneCache negative-cache error", e));
      }
      return jwks;
    });
    inflightFetches.set(issuer, inflight);
    inflight.finally(() => inflightFetches.delete(issuer));
  }

  return inflight;
}

export default async function keycloakMultiRealmJwt(
  request: ZuploRequest,
  context: ZuploContext
) {
  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Missing Bearer token",
    });
  }
  const token = authHeader.slice(7);

  // Decode without verifying to extract iss and kid.
  let payload: jose.JWTPayload;
  try {
    payload = jose.decodeJwt(token);
  } catch {
    return HttpProblems.unauthorized(request, context, {
      detail: "Malformed JWT",
    });
  }

  const iss = payload.iss;
  if (typeof iss !== "string" || !isTrustedIssuer(iss)) {
    context.log.warn(`Rejected untrusted issuer: ${iss}`);
    return HttpProblems.unauthorized(request, context, {
      detail: "Untrusted issuer",
    });
  }

  const jwks = await getJwks(iss, context);
  if (!jwks) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Could not retrieve JWKS for issuer",
    });
  }

  const keySet = jose.createLocalJWKSet(jwks);
  try {
    const { payload: verified } = await jose.jwtVerify(token, keySet, {
      issuer: iss,
      // audience intentionally omitted — enforce per-route or downstream
      // once the specific aud values per realm are known.
    });

    // Populate request.user so downstream policies (rate-limit, monetization)
    // work the same as with built-in JWT policies.
    request.user = {
      sub: verified.sub ?? "",
      data: verified,
    };

    context.log.info(`Authenticated sub=${verified.sub} realm=${iss}`);
  } catch (e) {
    context.log.warn(`JWT verification failed for issuer ${iss}`, e);
    return HttpProblems.unauthorized(request, context, {
      detail: "JWT verification failed",
    });
  }

  return request;
}
