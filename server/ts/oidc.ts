/** OpenID Connect (authorization code + PKCE) on plain WebCrypto, for Node and Workers. */
type FetchLike = typeof fetch;
export type OidcConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
};
export type Discovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};
export type Claims = {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nonce?: string;
  azp?: string;
  preferred_username?: string;
  email?: string;
  name?: string;
};

const utf8 = new TextEncoder();
export const b64u = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const fromB64u = (value: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );
const local = (host: string) =>
  ["localhost", "127.0.0.1", "[::1]"].includes(host);

/** An https URL (http only for localhost) without query or fragment. */
function endpoint(value: unknown, what: string): string {
  let url: URL;
  try {
    url = new URL(String(value));
  } catch {
    throw new Error(`OIDC ${what} is not a valid URL`);
  }
  if (
    (url.protocol !== "https:" &&
      !(url.protocol === "http:" && local(url.hostname))) ||
    url.username ||
    url.password ||
    url.hash
  )
    throw new Error(`OIDC ${what} must be an https URL`);
  return url.toString();
}
export function normalizeIssuer(value: string): string {
  const url = new URL(endpoint(value.trim(), "issuer"));
  if (url.search) throw new Error("OIDC issuer must not have a query");
  return url.toString().replace(/\/+$/, "");
}
export async function discover(
  issuer: string,
  fetchImpl: FetchLike = fetch,
): Promise<Discovery> {
  const response = await fetchImpl(
    `${issuer}/.well-known/openid-configuration`,
    { signal: AbortSignal.timeout(10000), redirect: "error" },
  );
  if (!response.ok) throw new Error("OIDC discovery failed");
  const doc = (await response.json()) as Record<string, unknown>;
  if (normalizeIssuer(String(doc.issuer ?? "")) !== issuer)
    throw new Error("OIDC issuer does not match the discovery document");
  return {
    issuer,
    authorization_endpoint: endpoint(
      doc.authorization_endpoint,
      "authorization endpoint",
    ),
    token_endpoint: endpoint(doc.token_endpoint, "token endpoint"),
    jwks_uri: endpoint(doc.jwks_uri, "JWKS URI"),
  };
}
export async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64u(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", utf8.encode(verifier)),
    ),
  );
  return { verifier, challenge };
}
export function authorizationUrl(
  d: Discovery,
  config: OidcConfig,
  redirectUri: string,
  state: string,
  nonce: string,
  challenge: string,
): string {
  const url = new URL(d.authorization_endpoint);
  for (const [key, value] of Object.entries({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: redirectUri,
    scope: "openid profile email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }))
    url.searchParams.set(key, value);
  return url.toString();
}
export async function exchangeCode(
  d: Discovery,
  config: OidcConfig,
  redirectUri: string,
  code: string,
  verifier: string,
  fetchImpl: FetchLike = fetch,
): Promise<string> {
  const response = await fetchImpl(d.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(10000),
    redirect: "error",
  });
  if (!response.ok) throw new Error("OIDC token request failed");
  const body = (await response.json()) as { id_token?: unknown };
  if (typeof body.id_token !== "string")
    throw new Error("OIDC provider returned no ID token");
  return body.id_token;
}

type Jwk = JsonWebKey & { kid?: string; use?: string; alg?: string };
async function verifySignature(
  alg: string,
  jwk: Jwk,
  signature: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  try {
    if (alg === "RS256") {
      const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
    }
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      data,
    );
  } catch {
    return false;
  }
}
/** Checks signature, issuer, audience, expiry and nonce; returns the claims. */
export async function verifyIdToken(
  token: string,
  d: Discovery,
  config: OidcConfig,
  nonce: string,
  fetchImpl: FetchLike = fetch,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<Claims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid ID token");
  const [head, body, sig] = parts;
  let header: { alg?: string; kid?: string };
  let claims: Claims;
  try {
    header = JSON.parse(new TextDecoder().decode(fromB64u(head)));
    claims = JSON.parse(new TextDecoder().decode(fromB64u(body)));
  } catch {
    throw new Error("Invalid ID token");
  }
  if (header.alg !== "RS256" && header.alg !== "ES256")
    throw new Error("Unsupported ID token algorithm");
  const response = await fetchImpl(d.jwks_uri, {
    signal: AbortSignal.timeout(10000),
    redirect: "error",
  });
  if (!response.ok) throw new Error("OIDC key request failed");
  const keys = ((await response.json()) as { keys?: Jwk[] }).keys ?? [];
  const wanted = header.alg === "RS256" ? "RSA" : "EC";
  const candidates = keys.filter(
    (key) =>
      key.kty === wanted &&
      (key.use === undefined || key.use === "sig") &&
      (!header.kid || key.kid === header.kid),
  );
  const data = utf8.encode(`${head}.${body}`);
  const signature = fromB64u(sig);
  let valid = false;
  for (const key of candidates)
    if (await verifySignature(header.alg, key, signature, data)) {
      valid = true;
      break;
    }
  if (!valid) throw new Error("ID token signature is invalid");
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (
    normalizeIssuer(String(claims.iss ?? "")) !== d.issuer ||
    !audience.includes(config.clientId) ||
    (audience.length > 1 && claims.azp !== config.clientId) ||
    !Number.isFinite(claims.exp) ||
    claims.exp < nowSeconds - 60 ||
    (claims.iat !== undefined && claims.iat > nowSeconds + 300) ||
    claims.nonce !== nonce ||
    typeof claims.sub !== "string" ||
    !claims.sub ||
    claims.sub.length > 255
  )
    throw new Error("ID token is not valid for this login");
  return claims;
}
