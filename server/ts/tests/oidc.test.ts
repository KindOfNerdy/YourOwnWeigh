import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { handleApp, type AppEnv } from "../app.ts";
import { adminBrowser, browser, household, location, ORIGIN, PASSWORD } from "./helpers_accounts.ts";

const ISSUER = "https://id.test";
const CLIENT = "yow-client";
const SECRET = "client-secret-1";
const b64 = (value: unknown) =>
  Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

/** A minimal identity provider: discovery, keys, tokens, with PKCE checked. */
function provider() {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const keys = [
    { ...rsa.publicKey.export({ format: "jwk" }), kid: "rsa1", use: "sig" },
    { ...ec.publicKey.export({ format: "jwk" }), kid: "ec1", use: "sig" },
  ];
  const pending = { nonce: "", challenge: "" };
  const idp = {
    /** What the next token carries; tests change it before the callback. */
    claims: {} as Record<string, unknown>,
    alg: "RS256" as string,
    signWith: "rsa" as "rsa" | "ec" | "other",
    rejectToken: false,
    mint(claims: Record<string, unknown>) {
      const kid = idp.signWith === "ec" ? "ec1" : "rsa1";
      const head = b64({ alg: idp.alg, kid, typ: "JWT" });
      const data = `${head}.${b64(claims)}`;
      const signature =
        idp.signWith === "ec"
          ? sign("sha256", Buffer.from(data), { key: ec.privateKey, dsaEncoding: "ieee-p1363" })
          : sign("sha256", Buffer.from(data), idp.signWith === "other" ? other.privateKey : rsa.privateKey);
      return `${data}.${signature.toString("base64url")}`;
    },
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${ISSUER}/.well-known/openid-configuration`)
        return Response.json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
        });
      if (url === `${ISSUER}/jwks`) return Response.json({ keys });
      if (url === `${ISSUER}/token`) {
        const form = new URLSearchParams(String(init?.body));
        const challenge = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
        if (
          idp.rejectToken ||
          form.get("client_id") !== CLIENT ||
          form.get("client_secret") !== SECRET ||
          form.get("grant_type") !== "authorization_code" ||
          challenge !== pending.challenge
        )
          return new Response("{}", { status: 400 });
        const now = Math.floor(Date.now() / 1000);
        return Response.json({
          id_token: idp.mint({
            iss: ISSUER,
            aud: CLIENT,
            sub: "sub-1",
            exp: now + 300,
            iat: now,
            nonce: pending.nonce,
            preferred_username: "jane",
            ...idp.claims,
          }),
        });
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch,
    reset() {
      idp.claims = {};
      idp.alg = "RS256";
      idp.signWith = "rsa";
      idp.rejectToken = false;
    },
    remember(authorizeUrl: URL) {
      pending.nonce = authorizeUrl.searchParams.get("nonce")!;
      pending.challenge = authorizeUrl.searchParams.get("code_challenge")!;
    },
  };
  return idp;
}

async function setup() {
  const idp = provider();
  const h = await household({ oidcFetch: idp.fetch });
  const admin = await adminBrowser(h.env);
  const configure = (extra: Record<string, string> = {}) =>
    admin.post(
      "/oidc",
      { enabled: "1", name: "Pocket ID", issuer: ISSUER, client_id: CLIENT, client_secret: SECRET, password_users: "1", ...extra },
      "/admin",
    );
  assert.match(location(await configure()), /OIDC\+settings\+saved/);
  return { idp, h, admin, configure };
}

/** The browser round trip: start, authenticate at the provider, come back. */
async function oidcLogin(env: AppEnv, idp: ReturnType<typeof provider>, tweak: { state?: string; cookie?: string | null } = {}) {
  const start = await handleApp(new Request(`${ORIGIN}/login/oidc`), env);
  assert.equal(start.status, 303);
  const authorize = new URL(start.headers.get("location")!);
  idp.remember(authorize);
  const state = authorize.searchParams.get("state")!;
  const cookie = tweak.cookie === undefined ? state : tweak.cookie;
  const callback = await handleApp(
    new Request(`${ORIGIN}/login/oidc/callback?code=abc&state=${tweak.state ?? state}`, {
      headers: cookie ? { Cookie: `yow_oidc=${cookie}` } : {},
    }),
    env,
  );
  const session = callback.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .find((c) => c.startsWith("yow_session="));
  return { start, authorize, state, callback, session };
}
const signedIn = async (env: AppEnv, session?: string) =>
  !!session && (await handleApp(new Request(`${ORIGIN}/`, { headers: { Cookie: session } }), env)).status === 200;

test("the login page offers the provider and the start redirects with PKCE", async () => {
  const { h, idp } = await setup();
  try {
    const page = await (await handleApp(new Request(`${ORIGIN}/login`), h.env)).text();
    assert.match(page, /href="\/login\/oidc"[^>]*>Sign In With Pocket ID/);
    const start = await handleApp(new Request(`${ORIGIN}/login/oidc`), h.env);
    const url = new URL(start.headers.get("location")!);
    assert.equal(url.origin + url.pathname, `${ISSUER}/authorize`);
    assert.equal(url.searchParams.get("client_id"), CLIENT);
    assert.equal(url.searchParams.get("redirect_uri"), `${ORIGIN}/login/oidc/callback`);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.match(start.headers.get("set-cookie") ?? "", /yow_oidc=[a-f0-9]{48}; HttpOnly; Secure; SameSite=Lax/);
    idp.reset();
  } finally {
    h.close();
  }
});

test("a pre-provisioned account without password signs in and is bound to the provider's subject", async () => {
  const { h, idp, admin } = await setup();
  try {
    const created = await admin.post(
      "/accounts",
      { username: "jane", password: "", role: "user", oidc_username: "JANE" },
      "/admin",
    );
    assert.match(location(created), /Account\+created/);
    const first = await oidcLogin(h.env, idp);
    assert.equal(first.callback.status, 200);
    assert.match(await first.callback.text(), /http-equiv="refresh" content="0;url=\//);
    assert.equal(await signedIn(h.env, first.session), true);
    const dashboard = await (
      await handleApp(new Request(`${ORIGIN}/`, { headers: { Cookie: first.session! } }), h.env)
    ).text();
    assert.match(dashboard, /Jane/);
    assert.doesNotMatch(dashboard, /Bob/);
    // The subject is now bound: a different name claim signs in as the same account.
    idp.claims = { preferred_username: "somebody-else" };
    const second = await oidcLogin(h.env, idp);
    assert.equal(await signedIn(h.env, second.session), true);
    const rows = await h.db.prepare("SELECT username,oidc_subject FROM accounts WHERE username='jane'").all<{ oidc_subject: string }>();
    assert.equal(rows.results[0].oidc_subject, "sub-1");
    // A second identity with the same name cannot take the bound account.
    idp.claims = { sub: "sub-2", preferred_username: "jane" };
    const stranger = await oidcLogin(h.env, idp);
    assert.equal(stranger.session, undefined);
    assert.match(location(stranger.callback), /No\+account\+is\+linked/);
    // The password login does not work for an account without a password.
    assert.match(location(await browser(h.env).login("jane", "")), /Invalid/);
  } finally {
    h.close();
  }
});

test("unknown identities are rejected, or get an account when auto-create is on", async () => {
  const { h, idp, configure } = await setup();
  try {
    idp.claims = { sub: "sub-new", preferred_username: "new user" };
    const refused = await oidcLogin(h.env, idp);
    assert.equal(refused.session, undefined);
    assert.match(location(refused.callback), /^\/login\?notice=No\+account\+is\+linked/);
    await configure({ auto_create: "1" });
    const created = await oidcLogin(h.env, idp);
    assert.equal(await signedIn(h.env, created.session), true);
    const row = await h.db
      .prepare("SELECT username,role,password_hash,oidc_issuer FROM accounts WHERE oidc_subject='sub-new'")
      .first<{ username: string; role: string; password_hash: string | null; oidc_issuer: string }>();
    assert.deepEqual({ ...row }, { username: "new.user", role: "user", password_hash: null, oidc_issuer: ISSUER });
  } finally {
    h.close();
  }
});

test("a login is refused when the token, the state or the browser does not match", async () => {
  const { h, idp, admin } = await setup();
  try {
    await admin.post("/accounts", { username: "jane", password: "", role: "user", oidc_username: "jane" }, "/admin");
    const now = Math.floor(Date.now() / 1000);
    const cases: Array<[string, () => Promise<{ session?: string; callback: Response }>]> = [
      ["wrong nonce", async () => { idp.claims = { nonce: "other" }; return oidcLogin(h.env, idp); }],
      ["wrong audience", async () => { idp.claims = { aud: "someone-else" }; return oidcLogin(h.env, idp); }],
      ["wrong issuer", async () => { idp.claims = { iss: "https://evil.test" }; return oidcLogin(h.env, idp); }],
      ["expired", async () => { idp.claims = { exp: now - 3600 }; return oidcLogin(h.env, idp); }],
      ["signed with another key", async () => { idp.signWith = "other"; return oidcLogin(h.env, idp); }],
      ["unsupported algorithm", async () => { idp.alg = "none"; return oidcLogin(h.env, idp); }],
      ["state of another login", async () => oidcLogin(h.env, idp, { state: "f".repeat(48) })],
      ["no state cookie", async () => oidcLogin(h.env, idp, { cookie: null })],
      ["state cookie of another login", async () => oidcLogin(h.env, idp, { cookie: "a".repeat(48) })],
      ["token request refused", async () => { idp.rejectToken = true; return oidcLogin(h.env, idp); }],
    ];
    for (const [name, run] of cases) {
      idp.reset();
      const result = await run();
      assert.equal(result.session, undefined, name);
      assert.match(location(result.callback), /^\/login\?notice=/, name);
    }
    // A state works once.
    idp.reset();
    const ok = await oidcLogin(h.env, idp);
    assert.equal(await signedIn(h.env, ok.session), true);
    const replay = await handleApp(
      new Request(`${ORIGIN}/login/oidc/callback?code=abc&state=${ok.state}`, { headers: { Cookie: `yow_oidc=${ok.state}` } }),
      h.env,
    );
    assert.match(location(replay), /^\/login\?notice=/);
  } finally {
    h.close();
  }
});

test("ES256 tokens are accepted", async () => {
  const { h, idp, admin } = await setup();
  try {
    await admin.post("/accounts", { username: "jane", password: "", role: "user", oidc_username: "jane" }, "/admin");
    idp.alg = "ES256";
    idp.signWith = "ec";
    assert.equal(await signedIn(h.env, (await oidcLogin(h.env, idp)).session), true);
  } finally {
    h.close();
  }
});

test("OIDC is off until configured and the settings are validated against the provider", async () => {
  const idp = provider();
  const h = await household({ oidcFetch: idp.fetch });
  try {
    assert.match(location(await handleApp(new Request(`${ORIGIN}/login/oidc`), h.env)), /OIDC\+sign-in\+is\+not\+enabled/);
    const admin = await adminBrowser(h.env);
    const bad = await admin.post("/oidc", { enabled: "1", issuer: "http://id.example.com", client_id: "x", client_secret: "y" }, "/admin");
    assert.match(location(bad), /must\+be\+an\+https\+URL/);
    const missing = await admin.post("/oidc", { enabled: "1", issuer: ISSUER }, "/admin");
    assert.match(location(missing), /needs\+an\+issuer/);
    const page = await (await admin.call("/admin")).text();
    assert.match(page, /name="issuer"/);
    assert.doesNotMatch(page, new RegExp(SECRET));
  } finally {
    h.close();
  }
});

test("password sign-in can be switched off for users while administrators keep it", async () => {
  const { h, admin, configure } = await setup();
  try {
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user", oidc_username: "jane" }, "/admin");
    assert.equal(location(await browser(h.env).login("jane", "jane-password-1")).startsWith("/?"), true);
    await configure({ password_users: "" });
    assert.match(location(await browser(h.env).login("jane", "jane-password-1")), /Invalid\+username/);
    assert.equal(location(await browser(h.env).login("owner", PASSWORD)).startsWith("/?"), true);
    const page = await (await handleApp(new Request(`${ORIGIN}/login`), h.env)).text();
    assert.match(page, /administrators only/);
    // Disabling OIDC puts the password login back for everybody.
    await configure({ enabled: "", password_users: "" });
    assert.equal(location(await browser(h.env).login("jane", "jane-password-1")).startsWith("/?"), true);
  } finally {
    h.close();
  }
});

test("administrators always keep a password; users can drop theirs once OIDC works", async () => {
  const { h, admin } = await setup();
  try {
    assert.match(
      location(await admin.post("/accounts", { username: "boss", password: "", role: "admin", oidc_username: "boss" }, "/admin")),
      /Administrators\+need\+a\+password/,
    );
    assert.match(
      location(await admin.post("/accounts", { username: "nobody", password: "", role: "user" }, "/admin")),
      /password%2C\+or\+an\+OIDC\+username|OIDC\+username/,
    );
    const own = (await h.db.prepare("SELECT id FROM accounts WHERE username='owner'").first<{ id: number }>())!.id;
    assert.match(
      location(await admin.post(`/accounts/${own}`, { remove_password: "1", oidc_username: "owner" }, "/admin")),
      /Administrators\+need\+a\+password|can\+only\+be\+removed/,
    );
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user", oidc_username: "jane" }, "/admin");
    const jane = (await h.db.prepare("SELECT id FROM accounts WHERE username='jane'").first<{ id: number }>())!.id;
    assert.match(
      location(await admin.post(`/accounts/${jane}`, { role: "user", oidc_username: "jane", remove_password: "1" }, "/admin")),
      /Account\+saved/,
    );
    assert.equal(
      (await h.db.prepare("SELECT password_hash FROM accounts WHERE id=?").bind(jane).first<{ password_hash: string | null }>())?.password_hash,
      null,
    );
    assert.match(
      location(await admin.post(`/accounts/${jane}`, { role: "admin", oidc_username: "jane" }, "/admin")),
      /Administrators\+need\+a\+password/,
    );
  } finally {
    h.close();
  }
});

test("a disabled account cannot sign in through OIDC, and unlinking allows a new binding", async () => {
  const { h, idp, admin } = await setup();
  try {
    await admin.post("/accounts", { username: "jane", password: "", role: "user", oidc_username: "jane" }, "/admin");
    const id = (await h.db.prepare("SELECT id FROM accounts WHERE username='jane'").first<{ id: number }>())!.id;
    assert.equal(await signedIn(h.env, (await oidcLogin(h.env, idp)).session), true);
    await admin.post(`/accounts/${id}`, { role: "user", oidc_username: "jane", disabled: "1" }, "/admin");
    const refused = await oidcLogin(h.env, idp);
    assert.equal(refused.session, undefined);
    await admin.post(`/accounts/${id}`, { role: "user", oidc_username: "jane", unlink_oidc: "1" }, "/admin");
    idp.claims = { sub: "sub-9" };
    assert.equal(await signedIn(h.env, (await oidcLogin(h.env, idp)).session), true);
    assert.equal(
      (await h.db.prepare("SELECT oidc_subject FROM accounts WHERE id=?").bind(id).first<{ oidc_subject: string }>())?.oidc_subject,
      "sub-9",
    );
  } finally {
    h.close();
  }
});

test("accounts without a password use a Sync token that is shown once and can be revoked", async () => {
  const { h, idp, admin } = await setup();
  try {
    await admin.post("/accounts", { username: "jane", password: "", role: "user", oidc_username: "jane" }, "/admin");
    const login = await oidcLogin(h.env, idp);
    const session = login.session!;
    const csrf = /name="_csrf" value="([a-f0-9]+)"/.exec(
      await (await handleApp(new Request(`${ORIGIN}/account`, { headers: { Cookie: session } }), h.env)).text(),
    )![1];
    const post = (purpose: string) =>
      handleApp(
        new Request(`${ORIGIN}/account`, {
          method: "POST",
          headers: { Cookie: session },
          body: new URLSearchParams({ _csrf: csrf, purpose }),
        }),
        h.env,
      );
    const created = await post("sync_token");
    assert.equal(created.status, 200);
    const token = /yow_[a-f0-9]{48}/.exec(await created.text())![0];
    const stored = await h.db.prepare("SELECT sync_token_hash FROM accounts WHERE username='jane'").first<{ sync_token_hash: string }>();
    assert.equal(stored?.sync_token_hash, createHash("sha256").update(token).digest("hex"));
    const get = (path: string, password: string) =>
      handleApp(new Request(`${ORIGIN}${path}`, { headers: { Authorization: `Basic ${btoa(`jane:${password}`)}` } }), h.env);
    assert.equal((await get("/api/users/1/weights", token)).status, 200);
    assert.equal((await get("/api/users/2/weights", token)).status, 404);
    assert.equal((await get("/api/users/1/weights", "yow_" + "0".repeat(48))).status, 401);
    assert.match(location(await post("sync_token_revoke")), /Sync\+token\+revoked/);
    assert.equal((await get("/api/users/1/weights", token)).status, 401);
  } finally {
    h.close();
  }
});

test("a backup keeps the OIDC settings, the account bindings and the see-all choice", async () => {
  const { h, admin } = await setup();
  const target = await household();
  try {
    await admin.post("/accounts", { username: "jane", password: "", role: "user", oidc_username: "jane" }, "/admin");
    const { exportBackup, stageBackup, commitBackup } = await import("../backup.ts");
    const backup = await exportBackup(h.db);
    assert.ok(backup.accessSettings.some((r) => r.key === "oidc_client_secret"));
    await adminBrowser(target.env);
    const preview = await stageBackup(target.db, JSON.stringify(backup), "admin");
    await commitBackup(target.db, preview.id, preview.digest, "admin", "replace", true);
    const jane = await target.db.prepare("SELECT password_hash,oidc_username,see_all FROM accounts WHERE username='jane'").first<{ password_hash: string | null; oidc_username: string; see_all: number }>();
    assert.deepEqual({ ...jane }, { password_hash: null, oidc_username: "jane", see_all: 0 });
    const owner = await target.db.prepare("SELECT see_all FROM accounts WHERE username='owner'").first<{ see_all: number }>();
    assert.equal(owner?.see_all, 1);
    assert.equal(
      (await target.db.prepare("SELECT value FROM settings WHERE key='oidc_issuer'").first<{ value: string }>())?.value,
      ISSUER,
    );
  } finally {
    h.close();
    target.close();
  }
});
