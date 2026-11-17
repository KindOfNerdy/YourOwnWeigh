import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalSqlite } from "../sqlite.ts";
import { handleApp, type AppEnv } from "../app.ts";
import { commitBackup, exportBackup, stageBackup } from "../backup.ts";

const ORIGIN = "https://local.test";

/** A household with two people, one scale, and one unassigned reading. */
async function household() {
  const directory = mkdtempSync(join(tmpdir(), "yow-accounts-"));
  const store = new LocalSqlite(join(directory, "accounts.sqlite3"));
  const db = store.asD1();
  const env: AppEnv = {
    DB: db,
    YOW_BOOTSTRAP_TOKEN: "dummy-test-bootstrap-token",
  };
  await db
    .prepare(
      "INSERT INTO users(id,name,short_name,height_cm,age_years,sex,reference_weight_kg,created_at) VALUES(1,'Jane','JAN',170,30,1,70,1),(2,'Bob','BOB',180,40,0,85,1)",
    )
    .run();
  await db
    .prepare(
      "INSERT INTO scales(id,label,model,mac,secret) VALUES(1,'Bathroom','WBS03','020000000003','0123456789abcdef')",
    )
    .run();
  const reading = (id: number, user: number | null, weight: number) =>
    db
      .prepare(
        "INSERT INTO readings(id,scale_id,user_id,attribution,candidate_ids,attribstatus,meastime,time_quality,weight_value,weight_unit,measures_json,payload_hash,first_received_at,last_received_at) VALUES(?,1,?,'assigned','[]',0,1793000000,'trusted',?, -3,'[]',?,1,1)",
      )
      .bind(id, user, weight, createHash("sha256").update(`reading-${id}`).digest("hex"))
      .run();
  await reading(1, 1, 61000);
  await reading(2, 2, 82000);
  await reading(3, null, 99000);
  return {
    env,
    db,
    close: () => {
      store.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

/** A browser: keeps the cookie, follows the CSRF token. */
function browser(env: AppEnv) {
  let cookie = "";
  const call = async (path: string, init: RequestInit = {}) => {
    const response = await handleApp(
      new Request(`${ORIGIN}${path}`, {
        ...init,
        headers: { ...(init.headers as object), Cookie: cookie },
      }),
      env,
    );
    const set = response.headers.get("set-cookie");
    if (set) cookie = set.split(";")[0];
    return response;
  };
  const csrf = async (path = "/login") =>
    /name="_csrf" value="([a-f0-9]+)"/.exec(
      await (await call(path)).text(),
    )![1];
  const post = async (
    path: string,
    fields: Record<string, string | string[]>,
    from = "/account",
  ) => {
    const form = new URLSearchParams({ _csrf: await csrf(from) });
    for (const [key, value] of Object.entries(fields))
      for (const item of [value].flat()) form.append(key, item);
    return call(path, { method: "POST", body: form });
  };
  const login = async (username: string, password: string) => {
    const response = await post("/login", { username, password }, "/login");
    return response;
  };
  return { call, post, login };
}

const location = (response: Response) => response.headers.get("location") ?? "";
const PASSWORD = "admin-password-123";

async function adminBrowser(env: AppEnv) {
  const admin = browser(env);
  await admin.post(
    "/setup",
    { step: "bootstrap", bootstrap_token: "dummy-test-bootstrap-token" },
    "/setup",
  );
  const setup = await admin.post(
    "/setup",
    { step: "password", username: "owner", password: PASSWORD, confirm: PASSWORD },
    "/setup",
  );
  assert.equal(setup.status, 303);
  return admin;
}

test("first-run setup creates the first administrator account", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    assert.equal((await admin.call("/")).status, 200);
    const row = await h.db
      .prepare("SELECT username,role FROM accounts")
      .first<{ username: string; role: string }>();
    assert.deepEqual({ ...row }, { username: "owner", role: "admin" });
    const other = browser(h.env);
    assert.match(
      location(await other.login("owner", "wrong-password")),
      /Invalid\+username\+or\+password/,
    );
    assert.equal(location(await other.login("OWNER", PASSWORD)).startsWith("/?"), true);
  } finally {
    h.close();
  }
});

test("the old shared admin password becomes the account admin", async () => {
  const h = await household();
  try {
    const { pbkdf2Sync } = await import("node:crypto");
    const salt = "00".repeat(16);
    const hash = pbkdf2Sync(PASSWORD, Buffer.from(salt, "hex"), 100000, 32, "sha256").toString("hex");
    await h.db
      .prepare("INSERT INTO settings(key,value) VALUES('admin_password',?),('auth_version','1')")
      .bind(`pbkdf2_sha256$100000$${salt}$${hash}`)
      .run();
    const old = browser(h.env);
    assert.equal(location(await old.login("admin", PASSWORD)).startsWith("/?"), true);
    assert.equal(
      await h.db.prepare("SELECT 1 AS x FROM settings WHERE key='admin_password'").first(),
      null,
    );
    assert.equal(
      (await h.db.prepare("SELECT role FROM accounts WHERE username='admin'").first<{ role: string }>())?.role,
      "admin",
    );
  } finally {
    h.close();
  }
});

test("an administrator creates a user account that is linked by name and sees only that person", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    const created = await admin.post(
      "/accounts",
      { username: "jane", password: "jane-password-1", role: "user" },
      "/settings",
    );
    assert.match(location(created), /Account\+created/);
    const links = await h.db.prepare("SELECT user_id FROM account_users").all<{ user_id: number }>();
    assert.deepEqual(links.results.map((r) => r.user_id), [1]);

    const jane = browser(h.env);
    assert.equal(location(await jane.login("jane", "jane-password-1")).startsWith("/?"), true);
    const dashboard = await (await jane.call("/")).text();
    assert.match(dashboard, /Jane/);
    assert.doesNotMatch(dashboard, /Bob/);
    const readings = await (await jane.call("/readings")).text();
    assert.match(readings, /Jane/);
    assert.doesNotMatch(readings, /Bob|82\.0/);
    assert.match(readings, /99\.0/); // unassigned readings are visible
    assert.doesNotMatch(readings, /\/readings\/3\/delete/);
    assert.equal((await jane.call("/users/1/readings")).status, 200);
    assert.equal((await jane.call("/users/2/readings")).status, 404);
    for (const path of ["/users", "/scales", "/settings", "/firmware"])
      assert.match(location(await jane.call(path)), /^\/\?notice=Administrator\+access\+required/);
    assert.equal((await jane.call("/api/backup/export")).status, 403);
    assert.equal((await jane.call("/api/devices")).status, 403);
    const nav = await (await jane.call("/")).text();
    assert.doesNotMatch(nav, /href="\/users"|href="\/settings"|href="\/firmware"/);
    assert.match(nav, /href="\/account"/);
  } finally {
    h.close();
  }
});

test("users assign unassigned readings only to their own people and cannot delete them", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/settings");
    const jane = browser(h.env);
    await jane.login("jane", "jane-password-1");
    const foreign = await jane.post("/readings/3/assign", { user_id: "2" }, "/readings");
    assert.match(location(foreign), /Unknown\+user/);
    assert.equal(
      (await h.db.prepare("SELECT user_id FROM readings WHERE id=3").first<{ user_id: number | null }>())?.user_id,
      null,
    );
    const deleted = await jane.post("/readings/3/delete", {}, "/readings");
    assert.match(location(deleted), /Administrator\+access\+required/);
    assert.ok(await h.db.prepare("SELECT 1 AS x FROM readings WHERE id=3").first());
    const own = await jane.post("/readings/3/assign", { user_id: "1" }, "/readings");
    assert.match(location(own), /Reading\+assigned/);
  } finally {
    h.close();
  }
});

test("users edit the profile of their own people only", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/settings");
    const jane = browser(h.env);
    await jane.login("jane", "jane-password-1");
    const profile = {
      name: "Jane D.",
      short_name: "JAN",
      height_cm: "171",
      birth_date: "",
      age_years: "31",
      sex: "1",
      reference_weight_kg: "69",
    };
    assert.equal((await jane.post("/users/1", profile)).status, 303);
    assert.equal(
      (await h.db.prepare("SELECT name,height_cm FROM users WHERE id=1").first<{ name: string; height_cm: number }>())?.name,
      "Jane D.",
    );
    assert.equal((await jane.post("/users/2", { ...profile, name: "Mallory" })).status, 404);
    assert.equal(
      (await h.db.prepare("SELECT name FROM users WHERE id=2").first<{ name: string }>())?.name,
      "Bob",
    );
    const retire = await jane.post("/users/1", { ...profile, purpose: "retire" });
    assert.equal(retire.status, 303);
    assert.equal(
      (await h.db.prepare("SELECT active FROM users WHERE id=1").first<{ active: number }>())?.active,
      1,
    );
  } finally {
    h.close();
  }
});

test("administrators cannot demote, block or delete their own account", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    const own = (await h.db.prepare("SELECT id FROM accounts").first<{ id: number }>())!.id;
    for (const [path, fields] of [
      [`/accounts/${own}/delete`, {}],
      [`/accounts/${own}`, { role: "user", disabled: "1" }],
    ] as const) {
      const response = await admin.post(path, fields, "/settings");
      assert.match(location(response), /^\/settings/);
    }
    assert.deepEqual(
      { ...(await h.db.prepare("SELECT role,disabled FROM accounts WHERE id=?").bind(own).first()) },
      { role: "admin", disabled: 0 },
    );
    // A second administrator can be created, edited and removed again.
    await admin.post("/accounts", { username: "second", password: "second-pass-1", role: "admin" }, "/settings");
    const second = (await h.db.prepare("SELECT id FROM accounts WHERE username='second'").first<{ id: number }>())!.id;
    assert.match(location(await admin.post(`/accounts/${second}/delete`, {}, "/settings")), /Account\+deleted/);
    assert.equal((await h.db.prepare("SELECT COUNT(*) AS c FROM accounts").first<{ c: number }>())?.c, 1);
  } finally {
    h.close();
  }
});

test("a disabled account cannot sign in and its sessions end", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/settings");
    const jane = browser(h.env);
    await jane.login("jane", "jane-password-1");
    assert.equal((await jane.call("/")).status, 200);
    const id = (await h.db.prepare("SELECT id FROM accounts WHERE username='jane'").first<{ id: number }>())!.id;
    await admin.post(`/accounts/${id}`, { role: "user", disabled: "1" }, "/settings");
    assert.equal(location(await jane.call("/")), "/login");
    assert.match(location(await browser(h.env).login("jane", "jane-password-1")), /Invalid\+username/);
  } finally {
    h.close();
  }
});

test("the Sync API follows the account: own people only, administrators and reader see everyone", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/settings");
    const get = (path: string, user: string, password: string) =>
      handleApp(
        new Request(`${ORIGIN}${path}`, {
          headers: { Authorization: `Basic ${btoa(`${user}:${password}`)}` },
        }),
        h.env,
      );
    assert.equal((await get("/api/users/1/weights", "jane", "jane-password-1")).status, 200);
    assert.equal((await get("/api/users/2/weights", "jane", "jane-password-1")).status, 404);
    assert.equal((await get("/api/users/1/weights", "jane", "wrong-password")).status, 401);
    assert.equal((await get("/api/users/2/weights", "owner", PASSWORD)).status, 200);
    // Legacy name with the shared admin password keeps whole-household access.
    assert.equal((await get("/api/users/2/weights", "reader", PASSWORD)).status, 200);
    assert.equal((await get("/api/users/1/weights", "reader", "jane-password-1")).status, 401);
  } finally {
    h.close();
  }
});

test("changing the own password signs out the other sessions of that account only", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/settings");
    const first = browser(h.env);
    const second = browser(h.env);
    await first.login("jane", "jane-password-1");
    await second.login("jane", "jane-password-1");
    const changed = await first.post("/account", {
      current: "jane-password-1",
      new: "jane-password-2",
      confirm: "jane-password-2",
    });
    assert.match(location(changed), /^\/account/);
    assert.equal((await first.call("/")).status, 200);
    assert.equal(location(await second.call("/")), "/login");
    assert.equal((await admin.call("/")).status, 200);
    assert.match(
      location(
        await first.post("/account", { current: "nope-nope-1", new: "jane-password-3", confirm: "jane-password-3" }),
      ),
      /Current\+password\+is\+incorrect/,
    );
  } finally {
    h.close();
  }
});

test("a backup carries the accounts and their people, restoring access replaces them", async () => {
  const source = await household();
  const target = await household();
  try {
    const admin = await adminBrowser(source.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/settings");
    const backup = await exportBackup(source.db);
    const entry = backup.accessSettings.find((r) => r.key === "accounts");
    assert.ok(entry);
    assert.equal(JSON.parse(String(entry.value)).length, 2);
    // The target already has an unrelated account that restoring access drops.
    await adminBrowser(target.env);
    const preview = await stageBackup(target.db, JSON.stringify(backup), "admin");
    assert.equal(preview.hasAccess, true);
    await commitBackup(target.db, preview.id, preview.digest, "admin", "replace", true);
    const names = await target.db.prepare("SELECT username FROM accounts ORDER BY username").all<{ username: string }>();
    assert.deepEqual(names.results.map((r) => r.username), ["jane", "owner"]);
    assert.deepEqual(
      (await target.db.prepare("SELECT user_id FROM account_users").all<{ user_id: number }>()).results.map((r) => r.user_id),
      [1],
    );
    assert.equal(
      await target.db.prepare("SELECT 1 AS x FROM settings WHERE key='accounts'").first(),
      null,
    );
    const jane = browser(target.env);
    assert.equal(location(await jane.login("jane", "jane-password-1")).startsWith("/?"), true);
    const broken = structuredClone(backup);
    broken.accessSettings = broken.accessSettings.map((r) =>
      r.key === "accounts" ? { ...r, value: JSON.stringify([{ username: "x", role: "root" }]) } : r,
    );
    await assert.rejects(stageBackup(target.db, JSON.stringify(broken), "admin"), /Invalid access settings/);
  } finally {
    source.close();
    target.close();
  }
});
