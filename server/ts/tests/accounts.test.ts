import test from "node:test";
import assert from "node:assert/strict";
import { commitBackup, exportBackup, stageBackup } from "../backup.ts";
import { handleApp } from "../app.ts";
import { adminBrowser, browser, household, location, ORIGIN, PASSWORD } from "./helpers_accounts.ts";

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
      "/admin",
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
    for (const path of ["/users", "/scales", "/admin", "/settings", "/firmware"])
      assert.match(location(await jane.call(path)), /^\/\?notice=Administrator\+access\+required/);
    assert.equal((await jane.call("/api/backup/export")).status, 403);
    assert.equal((await jane.call("/api/devices")).status, 403);
    const nav = await (await jane.call("/")).text();
    assert.doesNotMatch(nav, /href="\/users"|href="\/admin"|href="\/firmware"/);
    assert.match(nav, /href="\/account"/);
  } finally {
    h.close();
  }
});

test("users assign unassigned readings only to their own people and cannot delete them", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/admin");
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
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/admin");
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
      const response = await admin.post(path, fields, "/admin");
      assert.match(location(response), /^\/admin/);
    }
    assert.deepEqual(
      { ...(await h.db.prepare("SELECT role,disabled FROM accounts WHERE id=?").bind(own).first()) },
      { role: "admin", disabled: 0 },
    );
    // A second administrator can be created, edited and removed again.
    await admin.post("/accounts", { username: "second", password: "second-pass-1", role: "admin" }, "/admin");
    const second = (await h.db.prepare("SELECT id FROM accounts WHERE username='second'").first<{ id: number }>())!.id;
    assert.match(location(await admin.post(`/accounts/${second}/delete`, {}, "/admin")), /Account\+deleted/);
    assert.equal((await h.db.prepare("SELECT COUNT(*) AS c FROM accounts").first<{ c: number }>())?.c, 1);
  } finally {
    h.close();
  }
});

test("a disabled account cannot sign in and its sessions end", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/admin");
    const jane = browser(h.env);
    await jane.login("jane", "jane-password-1");
    assert.equal((await jane.call("/")).status, 200);
    const id = (await h.db.prepare("SELECT id FROM accounts WHERE username='jane'").first<{ id: number }>())!.id;
    await admin.post(`/accounts/${id}`, { role: "user", disabled: "1" }, "/admin");
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
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/admin");
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
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/admin");
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
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/admin");
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

test("accounts rename themselves; names stay unique", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    await admin.post("/accounts", { username: "jane", password: "jane-password-1", role: "user" }, "/admin");
    const jane = browser(h.env);
    await jane.login("jane", "jane-password-1");
    assert.match(
      location(await jane.post("/account", { purpose: "username", username: "Owner" })),
      /Username\+is\+already\+taken/,
    );
    assert.match(
      location(await jane.post("/account", { purpose: "username", username: "jane.d" })),
      /Username\+changed/,
    );
    assert.equal((await jane.call("/")).status, 200);
    assert.equal(
      location(await browser(h.env).login("jane.d", "jane-password-1")).startsWith("/?"),
      true,
    );
    assert.match(location(await browser(h.env).login("jane", "jane-password-1")), /Invalid\+username/);
  } finally {
    h.close();
  }
});

test("an administrator who narrows their own view only sees the chosen people, yet keeps admin rights", async () => {
  const h = await household();
  try {
    const admin = await adminBrowser(h.env);
    const own = (await h.db.prepare("SELECT id FROM accounts").first<{ id: number }>())!.id;
    // Without the "see all" box and with Jane selected, the views follow.
    const saved = await admin.post(`/accounts/${own}`, { people: "1" }, "/admin");
    assert.match(location(saved), /Account\+saved/);
    const dashboard = await (await admin.call("/")).text();
    assert.match(dashboard, /Jane/);
    assert.doesNotMatch(dashboard, /Bob/);
    assert.equal((await admin.call("/users/1/readings")).status, 200);
    assert.equal((await admin.call("/users/2/readings")).status, 404);
    const readings = await (await admin.call("/readings")).text();
    assert.doesNotMatch(readings, /82\.0/);
    // Management pages still list everyone, and admin actions are not narrowed.
    assert.match(await (await admin.call("/users")).text(), /Bob/);
    assert.equal((await admin.call("/admin")).status, 200);
    const assigned = await admin.post("/readings/3/assign", { user_id: "2" }, "/readings");
    assert.match(location(assigned), /Reading\+assigned/);
    // The Sync API follows the same choice.
    const get = (path: string) =>
      handleApp(
        new Request(`${ORIGIN}${path}`, {
          headers: { Authorization: `Basic ${btoa(`owner:${PASSWORD}`)}` },
        }),
        h.env,
      );
    assert.equal((await get("/api/users/1/weights")).status, 200);
    assert.equal((await get("/api/users/2/weights")).status, 404);
    // Ticking "see all" again restores the full view.
    await admin.post(`/accounts/${own}`, { see_all: "1" }, "/admin");
    assert.match(await (await admin.call("/")).text(), /Bob/);
    assert.equal((await get("/api/users/2/weights")).status, 200);
  } finally {
    h.close();
  }
});
