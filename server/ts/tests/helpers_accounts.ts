import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalSqlite } from "../sqlite.ts";
import { handleApp, type AppEnv } from "../app.ts";

export const ORIGIN = "https://local.test";

/** A household with two people, one scale, and one unassigned reading. */
export async function household(extra: Partial<AppEnv> = {}) {
  const directory = mkdtempSync(join(tmpdir(), "yow-accounts-"));
  const store = new LocalSqlite(join(directory, "accounts.sqlite3"));
  const db = store.asD1();
  const env: AppEnv = {
    DB: db,
    YOW_BOOTSTRAP_TOKEN: "dummy-test-bootstrap-token",
    ...extra,
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
export function browser(env: AppEnv) {
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

export const location = (response: Response) => response.headers.get("location") ?? "";
export const PASSWORD = "admin-password-123";

export async function adminBrowser(env: AppEnv) {
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

