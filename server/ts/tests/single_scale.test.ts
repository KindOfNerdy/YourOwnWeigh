import test from "node:test";
import assert from "node:assert/strict";
import {
  dashboardPage,
  readingsPage,
  scaleBatteries,
  userReadingsPage,
  usersPage,
} from "../ui.ts";

const scale = (id: number, label: string) => ({
  id,
  label,
  model: "WBS04",
  battery_level: 80,
  last_session_at: 1793000000,
});
const user = {
  id: 1,
  name: "Jane Doe",
  short_name: "JAN",
  height_cm: 170,
  birth_date: "1990-01-01",
  sex: 1,
  reference_weight_kg: 70,
  active: 1,
};
const reading = {
  id: 7,
  user_id: 1,
  user_name: "Jane Doe",
  scale_label: "Bathroom",
  weight_value: 70000,
  weight_unit: -3,
  measured_at: 1793000000,
  attribution: "device",
};
const card = (r = reading) => ({ user, readings: [r] });

test("dashboard hides the scale column with a single scale", () => {
  const one = dashboardPage([card()], "kg", [scale(1, "Bathroom")]);
  assert.doesNotMatch(one, /<th>Scale<\/th>/);
  assert.doesNotMatch(one, /<td>Bathroom<\/td>/);
  const two = dashboardPage([card()], "kg", [
    scale(1, "Bathroom"),
    scale(2, "Guest"),
  ]);
  assert.match(two, /<th>Scale<\/th>/);
  assert.match(two, /<td>Bathroom<\/td>/);
});

test("readings pages hide the scale column unless there are several scales", () => {
  const list = (show: boolean) =>
    readingsPage([reading], [user], "kg", "csrf", undefined, 1, "en", show);
  assert.doesNotMatch(list(false), /<th>Scale<\/th>|<td>Bathroom<\/td>/);
  assert.match(list(true), /<th>Scale<\/th>[^]*<td>Bathroom<\/td>/);
  const history = (show: boolean) =>
    userReadingsPage(user, [reading], "kg", undefined, 1, "en", show);
  assert.doesNotMatch(history(false), /<th>Scale<\/th>|<td>Bathroom<\/td>/);
  assert.match(history(true), /<th>Scale<\/th>[^]*<td>Bathroom<\/td>/);
});

test("battery pill names the scale only when there are several", () => {
  assert.doesNotMatch(scaleBatteries([scale(1, "Bathroom")]), /Bathroom/);
  const many = scaleBatteries([scale(1, "Bathroom"), scale(2, "Guest")]);
  assert.match(many, /<span>Bathroom<\/span>/);
  assert.match(many, /<span>Guest<\/span>/);
});

test("people page: no scale column and a plain checkbox with one scale", () => {
  const page = (scales: ReturnType<typeof scale>[]) =>
    usersPage(
      [user],
      scales,
      new Map([[1, new Set(scales.map((s) => s.id))]]),
      "csrf",
      undefined,
      "verified-tls",
    );
  const one = page([scale(1, "Bathroom")]);
  assert.doesNotMatch(one, /<th>Scales<\/th>|<fieldset>/);
  assert.match(one, /name="scales" value="1" checked> Set up on the scale/);
  assert.match(one, /<option value="1" selected>Bathroom<\/option>/);
  const two = page([scale(1, "Bathroom"), scale(2, "Guest")]);
  assert.match(two, /<th>Scales<\/th>/);
  assert.match(two, /<fieldset><legend>Scales<\/legend>/);
  const none = page([]);
  assert.doesNotMatch(none, /name="scales"/);
});
