import { getStore } from "@netlify/blobs";
import type { Config } from "@netlify/functions";

// Each account's login checks and locked keys live together in ONE record,
// so an account is saved all at once and can never end up half-created.
const store = () => getStore({ name: "lifechart-v2", consistency: "strong" });
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[a-zA-Z0-9-]{8,64}$/;
const B64 = /^[A-Za-z0-9+/=]{20,4000}$/;

// passkeys: Face ID / Touch ID sign-ins. Each holds a hash of a token and a locked copy of the
// records key; both come from a secret only that device's passkey can produce (WebAuthn PRF).
type Passkey = { id: string; fauth: string; wrapF: string; name: string; added: string };
type Account = { auth: string; rauth: string; wrapP: string; wrapR: string; passkeys?: Passkey[] };

async function sha256(text: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// Returns the account, or null if there is none or only a broken, half-saved one
async function getAccount(vault: string): Promise<Account | null> {
  const s = store();
  const acct = await s.get(`${vault}/account`, { type: "json" });
  if (acct && acct.auth && acct.rauth && acct.wrapP && acct.wrapR) return acct as Account;
  // Accounts created by the earlier version stored these as separate pieces
  const [auth, rauth, wrapP, wrapR] = await Promise.all(
    ["auth", "rauth", "wrapP", "wrapR"].map(k => s.get(`${vault}/${k}`)));
  if (auth && rauth && wrapP && wrapR) return { auth, rauth, wrapP, wrapR };
  return null;
}

// A finished account has its keys AND its record list. One missing the list
// never got through sign-up (for example, the recovery code was never shown),
// so the same email may sign up again and start fresh.
async function isComplete(vault: string) {
  return (await getAccount(vault)) !== null && (await store().get(`${vault}/index`)) !== null;
}

// Clears every leftover piece of a broken sign-up so the email can be used again
async function clearVault(vault: string) {
  const s = store();
  const { blobs } = await s.list({ prefix: `${vault}/` });
  await Promise.all(blobs.map(b => s.delete(b.key)));
}

const bad = (msg: string, status = 400) => new Response(msg, { status });
const SHARE_ID = /^[A-Za-z0-9_-]{20,40}$/;
async function deleteShare(id: string, vault: string) {
  const s = store();
  const { blobs } = await s.list({ prefix: `share/${id}/` });
  await Promise.all(blobs.map(b => s.delete(b.key)));
  if (HEX.test(vault)) await s.delete(`${vault}/shares/${id}`);
}

// ---------- AI summaries ----------
// The browser unlocks a record and sends it here only when the user asks for a summary.
// Nothing sent here is stored or logged; only the encrypted result is saved by the browser.
const env = (k: string) => (globalThis as any).Netlify?.env.get(k) ?? process.env[k];
const MODEL = () => env("ANTHROPIC_MODEL") || "claude-sonnet-5-5";
const IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];

const RECORD_PROMPT = `You are helping a patient keep an organized personal health record.
Summarize the attached medical document for the patient's own file. Use short plain-text bullets under these labels, skipping any label with nothing to report:
Document: type, date, provider or facility
Findings: key findings and impressions
Diagnoses / conditions
Test results: name, value, units, reference range; mark anything outside range with (HIGH) or (LOW)
Medications: anything started, stopped or changed
Follow-up: recommendations or next steps
Report only what the document says. Do not guess or add advice. Keep it under 300 words, and always finish your last sentence.`;

// The overall summary is written in three parts at the same time, so each part has room
// to finish and stays well inside the 60-second limit for a single request.
const OVERALL_PARTS = [
  ["## Overview", "## Conditions and diagnoses", "## Current medications", "## Allergies"],
  ["## Recent test results (flag anything out of range; include dates)", "## Health trends (from Apple Health or readings the patient entered, if present: notable changes over time in heart rate, blood pressure, weight, glucose, activity, sleep)", "## Imaging and procedures"],
  ["## Care team", "## Timeline (most recent first, at most 25 of the most important events, one line each: date, what happened, source file)", "## Questions to discuss with your doctor"],
];
const overallPrompt = (part: number) => `You are helping a patient keep an organized personal health record.
Above are the patient's profile, short summaries of each record in their file, and possibly Apple Health data (device trends and provider records). You are writing PART ${part + 1} OF 3 of a health summary the patient could read and share with a doctor; other parts are written separately.
Write ONLY these markdown sections, in this order (## headings, - bullets), skipping any with nothing to report:
${OVERALL_PARTS[part].join("\n")}
${part === 0 ? "Begin directly with the first section heading." : "Do not add a title, an introduction, or any other sections."}
Base everything only on the information given and name the source file for key facts. If records disagree or something is unclear, say so. Do not diagnose or give treatment advice. Write in plain language and keep it concise (under about 900 words) so it is not cut off.`;

const LABS_PROMPT = `Extract every numeric laboratory test result from the attached document.
Return ONLY a JSON array (no other text). One object per result:
{"test": "name as printed", "value": number, "unit": "unit as printed or empty", "low": number or null, "high": number or null, "flag": "H", "L" or "", "date": "YYYY-MM-DD" (specimen collection date; null if not shown)}
Rules: use the reference range printed next to the result for low/high (for "<100" use low null, high 100; for ">59" use low 59, high null). For a value printed as "<0.2" use 0.2. Skip results that are not numbers (such as "Negative" or "See note"), comments, and anything that is not a lab test. If there are no lab results, return [].`;

async function callClaude(content: any[], maxTokens: number) {
  const key = env("ANTHROPIC_API_KEY");
  if (!key) throw new Error("The AI key is not set up on the server yet.");
  const r = await fetch((env("ANTHROPIC_BASE_URL") || "https://api.anthropic.com") + "/v1/messages", {
    method: "POST",
    headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model: MODEL(), max_tokens: maxTokens, messages: [{ role: "user", content }] }),
  });
  const j: any = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j?.error?.message || `AI service error (${r.status})`);
  const text = (j.content || []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n").trim();
  return { text, truncated: j.stop_reason === "max_tokens" };
}

async function summarize(req: Request) {
  const b: any = await req.json().catch(() => null);
  if (!b) return bad("Bad request");
  try {
    if (b.mode === "labs") {
      let block: any;
      if (b.mime === "application/pdf") block = { type: "document", source: { type: "base64", media_type: "application/pdf", data: b.data } };
      else if (IMAGE_TYPES.includes(b.mime)) block = { type: "image", source: { type: "base64", media_type: b.mime, data: b.data } };
      else if (typeof b.text === "string") block = { type: "text", text: "Document text:\n" + b.text.slice(0, 200000) };
      else return bad("This file type can't be read.");
      const { text } = await callClaude([block, { type: "text", text: LABS_PROMPT }], 6000);
      const start = text.indexOf("["), end = text.lastIndexOf("]");
      let labs: any[] = [];
      try { labs = start >= 0 && end > start ? JSON.parse(text.slice(start, end + 1)) : []; } catch { return bad("The lab values couldn't be read from this file.", 502); }
      const num = (x: any) => (typeof x === "number" && isFinite(x) ? x : typeof x === "string" && isFinite(parseFloat(x)) ? parseFloat(x) : null);
      labs = (Array.isArray(labs) ? labs : []).map((l: any) => ({
        test: String(l?.test || "").slice(0, 120), value: num(l?.value), unit: String(l?.unit || "").slice(0, 30),
        low: num(l?.low), high: num(l?.high), flag: /^[HL]/i.test(l?.flag || "") ? String(l.flag)[0].toUpperCase() : "",
        date: /^\d{4}-\d\d-\d\d$/.test(l?.date || "") ? l.date : null,
      })).filter((l: any) => l.test && l.value !== null);
      return Response.json({ labs });
    }
    if (b.mode === "record") {
      const meta = `File: ${b.name || "record"}\nRecord type: ${b.category || "unknown"}\nDoctor or facility (entered by patient): ${b.doctor || "not given"}\nDate (entered by patient): ${b.date || "not given"}`;
      let block: any;
      if (b.mime === "application/pdf") block = { type: "document", source: { type: "base64", media_type: "application/pdf", data: b.data } };
      else if (IMAGE_TYPES.includes(b.mime)) block = { type: "image", source: { type: "base64", media_type: b.mime, data: b.data } };
      else if (typeof b.text === "string") block = { type: "text", text: "Document text:\n" + b.text.slice(0, 200000) };
      else return bad("This file type can't be summarized.");
      const { text, truncated } = await callClaude([block, { type: "text", text: meta + "\n\n" + RECORD_PROMPT }], 1600);
      return Response.json({ text, truncated });
    }
    if (b.mode === "overall") {
      const recs = (b.records || []).map((r: any) =>
        `### ${r.name} (${r.category || "record"}, ${r.date || "undated"}, ${r.doctor || "no doctor listed"})\n${r.summary || "(not summarized)"}`).join("\n\n");
      const appleData = typeof b.apple === "string" && b.apple ? `\n\nAPPLE HEALTH DATA (exported from the patient's iPhone: monthly averages from their devices, plus records their providers shared)\n${b.apple.slice(0, 150000)}` : "";
      const part = [0, 1, 2].includes(b.part) ? b.part : 0;
      const input = `PATIENT PROFILE\n${JSON.stringify(b.profile || {}, null, 1)}\n\nRECORD SUMMARIES\n${recs || "(none)"}${appleData}\n\n${overallPrompt(part)}`;
      const { text, truncated } = await callClaude([{ type: "text", text: input }], 3500);
      return Response.json({ text, truncated });
    }
    return bad("Bad request");
  } catch (e: any) {
    return bad(e?.message || "Summary failed", 502);
  }
}

export default async (req: Request) => {
  const s = store();
  const parts = new URL(req.url).pathname.replace(/^\/api\//, "").split("/");
  const route = parts[0];
  const vault = req.headers.get("x-vault") ?? "";
  const token = req.headers.get("x-token") ?? "";
  const rtoken = req.headers.get("x-rtoken") ?? "";

  // ---------- doctor share links: public, read-only ----------
  // /api/s/:id and /api/s/:id/file/:fid/:n. Everything stored here is encrypted with a key that
  // exists only in the link's #fragment, which browsers never send to the server.
  if (route === "s" && SHARE_ID.test(parts[1] ?? "") && req.method === "GET") {
    const id = parts[1], meta: any = await s.get(`share/${id}/meta`, { type: "json" });
    if (!meta) return bad("This link has been turned off or doesn't exist.", 404);
    if (Date.parse(meta.expires) < Date.now()) { await deleteShare(id, meta.vault); return bad("This link has expired.", 410); }
    if (parts[2] === "file" && ID.test(parts[3] ?? "")) {
      const n = Number(parts[4]); if (!Number.isInteger(n) || n < 0 || n > 999) return bad("Bad chunk");
      const chunk = await s.get(`share/${id}/files/${parts[3]}/${n}`, { type: "arrayBuffer" });
      return chunk === null ? bad("Not found", 404) : new Response(chunk, { headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } });
    }
    const bundle = await s.get(`share/${id}/bundle`);
    return bundle === null ? bad("Not found", 404) : new Response(bundle, { headers: { "cache-control": "no-store", "x-expires": meta.expires } });
  }

  if (!HEX.test(vault)) return bad("Bad request");

  // Is there a working account for this email?
  if (route === "exists" && req.method === "GET") {
    return new Response((await isComplete(vault)) ? "yes" : "no");
  }

  // Create an account (also replaces a broken, half-saved one)
  if (route === "signup" && req.method === "POST") {
    const b = await req.json().catch(() => null);
    if (!HEX.test(token) || !b || !HEX.test(b.rtoken ?? "") || !B64.test(b.wrapP ?? "") || !B64.test(b.wrapR ?? "")) return bad("Bad request");
    if (await isComplete(vault)) return bad("Account exists", 409);
    await clearVault(vault);
    const acct: Account = { auth: await sha256(token), rauth: await sha256(b.rtoken), wrapP: b.wrapP, wrapR: b.wrapR };
    await s.setJSON(`${vault}/account`, acct);
    // Read it back to confirm this sign-up's record is the one saved
    const saved = await getAccount(vault);
    if (!saved || saved.auth !== acct.auth) return bad("Account exists", 409);
    return new Response("created");
  }

  const acct = await getAccount(vault);
  if (!acct) return bad("No account", 404);

  // Forgot passphrase: the recovery code unlocks the backup key, then a new passphrase is set
  if (route === "recover" || route === "reset") {
    if (!HEX.test(rtoken) || acct.rauth !== (await sha256(rtoken))) return bad("Unauthorized", 401);
    if (route === "recover" && req.method === "GET") return new Response(acct.wrapR);
    if (route === "reset" && req.method === "POST") {
      const b = await req.json().catch(() => null);
      if (!b || !HEX.test(b.token ?? "") || !B64.test(b.wrapP ?? "")) return bad("Bad request");
      await s.setJSON(`${vault}/account`, { ...acct, auth: await sha256(b.token), wrapP: b.wrapP });
      return new Response("reset");
    }
    return bad("Not found", 404);
  }

  // Face ID sign-in: the device's passkey secret unlocks its locked copy of the records key
  if (route === "passkey" && parts[1] === "unlock" && req.method === "GET") {
    const ft = req.headers.get("x-ftoken") ?? "";
    if (!HEX.test(ft)) return bad("Bad request");
    const h = await sha256(ft), pk = (acct.passkeys || []).find(p => p.fauth === h);
    return pk ? new Response(pk.wrapF) : bad("Unauthorized", 401);
  }

  // Everything below needs to be signed in (passphrase, or a Face ID passkey)
  const th = HEX.test(token) ? await sha256(token) : "";
  if (!th || (acct.auth !== th && !(acct.passkeys || []).some(p => p.fauth === th))) return bad("Unauthorized", 401);

  if (route === "passkey") {
    const list = acct.passkeys || [];
    if (req.method === "GET") return Response.json(list.map(({ id, name, added }) => ({ id, name, added })));
    if (req.method === "POST") {
      const b = await req.json().catch(() => null);
      if (!b || typeof b.id !== "string" || !/^[A-Za-z0-9_-]{8,1400}$/.test(b.id) || !HEX.test(b.ftoken ?? "") || !B64.test(b.wrapF ?? "")) return bad("Bad request");
      if (list.length >= 10) return bad("Too many devices. Remove one first.", 409);
      const pk: Passkey = { id: b.id, fauth: await sha256(b.ftoken), wrapF: b.wrapF, name: String(b.name || "This device").slice(0, 60), added: new Date().toISOString() };
      await s.setJSON(`${vault}/account`, { ...acct, passkeys: [...list.filter(p => p.id !== b.id), pk] });
      return new Response("added");
    }
    if (req.method === "DELETE" && parts[1]) {
      await s.setJSON(`${vault}/account`, { ...acct, passkeys: list.filter(p => p.id !== parts[1]) });
      return new Response("removed");
    }
  }

  if (route === "keys" && req.method === "GET") return new Response(acct.wrapP);

  if (route === "summarize" && req.method === "POST") return summarize(req);

  // Encrypted profile, record list and saved health summary
  if (["profile", "index", "summary", "apple", "appleDaily", "manual", "shareList"].includes(route)) {
    if (req.method === "GET") {
      const v = await s.get(`${vault}/${route}`);
      return v === null ? bad("Not found", 404) : new Response(v);
    }
    if (req.method === "PUT") {
      await s.set(`${vault}/${route}`, await req.text());
      return new Response("saved");
    }
  }

  // Encrypted file chunks: /api/file/:id/:n
  // ---------- doctor share links: owner side ----------
  if (route === "share") {
    const id = parts[1] ?? "";
    if (req.method === "GET" && !id) { // the owner's links (just ids and dates; labels stay in the encrypted list)
      const { blobs } = await s.list({ prefix: `${vault}/shares/` });
      const out = [];
      for (const b of blobs) { const m: any = await s.get(b.key, { type: "json" }); if (m) out.push({ id: b.key.split("/").pop(), expires: m.expires }); }
      return Response.json(out);
    }
    if (!SHARE_ID.test(id)) return bad("Bad request");
    const meta: any = await s.get(`share/${id}/meta`, { type: "json" });
    if (meta && meta.vault !== vault) return bad("Not yours", 403);
    if (req.method === "POST" && !parts[2]) { // create: the encrypted bundle and the expiry date
      const b: any = await req.json().catch(() => null);
      const exp = Date.parse(b?.expires);
      if (meta || !b || typeof b.bundle !== "string" || b.bundle.length > 4500000 || !(exp > Date.now()) || exp > Date.now() + 366 * 864e5) return bad("Bad request");
      const m = { vault, expires: new Date(exp).toISOString(), created: new Date().toISOString() };
      await s.setJSON(`share/${id}/meta`, m); await s.set(`share/${id}/bundle`, b.bundle); await s.setJSON(`${vault}/shares/${id}`, { expires: m.expires });
      return new Response("created");
    }
    if (req.method === "PUT" && parts[2] === "file" && ID.test(parts[3] ?? "") && meta) { // a shared copy of a record, re-encrypted for the link
      const n = Number(parts[4]); if (!Number.isInteger(n) || n < 0 || n > 999) return bad("Bad chunk");
      await s.set(`share/${id}/files/${parts[3]}/${n}`, await req.arrayBuffer());
      return new Response("saved");
    }
    if (req.method === "DELETE") { await deleteShare(id, vault); return new Response("removed"); }
    return bad("Not found", 404);
  }

  if (route === "file" && ID.test(parts[1] ?? "")) {
    const base = `${vault}/files/${parts[1]}/`;
    if (req.method === "DELETE") {
      const { blobs } = await s.list({ prefix: base });
      await Promise.all(blobs.map(b => s.delete(b.key)));
      return new Response("deleted");
    }
    const n = Number(parts[2]);
    if (!Number.isInteger(n) || n < 0 || n > 999) return bad("Bad chunk");
    if (req.method === "PUT") {
      await s.set(base + n, await req.arrayBuffer());
      return new Response("saved");
    }
    if (req.method === "GET") {
      const chunk = await s.get(base + n, { type: "arrayBuffer" });
      if (chunk === null) return bad("Not found", 404);
      return new Response(chunk, { headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } });
    }
  }
  return bad("Not found", 404);
};

export const config: Config = { path: "/api/*" };
