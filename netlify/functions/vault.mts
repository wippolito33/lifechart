import { getStore } from "@netlify/blobs";
import type { Config } from "@netlify/functions";

// Each account's login checks and locked keys live together in ONE record,
// so an account is saved all at once and can never end up half-created.
const store = () => getStore({ name: "lifechart-v2", consistency: "strong" });
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[a-zA-Z0-9-]{8,64}$/;
const B64 = /^[A-Za-z0-9+/=]{20,4000}$/;

type Account = { auth: string; rauth: string; wrapP: string; wrapR: string };

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

export default async (req: Request) => {
  const s = store();
  const parts = new URL(req.url).pathname.replace(/^\/api\//, "").split("/");
  const route = parts[0];
  const vault = req.headers.get("x-vault") ?? "";
  const token = req.headers.get("x-token") ?? "";
  const rtoken = req.headers.get("x-rtoken") ?? "";
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

  // Everything below needs the passphrase login
  if (!HEX.test(token) || acct.auth !== (await sha256(token))) return bad("Unauthorized", 401);

  if (route === "keys" && req.method === "GET") return new Response(acct.wrapP);

  // Encrypted profile and record list
  if (route === "profile" || route === "index") {
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
