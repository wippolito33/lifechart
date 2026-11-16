import { getStore } from "@netlify/blobs";
import type { Config } from "@netlify/functions";

// v2 store: accounts with a profile and a recovery code
const store = () => getStore({ name: "lifechart-v2", consistency: "strong" });
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[a-zA-Z0-9-]{8,64}$/;
const B64 = /^[A-Za-z0-9+/=]{20,4000}$/;

async function sha256(text: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function matches(vault: string, token: string, slot: "auth" | "rauth") {
  if (!HEX.test(vault) || !HEX.test(token)) return false;
  const saved = await store().get(`${vault}/${slot}`);
  return saved !== null && saved === (await sha256(token));
}

const bad = (msg: string, status = 400) => new Response(msg, { status });

export default async (req: Request) => {
  const s = store();
  const parts = new URL(req.url).pathname.replace(/^\/api\//, "").split("/");
  const route = parts[0];
  const vault = req.headers.get("x-vault") ?? "";
  const token = req.headers.get("x-token") ?? "";
  const rtoken = req.headers.get("x-rtoken") ?? "";

  // Is this username taken?
  if (route === "exists" && req.method === "GET") {
    if (!HEX.test(vault)) return bad("Bad request");
    return new Response((await s.get(`${vault}/auth`)) === null ? "no" : "yes");
  }

  // Create an account
  if (route === "signup" && req.method === "POST") {
    const b = await req.json().catch(() => null);
    if (!HEX.test(vault) || !HEX.test(token) || !b || !HEX.test(b.rtoken ?? "") || !B64.test(b.wrapP ?? "") || !B64.test(b.wrapR ?? "")) return bad("Bad request");
    const { modified } = await s.set(`${vault}/auth`, await sha256(token), { onlyIfNew: true });
    if (!modified) return bad("Username taken", 409);
    await Promise.all([
      s.set(`${vault}/rauth`, await sha256(b.rtoken)),
      s.set(`${vault}/wrapP`, b.wrapP),
      s.set(`${vault}/wrapR`, b.wrapR),
    ]);
    return new Response("created");
  }

  // Forgot passphrase: the recovery code unlocks the backup key, then a new passphrase is set
  if (route === "recover" || route === "reset") {
    if (!(await matches(vault, rtoken, "rauth"))) return bad("Unauthorized", 401);
    if (route === "recover" && req.method === "GET") return new Response((await s.get(`${vault}/wrapR`)) ?? "");
    if (route === "reset" && req.method === "POST") {
      const b = await req.json().catch(() => null);
      if (!b || !HEX.test(b.token ?? "") || !B64.test(b.wrapP ?? "")) return bad("Bad request");
      await s.set(`${vault}/auth`, await sha256(b.token));
      await s.set(`${vault}/wrapP`, b.wrapP);
      return new Response("reset");
    }
    return bad("Not found", 404);
  }

  // Everything below needs the passphrase login
  if (!(await matches(vault, token, "auth"))) return bad("Unauthorized", 401);

  if (route === "keys" && req.method === "GET") return new Response((await s.get(`${vault}/wrapP`)) ?? "");

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
