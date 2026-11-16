import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";

const store = () => getStore({ name: "health-vault", consistency: "strong" });
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[a-zA-Z0-9-]{8,64}$/;

async function sha256(text: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function authorized(vault: string, token: string) {
  if (!HEX.test(vault) || !HEX.test(token)) return false;
  const saved = await store().get(`${vault}/auth`);
  return saved !== null && saved === (await sha256(token));
}

export default async (req: Request, context: Context) => {
  const s = store();
  const parts = new URL(req.url).pathname.replace(/^\/api\//, "").split("/");
  const vault = req.headers.get("x-vault") ?? "";
  const token = req.headers.get("x-token") ?? "";

  // First-time setup: claim a vault (only works if it doesn't exist yet)
  if (parts[0] === "setup" && req.method === "POST") {
    if (!HEX.test(vault) || !HEX.test(token)) return new Response("Bad request", { status: 400 });
    const { modified } = await s.set(`${vault}/auth`, await sha256(token), { onlyIfNew: true });
    if (!modified) return (await authorized(vault, token))
      ? new Response("ok") : new Response("Vault exists", { status: 409 });
    return new Response("created");
  }

  if (!(await authorized(vault, token))) return new Response("Unauthorized", { status: 401 });

  // Encrypted record index
  if (parts[0] === "index") {
    if (req.method === "GET") {
      const idx = await s.get(`${vault}/index`);
      return new Response(idx ?? "", { status: idx === null ? 404 : 200 });
    }
    if (req.method === "PUT") {
      await s.set(`${vault}/index`, await req.text());
      return new Response("saved");
    }
  }

  // Encrypted file chunks: /api/file/:id/:n
  if (parts[0] === "file" && ID.test(parts[1] ?? "")) {
    const base = `${vault}/files/${parts[1]}/`;
    if (req.method === "DELETE") {
      const { blobs } = await s.list({ prefix: base });
      await Promise.all(blobs.map(b => s.delete(b.key)));
      return new Response("deleted");
    }
    const n = Number(parts[2]);
    if (!Number.isInteger(n) || n < 0 || n > 999) return new Response("Bad chunk", { status: 400 });
    if (req.method === "PUT") {
      await s.set(base + n, await req.arrayBuffer());
      return new Response("saved");
    }
    if (req.method === "GET") {
      const chunk = await s.get(base + n, { type: "arrayBuffer" });
      if (chunk === null) return new Response("Not found", { status: 404 });
      return new Response(chunk, { headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } });
    }
  }
  return new Response("Not found", { status: 404 });
};

export const config: Config = { path: "/api/*" };
