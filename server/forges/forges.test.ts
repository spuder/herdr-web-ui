import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ForgeCheck, ForgeHostsReport } from "../../shared/protocol.ts";
import { CLI_TOKEN_TTL_MS, ForgeService, handleForgeRequest, normalizeForgeUrl, type ForgeServiceOptions } from "./index.ts";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

interface Call { url: string; authorization: string | null }

/** A ForgeService on a temp state dir, with a host that answers `answer` and a CLI that prints `cli`. */
function service(options: { env?: Record<string, string>; cli?: string | null; answer?: (url: string, auth: string | null) => Response; now?: () => number } = {}) {
  const stateDir = mkdtempSync(join(tmpdir(), "herdr-forges-"));
  dirs.push(stateDir);
  const calls: Call[] = [];
  const commands: string[][] = [];
  const fetch: ForgeServiceOptions["fetch"] = async (url, init) => {
    const authorization = new Headers(init.headers).get("authorization");
    calls.push({ url, authorization });
    return options.answer ? options.answer(url, authorization) : new Response("{}", { status: 404 });
  };
  const run = async (argv: string[]) => { commands.push(argv); return options.cli ?? null; };
  const forges = new ForgeService({ stateDir, env: options.env ?? {}, fetch, run, ...(options.now ? { now: options.now } : {}) });
  return { forges, stateDir, calls, commands, file: join(stateDir, "forges.json") };
}

const json = (body: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json", ...headers } });
const host = (report: ForgeHostsReport, url: string) => report.hosts.find((entry) => entry.url === url)!;

describe("normalizeForgeUrl", () => {
  it("keeps a host's address as one key", () => {
    expect(normalizeForgeUrl("GitHub.com")).toBe("https://github.com");
    expect(normalizeForgeUrl("https://git.example.com/gitea/")).toBe("https://git.example.com/gitea");
    expect(normalizeForgeUrl(" https://git.example.com:8443 ")).toBe("https://git.example.com:8443");
  });

  it("refuses an address a token must not be sent to", () => {
    for (const bad of ["http://git.example.com", "https://me:pw@git.example.com", "https://git.example.com/?a=1", "ftp://git.example.com", "", 42]) {
      expect(() => normalizeForgeUrl(bad)).toThrow();
    }
  });
});

describe("ForgeService credentials", () => {
  it("lists the built-in hosts, each with no credential when none is found", async () => {
    const { forges } = service();
    const report = await forges.report();
    expect(report.hosts.map((entry) => [entry.url, entry.kind, entry.builtin, entry.source])).toEqual([
      ["https://github.com", "github", true, null],
      ["https://gitlab.com", "gitlab", true, null],
      ["https://codeberg.org", "gitea", true, null],
    ]);
  });

  it("takes a saved token first, then the CLI, then the environment", async () => {
    const env = { GH_TOKEN: "ghp_env0000000000000000", GITLAB_TOKEN: "glpat-env" };
    const fromEnv = service({ env });
    expect(host(await fromEnv.forges.report(), "https://github.com")).toMatchObject({ source: "env", env_name: "GH_TOKEN", last4: null });
    expect(host(await fromEnv.forges.report(), "https://gitlab.com")).toMatchObject({ source: "env", env_name: "GITLAB_TOKEN" });

    const fromCli = service({ env, cli: "gho_cli000000000000000000" });
    expect(host(await fromCli.forges.report(), "https://github.com")).toMatchObject({ source: "cli", env_name: null });
    expect(fromCli.commands).toContainEqual(["gh", "auth", "token", "--hostname", "github.com"]);

    const saved = service({ env, cli: "gho_cli000000000000000000", answer: () => json({ login: "octo-dev" }, { "x-oauth-scopes": "repo, read:org" }) });
    await saved.forges.save({ url: "github.com", kind: "github", token: "ghp_saved00000000000000abcd" });
    expect(host(await saved.forges.report(), "https://github.com")).toMatchObject({ source: "token", last4: "abcd", login: "octo-dev", scopes: ["repo", "read:org"] });
  });

  it("asks the CLI again only after a minute", async () => {
    let now = 1_000;
    const { forges, commands } = service({ cli: "gho_cli", now: () => now });
    await forges.report();
    await forges.report();
    expect(commands.filter((argv) => argv[0] === "gh")).toHaveLength(1);
    now += CLI_TOKEN_TTL_MS;
    await forges.report();
    expect(commands.filter((argv) => argv[0] === "gh")).toHaveLength(2);
  });

  it("keeps a token only after the host accepted it, owner-only, and never answers it back", async () => {
    const token = "glpat-secret-token-9z9z";
    const { forges, file, calls } = service({
      answer: (url, auth) => auth !== `Bearer ${token}` ? new Response("", { status: 401 })
        : url.endsWith("/personal_access_tokens/self") ? json({ scopes: ["read_api", "read_repository"], expires_at: "2027-01-02" })
        : json({ username: "m.okafor" }),
    });
    await expect(forges.save({ url: "https://gitlab.example.com", kind: "gitlab", token: "glpat-wrong" })).rejects.toMatchObject({ code: "forge_auth", status: 422 });
    expect(() => statSync(file)).toThrow();

    const report = await forges.save({ url: "https://gitlab.example.com/", kind: "gitlab", token });
    expect(calls.at(-1)?.url).toBe("https://gitlab.example.com/api/v4/personal_access_tokens/self");
    expect(host(report, "https://gitlab.example.com")).toMatchObject({ kind: "gitlab", builtin: false, source: "token", login: "m.okafor", expires_at: "2027-01-02T00:00:00.000Z" });
    expect(JSON.stringify(report)).not.toContain(token);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readFileSync(file, "utf8")).toContain(token);
  });

  it("refuses a built-in host saved as another kind, and a token with spaces", async () => {
    const { forges } = service();
    await expect(forges.save({ url: "github.com", kind: "gitlab", token: "x" })).rejects.toMatchObject({ code: "invalid_request" });
    await expect(forges.save({ url: "github.com", kind: "github", token: "two words" })).rejects.toMatchObject({ code: "invalid_request" });
    await expect(forges.save({ url: "github.com", kind: "forgejo", token: "x" })).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("removes a hand-added host whole, and only the token of a built-in one", async () => {
    const { forges } = service({ answer: () => json({ login: "rivera" }) });
    await forges.save({ url: "git.example.org", kind: "gitea", token: "gitea-token" });
    await forges.save({ url: "codeberg.org", kind: "gitea", token: "codeberg-token" });
    let report = await forges.remove({ url: "https://git.example.org" });
    expect(report.hosts.some((entry) => entry.url === "https://git.example.org")).toBe(false);
    report = await forges.remove({ url: "https://codeberg.org" });
    expect(host(report, "https://codeberg.org")).toMatchObject({ source: null, last4: null });
    await expect(forges.remove({ url: "https://nowhere.example" })).rejects.toMatchObject({ code: "forge_unknown_host", status: 404 });
  });

  it("drops entries it cannot read instead of failing, and never quotes a broken file", async () => {
    const { forges, file } = service();
    writeFileSync(file, JSON.stringify({ version: 1, hosts: [{ url: "http://insecure.example", kind: "github", token: "t" }, { url: "https://ok.example", kind: "svn" }] }));
    expect((await forges.report()).hosts).toHaveLength(3);
    writeFileSync(file, "{ \"token\": \"leaked");
    await expect(forges.report()).rejects.toThrow(/is not valid JSON$/);
  });
});

describe("ForgeService test", () => {
  it("names the scopes a classic GitHub token lacks or holds beyond reading", async () => {
    const { forges, calls } = service({ cli: "gho_cli", answer: () => json({ login: "octo-dev" }, { "x-oauth-scopes": "repo, workflow", "github-authentication-token-expiration": "2027-01-02 00:00:00 UTC" }) });
    const check: ForgeCheck = await forges.test({ url: "https://github.com" });
    expect(calls[0]).toEqual({ url: "https://api.github.com/user", authorization: "Bearer gho_cli" });
    expect(check).toEqual({ url: "https://github.com", source: "cli", login: "octo-dev", scopes: ["repo", "workflow"], expires_at: "2027-01-02T00:00:00.000Z", missing_scopes: [], broad_scopes: ["repo"] });
  });

  it("leaves a fine-grained token's scopes unknown", async () => {
    const { forges } = service({ env: { GH_ENTERPRISE_TOKEN: "github_pat_x" }, answer: () => json({ login: "octo-dev" }) });
    await forges.save({ url: "https://github.example.com", kind: "github", token: "github_pat_saved" });
    expect(await forges.test({ url: "https://github.example.com" })).toMatchObject({ source: "token", scopes: null, missing_scopes: [], broad_scopes: [] });
  });

  it("only reaches a host it has no credential for", async () => {
    const { forges, calls } = service({ answer: () => new Response(null, { status: 200 }) });
    expect(await forges.test({ url: "https://codeberg.org" })).toMatchObject({ source: null, login: null });
    expect(calls).toEqual([{ url: "https://codeberg.org", authorization: null }]);
  });

  it("keeps the token out of a failure's message", async () => {
    const token = "gho_quoted_back";
    const { forges } = service({ cli: token, answer: () => { throw new Error(`connect failed for ${token}`); } });
    const failure = await forges.test({ url: "https://github.com" }).then(() => null, (error: unknown) => error as Error);
    expect(failure).toMatchObject({ code: "forge_unreachable", status: 502 });
    expect(failure?.message).not.toContain(token);
  });
});

describe("handleForgeRequest", () => {
  const post = (path: string, body: unknown, headers: Record<string, string> = { "x-herdr-forge": "1" }) =>
    new Request(`http://localhost${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

  it("needs the forge header and the same origin to change anything", async () => {
    const { forges } = service({ answer: () => json({ login: "octo-dev" }) });
    for (const headers of [{}, { "x-herdr-forge": "1", origin: "https://untrusted.invalid" }, { "x-herdr-forge": "1", "sec-fetch-site": "cross-site" }] as Record<string, string>[]) {
      const refused = await handleForgeRequest(post("/api/forge/hosts", { url: "github.com", kind: "github", token: "t" }, headers), "/api/forge/hosts", forges);
      expect(refused.status).toBe(403);
    }
    const saved = await handleForgeRequest(post("/api/forge/hosts", { url: "github.com", kind: "github", token: "ghp_abcd" }), "/api/forge/hosts", forges);
    expect(saved.status).toBe(200);
    const listed = await handleForgeRequest(new Request("http://localhost/api/forge/hosts"), "/api/forge/hosts", forges);
    expect(listed.headers.get("cache-control")).toBe("no-store");
    const text = await listed.text();
    expect(text).not.toContain("ghp_abcd");
    expect(host(JSON.parse(text) as ForgeHostsReport, "https://github.com").last4).toBe("abcd");
  });

  it("answers errors in the shared envelope", async () => {
    const { forges } = service();
    const bad = await handleForgeRequest(post("/api/forge/hosts/test", { url: "http://github.com" }), "/api/forge/hosts/test", forges);
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: { code: "invalid_request" } });
    const wrongMethod = await handleForgeRequest(new Request("http://localhost/api/forge/hosts/remove"), "/api/forge/hosts/remove", forges);
    expect(wrongMethod.status).toBe(405);
    const unknown = await handleForgeRequest(new Request("http://localhost/api/forge/hosts/nope"), "/api/forge/hosts/nope", forges);
    expect(unknown.status).toBe(404);
  });
});
