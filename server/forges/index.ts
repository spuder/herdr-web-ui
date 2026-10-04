/**
 * Git hosts (forges) and their credentials. A host's credential is looked up in this order: a
 * token saved in Settings, the host's CLI sign-in (`gh`), an environment variable, none. A saved
 * token lives in stateDir/forges.json (0600) and leaves this server only for the host it was
 * saved for; a CLI's token is read when needed, kept in memory for a minute, and never written.
 * No answer, log line or error message carries a token.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ForgeCheck, ForgeCredentialSource, ForgeHostStatus, ForgeHostsReport, ForgeKind } from "../../shared/protocol.ts";
import { errorResponse, isJsonObject, jsonResponse } from "../http.ts";
import { sameOrigin } from "../machine-security.ts";
import { gitea } from "./gitea.ts";
import { github } from "./github.ts";
import { gitlab } from "./gitlab.ts";
import { ForgeError, FORGE_TIMEOUT_MS, record, scrub, text, type ForgeFetch, type ForgeProvider } from "./provider.ts";

export { ForgeError } from "./provider.ts";

export const FORGE_PROVIDERS: Record<ForgeKind, ForgeProvider> = { github, gitlab, gitea };

/** Always listed: the public hosts most repositories live on. Codeberg runs Forgejo. */
export const BUILTIN_HOSTS: ReadonlyArray<{ url: string; kind: ForgeKind }> = [
  { url: "https://github.com", kind: "github" },
  { url: "https://gitlab.com", kind: "gitlab" },
  { url: "https://codeberg.org", kind: "gitea" },
];

/** How long a CLI's answer is reused: a sign-in changed in a terminal shows within a minute. */
export const CLI_TOKEN_TTL_MS = 60_000;
const TOKEN_MAX_CHARS = 2000;

interface StoredHost {
  url: string;
  kind: ForgeKind;
  token?: string;
  login?: string | null;
  scopes?: string[] | null;
  expires_at?: string | null;
}

interface ForgeFile {
  version: 1;
  hosts: StoredHost[];
}

export interface ForgeServiceOptions {
  stateDir: string;
  env: Record<string, string | undefined>;
  fetch: ForgeFetch;
  /** a command's trimmed stdout, or null when it is missing, fails or hangs (usage.ts runCommand) */
  run(argv: string[]): Promise<string | null>;
  now?: () => number;
}

interface Credential {
  source: ForgeCredentialSource;
  token: string | null;
  envName: string | null;
}

const invalid = (message: string) => new ForgeError("invalid_request", 400, message);
const isKind = (value: unknown): value is ForgeKind => value === "github" || value === "gitlab" || value === "gitea";

/**
 * A host's web address as the key it is kept under: https only, no credentials, query or
 * fragment, a lower-case host, no trailing slash. A bare host name is taken as https.
 */
export function normalizeForgeUrl(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw invalid("url must be a host's web address");
  const raw = value.trim();
  let url: URL;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`); } catch { throw invalid("url must be a host's web address"); }
  // a token is sent only over TLS
  if (url.protocol !== "https:") throw invalid("url must start with https://");
  if (url.username || url.password || url.search || url.hash) throw invalid("url must be only the host's address, without a user, query or fragment");
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** Owner-only, and written whole: a crash mid-write must not leave half a token file. */
function writeJsonPrivate(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

export class ForgeService {
  private readonly path: string;
  private readonly env: ForgeServiceOptions["env"];
  private readonly fetch: ForgeFetch;
  private readonly run: ForgeServiceOptions["run"];
  private readonly now: () => number;
  private readonly cliTokens = new Map<string, { token: string | null; at: number }>();

  constructor(options: ForgeServiceOptions) {
    this.path = join(options.stateDir, "forges.json");
    this.env = options.env;
    this.fetch = options.fetch;
    this.run = options.run;
    this.now = options.now ?? Date.now;
  }

  private read(): ForgeFile {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, hosts: [] };
      throw error;
    }
    let parsed: unknown;
    // the parser's message may quote the file, and the file holds tokens
    try { parsed = JSON.parse(raw); } catch { throw new Error(`${this.path} is not valid JSON`); }
    const hosts: StoredHost[] = [];
    const listed = record(parsed)["hosts"];
    for (const entry of Array.isArray(listed) ? listed : []) {
      const host = record(entry);
      let url: string;
      try { url = normalizeForgeUrl(host["url"]); } catch { continue; }
      if (!isKind(host["kind"]) || hosts.some((known) => known.url === url)) continue;
      const scopes = host["scopes"];
      hosts.push({
        url,
        kind: host["kind"],
        ...(text(host["token"]) ? { token: text(host["token"])! } : {}),
        login: text(host["login"]),
        scopes: Array.isArray(scopes) ? scopes.filter((scope): scope is string => typeof scope === "string") : null,
        expires_at: text(host["expires_at"]),
      });
    }
    return { version: 1, hosts };
  }

  /** The built-in hosts, then those added by hand, each once. */
  private known(file: ForgeFile): Array<StoredHost & { builtin: boolean }> {
    const builtins = BUILTIN_HOSTS.map((host) => ({ ...host, ...file.hosts.find((saved) => saved.url === host.url), kind: host.kind, builtin: true }));
    const added = file.hosts.filter((saved) => !BUILTIN_HOSTS.some((host) => host.url === saved.url)).map((saved) => ({ ...saved, builtin: false }));
    return [...builtins, ...added];
  }

  private async cliToken(provider: ForgeProvider, url: string): Promise<string | null> {
    if (!provider.cliTokenCommand) return null;
    const cached = this.cliTokens.get(url);
    if (cached && this.now() - cached.at < CLI_TOKEN_TTL_MS) return cached.token;
    const token = text(await this.run(provider.cliTokenCommand(url)));
    this.cliTokens.set(url, { token, at: this.now() });
    return token;
  }

  private async credential(host: StoredHost): Promise<Credential> {
    if (host.token) return { source: "token", token: host.token, envName: null };
    const provider = FORGE_PROVIDERS[host.kind];
    const fromCli = await this.cliToken(provider, host.url);
    if (fromCli) return { source: "cli", token: fromCli, envName: null };
    for (const name of provider.envNames(host.url)) {
      const value = text(this.env[name]);
      if (value) return { source: "env", token: value, envName: name };
    }
    return { source: null, token: null, envName: null };
  }

  async report(): Promise<ForgeHostsReport> {
    const hosts = await Promise.all(this.known(this.read()).map(async (host): Promise<ForgeHostStatus> => {
      const { source, envName } = await this.credential(host);
      const saved = source === "token";
      return {
        url: host.url,
        kind: host.kind,
        builtin: host.builtin,
        source,
        last4: saved && host.token ? host.token.slice(-4) : null,
        login: saved ? host.login ?? null : null,
        scopes: saved ? host.scopes ?? null : null,
        expires_at: saved ? host.expires_at ?? null : null,
        env_name: envName,
      };
    }));
    return { hosts };
  }

  /** `body` is a SaveForgeHostRequest off the wire, checked here. The host must accept the token before it is kept. */
  async save(body: unknown): Promise<ForgeHostsReport> {
    if (!isJsonObject(body)) throw invalid("Send a JSON object");
    const url = normalizeForgeUrl(body["url"]);
    const builtin = BUILTIN_HOSTS.find((host) => host.url === url);
    if (!isKind(body["kind"])) throw invalid("kind must be github, gitlab or gitea");
    if (builtin && builtin.kind !== body["kind"]) throw invalid(`${url} is a ${builtin.kind} host`);
    const token = body["token"];
    if (typeof token !== "string" || !token.trim() || token.length > TOKEN_MAX_CHARS || /\s/.test(token.trim())) {
      throw invalid("token must be a non-empty string without spaces");
    }
    const kind = body["kind"];
    const identity = await FORGE_PROVIDERS[kind].whoami(url, token.trim(), this.fetch);
    // read after the check: a save that landed meanwhile is kept
    const file = this.read();
    const next: StoredHost = { url, kind, token: token.trim(), login: identity.login, scopes: identity.scopes, expires_at: identity.expires_at };
    file.hosts = [...file.hosts.filter((host) => host.url !== url), next];
    writeJsonPrivate(this.path, file);
    return this.report();
  }

  /** Drops a saved token; a host added by hand goes with it, a built-in host stays and falls back to the CLI. */
  async remove(body: unknown): Promise<ForgeHostsReport> {
    if (!isJsonObject(body)) throw invalid("Send a JSON object");
    const url = normalizeForgeUrl(body["url"]);
    const file = this.read();
    if (!this.known(file).some((host) => host.url === url)) throw new ForgeError("forge_unknown_host", 404, `${url} is not a host on this PC`);
    file.hosts = file.hosts.filter((host) => host.url !== url);
    writeJsonPrivate(this.path, file);
    return this.report();
  }

  /** Signs in with the credential in use. Without one, the host is only reached. */
  async test(body: unknown): Promise<ForgeCheck> {
    if (!isJsonObject(body)) throw invalid("Send a JSON object");
    const url = normalizeForgeUrl(body["url"]);
    const host = this.known(this.read()).find((known) => known.url === url);
    if (!host) throw new ForgeError("forge_unknown_host", 404, `${url} is not a host on this PC`);
    const provider = FORGE_PROVIDERS[host.kind];
    const { source, token } = await this.credential(host);
    if (!token) {
      try {
        const response = await this.fetch(url, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(FORGE_TIMEOUT_MS) });
        await response.body?.cancel();
      } catch (error) {
        throw new ForgeError("forge_unreachable", 502, `Could not reach ${new URL(url).host}: ${error instanceof Error ? error.message : String(error)}`);
      }
      return { url, source, login: null, scopes: null, expires_at: null, missing_scopes: [], broad_scopes: [] };
    }
    try {
      const identity = await provider.whoami(url, token, this.fetch);
      const notes = identity.scopes === null ? { missing: [], broad: [] } : provider.scopeNotes(identity.scopes);
      return { url, source, ...identity, missing_scopes: notes.missing, broad_scopes: notes.broad };
    } catch (error) {
      // a CLI sign-in revoked in a terminal is read again next time
      if (source === "cli") this.cliTokens.delete(url);
      if (error instanceof ForgeError) throw new ForgeError(error.code, error.status, scrub(error.message, token));
      throw error;
    }
  }
}

function forgeError(error: unknown): Response {
  if (error instanceof ForgeError) return jsonResponse({ error: { code: error.code, message: error.message } }, error.status);
  return errorResponse(error);
}

/** The forge routes. A POST must come from this app: same origin and the `x-herdr-forge: 1` header. */
export async function handleForgeRequest(request: Request, pathname: string, service: ForgeService): Promise<Response> {
  const noStore = { "cache-control": "no-store" };
  const posts: Record<string, (body: unknown) => Promise<unknown>> = {
    "/api/forge/hosts": (body) => service.save(body),
    "/api/forge/hosts/remove": (body) => service.remove(body),
    "/api/forge/hosts/test": (body) => service.test(body),
  };
  if (pathname === "/api/forge/hosts" && request.method === "GET") {
    try { return jsonResponse(await service.report(), 200, noStore); } catch (error) { return forgeError(error); }
  }
  const post = posts[pathname];
  if (!post) return jsonResponse({ error: { code: "not_found", message: "not found" } }, 404);
  if (request.method !== "POST") {
    const allow = pathname === "/api/forge/hosts" ? "GET, POST" : "POST";
    return jsonResponse({ error: { code: "method_not_allowed", message: `Use ${allow} ${pathname}` } }, 405, { allow });
  }
  if (!sameOrigin(request) || request.headers.get("x-herdr-forge") !== "1") {
    return jsonResponse({ error: { code: "invalid_origin", message: "Manage git hosts from this app" } }, 403);
  }
  let body: unknown;
  try { body = await request.json(); } catch { return forgeError(invalid("Send a JSON object")); }
  try { return jsonResponse(await post(body), 200, noStore); } catch (error) { return forgeError(error); }
}
