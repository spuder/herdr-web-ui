/**
 * GitHub and GitHub Enterprise Server. github.com's API lives on api.github.com, a server's
 * under `/api/v3`. A classic token lists its scopes in `x-oauth-scopes`; a fine-grained token
 * lists none, and its permissions are not readable, so its scopes are null.
 */

import { getJson, hostOf, isoTime, record, text, type ForgeProvider } from "./provider.ts";

const GITHUB_COM = "https://github.com";

export const github: ForgeProvider = {
  kind: "github",
  apiBase: (url) => url === GITHUB_COM ? "https://api.github.com" : `${url}/api/v3`,
  // the variables gh itself reads, for github.com and for an Enterprise server
  envNames: (url) => url === GITHUB_COM ? ["GH_TOKEN", "GITHUB_TOKEN"] : ["GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"],
  cliTokenCommand: (url) => ["gh", "auth", "token", "--hostname", hostOf(url)],
  async whoami(url, token, fetch) {
    const { response, body } = await getJson(fetch, `${github.apiBase(url)}/user`, { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" }, token, hostOf(url));
    const listed = response.headers.get("x-oauth-scopes");
    return {
      login: text(record(body)["login"]),
      scopes: listed === null ? null : listed.split(",").map((scope) => scope.trim()).filter(Boolean),
      expires_at: isoTime(response.headers.get("github-authentication-token-expiration")),
    };
  },
  scopeNotes(scopes) {
    // a classic token reads a private repository only through `repo`, which also writes to it
    const reads = scopes.includes("repo") || scopes.includes("public_repo");
    return { missing: reads ? [] : ["repo"], broad: scopes.filter((scope) => scope === "repo" || scope === "delete_repo" || scope.startsWith("admin:")) };
  },
};
