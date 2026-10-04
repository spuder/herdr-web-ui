/**
 * GitLab, gitlab.com or self-managed. A personal, project or group access token describes itself
 * at `/personal_access_tokens/self`; an OAuth token cannot, and then its scopes are null.
 *
 * Placeholder: only the sign-in check works. Issues, branches and merge requests come after GitHub's.
 */

import { ForgeError, getJson, hostOf, isoTime, record, text, type ForgeProvider } from "./provider.ts";

export const gitlab: ForgeProvider = {
  kind: "gitlab",
  apiBase: (url) => `${url}/api/v4`,
  envNames: () => ["GITLAB_TOKEN"],
  async whoami(url, token, fetch) {
    const headers = { authorization: `Bearer ${token}` };
    const { body } = await getJson(fetch, `${gitlab.apiBase(url)}/user`, headers, token, hostOf(url));
    let scopes: string[] | null = null;
    let expires: string | null = null;
    try {
      const self = record((await getJson(fetch, `${gitlab.apiBase(url)}/personal_access_tokens/self`, headers, token, hostOf(url))).body);
      const listed = self["scopes"];
      if (Array.isArray(listed)) scopes = listed.filter((scope): scope is string => typeof scope === "string");
      expires = isoTime(text(self["expires_at"]));
    } catch (error) {
      if (!(error instanceof ForgeError)) throw error;
    }
    return { login: text(record(body)["username"]), scopes, expires_at: expires };
  },
  scopeNotes(scopes) {
    const missing: string[] = [];
    if (!scopes.includes("read_api") && !scopes.includes("api")) missing.push("read_api");
    if (!scopes.includes("read_repository") && !scopes.includes("write_repository")) missing.push("read_repository");
    return { missing, broad: scopes.filter((scope) => scope === "api" || scope === "write_repository" || scope === "sudo") };
  },
};
