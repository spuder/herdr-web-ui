/**
 * Gitea and Forgejo, which keep one API under `/api/v1`. Neither tells a token its own scopes,
 * so they are null.
 *
 * Placeholder: only the sign-in check works. Issues, branches and pull requests come after GitHub's.
 */

import { getJson, hostOf, record, text, type ForgeProvider } from "./provider.ts";

export const gitea: ForgeProvider = {
  kind: "gitea",
  apiBase: (url) => `${url}/api/v1`,
  envNames: () => ["GITEA_TOKEN", "FORGEJO_TOKEN"],
  async whoami(url, token, fetch) {
    const { body } = await getJson(fetch, `${gitea.apiBase(url)}/user`, { authorization: `token ${token}` }, token, hostOf(url));
    return { login: text(record(body)["login"]), scopes: null, expires_at: null };
  },
  scopeNotes: () => ({ missing: [], broad: [] }),
};
