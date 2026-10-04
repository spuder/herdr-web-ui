/**
 * Settings → Git hosts: the hosts this PC can read issues, branches and pull requests from, and
 * where each one's credential comes from. A token typed here goes to the server, which checks it
 * with the host before keeping it, and is never shown again: a row shows its last four characters.
 */
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Check, Plus, Server, TriangleAlert } from "lucide-react";

import "./ForgeSettings.css";

import { ApiError, fetchForgeHosts, removeForgeHost, saveForgeHost, testForgeHost } from "../lib/api.ts";
import { currentLocale, useT } from "../lib/i18n.ts";
import type { ForgeCheck, ForgeHostStatus, ForgeKind } from "../../shared/protocol.ts";

const KIND_NAME: Record<ForgeKind, string> = { github: "GitHub", gitlab: "GitLab", gitea: "Gitea · Forgejo" };
const KINDS: ForgeKind[] = ["github", "gitlab", "gitea"];
/** the least a token needs for issues, branches, pull requests and cloning, as each host names it */
const SCOPES: Record<ForgeKind, string> = {
  github: "Issues: read, Contents: read, Pull requests: read",
  gitlab: "read_api, read_repository",
  gitea: "read:issue, read:repository",
};
const HOST_PLACEHOLDER: Record<ForgeKind, string> = { github: "github.example.com", gitlab: "gitlab.example.com", gitea: "git.example.org" };

interface Draft {
  kind: ForgeKind;
  url: string;
  token: string;
  /** replacing the token of a listed host: its address and kind are fixed */
  fixed: boolean;
}

const said = (reason: unknown): string => reason instanceof ApiError ? reason.detail : reason instanceof Error ? reason.message : String(reason);
const hostName = (url: string): string => url.replace(/^https:\/\//, "");

export function ForgeSettings({ open }: { open: boolean }) {
  const t = useT();
  const [hosts, setHosts] = useState<readonly ForgeHostStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [checks, setChecks] = useState<Record<string, ForgeCheck | { failed: string }>>({});
  const [draft, setDraft] = useState<Draft | null>(null);

  const load = useCallback(() => {
    fetchForgeHosts().then((report) => { setHosts(report.hosts); setError(null); }, (reason: unknown) => setError(said(reason)));
  }, []);
  useEffect(() => {
    if (!open) return;
    setChecks({});
    setDraft(null);
    load();
  }, [open, load]);

  const run = async (key: string, task: () => Promise<void>): Promise<void> => {
    setBusy(key);
    setError(null);
    try { await task(); } catch (reason: unknown) { setError(said(reason)); } finally { setBusy(null); }
  };

  const test = (url: string) => void run(`test:${url}`, async () => {
    try {
      const check = await testForgeHost(url);
      setChecks((current) => ({ ...current, [url]: check }));
    } catch (reason: unknown) {
      setChecks((current) => ({ ...current, [url]: { failed: said(reason) } }));
    }
  });

  const remove = (url: string) => void run(`remove:${url}`, async () => {
    setHosts((await removeForgeHost(url)).hosts);
    setChecks(({ [url]: _gone, ...rest }) => rest);
  });

  const save = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (!draft || !draft.url.trim() || !draft.token.trim()) return;
    void run("save", async () => {
      const report = await saveForgeHost({ url: draft.url.trim(), kind: draft.kind, token: draft.token.trim() });
      setHosts(report.hosts);
      setDraft(null);
    });
  };

  const sourceLine = (host: ForgeHostStatus): string => {
    switch (host.source) {
      case "token": {
        const parts = [t("Saved token ending {last4}", { last4: host.last4 ?? "" })];
        if (host.login) parts.push(`@${host.login}`);
        // hosts state an expiry as a UTC date: shown in local time it would land a day early west of UTC
        if (host.expires_at) parts.push(t("expires {date}", { date: new Date(host.expires_at).toLocaleDateString(currentLocale(), { timeZone: "UTC" }) }));
        return parts.join(" · ");
      }
      case "cli": return t("Signed in through the GitHub CLI");
      case "env": return t("Token from {name}", { name: host.env_name ?? "" });
      default: return t("No credential: public repositories only");
    }
  };

  const checkLine = (check: ForgeCheck | { failed: string }) => {
    if ("failed" in check) return <p className="forge-check forge-check-bad" role="status"><TriangleAlert aria-hidden="true" /><span>{check.failed}</span></p>;
    const warnings = [
      ...(check.missing_scopes.length ? [t("Missing scopes: {scopes}", { scopes: check.missing_scopes.join(", ") })] : []),
      ...(check.broad_scopes.length ? [t("It can also write ({scopes}); a read-only token is enough.", { scopes: check.broad_scopes.join(", ") })] : []),
    ];
    const signedIn = check.login ? t("Signed in as @{login}", { login: check.login }) : t("Reachable without signing in");
    const scopes = check.scopes?.length ? ` · ${check.scopes.join(", ")}` : "";
    return (
      <p className={`forge-check ${warnings.length ? "forge-check-bad" : "forge-check-good"}`} role="status">
        {warnings.length ? <TriangleAlert aria-hidden="true" /> : <Check aria-hidden="true" />}
        <span>{signedIn}{scopes}{warnings.map((warning) => <span key={warning} className="forge-check-warning">{warning}</span>)}</span>
      </p>
    );
  };

  return (
    <div className="forge-settings">
      <p className="settings-description">{t("Used to list issues, branches and pull requests on this PC. A saved token is tried first, then a CLI sign-in, then an environment variable.")}</p>
      {hosts && (
        <ul className="forge-hosts">
          {hosts.map((host) => {
            const check = checks[host.url];
            return (
              <li key={host.url} className="forge-host">
                <Server aria-hidden="true" className="forge-host-icon" />
                <div className="forge-host-main">
                  <span className="settings-label">{hostName(host.url)} <span className="forge-kind">{KIND_NAME[host.kind]}</span></span>
                  <span className="settings-description">{sourceLine(host)}</span>
                </div>
                <div className="forge-host-actions">
                  <button type="button" className="btn" disabled={busy !== null} onClick={() => test(host.url)}>{t(busy === `test:${host.url}` ? "Testing…" : "Test")}</button>
                  <button type="button" className="btn" disabled={busy !== null} onClick={() => setDraft({ kind: host.kind, url: host.url, token: "", fixed: true })}>
                    {t(host.source === "token" ? "Replace token" : "Add token")}
                  </button>
                  {(host.source === "token" || !host.builtin) && (
                    <button type="button" className="btn btn-ghost" disabled={busy !== null} onClick={() => remove(host.url)}>{t(host.builtin ? "Remove token" : "Remove")}</button>
                  )}
                </div>
                {check && checkLine(check)}
              </li>
            );
          })}
        </ul>
      )}
      {draft ? (
        <form className="forge-add" onSubmit={save}>
          {!draft.fixed && (
            <div className="field">
              <span className="field-label" id="forge-kind-label">{t("Kind")}</span>
              <div className="segmented" role="group" aria-labelledby="forge-kind-label">
                {KINDS.map((kind) => <button key={kind} type="button" aria-pressed={draft.kind === kind} onClick={() => setDraft({ ...draft, kind })}>{KIND_NAME[kind]}</button>)}
              </div>
            </div>
          )}
          <label className="field">
            <span className="field-label">{t("Host")}</span>
            <input className="input" value={draft.fixed ? hostName(draft.url) : draft.url} readOnly={draft.fixed} placeholder={HOST_PLACEHOLDER[draft.kind]} autoComplete="off" spellCheck={false} autoCapitalize="off" autoCorrect="off" onChange={(event) => setDraft({ ...draft, url: event.target.value })} />
          </label>
          <label className="field">
            <span className="field-label">{t("Token")}</span>
            <input className="input" type="password" value={draft.token} autoComplete="off" spellCheck={false} autoCapitalize="off" autoCorrect="off" autoFocus onChange={(event) => setDraft({ ...draft, token: event.target.value })} />
            <span className="field-hint">{t("Needs {scopes}. The host checks it before it is saved, and it cannot be read back.", { scopes: SCOPES[draft.kind] })}</span>
          </label>
          <div className="forge-add-buttons">
            <button type="button" className="btn btn-ghost" disabled={busy === "save"} onClick={() => setDraft(null)}>{t("Cancel")}</button>
            <button type="submit" className="btn btn-primary" disabled={busy !== null || !draft.url.trim() || !draft.token.trim()}>{t(busy === "save" ? "Checking…" : "Check and save")}</button>
          </div>
        </form>
      ) : (
        <div>
          <button type="button" className="btn" disabled={hosts === null} onClick={() => setDraft({ kind: "gitlab", url: "", token: "", fixed: false })}><Plus aria-hidden="true" />{t("Add host")}</button>
        </div>
      )}
      {error && <p className="settings-hint forge-error" role="alert">{error}</p>}
    </div>
  );
}
