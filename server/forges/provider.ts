/**
 * What every git host adapter answers. Only the sign-in check is here so far: listing issues,
 * branches and pull requests, and cloning, come next, GitHub first, and an adapter without them
 * answers `forge_not_supported`.
 */

import type { ForgeKind } from "../../shared/protocol.ts";
import { isJsonObject } from "../http.ts";

/** The host's API took longer than a person waits on a settings button. */
export const FORGE_TIMEOUT_MS = 10_000;
const MESSAGE_MAX_CHARS = 300;

export type ForgeErrorCode =
  | "invalid_request" // 400: a malformed body or URL
  | "forge_unknown_host" // 404: no such host on this PC
  | "forge_auth" // 422: the host refused the token
  | "forge_unreachable" // 502: the host could not be reached
  | "forge_error" // 502: the host answered something else
  | "forge_not_supported"; // 501: this kind of host cannot do that yet

export class ForgeError extends Error {
  constructor(readonly code: ForgeErrorCode, readonly status: number, message: string) {
    super(message);
  }
}

export interface ForgeFetch {
  (url: string, init: RequestInit): Promise<Response>;
}

/** Who a token signs in as. `scopes` is null when the host does not list a token's scopes. */
export interface ForgeIdentity {
  login: string | null;
  scopes: string[] | null;
  expires_at: string | null;
}

export interface ForgeProvider {
  kind: ForgeKind;
  /** The REST root for a host's web address. */
  apiBase(url: string): string;
  /** Variables a token is read from, the first set one winning. */
  envNames(url: string): string[];
  /** The host's CLI command that prints its token, when the host has a common CLI. */
  cliTokenCommand?(url: string): string[];
  whoami(url: string, token: string, fetch: ForgeFetch): Promise<ForgeIdentity>;
  /** Scopes a token lacks for reading issues, branches and pull requests, and those it holds beyond reading. */
  scopeNotes(scopes: string[]): { missing: string[]; broad: string[] };
}

export function record(value: unknown): Record<string, unknown> {
  return isJsonObject(value) ? value : {};
}

export function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/** A host's words, without the token it may quote back. */
export function scrub(message: string, token: string | null): string {
  return (token ? message.split(token).join("***") : message).slice(0, MESSAGE_MAX_CHARS);
}

/** The host name of a web address, as a CLI keys its sign-ins. */
export function hostOf(url: string): string {
  return new URL(url).host;
}

/** An ISO 8601 time from whatever date text the host sends; null when it is not one. */
export function isoTime(value: string | null): string | null {
  if (!value) return null;
  const time = Date.parse(value.replace(/ UTC$/, "Z").replace(" ", "T"));
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

/**
 * A GET with the token, answered as JSON. 401 and 403 are the host refusing the token; the
 * response is returned with its body so a caller can read headers too.
 */
export async function getJson(fetch: ForgeFetch, url: string, headers: Record<string, string>, token: string, name: string): Promise<{ response: Response; body: unknown }> {
  let response: Response;
  try {
    response = await fetch(url, { method: "GET", headers: { accept: "application/json", "user-agent": "herdr-web-ui", ...headers }, redirect: "error", signal: AbortSignal.timeout(FORGE_TIMEOUT_MS) });
  } catch (error) {
    throw new ForgeError("forge_unreachable", 502, scrub(`Could not reach ${name}: ${error instanceof Error ? error.message : String(error)}`, token));
  }
  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel();
    throw new ForgeError("forge_auth", 422, `${name} refused the token (${response.status})`);
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new ForgeError("forge_error", 502, `${name} answered ${response.status}`);
  }
  let body: unknown;
  try { body = await response.json(); } catch { throw new ForgeError("forge_error", 502, `${name} answered something that is not JSON`); }
  return { response, body };
}
