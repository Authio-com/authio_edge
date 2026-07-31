/**
 * @useauthio/edge — verify Authio JWTs at any edge runtime.
 *
 * Runtime-agnostic: works on Cloudflare Workers, Vercel Edge, Deno Deploy,
 * Bun, and standard Node.js. Use this when you want sub-50ms session
 * checks at your edge without a network call back to auth-core.
 *
 * Multi-org-first: the verified `Session.userId` is the person; `orgId`
 * is the active organization claim, which may be null when the user has
 * authenticated but not yet selected an org.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

/** Authio's production JWT issuer. */
const DEFAULT_ISSUER = "https://identity.authio.com";
/** Authio's production JWT audience. */
const DEFAULT_AUDIENCE = "authio";

export interface EdgeAuthOptions {
  /** Auth-core base URL (e.g. https://identity.authio.com). */
  apiUrl: string;
  /**
   * Expected JWT issuer. Defaults to Authio's production issuer.
   *
   * This is ALWAYS enforced. It used to be passed straight through to
   * jose, which silently skips the check when the value is undefined —
   * and since the documented usage omitted it, the issuer was in
   * practice never verified. Pass an explicit value only when running
   * against a self-hosted or staging auth-core.
   */
  issuer?: string;
  /**
   * Expected JWT audience. Defaults to Authio's production audience.
   * Always enforced, for the same reason as `issuer`.
   */
  audience?: string;
  /**
   * Your Authio project id (`proj_…`). Strongly recommended.
   *
   * Every tenant's tokens are signed with the same key, issuer and
   * audience, so those three prove a token came from Authio but not
   * that it was minted for you. With `projectId` set, a token naming a
   * different project is rejected — which is what stops someone from
   * creating `ceo@your-company.com` in their own Authio project and
   * presenting that token here.
   */
  projectId?: string;
}

export interface EdgeSession {
  sessionId: string;
  userId: string;
  orgId: string | null;
  role: string | null;
  expiresAt: number;
}

interface AuthioJwt extends JWTPayload {
  sub: string;
  act_org?: string;
  act_role?: string;
  sid?: string;
  project_id?: string;
}

export class EdgeAuth {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private readonly issuer: string;
  private readonly audience: string;
  private warnedNoProjectConfigured = false;
  private warnedClaimAbsent = false;

  constructor(private readonly opts: EdgeAuthOptions) {
    if (!opts.apiUrl) throw new Error("EdgeAuth: apiUrl is required");
    // An explicitly empty issuer/audience used to disable the check
    // silently inside jose. Refuse it rather than pretend to verify.
    if (opts.issuer !== undefined && opts.issuer.trim() === "") {
      throw new Error("EdgeAuth: issuer cannot be empty; omit it to use the Authio default");
    }
    if (opts.audience !== undefined && opts.audience.trim() === "") {
      throw new Error("EdgeAuth: audience cannot be empty; omit it to use the Authio default");
    }
    this.issuer = opts.issuer ?? DEFAULT_ISSUER;
    this.audience = opts.audience ?? DEFAULT_AUDIENCE;
    this.jwks = createRemoteJWKSet(
      new URL(opts.apiUrl.replace(/\/$/, "") + "/v1/auth/.well-known/jwks.json"),
      { cooldownDuration: 30_000, cacheMaxAge: 600_000 },
    );
  }

  /** Verify the access token from any source (cookie, Authorization header, query). */
  async verify(token: string): Promise<EdgeSession | null> {
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ["EdDSA"],
      });
      const claims = payload as AuthioJwt;
      if (!this.tenantOk(claims)) return null;
      return {
        sessionId: claims.sid ?? "",
        userId: claims.sub,
        orgId: claims.act_org ? claims.act_org : null,
        role: claims.act_role ? claims.act_role : null,
        expiresAt: typeof claims.exp === "number" ? claims.exp * 1000 : 0,
      };
    } catch {
      return null;
    }
  }

  /**
   * Tenant binding. A MISMATCH fails the verification outright: the
   * token belongs to another project, which is exactly the
   * cross-tenant forgery this guards against.
   *
   * An ABSENT claim only warns. auth-core has only just started
   * stamping project_id on user tokens and sessions issued before
   * that are still valid until they expire; rejecting them would sign
   * real users out to defend against a token that can no longer be
   * minted. A later release turns absence into a rejection.
   */
  private tenantOk(claims: AuthioJwt): boolean {
    if (!this.opts.projectId) {
      if (!this.warnedNoProjectConfigured) {
        this.warnedNoProjectConfigured = true;
        console.warn(
          "authio: no projectId configured, so tokens are not checked against your tenant. " +
            "Any Authio-issued token will verify here, including one minted in someone else's project.",
        );
      }
      return true;
    }
    if (typeof claims.project_id !== "string") {
      if (!this.warnedClaimAbsent) {
        this.warnedClaimAbsent = true;
        console.warn(
          "authio: token carries no project_id claim, so it could not be checked against your tenant. " +
            "Expected for sessions issued before 2026-07; a future release will reject these.",
        );
      }
      return true;
    }
    return claims.project_id === this.opts.projectId;
  }

  /** Convenience: pull the cookie or Authorization-header token from a Request. */
  async verifyRequest(req: Request): Promise<EdgeSession | null> {
    const auth = req.headers.get("authorization") ?? "";
    if (auth.toLowerCase().startsWith("bearer ")) {
      return this.verify(auth.slice(7).trim());
    }
    const cookieHeader = req.headers.get("cookie") ?? "";
    const cookie = parseCookie(cookieHeader, "authio_session");
    if (cookie) return this.verify(cookie);
    return null;
  }
}

function parseCookie(header: string, name: string): string | null {
  const parts = header.split(";");
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (k === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}
