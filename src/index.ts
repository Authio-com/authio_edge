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

export interface EdgeAuthOptions {
  /** Auth-core base URL (e.g. https://api.authio.com). */
  apiUrl: string;
  /** Expected JWT issuer. */
  issuer?: string;
  /** Expected JWT audience. */
  audience?: string;
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
}

export class EdgeAuth {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly opts: EdgeAuthOptions) {
    if (!opts.apiUrl) throw new Error("EdgeAuth: apiUrl is required");
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
        issuer: this.opts.issuer,
        audience: this.opts.audience,
        algorithms: ["EdDSA"],
      });
      const claims = payload as AuthioJwt;
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
