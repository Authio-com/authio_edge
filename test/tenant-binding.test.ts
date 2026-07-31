import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { EdgeAuth } from "../src/index";

/**
 * Two properties are under test here.
 *
 * 1. Issuer and audience are ALWAYS checked. They used to be passed
 *    through to jose as `undefined` whenever the caller omitted them,
 *    and jose silently skips a check for an undefined value — so with
 *    the documented usage (`{ apiUrl }` only) neither was ever
 *    verified.
 *
 * 2. A token minted for another Authio project is rejected. Every
 *    tenant shares one signing key, issuer and audience, so nothing
 *    else in the token distinguishes them.
 *
 * Real Ed25519 keys, real jose verification, real JWKS over loopback.
 */

const PROD_ISSUER = "https://identity.authio.com";
const PROD_AUDIENCE = "authio";

let privateKey: CryptoKey;
let server: Server;
let apiUrl: string;

beforeEach(async () => {
  const { privateKey: priv, publicKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  privateKey = priv as CryptoKey;
  const jwk = await exportJWK(publicKey);
  jwk.kid = "test-kid";
  jwk.alg = "EdDSA";
  jwk.use = "sig";
  const jwksBody = JSON.stringify({ keys: [jwk] });

  server = createServer((req, res) => {
    if (req.url?.includes("jwks.json")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(jwksBody);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (typeof addr === "string" || addr === null) throw new Error("no port");
  apiUrl = `http://127.0.0.1:${addr.port}`;
});

afterEach(async () => {
  vi.restoreAllMocks();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function mint(claims: Record<string, unknown>, opts?: { iss?: string; aud?: string }) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid: "test-kid" })
    .setIssuer(opts?.iss ?? PROD_ISSUER)
    .setAudience(opts?.aud ?? PROD_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("EdgeAuth issuer/audience enforcement", () => {
  it("rejects a foreign issuer even when the caller configured neither", async () => {
    // This is the regression: with `{ apiUrl }` only, jose used to be
    // handed issuer: undefined and skipped the check entirely.
    const auth = new EdgeAuth({ apiUrl });
    const token = await mint({ sub: "u1" }, { iss: "https://evil.example.com" });
    expect(await auth.verify(token)).toBeNull();
  });

  it("rejects a foreign audience even when the caller configured neither", async () => {
    const auth = new EdgeAuth({ apiUrl });
    const token = await mint({ sub: "u1" }, { aud: "someone-else" });
    expect(await auth.verify(token)).toBeNull();
  });

  it("accepts a genuine production-issued token with no explicit config", async () => {
    const auth = new EdgeAuth({ apiUrl });
    const token = await mint({ sub: "u1", sid: "s1" });
    const session = await auth.verify(token);
    expect(session?.userId).toBe("u1");
  });

  it("refuses an explicitly empty issuer rather than silently skipping", () => {
    expect(() => new EdgeAuth({ apiUrl, issuer: "" })).toThrow(/issuer cannot be empty/);
    expect(() => new EdgeAuth({ apiUrl, audience: "" })).toThrow(/audience cannot be empty/);
  });
});

describe("EdgeAuth tenant binding", () => {
  it("rejects a token minted for another project", async () => {
    const auth = new EdgeAuth({ apiUrl, projectId: "proj_victim" });
    const token = await mint({
      sub: "user_attacker",
      email: "ceo@victim-customer.com",
      project_id: "proj_attacker",
    });
    expect(await auth.verify(token)).toBeNull();
  });

  it("accepts a token minted for the configured project", async () => {
    const auth = new EdgeAuth({ apiUrl, projectId: "proj_victim" });
    const token = await mint({ sub: "user_real", sid: "s1", project_id: "proj_victim" });
    const session = await auth.verify(token);
    expect(session?.userId).toBe("user_real");
  });

  it("warns but accepts a token with no project_id claim", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth = new EdgeAuth({ apiUrl, projectId: "proj_victim" });
    const session = await auth.verify(await mint({ sub: "user_legacy", sid: "s1" }));
    expect(session?.userId).toBe("user_legacy");
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/no project_id claim/));
  });

  it("warns once, not per request", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth = new EdgeAuth({ apiUrl, projectId: "proj_victim" });
    for (let i = 0; i < 3; i++) {
      await auth.verify(await mint({ sub: "u", sid: `s${i}` }));
    }
    expect(warn).toHaveBeenCalledTimes(1);
  });
});
