<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# @useauthio/edge

> Part of **[Authio Lobby](https://authio.com/products/lobby)** —
> Authio's drop-in passwordless authentication. Learn more at
> https://authio.com/products/lobby.

Verify Authio JWTs at any edge runtime — Cloudflare Workers, Vercel Edge, Deno Deploy, Bun, and Node. JWKS is fetched once and cached. No round-trip to auth-core on the hot path.

## Install

```bash
pnpm add @useauthio/edge
```

## Quick start

```ts
import { EdgeAuth } from "@useauthio/edge";

const auth = new EdgeAuth({ apiUrl: "https://api.authio.com" });

export default {
  async fetch(req: Request) {
    const session = await auth.verifyRequest(req);
    if (!session) return new Response("Unauthorized", { status: 401 });
    return Response.json({ userId: session.userId, orgId: session.orgId });
  },
};
```

## License

MIT
