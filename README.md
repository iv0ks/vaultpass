# vaultpass

![CWE-284](https://img.shields.io/badge/CWE--284-Broken%20Access%20Control-red?style=flat-square)
![Node](https://img.shields.io/badge/Node-NestJS-E0234E?style=flat-square&logo=nestjs&logoColor=white)
![Docker](https://img.shields.io/badge/Lab-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
[![GHCR](https://img.shields.io/badge/ghcr.io-iv0ks%2Fvaultpass-blue?logo=docker)](https://github.com/iv0ks/vaultpass/pkgs/container/vaultpass)

**vaultpass is an intentionally vulnerable application built for security education.** It contains a deliberate [broken access control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
(CWE-284) flaw in an **access-management platform** — proving that a token the server signed is only trustworthy if the server actually _checks_ that signature when it comes back.

<br>

<div align="center">

| 🛡️ Vulnerability | 🎯 Difficulty | 🛠️ Stack | 🚩 Entry point |
| :--- | :--- | :--- | :--- |
| Broken authorization trust: unverified JWT `role` claim (CWE-284) | ⭐⭐⭐⭐⭐⭐⭐ Level 9 | Node · NestJS | `GET /api/admin/credentials` · `GET /api/admin/users` · `GET /api/vault/personal` |

</div>

<br>

> [!NOTE]
> The guided, spoiler-free path is [GUIDE.md](GUIDE.md); the full answer waits in [SOLUTION.md](SOLUTION.md) whenever you want it.

<br>

## 📂 Project layout

The repository is organised so the vulnerable code is easy to find and reason
about. The **application** lives in `src/` (a small NestJS API plus a static
single-page UI), the **data layer** is Drizzle ORM over Postgres (`src/db/` +
`drizzle/` migrations), and the **tooling** around it (Docker, CI/CD, linters)
turns the lab into a production-shaped project. The challenge flag is never in
the repo — it is baked into the image and seeded into an administrators-only
credential.

```
vaultpass/
├── src/                      # the application (the bug lives here)
│   ├── main.ts               # bootstrap: validation pipe, static UI
│   ├── app.module.ts         # root module
│   ├── health.controller.ts  # GET /healthz → "ok"
│   ├── config.ts             # env-backed configuration (JWT secret, flag)
│   ├── auth.ts               # password hashing
│   ├── auth/
│   │   ├── token.ts          # issue / readClaims (decode) / verifyClaims (verify)
│   │   ├── guards.ts         # AuthGuard · AdminGuard · VerifiedTokenGuard
│   │   ├── auth.controller.ts   # POST /api/login · GET /api/me
│   │   └── users.service.ts
│   ├── vault/                # team + personal credentials (any signed-in account)
│   ├── admin/                # the administrators' console API
│   ├── db/
│   │   ├── schema.ts         # Drizzle schema (users + credentials + audit)
│   │   ├── client.ts         # Postgres connection
│   │   ├── migrate.ts        # applies migrations on startup
│   │   └── seed.ts           # seeds 3 accounts (flag in the admin-only key)
│   └── public/               # the vault UI (html/css/js)
├── drizzle/                  # generated SQL migrations
├── tests/                    # token unit tests + http tests (vitest + supertest)
├── GUIDE.md                  # non-spoiler learning guide
├── SOLUTION.md               # exploit writeup + the fix (spoilers)
├── SECURITY.md               # security policy (it's a lab — read before reporting)
├── .github/workflows/        # integration · delivery · security · release
├── Dockerfile                # hardened multi-stage image (node:26-slim)
├── docker-compose.yml        # postgres + vaultpass + traefik stack
├── docker-entrypoint.sh      # migrates + seeds, then starts the app
└── .env.example              # DB creds, JWT secret, Traefik ACME
```

The flag is **not** in the repo: the `Dockerfile` bakes it in via a build arg
and the seed writes it into the administrators-only credential.

<br>

## 🚀 The Lab

The lab ships as a Docker Compose stack with three services:

- **`postgres`** — Postgres 16. The app waits until it is *healthy* before migrating.
- **`vaultpass`** — the API + vault UI, published on port `3000`.
- **`traefik`** — an optional reverse proxy for HTTPS on a real hostname.

Because the stack attaches to an **external** Docker network (`iv0ks-dev`),
create it once before the first run:

```bash
docker network create iv0ks-dev
```

<br>

#### Option A — app + database (quickest)

Copy the example environment file, then build and start the database and the app
(Compose skips `traefik` when you name services explicitly):

```bash
cp .env.example .env
docker compose up -d --build postgres vaultpass
```

The entrypoint migrates the schema and seeds the data automatically, so the app
is ready at:

- **<http://localhost:3000>**

Sign in with the seeded demo account **`alice` / `password123`**. That is all
you need to start playing with Burp Suite.

<br>

#### Option B — full stack with Traefik (HTTPS + hostname)

Bring up everything to also expose the app through Traefik with TLS:

```bash
docker compose up -d --build
```

Now the _same_ app is reachable two ways at once:

- **<http://localhost:3000>** — direct, no TLS (handy for quick testing).
- **<https://vaultpass.iv0ks.dev>** — proxied by Traefik with a real certificate.

Traefik routing is defined in `tools/traefik/`. TLS uses the ACME DNS-01
challenge via Namecheap, so Traefik needs those API credentials — fill them in
`.env` (the `.env` file is gitignored). The dashboard is at
`https://traefik.iv0ks.dev`.

<br>

> [!CAUTION]
> The `vaultpass.iv0ks.dev` hostname must resolve to the host running the stack.
> For purely local experiments, Option A (localhost) is simpler and needs no
> DNS or certificates.

<br>

## 🎯 The Challenge

### The Scenario

vaultpass is the shared credential vault of a company called *Northwind*. Every
account has a **role**: **members** open the team's shared credentials and their
own personal items; **administrators** also get an *Admin console* with every
account, the full vault — production database, billing root, the offline
**root recovery key** — and the audit trail. You sign in as **alice**, a
plain member. The API hands you a signed access token when you log in, and every
request after that carries it. You're going to find out how much the server
really believes of what that token says.

### Your objective

Reach the administrators-only **root recovery key** and capture the flag stored
in it — without ever knowing an administrator's password.

> [!NOTE]
> The flag has the format `FLAG{...}`.

### The rules

Everything happens over HTTP against the running app — no need to read the
source to win (though you can). The flag is **not** in the repo: it lives in a
credential that only administrators may open, reachable only by breaking access
control on the running app. Look closely at the token you receive when you sign
in, and at what the server does with it afterwards.

> [!TIP]
> For the full method, the **[Learning Guide](GUIDE.md)** walks you through it.

<br>

## ⚖️ Legal / ethics

This is an **educational, deliberately vulnerable** lab. Run it only locally, on
owned, isolated infrastructure (Docker). Never deploy it publicly, and never use
these techniques against systems without explicit written authorization.
