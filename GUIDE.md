# vaultpass: Learning Guide

![CWE-284](https://img.shields.io/badge/CWE--284-Broken%20Access%20Control-red?style=flat-square)
![Node](https://img.shields.io/badge/Node-NestJS-E0234E?style=flat-square&logo=nestjs&logoColor=white)
![Docker](https://img.shields.io/badge/Lab-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

**vaultpass is an intentionally vulnerable application built for security education.** It contains a deliberate [broken access control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
(CWE-284) flaw so you can practice finding and exploiting it in a safe and controlled environment.

<br>

> [!TIP]
> A guided, **non-spoiler** path to solving this lab. It teaches the *method*, not the answer — the exact winning request and the flag stay in [SOLUTION.md](SOLUTION.md).

<br>

## 🧬 What broken access control is

Here is the whole idea in one sentence:

> **Broken access control happens when an app checks _who you are_ but forgets
> to check _whether you're allowed to do this_ — or believes the wrong witness
> when it asks.**

Logging in answers "who are you?" — that's **authentication**. Deciding whether
*this* user may perform *this* action is a separate question — that's
**authorization**. The earlier labs asked the second question and got a wrong
answer from a missing check. This lab is subtler: the check **exists**, and it
compares the right thing — the caller's **role** — but the role it compares
comes from a place the caller controls.

Modern APIs often hand out a **JSON Web Token (JWT)** at login. A JWT is three
base64 chunks, `header.payload.signature`. The payload holds *claims* — who you
are, what role you have. The signature is what makes those claims believable:
only the server knows the secret, so only the server could have produced a
matching signature. A token is only as trustworthy as the **verification** the
server performs when it comes back. Skip that step and the payload is just text
the client wrote.

Think of a nightclub wristband. It only means something if the doorman checks
that it is the real band — not a sticker anyone can draw, with "VIP" written on
it.

> Want the deeper background — horizontal vs vertical escalation, why a
> client-held value is never a control, and the full workflow with **Burp
> Suite** and **OWASP ZAP**? Read the shared
> **[Broken Access Control field guide](https://github.com/iv0ks/appsec-labs/blob/main/docs/broken-access-control.md)**.
> This lab is a hands-on application of it.

<br>

## 🎓 What this level teaches

**Level 9 — broken authorization trust: the role comes from a token nobody checks.**
The server signs a perfectly good token at login. Then most of its routes read
that token without verifying it.

- **Entry points:**
  - `GET /api/admin/credentials` — the whole vault.
  - `GET /api/admin/users` — every account and its role.
  - `GET /api/vault/personal` — personal items of whoever the token names.
- **The broken defence:** "the token was signed by us, so whatever it says is
  true" — the server trusts the claim without checking the signature that
  vouches for it.
- **What you can see legitimately:** the team vault and your own personal items,
  plus `GET /api/me`, which tells you which role the API believes you have.
- **The target:** a credential reserved for administrators. You are `alice`, a
  **member** — the UI never even draws the admin console for you.

## 🪧 How to approach it

1. Sign in as `alice` through your proxy and capture `POST /api/login`. The
   response includes a `token` — that's a JWT. Copy it.
2. A JWT is `header.payload.signature`, each part base64url-encoded. Paste the
   token into a decoder (or do it by hand: base64-decode the middle part). Read
   the payload — it names your account and your **role**.
3. Base64 encoding is not encryption. Edit the decoded payload (change the role),
   re-encode it, and splice it back between the original header and the
   original signature. Send that token on a request that previously answered
   "member, no". What changes?
4. If that alone does not open every route, look again at *how* the header
   names the signing algorithm. Some libraries treat "no algorithm" as a
   valid instruction. What happens if you remove the signature instead of
   forging it?
5. Once you can reach the admin routes, see what every one of them returns —
   not just the account list.

## 🕵️‍♂️ Going further

The same trust problem affects more than one claim. If the role claim is never
checked, ask what *else* in the payload might not be checked — the field that
says which account's data a route hands back, for instance. Try changing that
value too, on a route that is not about roles at all.

Not every route in this API makes the same mistake — one of them really does
check the signature. Find it, and use it as your control group: the same forged
token that works everywhere else should fail there. That contrast is how you
prove the bug is "nobody verifies the signature", not "the admin check is
missing".

## 🤔 Why it matters

JWTs are everywhere specifically because a signature lets a server trust a
claim *without* a database round trip — that is the whole point of the format.
The instant a route reads the payload with a "decode" function instead of a
"verify" function, that promise is gone, and the token becomes exactly as
trustworthy as a cookie value the user is allowed to edit. This bug class has
taken down real production APIs, often hiding behind a popular library whose
`decode()` and `verify()` happen to have confusingly similar names. Knowing
which one a piece of code calls — and testing both outcomes by hand — is a core
API security skill.

---

When you have captured the flag (or want to check the fix and the *why* behind
it), continue to **[SOLVE → SOLUTION.md](SOLUTION.md)**.

<br>

> **Legal / ethics.** This is an educational, deliberately vulnerable lab. Run it
> only locally, on owned, isolated infrastructure, and never use these techniques
> against systems without explicit written authorization.
