// Access tokens (JWT, HS256).
//
// At login the server signs a short-lived token that carries the caller's
// identity and — importantly — their **role**:
//
//   { "sub": "1", "username": "alice", "role": "member", "iat": …, "exp": … }
//
// Two helpers read a token back:
//
//   verifyClaims() — checks the signature (and expiry) against JWT_SECRET.
//   readClaims()   — only base64-decodes the payload. It accepts ANY token
//                    that is shaped like a JWT, whoever wrote it.
//
// Most of the API uses readClaims(). That is the lab (CWE-284): the backend
// takes an authorization decision (`role === 'admin'`) from a value the client
// is free to rewrite.
import jwt from 'jsonwebtoken';
import { config } from '../config.js';

export interface Claims {
  sub: number;
  username: string;
  role: string;
}

export function issueToken(user: { id: number; username: string; role: string }): string {
  return jwt.sign({ username: user.username, role: user.role }, config.jwtSecret, {
    algorithm: 'HS256',
    subject: String(user.id),
    expiresIn: config.jwtTtl as jwt.SignOptions['expiresIn'],
  });
}

function toClaims(payload: unknown): Claims | null {
  if (!payload || typeof payload !== 'object') return null;
  const { sub, username, role } = payload as Record<string, unknown>;
  const id = Number(sub);
  if (!Number.isInteger(id) || typeof username !== 'string' || typeof role !== 'string') {
    return null;
  }
  return { sub: id, username, role };
}

// ⚠️ VULNERABLE: `jwt.decode()` is NOT `jwt.verify()`. It parses the payload and
// returns it — it never looks at the signature, the algorithm or the expiry.
// A token whose payload was edited by the client (or one with `alg: none`)
// decodes just as happily as one this server issued.
export function readClaims(token: string): Claims | null {
  return toClaims(jwt.decode(token));
}

// SAFE: checks the HS256 signature and the expiry, and pins the algorithm so an
// `alg: none` token is refused. Returns null for anything that does not verify.
export function verifyClaims(token: string): Claims | null {
  try {
    return toClaims(jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }));
  } catch {
    return null;
  }
}

// Pulls the token out of `Authorization: Bearer <token>`.
export function bearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const [scheme, token] = header.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !token) return null;
  return token;
}
