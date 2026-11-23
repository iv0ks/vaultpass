// Unit tests for the token helpers — the heart of the lab.
//
// readClaims() only decodes; verifyClaims() checks the signature. The vulnerable
// routes use the first, the audit route uses the second.
import { describe, expect, it } from 'vitest';
import jwt from 'jsonwebtoken';
import { bearerToken, issueToken, readClaims, verifyClaims } from '../src/auth/token.js';

const member = { id: 1, username: 'alice', role: 'member' };

function b64(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// Rewrites the payload but keeps the original signature (it no longer matches).
function tamper(token: string, patch: Record<string, unknown>): string {
  const [header, payload, signature] = token.split('.');
  const edited = { ...JSON.parse(Buffer.from(payload!, 'base64url').toString()), ...patch };
  return `${header}.${b64(edited)}.${signature}`;
}

// An unsigned token: `alg: none` and an empty signature.
function unsigned(payload: Record<string, unknown>): string {
  return `${b64({ alg: 'none', typ: 'JWT' })}.${b64(payload)}.`;
}

describe('issueToken', () => {
  it('signs an HS256 token carrying sub, username and role', () => {
    const token = issueToken(member);
    expect(jwt.decode(token, { complete: true })?.header.alg).toBe('HS256');
    expect(verifyClaims(token)).toEqual({ sub: 1, username: 'alice', role: 'member' });
  });
});

describe('verifyClaims (safe)', () => {
  it('accepts a token this server issued', () => {
    expect(verifyClaims(issueToken(member))?.role).toBe('member');
  });

  it('rejects a payload edited after signing', () => {
    expect(verifyClaims(tamper(issueToken(member), { role: 'admin' }))).toBeNull();
  });

  it('rejects an alg:none token', () => {
    expect(verifyClaims(unsigned({ sub: '2', username: 'bob', role: 'admin' }))).toBeNull();
  });

  it('rejects a token signed with another secret', () => {
    const foreign = jwt.sign({ username: 'alice', role: 'admin' }, 'not-the-secret', {
      subject: '1',
    });
    expect(verifyClaims(foreign)).toBeNull();
  });

  it('rejects an expired token', () => {
    const expired = jwt.sign({ username: 'alice', role: 'member' }, 'x', {
      subject: '1',
      expiresIn: -10,
    });
    expect(verifyClaims(expired)).toBeNull();
  });
});

describe('readClaims (vulnerable: decode only)', () => {
  it('believes a payload edited after signing — the lab', () => {
    const forged = tamper(issueToken(member), { role: 'admin' });
    expect(readClaims(forged)?.role).toBe('admin');
  });

  it('believes an alg:none token with any identity', () => {
    const claims = readClaims(unsigned({ sub: '2', username: 'bob', role: 'admin' }));
    expect(claims).toEqual({ sub: 2, username: 'bob', role: 'admin' });
  });

  it('still refuses garbage and incomplete claims', () => {
    expect(readClaims('not-a-token')).toBeNull();
    expect(readClaims(unsigned({ username: 'x' }))).toBeNull();
  });
});

describe('bearerToken', () => {
  it('extracts the token from an Authorization header', () => {
    expect(bearerToken('Bearer abc.def.ghi')).toBe('abc.def.ghi');
    expect(bearerToken('bearer abc')).toBe('abc');
  });

  it('returns null for a missing or foreign scheme', () => {
    expect(bearerToken(undefined)).toBeNull();
    expect(bearerToken('Basic abc')).toBeNull();
    expect(bearerToken('Bearer')).toBeNull();
  });
});
