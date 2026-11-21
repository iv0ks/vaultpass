// Seed script — idempotent, and it resets the lab to a known state on boot.
//
// Three accounts:
//
//   alice (id 1) — member. You. Can open the team vault and her own items.
//   bob   (id 2) — admin. The victim. Owns the platform and its crown jewels.
//   carol (id 3) — member. A bystander.
//
// Eleven credentials in three visibility levels. The **root recovery key**
// (id 10) is admin-only and carries the FLAG as its secret. alice's role is
// `member`, so a legitimate alice never reaches it — forging the claim is the
// lab.
import { db, sql } from './client.js';
import { auditEvents, credentials, users } from './schema.js';
import { hashPassword } from '../auth.js';
import { config } from '../config.js';

const seedUsers = [
  {
    id: 1,
    username: 'alice',
    password: 'password123',
    displayName: 'Alice Martins',
    role: 'member',
  },
  {
    id: 2,
    username: 'bob',
    password: 'correct-horse-battery-staple',
    displayName: 'Bob Keller',
    role: 'admin',
  },
  {
    id: 3,
    username: 'carol',
    password: 'hunter2hunter2',
    displayName: 'Carol Nwosu',
    role: 'member',
  },
];

type SeedCredential = {
  id: number;
  ownerId: number | null;
  visibility: 'team' | 'personal' | 'admin';
  name: string;
  username: string;
  secret: string;
  notes: string;
};

const seedCredentials: SeedCredential[] = [
  // --- team: every signed-in account -------------------------------------
  {
    id: 1,
    ownerId: null,
    visibility: 'team',
    name: 'Office Wi-Fi',
    username: 'northwind-guest',
    secret: 'blue-heron-42-lantern',
    notes: 'Guest network, rotated every quarter.',
  },
  {
    id: 2,
    ownerId: null,
    visibility: 'team',
    name: 'Staging database (read-only)',
    username: 'stg_readonly',
    secret: 'stg-ro-7Hq2-vX9m',
    notes: 'Safe to use for debugging. Never points at production.',
  },
  {
    id: 3,
    ownerId: null,
    visibility: 'team',
    name: 'Status page editor',
    username: 'status@northwind.example',
    secret: 'status-page-Pd83kQ',
    notes: 'Post incident updates here.',
  },
  {
    id: 4,
    ownerId: null,
    visibility: 'team',
    name: 'Shared analytics seat',
    username: 'analytics@northwind.example',
    secret: 'analytics-seat-93nXc',
    notes: 'One seat for the whole team — please sign out.',
  },

  // --- personal: only the owner ------------------------------------------
  {
    id: 5,
    ownerId: 1,
    visibility: 'personal',
    name: 'GitHub personal access token',
    username: 'alice-martins',
    secret: 'ghp_alice_notARealToken_8f3k2',
    notes: 'Read-only, expires in March.',
  },
  {
    id: 6,
    ownerId: 2,
    visibility: 'personal',
    name: 'Laptop disk-encryption PIN',
    username: 'bob-laptop',
    secret: 'pin-5921-0377',
    notes: 'Do not write this down. (Bob wrote it down.)',
  },
  {
    id: 7,
    ownerId: 3,
    visibility: 'personal',
    name: 'Conference portal login',
    username: 'carol.nwosu',
    secret: 'conf-portal-Zk44mQ',
    notes: 'Speaker account for the autumn meetup.',
  },

  // --- admin: administrators only ----------------------------------------
  {
    id: 8,
    ownerId: null,
    visibility: 'admin',
    name: 'Production database (read/write)',
    username: 'prod_admin',
    secret: 'prod-rw-Jx7!q2Lm-93aV',
    notes: 'Break-glass only. Every use is reviewed.',
  },
  {
    id: 9,
    ownerId: null,
    visibility: 'admin',
    name: 'Cloud billing root account',
    username: 'billing-root@northwind.example',
    secret: 'billing-root-Qw8z-Lp40',
    notes: 'Owner of the cloud organisation. MFA device is in the safe.',
  },
  {
    // The target. Carries the flag.
    id: 10,
    ownerId: null,
    visibility: 'admin',
    name: 'Root recovery key',
    username: 'root-recovery',
    secret: config.flag,
    notes: 'Offline recovery key for the whole vault. Administrators only.',
  },
  {
    id: 11,
    ownerId: null,
    visibility: 'admin',
    name: 'SSO identity-provider admin',
    username: 'idp-admin',
    secret: 'idp-admin-Rt61-vN3s',
    notes: 'Can mint sessions for every employee.',
  },
];

const seedAudit = [
  { id: 1, actor: 'bob', action: 'credential.read', target: 'Production database (read/write)' },
  { id: 2, actor: 'bob', action: 'credential.rotate', target: 'Cloud billing root account' },
  { id: 3, actor: 'alice', action: 'login', target: 'vaultpass' },
  { id: 4, actor: 'carol', action: 'credential.read', target: 'Office Wi-Fi' },
  { id: 5, actor: 'bob', action: 'credential.read', target: 'Root recovery key' },
];

async function main(): Promise<void> {
  console.log('[seed] seeding users …');
  for (const u of seedUsers) {
    const passwordHash = hashPassword(u.password);
    await db
      .insert(users)
      .values({
        id: u.id,
        username: u.username,
        passwordHash,
        displayName: u.displayName,
        role: u.role,
      })
      .onConflictDoUpdate({
        target: users.id,
        set: {
          username: u.username,
          passwordHash,
          displayName: u.displayName,
          role: u.role,
        },
      });
  }

  console.log('[seed] seeding credentials …');
  for (const c of seedCredentials) {
    await db
      .insert(credentials)
      .values(c)
      .onConflictDoUpdate({
        target: credentials.id,
        set: {
          ownerId: c.ownerId,
          visibility: c.visibility,
          name: c.name,
          username: c.username,
          secret: c.secret,
          notes: c.notes,
        },
      });
  }

  console.log('[seed] seeding audit trail …');
  for (const e of seedAudit) {
    await db
      .insert(auditEvents)
      .values(e)
      .onConflictDoUpdate({
        target: auditEvents.id,
        set: { actor: e.actor, action: e.action, target: e.target },
      });
  }

  console.log(
    '[seed] done. accounts: alice (member), bob (admin), carol (member). flag seeded in the admin-only root recovery key (credential 10).',
  );
  await sql.end();
}

main().catch((err) => {
  console.error('[seed] failed:', err);
  process.exit(1);
});
