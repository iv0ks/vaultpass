// Database schema (Drizzle ORM).
//
// vaultpass is a small access-management platform: a team keeps its shared
// credentials in a vault, and every account has a **role** — `member` or
// `admin`. The role decides which credentials you may open:
//
//   visibility 'team'     → every signed-in account
//   visibility 'personal' → only the account that owns it
//   visibility 'admin'    → administrators only (the crown jewels)
//
// The role is stored here, in `users.role`, and copied into the JWT at login.
// What the API later *believes* about the caller comes from that token — and
// that is the lab (CWE-284).
import { pgTable, integer, text, timestamp } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: integer('id').primaryKey(),
  username: text('username').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  displayName: text('display_name').notNull(),
  // 'member' | 'admin'
  role: text('role').notNull().default('member'),
});

export const credentials = pgTable('credentials', {
  id: integer('id').primaryKey(),
  // Owner of a 'personal' credential; null for team / admin ones.
  ownerId: integer('owner_id').references(() => users.id),
  // 'team' | 'personal' | 'admin'
  visibility: text('visibility').notNull().default('team'),
  name: text('name').notNull(),
  // The account name stored next to the secret.
  username: text('username').notNull(),
  // The secret itself. The admin-only "root recovery key" carries the FLAG.
  secret: text('secret').notNull(),
  notes: text('notes').notNull().default(''),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const auditEvents = pgTable('audit_events', {
  id: integer('id').primaryKey(),
  actor: text('actor').notNull(),
  action: text('action').notNull(),
  target: text('target').notNull(),
  at: timestamp('at', { withTimezone: true }).notNull().defaultNow(),
});

export type User = typeof users.$inferSelect;
export type Credential = typeof credentials.$inferSelect;
export type AuditEvent = typeof auditEvents.$inferSelect;
