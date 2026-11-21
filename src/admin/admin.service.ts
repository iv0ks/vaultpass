// Admin data layer: everything the administrators' console reads.
import { asc, desc } from 'drizzle-orm';
import { db } from '../db/client.js';
import { auditEvents, credentials, users } from '../db/schema.js';

export function listUsers() {
  return db
    .select({
      id: users.id,
      username: users.username,
      displayName: users.displayName,
      role: users.role,
    })
    .from(users)
    .orderBy(asc(users.id));
}

// Every credential in the vault, including the admin-only ones.
export function listAllCredentials() {
  return db.select().from(credentials).orderBy(asc(credentials.id));
}

export function listAuditEvents() {
  return db.select().from(auditEvents).orderBy(desc(auditEvents.id));
}
