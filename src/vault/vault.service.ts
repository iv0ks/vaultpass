// Vault data layer: the credentials a signed-in account may open.
import { and, asc, eq } from 'drizzle-orm';
import { db } from '../db/client.js';
import { credentials } from '../db/schema.js';

// Shared team credentials — visible to every signed-in account.
export function listTeamCredentials() {
  return db
    .select()
    .from(credentials)
    .where(eq(credentials.visibility, 'team'))
    .orderBy(asc(credentials.id));
}

// Personal credentials of one account.
export function listPersonalCredentials(ownerId: number) {
  return db
    .select()
    .from(credentials)
    .where(and(eq(credentials.visibility, 'personal'), eq(credentials.ownerId, ownerId)))
    .orderBy(asc(credentials.id));
}
