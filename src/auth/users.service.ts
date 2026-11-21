// Users data layer: look an account up by its username.
import { eq } from 'drizzle-orm';
import { db } from '../db/client.js';
import { users, type User } from '../db/schema.js';

export async function findUserByUsername(username: string): Promise<User | undefined> {
  const [row] = await db.select().from(users).where(eq(users.username, username)).limit(1);
  return row;
}
