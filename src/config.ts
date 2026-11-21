// Runtime configuration, read once from the environment.
function required(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (value === undefined) {
    throw new Error(`missing required env var: ${name}`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  databaseUrl: required('DATABASE_URL', 'postgres://vaultpass:vaultpass@localhost:5432/vaultpass'),

  // Secret used to sign the access tokens issued at login (HS256). It is a
  // perfectly good secret — the lab is not about cracking it. The bug is that
  // most routes never use it to *check* the token they receive.
  jwtSecret: required('JWT_SECRET', 'dev-only-insecure-secret-change-me-0123456789'),
  jwtTtl: process.env.JWT_TTL ?? '1h',

  // The challenge flag, baked into the image at build time and seeded into the
  // admin-only "root recovery key" credential. Never committed.
  flag: required('FLAG', 'FLAG{VAULTPASS_FORGED_THE_CLAIM}'),
};
