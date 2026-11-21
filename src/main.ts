// Application bootstrap.
//
// Kept as a factory (createApp) so tests can boot an isolated Nest instance
// without binding a port.
import 'reflect-metadata';
import { ValidationPipe, type INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AppModule } from './app.module.js';
import { config } from './config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

export async function createApp(): Promise<INestApplication> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: ['error', 'warn', 'log'],
  });

  // Behind Traefik the app sees a proxy; trust it.
  app.set('trust proxy', 1);

  // Standard validation — input hardening is not the vulnerability here, so
  // this is configured the safe way.
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));

  // Static single-page UI (served from dist/public at runtime).
  app.useStaticAssets(PUBLIC_DIR);

  return app;
}

async function bootstrap(): Promise<void> {
  const app = await createApp();
  await app.listen(config.port, '0.0.0.0');
  console.log(`vaultpass listening on http://0.0.0.0:${config.port}`);
}

if (process.env.NODE_ENV !== 'test') {
  bootstrap().catch((err) => {
    console.error('failed to start:', err);
    process.exit(1);
  });
}
