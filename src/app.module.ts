import { Module } from '@nestjs/common';
import { AdminController } from './admin/admin.controller.js';
import { AuthController } from './auth/auth.controller.js';
import { HealthController } from './health.controller.js';
import { VaultController } from './vault/vault.controller.js';

@Module({
  controllers: [HealthController, AuthController, VaultController, AdminController],
})
export class AppModule {}
