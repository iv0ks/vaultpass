// Administrators' console API.
//
//   GET /api/admin/users        → every account and its role
//   GET /api/admin/credentials  → every credential, admin-only ones included
//   GET /api/admin/audit        → the audit trail
//
// The class is guarded by AuthGuard + AdminGuard: "there is a token, and the
// token says role = admin". Both read the token with decode(), so the role is
// whatever the caller wrote into it (CWE-284).
//
// /api/admin/audit is the contrast: it adds VerifiedTokenGuard, which checks the
// signature. A forged token that walks through the other two routes is
// refused here — proof that the secret and the verification code were always
// available, the other routes just never used them.
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AdminGuard, AuthGuard, VerifiedTokenGuard } from '../auth/guards.js';
import { listAllCredentials, listAuditEvents, listUsers } from './admin.service.js';

@Controller('api/admin')
@UseGuards(AuthGuard, AdminGuard)
export class AdminController {
  // ⚠️ role taken from the unverified token.
  @Get('users')
  async users() {
    return { users: await listUsers() };
  }

  // ⚠️ role taken from the unverified token.
  @Get('credentials')
  async credentials() {
    return { credentials: await listAllCredentials() };
  }

  // SAFE: signature verified before the role is believed.
  @Get('audit')
  @UseGuards(VerifiedTokenGuard)
  async audit() {
    return { events: await listAuditEvents() };
  }
}
