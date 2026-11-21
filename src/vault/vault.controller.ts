// Vault controller — what an ordinary signed-in account can open.
//
//   GET /api/vault           → the shared team credentials
//   GET /api/vault/personal  → the caller's own credentials (owner = token `sub`)
//
// Both only need a signed-in account. The owner of the personal list is read
// from the token's `sub` claim — which, like `role`, is taken on trust.
import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard, type AuthedRequest } from '../auth/guards.js';
import { listPersonalCredentials, listTeamCredentials } from './vault.service.js';

@Controller('api/vault')
@UseGuards(AuthGuard)
export class VaultController {
  @Get()
  async team() {
    return { credentials: await listTeamCredentials() };
  }

  @Get('personal')
  async personal(@Req() req: AuthedRequest) {
    return { credentials: await listPersonalCredentials(req.user!.sub) };
  }
}
