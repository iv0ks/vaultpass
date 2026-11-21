// Route guards.
//
//   AuthGuard           → "is there a token?"        (authentication)
//   AdminGuard          → "does the token say admin?" (authorization)
//   VerifiedTokenGuard  → "was the token really issued by us?"
//
// AuthGuard and AdminGuard both work from `readClaims()`, i.e. from whatever the
// token's payload *says*. Nothing ever checks that the payload was not edited,
// so the `role` the AdminGuard compares is a value the caller chose. Only
// VerifiedTokenGuard — used on a single route — validates the signature.
import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { bearerToken, readClaims, verifyClaims, type Claims } from './token.js';

export type AuthedRequest = Request & { user?: Claims };

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<AuthedRequest>();
    const token = bearerToken(req.headers.authorization);
    if (!token) {
      throw new UnauthorizedException('Not authenticated. POST /api/login first.');
    }
    // ⚠️ decode, not verify — see token.ts.
    const claims = readClaims(token);
    if (!claims) {
      throw new UnauthorizedException('Malformed token.');
    }
    req.user = claims;
    return true;
  }
}

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<AuthedRequest>();
    // ⚠️ the role comes straight from the (unverified) token payload.
    if (req.user?.role !== 'admin') {
      throw new ForbiddenException('Administrator role required.');
    }
    return true;
  }
}

// The one route that does it properly (the audit trail): the signature must
// check out against the server's secret before the token is believed.
@Injectable()
export class VerifiedTokenGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<AuthedRequest>();
    const token = bearerToken(req.headers.authorization);
    const claims = token ? verifyClaims(token) : null;
    if (!claims) {
      throw new UnauthorizedException('Invalid token signature.');
    }
    if (claims.role !== 'admin') {
      throw new ForbiddenException('Administrator role required.');
    }
    req.user = claims;
    return true;
  }
}
