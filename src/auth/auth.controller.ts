// Authentication controller: login and "who am I".
//
// Login checks the password against the database and issues a signed token
// carrying the account's id, username and role. /api/me reports back what the
// token says — it is the quickest way to see which role the API thinks you have.
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { verifyPassword } from '../auth.js';
import { AuthGuard, type AuthedRequest } from './guards.js';
import { issueToken } from './token.js';
import { findUserByUsername } from './users.service.js';

@Controller('api')
export class AuthController {
  @Post('login')
  @HttpCode(200)
  async login(@Body() body: { username?: unknown; password?: unknown }) {
    const { username, password } = body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      throw new BadRequestException('username and password are required');
    }

    const user = await findUserByUsername(username);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return {
      ok: true,
      token: issueToken(user),
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        role: user.role,
      },
    };
  }

  @Get('me')
  @UseGuards(AuthGuard)
  me(@Req() req: AuthedRequest) {
    const { sub, username, role } = req.user!;
    return { id: sub, username, role };
  }
}
