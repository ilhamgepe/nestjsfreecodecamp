import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import * as argon from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(bodyDto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(bodyDto.password);
    // save the new user
    try {
      const user = await this.prisma.user.create({
        data: {
          email: bodyDto.email,
          password: hash,
          firstName: bodyDto.firstName || null,
          lastName: bodyDto.lastName || null,
        },
      });

      // return the saved user
      delete user.password;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials already in use');
        }

        throw error;
      }
    }
  }
  async signin(bodyDto: AuthDto) {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: bodyDto.email,
      },
    });
    // if user does not exist, throw an error exception
    if (!user || user === null || undefined)
      throw new ForbiddenException('Invalid credentials');

    // compare the password hash
    const passwordValid = await argon.verify(user.password, bodyDto.password);
    // if the password does not match, throw an error exception
    if (!passwordValid) throw new ForbiddenException('Invalid credentials');

    // send back the user
    delete user.password;
    const { token } = await this.signToken(user.id, user.email);
    return { ...user, token };
  }

  async signToken(userId: number, email: string): Promise<{ token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '20m',
      secret: this.config.get('JWT_SECRET'),
    });
    return { token };
  }
}
