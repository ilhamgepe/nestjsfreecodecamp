import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authservice: AuthService) {}

  @Post('signup')
  signup(@Body() bodyDto: AuthDto) {
    console.log({ bodyDto });

    return this.authservice.signup(bodyDto);
  }

  @Post('signin')
  signin(@Body() bodyDto: AuthDto) {
    return this.authservice.signin(bodyDto);
  }
}
