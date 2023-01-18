import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto/auth.dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import {ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService,
              private readonly jwt: JwtService,
              private readonly config: ConfigService) {
  }

 async signup(dto: AuthDto){
    const hash = await argon.hash(dto.password)
   try {
     const user = await this.prisma.user.create({
       data: {
         email: dto.email,
         hash
       }

     })
     delete user.hash
     return this.signToken(user.id, user.email)
   }catch (e) {
     if (e instanceof PrismaClientKnownRequestError){
        if (e.code === 'P2002'){
          throw new ForbiddenException('Credentials taken')
        }
        throw e
     }
   }

  }

  async signin(dto: AuthDto){

    const user = await this.prisma.user.findUnique({where: {email: dto.email}})
    if (!user){
      throw new ForbiddenException('Invalid data')
    }
    const pwMatches = await argon.verify(user.hash, dto.password)
    if (!pwMatches){
      throw new ForbiddenException('Invalid data')
    }
    return this.signToken(user.id, user.email)
  }

  async signToken(userId: number, email: string): Promise<any>{
     const payload = {
       sub: userId,
       email
     }
     const token = await this.jwt.signAsync(payload, {
       expiresIn: '15m',
       secret: this.config.get('JWT_SECRET')
     })
    return {
       access_token: token
    }
  }

}
