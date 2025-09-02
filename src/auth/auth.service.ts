import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './dto/interfaces/jwt-payload';
@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  

  private readonly  logger = new Logger('AuthServices');
  constructor( private jwtService: JwtService){
  super();
  }

    onModuleInit() {
    this.$connect();
    this.logger.log('Connected to the database');
  }

  async signJWT(payload: JwtPayload) {
   
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {

    const { email, password, name } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where:{ 
          email: email, 
        }
      })


      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists'
        })
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10), // TODO: Hash password before saving
          name: name
        }
      })
      const { password:__, ...rest } = newUser;
      return {
        User: rest,
        token: await this.signJWT(rest)
    };

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }

  
  }


  async loginUser(loginUserDto: LoginUserDto) {

    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where:{ 
          email: email, 
        }
      })

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not vailid'
        })
      }

    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      throw new RpcException({
        status: 400,
        message: 'User/Password not vailid'
      })
    }


    const { password:__, ...rest } = user;

    return {
      User: rest,
      token: await this.signJWT(rest)
    };
  }catch (error) {  
    throw new RpcException({
      status: 400,
      message: 'User/Password not valid'
    })

  }

  }


  async verifyUser(token: string) {
    try {
      const {sub,iat,exp, ...user} = this.jwtService.verify(
        token,
        {
          secret: process.env.JWT_SECRET,
        }
      );
      return {
        user: user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: 401,
        message: 'Invalid token'
      });
    }
  }
}
