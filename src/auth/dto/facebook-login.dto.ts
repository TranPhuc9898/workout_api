import { IsNotEmpty, IsString } from 'class-validator';

export class FacebookLoginDto {
  @IsString()
  @IsNotEmpty()
  identityToken: string;
}
