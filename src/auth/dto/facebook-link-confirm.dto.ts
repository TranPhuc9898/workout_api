import { IsNotEmpty, IsString } from 'class-validator';

export class FacebookLinkConfirmDto {
  @IsString()
  @IsNotEmpty()
  identityToken: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
