import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger"
import {
  ArrayMaxSize,
  IsArray,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
} from "class-validator"

// A permissive but real domain-name shape: labels of letters/digits/hyphens separated by dots.
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i

export class CreateDomainDto {
  @ApiProperty({ example: "whitehatengineering.com" })
  @IsString()
  @MaxLength(253)
  @Matches(DOMAIN_RE, { message: "name must be a valid domain, e.g. example.com" })
  name!: string

  @ApiPropertyOptional({ type: [String], example: ["google"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  dkimSelectors?: string[]

  @ApiPropertyOptional({ type: [String], example: ["203.0.113.10"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @IsString({ each: true })
  sendingIps?: string[]
}

export class UpdateDomainDto {
  @ApiPropertyOptional({ type: [String], example: ["google", "s1"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  dkimSelectors?: string[]

  @ApiPropertyOptional({ type: [String], example: ["203.0.113.10"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @IsString({ each: true })
  sendingIps?: string[]
}
