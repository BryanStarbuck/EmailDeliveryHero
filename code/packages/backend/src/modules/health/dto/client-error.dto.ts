import { ApiProperty } from "@nestjs/swagger"
import { IsIn, IsOptional, IsString, MaxLength } from "class-validator"

/**
 * Body of POST /api/health/client-error — a browser-side fault forwarded so it lands in the one
 * backend fault trail (error.err), tagged [Frontend]. See pm/errors.mdx §3. Fields are bounded so a
 * misbehaving or hostile client cannot flood the log with unbounded payloads.
 */
export class ClientErrorDto {
  @ApiProperty({ enum: ["error", "warn"], default: "error" })
  @IsOptional()
  @IsIn(["error", "warn"])
  level?: "error" | "warn"

  @ApiProperty({ description: "Human-readable error message" })
  @IsString()
  @MaxLength(2000)
  message!: string

  @ApiProperty({ required: false, description: "Where in the UI it happened (component/route)" })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  context?: string

  @ApiProperty({ required: false, description: "Stack trace or extra detail" })
  @IsOptional()
  @IsString()
  @MaxLength(8000)
  stack?: string

  @ApiProperty({ required: false, description: "Browser URL at the time of the error" })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  url?: string
}
