import { ApiProperty } from "@nestjs/swagger"

/** The authenticated employee, as returned by GET /auth/me (from the verified token claims). */
export class MeDto {
  @ApiProperty({ example: "user_2ab..." })
  userId!: string

  @ApiProperty({ example: "bryan@whitehatengineering.com" })
  email!: string

  @ApiProperty({ nullable: true, example: "sess_..." })
  sessionId!: string | null

  @ApiProperty({ nullable: true, example: null })
  orgId!: string | null

  @ApiProperty({ type: [String], example: ["admin"] })
  roles!: string[]

  @ApiProperty({ type: [String], example: [] })
  permissions!: string[]
}
