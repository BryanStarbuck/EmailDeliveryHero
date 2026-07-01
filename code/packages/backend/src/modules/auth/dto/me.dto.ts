import { ApiProperty } from "@nestjs/swagger"

/**
 * The current user, as returned by GET /auth/me. When signed in this is the verified identity from
 * the OpenAuthFederated token claims; when logged out it is the built-in `default` user
 * (`authenticated: false`). See pm/security.mdx §2–§3.
 */
export class MeDto {
  @ApiProperty({ example: "user_2ab...", description: '`"default"` when logged out' })
  userId!: string

  @ApiProperty({
    example: "bryan@whitehatengineering.com",
    description: '`"default"` when logged out',
  })
  email!: string

  @ApiProperty({
    example: true,
    description: "true for a verified signed-in identity; false for the default (logged-out) user",
  })
  authenticated!: boolean

  @ApiProperty({ nullable: true, example: "sess_..." })
  sessionId!: string | null

  @ApiProperty({ nullable: true, example: null })
  orgId!: string | null

  @ApiProperty({ type: [String], example: ["admin"] })
  roles!: string[]

  @ApiProperty({ type: [String], example: [] })
  permissions!: string[]
}
