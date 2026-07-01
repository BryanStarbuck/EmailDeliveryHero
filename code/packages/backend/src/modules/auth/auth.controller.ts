import { Controller, Get, UnauthorizedException } from "@nestjs/common"
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from "@nestjs/swagger"
import { type AuthUser, CurrentUser } from "@shared/current-user.decorator"
import { logWarn } from "@shared/logging"
import { MeDto } from "./dto/me.dto"

/**
 * There is no `/auth/login` — sign-in is a federated handoff handled entirely by
 * OpenAuthFederated on the browser side. The backend only reads the verified identity.
 */
@ApiTags("auth")
@ApiBearerAuth()
@Controller("auth")
export class AuthController {
  @Get("me")
  @ApiOperation({ summary: "Current authenticated user (from the verified token)" })
  @ApiOkResponse({ type: MeDto })
  me(@CurrentUser() user: AuthUser): MeDto {
    if (!user) {
      logWarn("GET /auth/me reached with no authenticated user on the request", "AuthController")
      throw new UnauthorizedException()
    }
    return user
  }
}
