import { Controller, Get } from "@nestjs/common";
import {
	ApiBearerAuth,
	ApiOkResponse,
	ApiOperation,
	ApiTags,
} from "@nestjs/swagger";
import { type AuthUser, CurrentUser } from "@shared/current-user.decorator";
import { MeDto } from "./dto/me.dto";

/**
 * There is no `/auth/login` — sign-in is a federated handoff handled entirely by
 * OpenAuthFederated on the browser side. The backend only reads the current identity.
 */
@ApiTags("auth")
@ApiBearerAuth()
@Controller("auth")
export class AuthController {
	@Get("me")
  @ApiOperation({
    summary: "The current user — the verified identity when signed in, else the `default` user",
  })
  @ApiOkResponse({ type: MeDto })
  me(@CurrentUser() user: AuthUser): MeDto {
    // Login is optional: the global guard always supplies a user (the `default` user when logged
    // out), so this never 401s. Callers read `authenticated` to know which case they got.
    return user
  }
}
