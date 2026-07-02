import { Module } from "@nestjs/common";
import { PassportModule } from "@nestjs/passport";
import { AuthController } from "./auth.controller";
import { AuthFederatedStrategy } from "./auth.strategy";

/**
 * Auth wiring. There is NO local credential store or token signing here — the app is a consumer of
 * OpenAuthFederated (the embedded Frontend API middleware is mounted in main.ts; see
 * auth-frontend.ts). This strategy verifies inbound Bearer tokens; the global JwtAuthGuard
 * (registered in app.module) enforces it on every route.
 */
@Module({
	imports: [PassportModule],
	controllers: [AuthController],
	providers: [AuthFederatedStrategy],
})
export class AuthModule {}
