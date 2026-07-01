import { AppConfigModule } from "@config/app-config.module"
import { AuditModule } from "@module/audit/audit.module"
import { AuthModule } from "@module/auth/auth.module"
import { JwtAuthGuard } from "@module/auth/jwt-auth.guard"
import { RolesGuard } from "@module/auth/roles.guard"
import { DomainsModule } from "@module/domains/domains.module"
import { HealthModule } from "@module/health/health.module"
import { Module } from "@nestjs/common"
import { ConfigModule } from "@nestjs/config"
import { APP_GUARD } from "@nestjs/core"

/**
 * Root module. Two global guards run in order (pm/security.mdx §3.3):
 *   1. JwtAuthGuard — "identify, don't gate": verifies any Bearer token and attaches the current
 *      user (the `default` user when logged out); never 401s. @Public() routes skip it.
 *   2. RolesGuard — enforces @RequireRole / @RequirePermission where present (403 for the `default`
 *      user and anyone else lacking the role/permission); ungated routes pass through untouched.
 * Registration order matters: JwtAuthGuard must populate request.user before RolesGuard reads it.
 */
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    AppConfigModule,
    AuthModule,
    HealthModule,
    DomainsModule,
    AuditModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule {}
