import { AppConfigModule } from "@config/app-config.module"
import { AuditModule } from "@module/audit/audit.module"
import { AuthModule } from "@module/auth/auth.module"
import { JwtAuthGuard } from "@module/auth/jwt-auth.guard"
import { DomainsModule } from "@module/domains/domains.module"
import { HealthModule } from "@module/health/health.module"
import { Module } from "@nestjs/common"
import { ConfigModule } from "@nestjs/config"
import { APP_GUARD } from "@nestjs/core"

/**
 * Root module. Auth is on by default, app-wide: JwtAuthGuard is registered as a global APP_GUARD so
 * every route requires a valid OpenAuthFederated token unless the handler is marked @Public()
 * (health + the embedded auth API mounted in main.ts).
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
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
})
export class AppModule {}
