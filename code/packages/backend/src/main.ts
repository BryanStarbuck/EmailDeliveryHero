import "reflect-metadata"
import { Logger, ValidationPipe } from "@nestjs/common"
import { ConfigService } from "@nestjs/config"
import { NestFactory } from "@nestjs/core"
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger"
import { appLogger, LOG_DIR } from "@shared/logging"
import helmet from "helmet"
import { AppModule } from "./app.module"
import { buildAuthFrontend } from "./modules/auth/auth-frontend"

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true })
  app.useLogger(appLogger)
  const config = app.get(ConfigService)
  const logger = new Logger("Bootstrap")

  // All REST routes live under /api.
  app.setGlobalPrefix("api")

  // Hardened security headers. CSP is tuned for an API + same-origin SPA; Google's OAuth/JWKS
  // endpoints are allowed for the sign-in redirect flow.
  const isProd = (config.get<string>("NODE_ENV") ?? "development") === "production"
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "base-uri": ["'self'"],
          "frame-ancestors": ["'none'"],
          "object-src": ["'none'"],
          "connect-src": ["'self'", "https://accounts.google.com", "https://www.googleapis.com"],
          "img-src": ["'self'", "data:"],
        },
      },
      hsts: isProd ? { maxAge: 15552000, includeSubDomains: true, preload: false } : false,
      crossOriginEmbedderPolicy: false,
      referrerPolicy: { policy: "no-referrer" },
    }),
  )

  // CORS for the Vite front-end. NEVER reflect an arbitrary Origin with credentials — require an
  // explicit allowlist and fail closed at boot if it is empty.
  const origins = (config.get<string>("CORS_ORIGINS") ?? "http://localhost:9311")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)
  if (origins.length === 0) {
    throw new Error(
      "CORS_ORIGINS is empty. Refusing to start: CORS with credentials requires an explicit " +
        "origin allowlist (e.g. CORS_ORIGINS=http://localhost:9311).",
    )
  }
  app.enableCors({ origin: origins, credentials: true })

  // Embedded OpenAuthFederated Frontend API (real Google Workspace OIDC, in-process — no separate
  // auth server). Mounted as raw middleware at /api/v1 so it sits outside the global prefix's
  // controllers and the JwtAuthGuard: these are the unauthenticated sign-in endpoints the
  // @auth/react client calls (frontendApi '/api' → '/api/v1/...').
  app.use("/api/v1", buildAuthFrontend(config))

  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, transform: true, forbidNonWhitelisted: true }),
  )

  // Swagger → the front-end's OpenAPI codegen can read this spec at /api-json.
  const swaggerConfig = new DocumentBuilder()
    .setTitle("EmailDeliveryHero API")
    .setDescription("Audit email deliverability — spam filters, blacklists, and the fixes to apply.")
    .setVersion("0.1.0")
    .addBearerAuth()
    .build()
  const document = SwaggerModule.createDocument(app, swaggerConfig)
  SwaggerModule.setup("api-docs", app, document, { jsonDocumentUrl: "api-json" })

  process.on("unhandledRejection", (reason) => appLogger.error?.("Unhandled promise rejection", String(reason), "Process"))
  process.on("uncaughtException", (err) => appLogger.error?.("Uncaught exception", String(err), "Process"))

  const raw = config.get<string>("PORT") ?? "9312"
  const port = Number(raw)
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PORT value: ${raw}`)
  }
  await app.listen(port)
  logger.log(`EmailDeliveryHero backend on http://localhost:${port} (docs: /api-docs, spec: /api-json)`)
  logger.log(`Logs: ${LOG_DIR} (info.log, error.log)`)
}

bootstrap().catch((err) => {
  appLogger.error?.("Fatal: backend failed to bootstrap", String(err), "Bootstrap")
  process.exit(1)
})
