import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
} from "@nestjs/common"
import type { Request, Response } from "express"
import { appLogger } from "./logging"

/**
 * Global exception filter (see pm/errors.mdx §3). `@Catch()` with no argument catches EVERY
 * exception thrown out of any route — expected HttpExceptions (validation, 404, 401) and
 * *unexpected* thrown values alike — so a developer never has to remember to wrap a handler.
 *
 * Expected 4xx HttpExceptions are logged as WARN; 5xx and non-HTTP throwables are logged as ERROR
 * with the stack, and the client gets a clean JSON body that never leaks internals.
 *
 * Registered in main.ts via `app.useGlobalFilters(new AllExceptionsFilter())`.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest<Request>()

    const isHttp = exception instanceof HttpException
    const status = isHttp ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR

    // Derive a client-safe message. For 5xx / unknown throwables we never echo internals.
    let clientMessage: string | string[]
    if (isHttp) {
      const body = exception.getResponse()
      clientMessage =
        typeof body === "string"
          ? body
          : ((body as { message?: string | string[] })?.message ?? exception.message)
    } else {
      clientMessage = "Internal server error"
    }

    const where = request ? `${request.method} ${request.originalUrl ?? request.url}` : "unknown"
    const detail = exception instanceof Error ? exception : String(exception)

    // 4xx are expected client mistakes → WARN. 5xx / non-HTTP are real faults → ERROR (with stack).
    if (status >= HttpStatus.INTERNAL_SERVER_ERROR) {
      appLogger.logError(`Unhandled error on ${where} → ${status}`, detail, "HttpException")
    } else {
      const msg = Array.isArray(clientMessage) ? clientMessage.join("; ") : clientMessage
      appLogger.logWarn(`${where} → ${status}: ${msg}`, "HttpException")
    }

    if (response.headersSent) return
    try {
      response.status(status).json({
        statusCode: status,
        error: HttpStatus[status] ?? "Error",
        message: clientMessage,
        path: request?.originalUrl ?? request?.url,
        timestamp: new Date().toISOString(),
      })
    } catch (sendErr) {
      // Even failing to send the error response is logged rather than swallowed.
      appLogger.logError("Failed to send error response", sendErr, "HttpException")
    }
  }
}
