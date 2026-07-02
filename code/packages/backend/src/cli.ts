#!/usr/bin/env node
/**
 * `edh` — the headless CLI entrypoint (pm/run_checks.mdx §1 trigger #4, §9).
 *
 * `edh scheduler run` boots the store + audit engine WITHOUT an HTTP server (a Nest application
 * context, not a listener) and calls the very same SchedulerService.runNow the REST endpoint
 * uses — one code path for manual, scheduled, and headless runs. It exists for OS schedulers
 * (launchd / cron / systemd / schtasks) on machines where the backend isn't kept running; it is
 * a thin main() around the same service.
 *
 * Exit codes: 0 = run completed (or was legitimately skipped: disabled / already running /
 * recently ran), 2 = usage error, 1 = unexpected failure.
 */
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { logError, logInfo } from "@shared/logging";
import { AppModule } from "./app.module";
import { SchedulerService } from "./modules/scheduler/scheduler.service";

const USAGE = "Usage: edh scheduler run";

async function main(): Promise<number> {
	const [command, subcommand] = process.argv.slice(2);
	if (command !== "scheduler" || subcommand !== "run") {
		console.error(USAGE);
		return 2;
	}
	// No HTTP server (headless): an application context wires the same providers — store, audit
	// engine, scheduler — the web app uses, and nothing listens on a port.
	const app = await NestFactory.createApplicationContext(AppModule, {
		logger: false,
	});
	try {
		logInfo("Headless CLI run starting (edh scheduler run)", "Cli");
		const outcome = await app.get(SchedulerService).runNow("os");
		if (outcome.started) {
			console.log(
				`Scheduled check run finished (${outcome.domains ?? 0} domain(s))`,
			);
		} else {
			console.log(
				`Scheduled check run skipped (${outcome.reason ?? "unknown"})`,
			);
		}
		return 0;
	} catch (err) {
		logError("Headless CLI run failed", err, "Cli");
		console.error(
			`edh scheduler run failed: ${err instanceof Error ? err.message : String(err)}`,
		);
		return 1;
	} finally {
		await app.close();
	}
}

main().then(
	(code) => process.exit(code),
	(err) => {
		console.error(
			`edh failed: ${err instanceof Error ? err.message : String(err)}`,
		);
		process.exit(1);
	},
);
