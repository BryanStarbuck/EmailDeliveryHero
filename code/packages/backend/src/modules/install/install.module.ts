import { Module } from "@nestjs/common";
import { InstallController } from "./install.controller";
import { InstallService } from "./install.service";

/**
 * The Install module (pm/install_brew.mdx, pm/install_npm.mdx): detects which Brew/OS tools and
 * npm/pnpm packages are missing for a pending run, installs the selected ones serially via
 * execFile (no shell), and streams per-row progress. Self-contained — no store; detection is
 * computed fresh from the ToolLocator + node_modules resolve.
 */
@Module({
	controllers: [InstallController],
	providers: [InstallService],
	exports: [InstallService],
})
export class InstallModule {}
