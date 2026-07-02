import { SchedulerModule } from "@module/scheduler/scheduler.module"
import { Module } from "@nestjs/common"
import { SettingsController } from "./settings.controller"
import { SettingsService } from "./settings.service"

/**
 * The Settings concern (pm/settings.mdx): GET/PUT /api/settings, the admin-only global write, and
 * the §4–§6 actions (test notification, tool re-detect, export/import/reset). Imports the
 * scheduler module because the §3 `schedule:` block is owned there — settings writes that touch
 * it delegate so the in-process timer re-arms on save.
 */
@Module({
  imports: [SchedulerModule],
  controllers: [SettingsController],
  providers: [SettingsService],
})
export class SettingsModule {}
