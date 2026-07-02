import { RequireRole } from "@module/auth/roles.decorator"
import { Body, Controller, Get, Header, Post, Put, StreamableFile } from "@nestjs/common"
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger"
import { type AuthUser, CurrentUser } from "@shared/current-user.decorator"
import {
  ImportArchiveDto,
  ResetDto,
  UpdateAdminSettingsDto,
  UpdateUserSettingsDto,
} from "./dto/settings.dto"
import { SettingsService } from "./settings.service"
import type {
  ResetResult,
  SettingsView,
  TestNotificationResult,
  ToolsDetection,
} from "./settings.types"

/**
 * The Settings API (pm/settings.mdx "REST contract"). Reads and the per-user write are open to
 * every user — including the logged-out `default` user (pm/security.mdx optional-login model) —
 * while the admin-only global write and the destructive actions carry `@RequireRole("admin")`, so
 * the backend refuses them with 403 regardless of what the UI showed (acceptance #11).
 */
@ApiTags("settings")
@ApiBearerAuth()
@Controller("settings")
export class SettingsController {
  constructor(private readonly settings: SettingsService) {}

  @Get()
  @ApiOperation({ summary: "Effective settings: global config + my per-user block + tool status" })
  view(@CurrentUser() user: AuthUser): Promise<SettingsView> {
    return this.settings.view(user)
  }

  @Put()
  @ApiOperation({ summary: "Update MY per-user fields (notification prefs, appearance)" })
  updateUser(
    @CurrentUser() user: AuthUser,
    @Body() dto: UpdateUserSettingsDto,
  ): Promise<SettingsView> {
    return this.settings.updateUser(user, dto)
  }

  @Put("admin")
  @RequireRole("admin")
  @ApiOperation({ summary: "Update admin-only global fields (checks, channels, storage, tools, access)" })
  updateAdmin(
    @CurrentUser() user: AuthUser,
    @Body() dto: UpdateAdminSettingsDto,
  ): Promise<SettingsView> {
    return this.settings.updateAdmin(user, dto)
  }

  @Post("notifications/test")
  @ApiOperation({ summary: "Send a test notification on my selected channels" })
  testNotification(@CurrentUser() user: AuthUser): Promise<TestNotificationResult> {
    return this.settings.testNotification(user)
  }

  @Post("tools/detect")
  @ApiOperation({ summary: "Re-probe the environment for dig/swaks and return their status" })
  detectTools(): Promise<ToolsDetection> {
    return this.settings.redetectTools()
  }

  @Post("open-state-dir")
  @ApiOperation({ summary: "Reveal the state dir in the OS file manager (Finder on macOS)" })
  openStateDir(): Promise<{ opened: boolean; stateDir: string }> {
    return this.settings.openStateDir()
  }

  @Get("export")
  @Header("Content-Type", "application/zip")
  @ApiOperation({ summary: "Download a zip of config.yaml + domains.yaml + audit history" })
  async exportArchive(): Promise<StreamableFile> {
    const { fileName, data } = await this.settings.exportArchive()
    return new StreamableFile(data, {
      disposition: `attachment; filename="${fileName}"`,
    })
  }

  @Post("import")
  @RequireRole("admin")
  @ApiOperation({ summary: "Restore from a previously exported archive (validated on read)" })
  importArchive(@Body() dto: ImportArchiveDto): Promise<{ imported: string[] }> {
    return this.settings.importArchive(dto.archiveBase64)
  }

  @Post("reset")
  @RequireRole("admin")
  @ApiOperation({ summary: "Reset audit history or the whole app (body selects the scope)" })
  reset(@Body() dto: ResetDto, @CurrentUser() user: AuthUser): Promise<ResetResult> {
    return this.settings.reset(dto.scope, user)
  }
}
