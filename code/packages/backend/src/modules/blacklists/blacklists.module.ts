import { Module } from "@nestjs/common"
import { BlacklistsController } from "./blacklists.controller"

/** The Blacklists technology API — see pm/checks/blacklists.mdx §13 and blacklists.controller.ts. */
@Module({
  controllers: [BlacklistsController],
})
export class BlacklistsModule {}
