import { Global, Module } from "@nestjs/common"
import { AppConfig } from "./app-config"

/** Global typed config accessor — available to every feature module without re-importing. */
@Global()
@Module({
  providers: [AppConfig],
  exports: [AppConfig],
})
export class AppConfigModule {}
