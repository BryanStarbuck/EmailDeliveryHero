import {
	Body,
	Controller,
	Delete,
	Get,
	HttpCode,
	Param,
	Patch,
	Post,
} from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { type AuthUser, CurrentUser } from "@shared/current-user.decorator";
import type { MonitoredDomain } from "./domain.types";
import type { DomainsService } from "./domains.service";
import type { CreateDomainDto, UpdateDomainDto } from "./dto/domain.dto";

@ApiTags("domains")
@ApiBearerAuth()
@Controller("domains")
export class DomainsController {
	constructor(private readonly domains: DomainsService) {}

	@Get()
	@ApiOperation({ summary: "List all monitored domains" })
	list(): MonitoredDomain[] {
		return this.domains.list();
	}

	@Get(":id")
  @ApiOperation({ summary: "Get one monitored domain" })
  get(@Param("id") id: string): MonitoredDomain {
    return this.domains.get(id)
  }

	@Post()
	@ApiOperation({ summary: "Add a domain to monitor" })
	create(
		@Body() dto: CreateDomainDto,
		@CurrentUser() user: AuthUser,
	): MonitoredDomain {
		return this.domains.create(dto, user.email);
	}

	@Patch(":id")
	@ApiOperation({
		summary: "Update a monitored domain (label, DKIM selectors, IPs, schedule)",
	})
	update(
		@Param("id") id: string,
		@Body() dto: UpdateDomainDto,
	): MonitoredDomain {
		return this.domains.update(id, dto);
	}

	@Delete(":id")
  @HttpCode(204)
  @ApiOperation({ summary: "Stop monitoring a domain (also removes its audit history)" })
  async remove(@Param("id") id: string): Promise<void> {
    await this.domains.remove(id)
  }
}
