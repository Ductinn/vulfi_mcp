/**
 * Optional OMP triage board.
 *
 * This is a session-local view of validated VulFi MCP results. It is not a
 * second MCP client, not a store, and not OMP's native todo list. Operator
 * commands spawn `vulfi-mcp` with a fixed argv only after a TUI confirmation.
 * A shell-capable agent that already has the operator's OS credentials can
 * still run that binary; the confirmation is not a credential boundary.
 */
import { accessSync, constants, readFileSync } from "node:fs";
import path from "node:path";

const VULFI_TOOLS: Record<string, true> = {
	vulfi_scan: true,
	vulfi_findings: true,
	vulfi_prepare: true,
	vulfi_preparation: true,
	vulfi_propose_recovery: true,
	vulfi_triage: true,
};

const TRIAGE_STATUSES: Record<string, true> = {
	"Not Checked": true,
	"False Positive": true,
	Suspicious: true,
	Vulnerable: true,
};

const BACKENDS: Record<string, true> = { ida: true, ghidra: true, r2: true };
const CHOSEN_SOURCES: Record<string, true> = { ida: true, external: true, new: true };
const STATUS_ORDER = ["Not Checked", "False Positive", "Suspicious", "Vulnerable"] as const;

interface FindingRow {
	id: string;
	backend: string;
	status: string;
	stale: boolean;
	address: string;
	addressSpace: string;
	functionName: string;
	linkId: string;
	rationale: string;
}

interface LinkRow {
	linkId: string;
	syncState: string;
	idaFindingId: string;
	externalFindingId: string;
	status: string;
	rationale: string;
}

interface ScopeRow {
	scope: string;
	state: string;
	total: number;
	staleTotal: number;
	coverage: string;
}

interface ProposalRow {
	proposalId: string;
	effect: string;
	expectedRevision: number;
	evidence: string;
	state: string;
}

interface BoardState {
	path: string;
	findings: FindingRow[];
	links: LinkRow[];
	statusCounts: Record<string, Record<string, number>>;
	scopes: Array<{ backend: string; row: ScopeRow }>;
	storeWarnings: string[];
	loaded: number;
	targetTotal: number;
	incomplete: boolean;
	refreshedAt: string;
	findingsStale: boolean;
	prepLines: string[];
	prepRefreshedAt: string;
	prepStale: boolean;
	proposals: ProposalRow[];
	proposalPath: string;
	proposalRevision: number;
}

function emptyBoard(): BoardState {
	return {
		path: "",
		findings: [],
		links: [],
		statusCounts: {},
		scopes: [],
		storeWarnings: [],
		loaded: 0,
		targetTotal: 0,
		incomplete: false,
		refreshedAt: "",
		findingsStale: false,
		prepLines: [],
		prepRefreshedAt: "",
		prepStale: false,
		proposals: [],
		proposalPath: "",
		proposalRevision: 0,
	};
}

function trustedServers(cwd: string): Record<string, true> {
	const trusted: Record<string, true> = {};
	for (const relative of [".mcp.json", "mcp.json", path.join(".omp", "mcp.json")]) {
		let parsed: unknown;
		try {
			parsed = JSON.parse(readFileSync(path.join(cwd, relative), "utf8"));
		} catch {
			continue;
		}
		if (!isRecord(parsed) || !isRecord(parsed.mcpServers)) continue;
		for (const [name, config] of Object.entries(parsed.mcpServers)) {
			if (!isRecord(config) || typeof config.command !== "string") continue;
			if (path.basename(config.command) === "vulfi-mcp") trusted[name] = true;
		}
	}
	return trusted;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function mintedToolName(serverName: string, toolName: string): string {
	const sanitize = (value: string, fallback: string) => {
		const cleaned = value
			.toLowerCase()
			.replace(/[^a-z0-9_]+/g, "_")
			.replace(/_+/g, "_")
			.replace(/^_+|_+$/g, "");
		return cleaned.length > 0 ? cleaned : fallback;
	};
	const server = sanitize(serverName, "server");
	let tool = sanitize(toolName, "tool");
	const prefix = `${server}_`;
	if (tool.startsWith(prefix)) tool = tool.slice(prefix.length);
	return `mcp__${server}_${tool}`;
}
function stripUntrusted(value: string): string {
	const withoutControls = value
		.replace(/\u001b\][\s\S]*?(?:\u0007|\u001b\\)/g, "")
		.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
		.replace(/\u001b[@-_]/g, "")
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
	return withoutControls
		.split("\n")
		.filter(line => !/ignore (all|any|previous) instructions|^\s*system\s*:|provider instructions|you are now/i.test(line))
		.join("\n")
		.trim();
}

function textPayload(content: unknown): string {
	if (!Array.isArray(content)) return "";
	return content
		.map(block => (isRecord(block) && block.type === "text" && typeof block.text === "string" ? block.text : ""))
		.join("\n");
}

function parseJson(text: string): unknown {
	const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
	const source = fenced?.[1] ?? text;
	const start = source.indexOf("{");
	if (start < 0) return undefined;
	try {
		return JSON.parse(source.slice(start));
	} catch {
		return undefined;
	}
}

function findingRow(value: unknown): FindingRow | undefined {
	if (!isRecord(value) || typeof value.id !== "string" || value.id.length === 0) return undefined;
	if (typeof value.backend !== "string" || !BACKENDS[value.backend]) return undefined;
	if (typeof value.status !== "string" || !TRIAGE_STATUSES[value.status]) return undefined;
	if (typeof value.stale !== "boolean") return undefined;
	return {
		id: value.id,
		backend: value.backend,
		status: value.status,
		stale: value.stale,
		address: typeof value.address === "string" ? value.address : "",
		addressSpace: typeof value.address_space === "string" ? value.address_space : "",
		functionName: typeof value.function_name === "string" ? stripUntrusted(value.function_name) : "",
		linkId: typeof value.link_id === "string" ? value.link_id : "",
		rationale: typeof value.rationale === "string" ? stripUntrusted(value.rationale) : "",
	};
}

function linkRow(value: unknown): LinkRow | undefined {
	if (!isRecord(value) || typeof value.link_id !== "string" || typeof value.sync_state !== "string") return undefined;
	return {
		linkId: value.link_id,
		syncState: value.sync_state,
		idaFindingId: typeof value.ida_finding_id === "string" ? value.ida_finding_id : "",
		externalFindingId: typeof value.external_finding_id === "string" ? value.external_finding_id : "",
		status: typeof value.status === "string" ? value.status : "",
		rationale: typeof value.rationale === "string" ? stripUntrusted(value.rationale) : "",
	};
}

function countLines(counts: Record<string, Record<string, number>>): string[] {
	const lines: string[] = [];
	for (const backend of Object.keys(counts).sort((left, right) => (left === "aggregate" ? 1 : right === "aggregate" ? -1 : left.localeCompare(right)))) {
		const row = counts[backend];
		if (!row) continue;
		const parts = STATUS_ORDER.filter(status => typeof row[status] === "number").map(status => `${status}=${row[status]}`);
		lines.push(`counts ${backend} ${parts.join(" ")}`.trimEnd());
	}
	return lines;
}

function storeWarnings(health: unknown): string[] {
	if (!isRecord(health)) return [];
	const warnings: string[] = [];
	for (const [name, value] of Object.entries(health)) {
		if (!isRecord(value) || value.available !== false) continue;
		const reason = typeof value.reason === "string" ? stripUntrusted(value.reason) : "unavailable";
		warnings.push(`offline ${name}: ${reason}`);
	}
	return warnings;
}

function scopeRows(health: unknown): Array<{ backend: string; row: ScopeRow }> {
	if (!isRecord(health)) return [];
	const rows: Array<{ backend: string; row: ScopeRow }> = [];
	for (const [backend, value] of Object.entries(health)) {
		if (!isRecord(value) || !Array.isArray(value.scopes)) continue;
		for (const scope of value.scopes) {
			if (!isRecord(scope)) continue;
			rows.push({
				backend,
				row: {
					scope: typeof scope.scope === "string" ? scope.scope : "",
					state: typeof scope.state === "string" ? scope.state : "",
					total: typeof scope.total === "number" ? scope.total : 0,
					staleTotal: typeof scope.stale_total === "number" ? scope.stale_total : 0,
					coverage: typeof scope.coverage === "string" ? scope.coverage : "",
				},
			});
		}
	}
	return rows;
}

function boardLines(state: BoardState): string[] {
	const lines = [
		[
			"VulFi",
			state.refreshedAt ? `refreshed ${state.refreshedAt}` : "not refreshed",
			state.findingsStale ? "stale until vulfi_findings" : "",
			state.prepStale ? "stale until vulfi_preparation" : "",
		]
			.filter(part => part.length > 0)
			.join("  "),
	];
	if (state.path) lines.push(`path ${state.path}`);
	if (state.targetTotal > 0 || state.loaded > 0) {
		lines.push(`loaded ${state.loaded} / ${state.targetTotal}${state.incomplete ? " incomplete" : ""}`);
	}
	lines.push(...state.storeWarnings);
	lines.push(...countLines(state.statusCounts));
	if (state.findings.length > 0) {
		lines.push(`findings ${state.findings.length} (not vulnerabilities)`);
	}
	for (const row of state.findings) {
		const label = row.functionName.length > 0 ? ` function=${row.functionName}` : " function=";
		const rationale = row.rationale.length > 0 ? ` ${row.rationale.replace(/\n/g, " ")}` : "";
		lines.push(
			`${row.backend} id=${row.id} space=${row.addressSpace} address=${row.address} status=${row.status} ${row.stale ? "stale" : "fresh"}${row.linkId ? ` link=${row.linkId}` : ""}${label}${rationale}`,
		);
	}
	for (const link of state.links) {
		lines.push(
			`link ${link.linkId} ${link.syncState} ida=${link.idaFindingId} external=${link.externalFindingId}`,
		);
	}
	for (const scope of state.scopes) {
		const coverage = scope.row.coverage.length > 0 ? ` coverage=${scope.row.coverage}` : "";
		lines.push(
			`scope ${scope.backend} ${scope.row.scope} state=${scope.row.state} total=${scope.row.total} stale_total=${scope.row.staleTotal}${coverage}`,
		);
	}
	if (state.prepRefreshedAt) lines.push(`prep refreshed ${state.prepRefreshedAt}`);
	lines.push(...state.prepLines);
	return lines;
}

function publish(ctx: ExtensionContext, state: BoardState): void {
	ctx.ui.setWidget(
		"vulfi",
		() => ({
			render(width: number) {
				return boardLines(state).map(line => (line.length > width ? line.slice(0, width) : line));
			},
		}),
		{ placement: "belowEditor" },
	);
}

function applyFindings(state: BoardState, page: Record<string, unknown>, append: boolean): boolean {
	if (typeof page.path !== "string" || !Array.isArray(page.findings)) return false;
	if (typeof page.loaded !== "number" || typeof page.target_total !== "number") return false;
	if (!isRecord(page.store_health) || !isRecord(page.status_counts)) return false;
	const rows: FindingRow[] = [];
	for (const item of page.findings) {
		const row = findingRow(item);
		if (!row) return false;
		rows.push(row);
	}
	const links = Array.isArray(page.links) ? page.links.map(linkRow).filter((row): row is LinkRow => row !== undefined) : [];
	if (append && state.path === page.path) {
		const byId: Record<string, FindingRow> = {};
		for (const row of state.findings) byId[row.id] = row;
		for (const row of rows) byId[row.id] = row;
		state.findings = Object.values(byId);
	} else {
		state.findings = rows;
	}
	state.path = page.path;
	state.links = links;
	state.statusCounts = page.status_counts as Record<string, Record<string, number>>;
	state.scopes = scopeRows(page.scope_health);
	state.storeWarnings = storeWarnings(page.store_health);
	state.loaded = page.loaded;
	state.targetTotal = page.target_total;
	state.incomplete = page.target_total_complete === false;
	state.refreshedAt = new Date().toISOString();
	state.findingsStale = false;
	return true;
}

function markFindingsStale(state: BoardState, page: Record<string, unknown>): boolean {
	if (typeof page.path !== "string") return false;
	if (!Array.isArray(page.findings) && !isRecord(page.finding)) return false;
	if (state.path.length > 0 || state.findings.length > 0) state.findingsStale = true;
	return true;
}

function proposalRow(value: unknown): ProposalRow | undefined {
	if (!isRecord(value) || value.accepted === false) return undefined;
	if (typeof value.proposal_id !== "string" || typeof value.expected_revision !== "number") return undefined;
	const evidence = isRecord(value.evidence) ? stripUntrusted(JSON.stringify(value.evidence)) : "";
	return {
		proposalId: value.proposal_id,
		effect: typeof value.effect === "string" ? stripUntrusted(value.effect) : "",
		expectedRevision: value.expected_revision,
		evidence,
		state: typeof value.state === "string" ? value.state : "pending",
	};
}

function applyProposals(state: BoardState, page: Record<string, unknown>): boolean {
	if (typeof page.path !== "string" || page.applied !== false || !Array.isArray(page.proposals)) return false;
	if (typeof page.preparation_revision !== "number") return false;
	const proposals: ProposalRow[] = [];
	for (const item of page.proposals) {
		const row = proposalRow(item);
		if (row) proposals.push(row);
	}
	state.proposals = proposals;
	state.proposalPath = page.path;
	state.proposalRevision = page.preparation_revision;
	return true;
}

function prepLines(page: Record<string, unknown>): string[] {
	const lines: string[] = [];
	if (typeof page.candidate_total === "number") lines.push(`prep candidates ${page.candidate_total}`);
	if (typeof page.loaded === "number" && typeof page.total === "number") {
		lines.push(`prep loaded ${page.loaded} / ${page.total}`);
	}
	const passes = Array.isArray(page.passes) ? page.passes : [];
	for (const pass of passes) {
		if (!isRecord(pass)) continue;
		const name = typeof pass.pass === "string" ? pass.pass : "";
		const backend = typeof pass.backend === "string" ? pass.backend : "";
		const coverage = typeof pass.coverage === "string" ? pass.coverage : "";
		if (backend.length === 0 && name.length === 0) continue;
		lines.push(`prep ${backend} ${name} coverage=${coverage}`.trim());
	}
	return lines;
}

function applyPreparation(state: BoardState, page: Record<string, unknown>, refresh: boolean): boolean {
	if (typeof page.path !== "string") return false;
	if (page.available === false) {
		const reason =
			typeof page.reason === "string" && page.reason.length > 0
				? stripUntrusted(page.reason)
				: "preparation is unavailable";
		const line = `prep unavailable: ${reason}`;
		if (refresh) {
			state.prepLines = [line];
			state.prepRefreshedAt = new Date().toISOString();
			state.prepStale = false;
		} else {
			state.prepStale = true;
			if (state.prepLines.length === 0) state.prepLines = [line];
		}
		return true;
	}
	const lines = prepLines(page);
	if (lines.length === 0 && !Array.isArray(page.passes) && typeof page.candidate_total !== "number") return false;
	if (refresh) {
		state.prepLines = lines;
		state.prepRefreshedAt = new Date().toISOString();
		state.prepStale = false;
		return true;
	}
	state.prepStale = true;
	if (state.prepLines.length === 0) state.prepLines = lines;
	return true;
}

function ingest(state: BoardState, tool: string, payload: unknown): boolean {
	if (!isRecord(payload)) return false;
	if (tool === "vulfi_findings") {
		const offset = typeof payload.offset === "number" ? payload.offset : 0;
		return applyFindings(state, payload, offset > 0);
	}
	if (tool === "vulfi_scan" || tool === "vulfi_triage") return markFindingsStale(state, payload);
	if (tool === "vulfi_propose_recovery") return applyProposals(state, payload);
	if (tool === "vulfi_preparation") return applyPreparation(state, payload, true);
	if (tool === "vulfi_prepare") return applyPreparation(state, payload, false);
	return false;
}

function interactive(ctx: ExtensionCommandContext): boolean {
	return ctx.hasUI && ctx.mode === "tui";
}

function flagValue(args: string[], name: string): string | undefined {
	const index = args.indexOf(name);
	const value = index >= 0 ? args[index + 1] : undefined;
	return value && !value.startsWith("--") ? value : undefined;
}

function resolveCli(): string | undefined {
	const pathValue = process.env.PATH ?? "";
	for (const dir of pathValue.split(path.delimiter)) {
		if (dir.length === 0) continue;
		const candidate = path.join(dir, "vulfi-mcp");
		try {
			accessSync(candidate, constants.X_OK);
		} catch {
			continue;
		}
		return candidate;
	}
	return undefined;
}

async function runCli(pi: ExtensionAPI, ctx: ExtensionCommandContext, args: string[]): Promise<void> {
	const command = resolveCli();
	if (!command) {
		ctx.ui.notify("vulfi-mcp is not on PATH", "error");
		return;
	}
	const result = await pi.exec(command, args);
	const output = [result.stdout, result.stderr].filter(part => part.trim().length > 0).join("\n");
	if (result.code !== 0) {
		ctx.ui.notify(`vulfi-mcp exited ${result.code}${output.length > 0 ? `\n${output}` : ""}`, "error");
		return;
	}
	if (output.length > 0) ctx.ui.notify(output, "info");
}

function tokenize(raw: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let quote = "";
	for (const char of raw) {
		if (quote.length > 0) {
			if (char === quote) quote = "";
			else current += char;
			continue;
		}
		if (char === "'" || char === '"') {
			quote = char;
			continue;
		}
		if (/\s/.test(char)) {
			if (current.length > 0) {
				tokens.push(current);
				current = "";
			}
			continue;
		}
		current += char;
	}
	if (current.length > 0) tokens.push(current);
	return tokens;
}

function cachedMapping(state: BoardState, id: string): string {
	const row = state.findings.find(item => item.id === id);
	if (!row) return `${id} is not on the cached page`;
	return `${row.backend} id=${row.id} space=${row.addressSpace} address=${row.address} status=${row.status}${row.stale ? " stale" : ""}`;
}

function statusRefusal(status: string | undefined): string | undefined {
	if (status && TRIAGE_STATUSES[status]) return undefined;
	return `status ${status ?? "(missing)"} is not one of Not Checked, False Positive, Suspicious, Vulnerable`;
}

export default function vulfiBoard(pi: ExtensionAPI): void {
	const state = emptyBoard();

	pi.on("tool_result", (event, ctx) => {
		if (ctx.agent.kind !== "main") return;
		if (event.isError) return;
		if (!isRecord(event.details)) return;
		const serverName = event.details.serverName;
		const mcpToolName = event.details.mcpToolName;
		if (typeof serverName !== "string" || typeof mcpToolName !== "string") return;
		const trusted = { ...trustedServers(ctx.cwd), ...trustedServers(process.cwd()) };
		if (!trusted[serverName] || !VULFI_TOOLS[mcpToolName]) return;
		if (event.toolName !== mintedToolName(serverName, mcpToolName)) return;
		if (event.details.isError === true) return;
		const payload = parseJson(textPayload(event.content));
		if (!ingest(state, mcpToolName, payload)) return;
		publish(ctx, state);
	});

	pi.registerCommand("vulfi-board", {
		description: "Show the cached VulFi triage board. Does not change native todos or spawn a command.",
		handler: async (_args, ctx) => {
			publish(ctx, state);
			const summary = state.path
				? `VulFi board ${state.path} loaded ${state.loaded} / ${state.targetTotal}`
				: "VulFi board is empty until vulfi_findings or vulfi_preparation returns";
			ctx.ui.notify(summary, "info");
		},
	});

	pi.registerCommand("vulfi-review", {
		description: "Show a cached proposal and, only after confirmation, run vulfi-mcp review.",
		handler: async (raw, ctx) => {
			if (!interactive(ctx)) return;
			const [decision, proposalId] = raw.trim().split(/\s+/);
			const proposal = state.proposals.find(item => item.proposalId === proposalId);
			if ((decision === "approve" || decision === "reject") && proposal) {
				const evidence = [
					`proposal ${proposal.proposalId}`,
					proposal.effect,
					`expected revision ${proposal.expectedRevision}`,
					proposal.evidence,
				]
					.filter(part => part.length > 0)
					.join("\n");
				const accepted = await ctx.ui.confirm(
					decision === "approve" ? "Approve proposal" : "Reject proposal",
					evidence,
				);
				if (!accepted) return;
				const args = [
					"review",
					decision,
					"--path",
					state.proposalPath,
					"--proposal-id",
					proposal.proposalId,
					"--expected-revision",
					String(proposal.expectedRevision),
					"--confirmed",
					decision,
				];
				if (decision === "reject") {
					const reason = tokenize(raw).slice(2).join(" ");
					if (reason.length === 0) return;
					args.push("--reason", reason);
				}
				await runCli(pi, ctx, args);
				return;
			}
			if (!state.proposalPath && !state.path) {
				ctx.ui.notify("No cached VulFi target to review", "warning");
				return;
			}
			const listed = state.proposals.map(item => `${item.proposalId} ${item.effect}`).join("\n");
			const accepted = await ctx.ui.confirm(
				"Review stored proposals",
				listed.length > 0 ? listed : `No cached proposals for ${state.path || state.proposalPath}`,
			);
			if (!accepted) return;
			await runCli(pi, ctx, ["review", "list", "--path", state.proposalPath || state.path, "--json"]);
		},
	});

	pi.registerCommand("vulfi-link", {
		description: "Show link evidence and, only after confirmation, run vulfi-mcp link or resolve.",
		handler: async (raw, ctx) => {
			if (!interactive(ctx)) return;
			const tokens = tokenize(raw);
			if (tokens[0] === "resolve") {
				const linkId = tokens[1];
				const source = flagValue(tokens, "--source");
				const status = flagValue(tokens, "--status");
				const rationale = flagValue(tokens, "--rationale");
				const refused = statusRefusal(status);
				if (refused) {
					ctx.ui.notify(refused, "error");
					return;
				}
				if (!linkId || !source || !CHOSEN_SOURCES[source] || !rationale || !state.path) return;
				const link = state.links.find(item => item.linkId === linkId);
				const accepted = await ctx.ui.confirm(
					"Resolve conflict",
					[
						cachedMapping(state, link?.idaFindingId ?? ""),
						cachedMapping(state, link?.externalFindingId ?? ""),
						link ? `link ${link.linkId} ${link.syncState}` : `${linkId} is not on the cached page`,
					].join("\n"),
				);
				if (!accepted) return;
				await runCli(pi, ctx, [
					"resolve",
					"--path",
					state.path,
					"--link-id",
					linkId,
					"--source",
					source,
					"--status",
					status!,
					"--rationale",
					rationale,
					"--confirmed",
					source,
				]);
				return;
			}
			const idaId = tokens[0];
			const externalId = tokens[1];
			const binary = flagValue(tokens, "--binary");
			const source = flagValue(tokens, "--source");
			const status = flagValue(tokens, "--status");
			const rationale = flagValue(tokens, "--rationale");
			const refused = statusRefusal(status);
			if (refused) {
				ctx.ui.notify(refused, "error");
				return;
			}
			if (!idaId || !externalId || !binary || !source || !CHOSEN_SOURCES[source] || !rationale || !state.path) return;
			const accepted = await ctx.ui.confirm(
				"Link findings",
				[cachedMapping(state, idaId), cachedMapping(state, externalId)].join("\n"),
			);
			if (!accepted) return;
			await runCli(pi, ctx, [
				"link",
				"--path",
				state.path,
				"--ida-id",
				idaId,
				"--external-id",
				externalId,
				"--binary",
				binary,
				"--source",
				source,
				"--status",
				status!,
				"--rationale",
				rationale,
				"--confirmed",
				source,
			]);
		},
	});
}
