import type { Page, Request } from "playwright";

import { BasePlugin } from "../engine/BasePlugin.js";
import type {
    EngineState,
    IPlugin,
    PluginPhase,
    Report,
    ResourceContext,
} from "../engine/types.js";

const RESOURCE_TYPE_TO_DIRECTIVE: Record<string, string> = {
    document: "default-src",
    script: "script-src",
    stylesheet: "style-src",
    image: "img-src",
    font: "font-src",
    xhr: "connect-src",
    fetch: "connect-src",
    websocket: "connect-src",
    eventsource: "connect-src",
    ping: "connect-src",
    media: "media-src",
    object: "object-src",
    embed: "object-src",
    frame: "frame-src",
    iframe: "frame-src",
    worker: "worker-src",
    sharedworker: "worker-src",
    manifest: "manifest-src",
    other: "default-src",
};

const DIRECTIVE_ORDER = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "font-src",
    "connect-src",
    "media-src",
    "object-src",
    "frame-src",
    "worker-src",
    "manifest-src",
];

type CspEntry = {
    origin: string;
    resourceType: string;
    directive: string;
    count: number;
    exampleUrls: string[];
};

type CspInventoryState = {
    entries: Record<string, CspEntry>;
};

type PageCspState = {
    attached: boolean;
    requests: Array<{ origin: string; resourceType: string; url: string }>;
    requestListener: ((request: Request) => void) | null;
};

export type CspInventoryPluginOptions = {
    /**
     * Maximum number of example URLs to store per origin+resourceType combination.
     * Defaults to 3.
     */
    maxExampleUrls?: number;
};

export class CspInventoryPlugin extends BasePlugin implements IPlugin {
    name = "csp-inventory";
    phases: PluginPhase[] = ["beforeGoto", "afterGoto", "finally"];

    private readonly maxExampleUrls: number;
    private readonly pageStates = new WeakMap<Page, PageCspState>();

    constructor(options: CspInventoryPluginOptions = {}) {
        super();
        this.maxExampleUrls = options.maxExampleUrls ?? 3;
    }

    applies(ctx: ResourceContext): boolean {
        return !ctx.download;
    }

    async run(phase: PluginPhase, ctx: ResourceContext): Promise<void> {
        if (ctx.download) return;

        const pageState = this.getPageState(ctx.page);

        if (phase === "beforeGoto") {
            pageState.requests = [];
            this.attachListeners(ctx.page, pageState, ctx.engineState.origin);
            this.register(ctx);
            return;
        }

        if (phase === "afterGoto") {
            const globalState = this.getInventoryState(ctx.engineState);
            const perPageOrigins: Record<
                string,
                { directive: string; resourceTypes: string[]; exampleUrls: string[] }
            > = {};

            for (const { origin, resourceType, url } of pageState.requests) {
                const directive = RESOURCE_TYPE_TO_DIRECTIVE[resourceType] ?? "default-src";
                const globalKey = `${origin}|${resourceType}`;

                // Merge into global crawl state
                if (!globalState.entries[globalKey]) {
                    globalState.entries[globalKey] = {
                        origin,
                        resourceType,
                        directive,
                        count: 0,
                        exampleUrls: [],
                    };
                }
                const entry = globalState.entries[globalKey];
                entry.count += 1;
                if (
                    entry.exampleUrls.length < this.maxExampleUrls &&
                    !entry.exampleUrls.includes(url)
                ) {
                    entry.exampleUrls.push(url);
                }

                // Build per-page summary (grouped by origin)
                if (!perPageOrigins[origin]) {
                    perPageOrigins[origin] = { directive, resourceTypes: [], exampleUrls: [] };
                }
                const pageOrigin = perPageOrigins[origin];
                if (!pageOrigin.resourceTypes.includes(resourceType)) {
                    pageOrigin.resourceTypes.push(resourceType);
                }
                if (
                    pageOrigin.exampleUrls.length < this.maxExampleUrls &&
                    !pageOrigin.exampleUrls.includes(url)
                ) {
                    pageOrigin.exampleUrls.push(url);
                }
            }

            const originCount = Object.keys(perPageOrigins).length;
            if (originCount > 0) {
                this.registerInfo(
                    ctx,
                    "security",
                    "CSP_EXTERNAL_RESOURCE",
                    `Loads resources from ${originCount} external origin(s).`,
                    { externalOrigins: perPageOrigins },
                );
            } else {
                this.register(ctx);
            }
            return;
        }

        if (phase === "finally") {
            this.detachListeners(ctx.page, pageState);
            this.register(ctx);
        }
    }

    getReport(engineState: EngineState): Report {
        const state = this.getInventoryState(engineState);
        const entries = Object.values(state.entries);

        // Collect unique origins and total request counts per directive
        const byDirective: Record<string, { origins: Set<string>; count: number }> = {};
        for (const entry of entries) {
            if (!byDirective[entry.directive]) {
                byDirective[entry.directive] = { origins: new Set(), count: 0 };
            }
            byDirective[entry.directive].origins.add(entry.origin);
            byDirective[entry.directive].count += entry.count;
        }

        const uniqueOrigins = new Set(entries.map((e) => e.origin)).size;

        const reportItems: Array<{ key: string; label: string; value: string | number }> = [
            {
                key: "uniqueExternalOrigins",
                label: "Unique external origins",
                value: uniqueOrigins,
            },
        ];

        const allDirectives = [
            ...DIRECTIVE_ORDER,
            ...Object.keys(byDirective).filter((d) => !DIRECTIVE_ORDER.includes(d)),
        ];

        for (const directive of allDirectives) {
            const group = byDirective[directive];
            if (!group) continue;
            reportItems.push({
                key: directive,
                label: directive,
                value: [...group.origins].sort().join(", "),
            });
        }

        return {
            plugin: this.name,
            label: "CSP Inventory",
            items: reportItems,
        };
    }

    private attachListeners(page: Page, state: PageCspState, origin: string): void {
        if (state.attached) return;

        let startHostname: string;
        try {
            startHostname = new URL(origin).hostname;
        } catch {
            return;
        }

        state.requestListener = (request: Request) => {
            const url = request.url();
            try {
                const parsed = new URL(url);
                // Skip same-origin and non-http(s) requests (data:, blob:, etc.)
                if (parsed.hostname === startHostname) return;
                if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return;

                state.requests.push({
                    origin: parsed.origin,
                    resourceType: request.resourceType(),
                    url,
                });
            } catch {
                // Ignore unparseable URLs
            }
        };

        page.on("request", state.requestListener);
        state.attached = true;
    }

    private detachListeners(page: Page, state: PageCspState): void {
        if (!state.attached || !state.requestListener) return;
        page.off("request", state.requestListener);
        state.requestListener = null;
        state.attached = false;
    }

    private getPageState(page: Page): PageCspState {
        let existing = this.pageStates.get(page);
        if (!existing) {
            existing = { attached: false, requests: [], requestListener: null };
            this.pageStates.set(page, existing);
        }
        return existing;
    }

    private getInventoryState(engineState: EngineState): CspInventoryState {
        const key = "cspInventoryState";
        const existing = engineState.any[key];
        if (existing && typeof existing === "object" && "entries" in (existing as object)) {
            return existing as CspInventoryState;
        }
        const created: CspInventoryState = { entries: {} };
        engineState.any[key] = created;
        return created;
    }
}
