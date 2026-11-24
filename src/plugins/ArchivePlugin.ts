import fs from "node:fs/promises";
import path from "node:path";
import { BasePlugin } from "../engine/BasePlugin.js";
import { PluginPhase, ResourceContext } from "../engine/types.js";

/**
 * ArchivePlugin
 * - Archives HTML pages (raw or rendered DOM)
 * - Archives assets per page, deduplicated
 * - Optionally skips local assets
 * - Stores outputs in folder including site identifier
 * - Reports archived pages count
 */

export class ArchivePlugin extends BasePlugin {
    name = "archive";
    phases: PluginPhase[] = ["afterGoto", "process"];
    private htmlMode: "raw" | "dom" =
        process.env.ARCHIVE_HTML_MODE === "dom" ? "dom" : "raw";
    private websiteId: string =
        process.env.WEBSITE_ID ||
        (process.env.START_URL ? new URL(process.env.START_URL).hostname : "unknown_site");
    private outputDir: string = path.resolve(
        process.env.ARCHIVE_OUTPUT_DIR || "downloads/archive",
        this.websiteId
    );
    private storeLocalAssets: boolean = process.env.ARCHIVE_STORE_LOCAL_ASSETS !== "false";
    // Exclusion options
    private excludePaths: string[] = (process.env.ARCHIVE_EXCLUDE_ASSETS_PATHS || '').split(',').map(s=>s.trim()).filter(Boolean);
    private excludeExtensions: string[] = (process.env.ARCHIVE_EXCLUDE_ASSETS_EXTENSIONS || '').split(',').map(s=>s.trim().replace(/^\./, '').toLowerCase()).filter(Boolean);
    private seenAssets = new Set<string>();
    private savedPages = new Set<string>();
    private savedAssets: { path: string, ext: string, mime?: string }[] = [];

    applies(ctx: ResourceContext): boolean {
        // Only archive HTML pages (not PDFs or downloads etc)
        return !!ctx.mime && ctx.mime.startsWith("text/html") && !ctx.download;
    }

    async run(phase: PluginPhase, ctx: ResourceContext): Promise<void> {
        try {
            if (phase === "afterGoto") {
                await this.archiveHtml(ctx);
            }
            if (phase === "process") {
                await this.archiveAssets(ctx);
            }
        } catch (e: any) {
            this.registerError(
                ctx,
                "content",
                "ARCHIVE_UNEXPECTED_ERROR",
                `ArchivePlugin failed: ${e instanceof Error ? e.message : String(e)}`
            );
        }
    }

    private async archiveHtml(ctx: ResourceContext) {
        const urlObj = new URL(ctx.url);
        // Copy full path (as in static site exporters)
        let relPath = urlObj.pathname;
        if (!relPath || relPath === "/") {
            relPath = "/index.html";
        } else if (relPath.endsWith("/")) {
            relPath = relPath + "index.html";
        } else if (!relPath.match(/\.[a-zA-Z0-9]+$/)) {
            relPath = relPath + "/index.html";
        }
        relPath = relPath.replace(/^\//, "");
        const destPath = path.join(this.outputDir, relPath); // No /pages prefix
        await fs.mkdir(path.dirname(destPath), { recursive: true });
        let html = "";
        if (this.htmlMode === "dom" && ctx.page) {
            html = await ctx.page.content();
        } else if (ctx.response) {
            html = await ctx.response.text();
        }
        await fs.writeFile(destPath, html, "utf8");
        this.savedPages.add(ctx.url);
        this.registerInfo(
            ctx,
            "content",
            "ARCHIVED_HTML",
            `HTML archived to ${destPath}`
        );
    }

    private async archiveAssets(ctx: ResourceContext) {
        if (!ctx.page) return;
        // --- Extra: Capture all font network requests ---
        const fontRequests = new Set<string>();
        const fontMimeRegex = /font|woff|truetype|opentype/;
        const extFontRegex = /\.(woff2?|ttf|otf|eot)(\?.*)?$/i;
        // Attach only ONCE per page
        ctx.page.on('requestfinished', async (request) => {
            try {
                const response = await request.response();
                const url = request.url();
                if (!response || !url) return;
                const ct = response.headers()['content-type'] || '';
                if (fontMimeRegex.test(ct) || extFontRegex.test(url)) {
                    fontRequests.add(url);
                }
            } catch (e) {
                // Ignore
            }
        });
        // --- Standard DOM asset collection ---
        const assetUrls: string[] = await ctx.page.evaluate(() => {
            const urls: string[] = [];
            document.querySelectorAll('img[src]')
                .forEach(img => urls.push((img as HTMLImageElement).src));
            document.querySelectorAll('script[src]')
                .forEach(script => urls.push((script as HTMLScriptElement).src));
            document.querySelectorAll('link[rel="stylesheet"][href]')
                .forEach(link => urls.push((link as HTMLLinkElement).href));
            document.querySelectorAll('link[rel="preload"][href][as="font"]')
                .forEach(link => urls.push((link as HTMLLinkElement).href));
            document.querySelectorAll('link[rel="icon"][href],link[rel="shortcut icon"][href]')
                .forEach(link => urls.push((link as HTMLLinkElement).href));
            return Array.from(new Set(urls));
        });
        // Add collected font requests after network idle (0.7s)
        await ctx.page.waitForTimeout(700);
        for (const fontUrl of fontRequests) {
            if (!assetUrls.includes(fontUrl)) assetUrls.push(fontUrl);
        }
        const origin = ctx.engineState.origin || (new URL(ctx.url)).origin;
        for (const assetUrl of assetUrls) {
            try {
                if (!assetUrl) continue;
                const absUrl = assetUrl.startsWith("http") ? assetUrl : new URL(assetUrl, ctx.url).href;
                if (!this.storeLocalAssets && absUrl.startsWith(origin)) {
                    continue;
                }
                // Only copy local files
                if (!absUrl.startsWith(origin)) continue;
                if (this.seenAssets.has(absUrl)) continue;
                this.seenAssets.add(absUrl);

                const urlObj = new URL(absUrl);
                let assetRelPath = urlObj.pathname.replace(/^\//, "");
                // Exclude certain paths
                if (this.excludePaths.some(sub => assetRelPath.includes(sub))) continue;
                // Exclude certain extensions
                const ext = path.extname(assetRelPath).replace('.', '').toLowerCase() || 'noext';
                if (this.excludeExtensions.includes(ext)) continue;
                const destPath = path.join(this.outputDir, assetRelPath);

                // Only create directory if about to write the file
                const assetResp = await fetch(absUrl);
                if (assetResp.ok) {
                    await fs.mkdir(path.dirname(destPath), { recursive: true });
                    const buffer = await assetResp.arrayBuffer();
                    await fs.writeFile(destPath, Buffer.from(buffer));
                    // Track extension and mime for report
                    const mime = assetResp.headers.get("content-type") || undefined;
                    this.savedAssets.push({ path: assetRelPath, ext, mime });
                    this.registerInfo(
                        ctx,
                        "resources",
                        "ARCHIVED_ASSET",
                        `Asset archived to ${destPath}`,
                        { assetUrl }
                    );
                } else {
                    this.registerWarning(
                        ctx,
                        "resources",
                        "ARCHIVE_UNEXPECTED_ERROR",
                        `Failed to archive asset ${assetUrl}: HTTP status ${assetResp.status}`
                    );
                }
            } catch (e) {
                this.registerWarning(
                    ctx,
                    "resources",
                    "ARCHIVE_UNEXPECTED_ERROR",
                    `Failed to archive asset ${assetUrl}: ${e instanceof Error ? e.message : String(e)}`
                );
            }
        }
    }

    getReport() {
        // Assets breakdown by extension
        const extCount: Record<string, number> = {};
        for (const asset of this.savedAssets) {
            extCount[asset.ext] = (extCount[asset.ext] || 0) + 1;
        }
        return {
            plugin: this.name,
            label: "Pages & assets archived",
            items: [
                {
                    key: "archiveFolder",
                    label: "Archive folder",
                    value: this.outputDir,
                },
                {
                    key: "pagesSaved",
                    label: "Pages archived",
                    value: this.savedPages.size,
                },
                ...Object.entries(extCount).sort((a,b)=>b[1]-a[1]).map(([ext,count])=>({
                    key: `assets_${ext}`,
                    label: `Assets .${ext}`,
                    value: count,
                })),
            ],
        };
    }
}

