import fs from "node:fs/promises";
import path from "node:path";
import { BasePlugin } from "../engine/BasePlugin.js";
import { PluginPhase, ResourceContext } from "../engine/types.js";

// --- Helper: Static-site export mapping ---
function htmlUrlToArchivePath(url: string): string {
    const urlObj = new URL(url);
    let relPath = urlObj.pathname;
    const htmlExts = [".html", ".htm", ".xhtml"];
    if (relPath === "/" || relPath === "") return "index.html";
    relPath = relPath.replace(/^\/+/, "");
    const endsWithSlash = urlObj.pathname.endsWith("/");
    const ext = path.extname(urlObj.pathname).toLowerCase();
    if (endsWithSlash || !ext || !htmlExts.includes(ext)) {
        return path.join(relPath.replace(/\/+$/,""), "index.html");
    }
    return relPath;
}

// --- Helper: Write meta/JS redirect page ---
async function writeRedirectHtml(destPath: string, targetPath: string) {
    const redirectHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; URL='${targetPath}'" />
    <link rel="canonical" href="${targetPath}">
    <script>window.location.replace(${JSON.stringify(targetPath)});</script>
</head>
<body>
    <p>Redirecting to <a href="${targetPath}">${targetPath}</a> ...</p>
</body>
</html>`;
    await fs.mkdir(path.dirname(destPath), { recursive: true });
    await fs.writeFile(destPath, redirectHtml, "utf8");
}

// -------- MAIN PLUGIN --------
export class ArchivePlugin extends BasePlugin {
    name = "archive";
    phases: PluginPhase[] = ["afterGoto", "process"];

    private htmlMode: "raw" | "dom" =
        process.env.ARCHIVE_HTML_MODE === "dom" ? "dom" : "raw";
    private websiteId: string =
        process.env.WEBSITE_ID ||
        (process.env.START_URL
            ? new URL(process.env.START_URL).hostname
            : "unknown_site");
    private outputDir: string = path.resolve(
        process.env.ARCHIVE_OUTPUT_DIR || "downloads/archive",
        this.websiteId
    );
    private storeLocalAssets: boolean =
        process.env.ARCHIVE_STORE_LOCAL_ASSETS !== "false";
    private excludePaths: string[] = (process.env.ARCHIVE_EXCLUDE_ASSETS_PATHS || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    private excludeExtensions: string[] = (process.env.ARCHIVE_EXCLUDE_ASSETS_EXTENSIONS || "")
        .split(",")
        .map((s) => s.trim().replace(/^\./, "").toLowerCase())
        .filter(Boolean);

    private seenAssets = new Set<string>();
    private savedPages = new Set<string>();
    private savedAssets: { path: string; ext: string; mime?: string }[] = [];
    private networkRequestsMap = new WeakMap<any, string[]>();

    applies(ctx: ResourceContext): boolean {
        return !!ctx.mime && ctx.mime.startsWith("text/html") && !ctx.download;
    }

    async run(phase: PluginPhase, ctx: ResourceContext): Promise<void> {
        try {
            if (phase === "afterGoto") {
                await this.archiveHtml(ctx);
                if (ctx.page) this.attachNetworkLogger(ctx.page);
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
        // Skip archiving HTML pages for non-OK (404/500/etc) responses
        if (ctx.response && (!ctx.response.ok() || (ctx.response.status() && ctx.response.status() >= 400))) {
            // Optionally log: console.warn(`[ArchivePlugin] SKIP HTML (non-OK response): ${ctx.page?.url() || ctx.url} status=${ctx.response.status()}`);
            return;
        }
        const originalUrl = ctx.url;
        const finalUrl = ctx.page?.url?.() ? ctx.page.url() : ctx.url;
        const archiveRelPath = htmlUrlToArchivePath(finalUrl);
        const destPath = path.join(this.outputDir, archiveRelPath);

        // Remove file if it's in the way of a directory creation
        const parentDir = path.dirname(destPath);
        try {
            const stats = await fs.stat(parentDir).catch(() => null);
            if (stats && stats.isFile()) {
                await fs.unlink(parentDir);
            }
        } catch {}

        await fs.mkdir(path.dirname(destPath), { recursive: true });
        let html = "";
        if (this.htmlMode === "dom" && ctx.page) {
            html = await ctx.page.content();
        } else if (ctx.response) {
            html = await ctx.response.text();
        }


        await fs.writeFile(destPath, html, "utf8");
        this.savedPages.add(finalUrl);
        this.registerInfo(
            ctx,
            "content",
            "ARCHIVED_HTML",
            `HTML archived to ${destPath}`
        );

        // --- SYNTHETIC ROOT /index.html On Redirect ---
        const originalPathname = new URL(originalUrl).pathname;
        const finalPathname = new URL(finalUrl).pathname;

        if ((originalPathname === "/" || originalPathname === "") && finalPathname !== originalPathname) {
            const relativeTarget = finalPathname + new URL(finalUrl).search + new URL(finalUrl).hash;
            const rootIndex = path.join(this.outputDir, "index.html");
            await writeRedirectHtml(rootIndex, relativeTarget);
            this.savedPages.add(originalUrl);
            this.registerInfo(
                ctx,
                "content",
                "ARCHIVED_HTML",
                `Synthetic /index.html redirecting to ${relativeTarget}`
            );
        }
    }

    private attachNetworkLogger(page: any) {
        if (!this.networkRequestsMap.has(page)) {
            const reqs: string[] = [];
            this.networkRequestsMap.set(page, reqs);
            page.on("requestfinished", (req: any) => {
                const url = req.url();
                const rt = req.resourceType ? req.resourceType() : "";
                if (rt !== "document" && !reqs.includes(url)) {
                    reqs.push(url);
                }
            });
        }
    }

    private async archiveAssets(ctx: ResourceContext) {
        const origin = new URL(ctx.url).origin;
        const page = ctx.page;

        let netAssetUrls: string[] =
            page && this.networkRequestsMap.has(page)
                ? this.networkRequestsMap.get(page)!
                : [];

        // Universal DOM scrape for any link[href][rel] and src assets (img, script, etc.)
        const domAssets: string[] = await page.evaluate(() => {
            const urls: string[] = [];
            document.querySelectorAll('img[src],script[src],video[src],audio[src],source[src],iframe[src]')
                .forEach((e: any) => urls.push(e.src));
            document.querySelectorAll('link[rel][href]')
                .forEach((e: any) => urls.push(e.href));
            return urls;
        });

        // --- CSS: Extract all asset URLs (fonts, images, SVG, etc)
        const cssAssetUrls: string[] = await page.evaluate(() => {
            const urls: string[] = [];
            for (const styleSheet of Array.from(document.styleSheets)) {
                let rules: CSSRuleList | null = null;
                try { rules = styleSheet.cssRules; } catch { continue; }
                if (!rules) continue;
                for (const rule of Array.from(rules)) {
                    // Look in any CSS rule, not just font-face!
                    const text = rule.cssText;
                    const matches = text.match(/url\(([^)]+)\)/g);
                    if (matches) {
                        for (const m of matches) {
                            let urlValue = m.replace(/^url\(["']?/, "").replace(/["']?\)$/, "");
                            urlValue = urlValue.trim();
                            if (urlValue && !urlValue.startsWith("data:")) urls.push(urlValue);
                        }
                    }
                }
            }
            return urls;
        });
        for (const url of cssAssetUrls) netAssetUrls.push(url);

        // Merge, deduplicate, filter
        const assetUrls = new Set<string>([
            ...netAssetUrls,
            ...domAssets
        ]);

        for (const assetUrl of assetUrls) {
            try {
                if (!assetUrl) continue;
                // Relative URLs for fonts and CSS: resolve against document!
                const absUrl = assetUrl.startsWith("http")
                    ? assetUrl
                    : new URL(assetUrl, ctx.url).href;
                if (!this.storeLocalAssets && absUrl.startsWith(origin)) continue;
                if (!absUrl.startsWith(origin)) continue;
                if (this.seenAssets.has(absUrl)) continue;
                this.seenAssets.add(absUrl);

                const urlObj = new URL(absUrl);
                let assetRelPath = urlObj.pathname.replace(/^\//, "");

                // Defensive cleaning: remove spaces/newlines from HTML references
                assetRelPath = assetRelPath.trim();
                if (!assetRelPath || assetRelPath.endsWith("/")) {
                    continue;
                }
                if (this.excludePaths.some((sub) => assetRelPath.includes(sub))) continue;
                const ext = path.extname(assetRelPath).replace(".", "").toLowerCase() || "noext";
                if (this.excludeExtensions.includes(ext)) continue;
                const destPath = path.join(this.outputDir, assetRelPath);


                // Remove destPath if it's a directory
                try {
                    const stat = await fs.stat(destPath).catch(() => null);
                    if (stat && stat.isDirectory()) {
                        await fs.rm(destPath, { recursive: true, force: true });
                    }
                } catch {}

                const assetResp = await fetch(absUrl);
                const contentType = assetResp.headers.get("content-type");
                if (!assetResp.ok) {
                    continue;
                }
                if (!contentType || contentType.startsWith("text/html")) {
                    continue;
                }
                // Only now, after validating, create parent dir and write file
                const parent = path.dirname(destPath);
                try {
                    const stat = await fs.stat(parent).catch(() => null);
                    if (stat && stat.isFile()) {
                        await fs.unlink(parent);
                    }
                } catch {}
                await fs.mkdir(parent, { recursive: true });

                const buffer = await assetResp.arrayBuffer();
                await fs.writeFile(destPath, Buffer.from(buffer));
                const mime = contentType || undefined;
                this.savedAssets.push({ path: assetRelPath, ext, mime });
                this.registerInfo(
                    ctx,
                    "resources",
                    "ARCHIVED_ASSET",
                    `Asset archived to ${destPath}`,
                    { assetUrl }
                );
            } catch (e) {
                this.registerWarning(
                    ctx,
                    "resources",
                    "ARCHIVE_UNEXPECTED_ERROR",
                    `Failed to archive asset ${assetUrl}: ${
                        e instanceof Error ? e.message : String(e)
                    }`
                );
            }
        }
    }

    getReport() {
        const extCount: Record<string, number> = {};
        for (const asset of this.savedAssets) {
            extCount[asset.ext] = (extCount[asset.ext] || 0) + 1;
        }
        // Remove 'noext' from report
        if (extCount["noext"]) delete extCount["noext"];
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
                ...this.mapAssetExtensionBreakdown(extCount),
            ],
        };
    }

    private mapAssetExtensionBreakdown(extCount: Record<string, number>) {
        return Object.entries(extCount)
            .sort((a, b) => b[1] - a[1])
            .map(([ext, count]) => ({
                key: `assets_${ext}`,
                label: `Assets .${ext}`,
                value: count,
            }));
    }
}
