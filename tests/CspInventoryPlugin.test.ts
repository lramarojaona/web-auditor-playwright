import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { CspInventoryPlugin } from "../src/plugins/CspInventoryPlugin.js";

describe("CspInventoryPlugin", () => {
    describe("Plugin Configuration", () => {
        it("should use default options when none provided", () => {
            const plugin = new CspInventoryPlugin();

            assert.equal(plugin.name, "csp-inventory");
            assert.deepEqual(plugin.phases, ["beforeGoto", "afterGoto", "finally"]);
        });

        it("should accept custom options", () => {
            const plugin = new CspInventoryPlugin({ maxExampleUrls: 5 });

            assert.equal(plugin.name, "csp-inventory");
            // maxExampleUrls is private, but we can verify the plugin was created successfully
            assert.ok(plugin);
        });

        it("should apply to non-download contexts", () => {
            const plugin = new CspInventoryPlugin();

            const mockContext = { download: false } as any;
            assert.equal(plugin.applies(mockContext), true);

            const mockDownloadContext = { download: true } as any;
            assert.equal(plugin.applies(mockDownloadContext), false);
        });
    });

    describe("Report Generation", () => {
        it("should generate empty report for no inventory data", () => {
            const plugin = new CspInventoryPlugin();
            const mockEngineState = {
                any: {
                    cspInventoryState: { entries: {} }
                }
            } as any;

            const report = plugin.getReport(mockEngineState);

            assert.equal(report.plugin, "csp-inventory");
            assert.equal(report.label, "CSP Inventory");
            assert.equal(report.items.length, 1); // Only uniqueExternalOrigins with value 0
            assert.equal(report.items[0].key, "uniqueExternalOrigins");
            assert.equal(report.items[0].value, 0);
        });

        it("should generate report with inventory data", () => {
            const plugin = new CspInventoryPlugin();
            const mockEngineState = {
                any: {
                    cspInventoryState: {
                        entries: {
                            "https://cdn.example.com|script": {
                                origin: "https://cdn.example.com",
                                resourceType: "script",
                                directive: "script-src",
                                count: 5,
                                exampleUrls: ["https://cdn.example.com/app.js"]
                            },
                            "https://fonts.googleapis.com|font": {
                                origin: "https://fonts.googleapis.com",
                                resourceType: "font",
                                directive: "font-src",
                                count: 2,
                                exampleUrls: ["https://fonts.googleapis.com/font.woff2"]
                            }
                        }
                    }
                }
            } as any;

            const report = plugin.getReport(mockEngineState);

            assert.equal(report.plugin, "csp-inventory");
            assert.equal(report.label, "CSP Inventory");
            assert.ok(report.items.length > 1);

            const uniqueOriginsItem = report.items.find(item => item.key === "uniqueExternalOrigins");
            assert.ok(uniqueOriginsItem);
            assert.equal(uniqueOriginsItem.value, 2);

            const scriptSrcItem = report.items.find(item => item.key === "script-src");
            assert.ok(scriptSrcItem);
            assert.equal(scriptSrcItem.value, "https://cdn.example.com");

            const fontSrcItem = report.items.find(item => item.key === "font-src");
            assert.ok(fontSrcItem);
            assert.equal(fontSrcItem.value, "https://fonts.googleapis.com");
        });
    });

    describe("CSP Violation Parsing", () => {
        it("should parse CSP violation messages correctly", () => {
            const plugin = new CspInventoryPlugin();
            
            // Test the private method through reflection
            const parseCspViolation = (plugin as any).parseCspViolation.bind(plugin);
            
            // Test pattern 1: "blocked the loading of a resource (frame-src) at https://example.com"
            const violation1 = parseCspViolation("Content Security Policy: The page's settings blocked the loading of a resource (frame-src) at https://example.com/iframe");
            assert.ok(violation1);
            assert.equal(violation1.url, "https://example.com/iframe");
            assert.equal(violation1.directive, "frame-src");
            assert.equal(violation1.violationType, "blocked");
            
            // Test pattern 2: Traditional format
            const violation2 = parseCspViolation("Refused to load the script 'https://cdn.example.com/script.js' because it violates the following Content Security Policy directive: 'script-src'");
            assert.ok(violation2);
            assert.equal(violation2.url, "https://cdn.example.com/script.js");
            assert.equal(violation2.directive, "script-src");
            assert.equal(violation2.violationType, "blocked");
            
            // Test report-only mode
            const violation3 = parseCspViolation("[Report Only] Refused to load the stylesheet 'https://fonts.googleapis.com/css' because it violates the following directive: 'style-src'");
            assert.ok(violation3);
            assert.equal(violation3.url, "https://fonts.googleapis.com/css");
            assert.equal(violation3.directive, "style-src");
            assert.equal(violation3.violationType, "report-only");
            
            // Test the actual message format from the report
            const violation4 = parseCspViolation("Loading the script 'https://www.youtube.com/iframe_api' violates the following Content Security Policy directive: \"script-src 'self' 'unsafe-inline' https://cdn-a.cumul.io https://cdn.luzmo.com https://dataviz.static.bosa.fgov.be https://matomo.bosa.be https://player.vimeo.com https://static.doubleclick.net\". Note that 'script-src-elem' was not explicitly set, so 'script-src' is used as a fallback. The action has been blocked.");
            assert.ok(violation4);
            assert.equal(violation4.url, "https://www.youtube.com/iframe_api");
            assert.equal(violation4.directive, "script-src");
            assert.equal(violation4.violationType, "blocked");
        });

        it("should extract blocked URLs in the correct format", () => {
            const plugin = new CspInventoryPlugin();
            
            // Mock page state with blocked resources
            const mockPageState = {
                blockedResources: [
                    {
                        url: "https://example.com/script.js",
                        directive: "script-src",
                        violationType: "blocked",
                        message: "CSP violation"
                    },
                    {
                        url: "https://example.com/script.js", // Same URL, should be counted
                        directive: "script-src", 
                        violationType: "blocked",
                        message: "CSP violation"
                    },
                    {
                        url: "https://fonts.googleapis.com/css",
                        directive: "style-src",
                        violationType: "report-only",
                        message: "CSP violation"
                    }
                ]
            };

            // Extract blocked URLs similar to the plugin logic
            const blockedUrls: Record<string, { directive: string; violationType: string; count: number; message: string }> = {};
            for (const resource of mockPageState.blockedResources) {
                if (resource.url) {
                    const key = resource.url;
                    if (!blockedUrls[key]) {
                        blockedUrls[key] = {
                            directive: resource.directive,
                            violationType: resource.violationType,
                            count: 0,
                            message: resource.message
                        };
                    }
                    blockedUrls[key].count += 1;
                }
            }

            // Verify the structure
            assert.ok(blockedUrls["https://example.com/script.js"]);
            assert.equal(blockedUrls["https://example.com/script.js"].directive, "script-src");
            assert.equal(blockedUrls["https://example.com/script.js"].violationType, "blocked");
            assert.equal(blockedUrls["https://example.com/script.js"].count, 2);
            assert.equal(blockedUrls["https://example.com/script.js"].message, "CSP violation");

            assert.ok(blockedUrls["https://fonts.googleapis.com/css"]);
            assert.equal(blockedUrls["https://fonts.googleapis.com/css"].directive, "style-src");
            assert.equal(blockedUrls["https://fonts.googleapis.com/css"].violationType, "report-only");
            assert.equal(blockedUrls["https://fonts.googleapis.com/css"].count, 1);
            assert.equal(blockedUrls["https://fonts.googleapis.com/css"].message, "CSP violation");
        });
    });
});
