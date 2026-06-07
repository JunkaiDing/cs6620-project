// local-test.js — run the scanner the same way the Lambda does, but against a
// local folder and with no AWS calls. Lets you verify scanning before deploying.
//
//   node local-test.js <path-to-folder-to-scan>
//   (defaults to the bundled sample if no path given)

import { scanDirectory } from "./scanner.js";

const target = process.argv[2] || "./sample";

try {
  const results = scanDirectory(target);
  const all = Object.values(results).flat();
  const summary = {
    filesScanned: Object.keys(results).length,
    totalVulnerabilities: all.length,
    high: all.filter((v) => v.severity === "HIGH").length,
    medium: all.filter((v) => v.severity === "MEDIUM").length,
    low: all.filter((v) => v.severity === "LOW").length,
  };
  console.log("Scanned:", target);
  console.log("Summary:", JSON.stringify(summary, null, 2));
  console.log("Report:", JSON.stringify(results, null, 2));
} catch (err) {
  console.error("Scan failed:", err.message);
  process.exit(1);
}
