import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";
import { isPythonTestFile } from "./python-utils.js";

const FLASK_CONTEXT_RE =
  /(?:^|\n)\s*(?:from\s+flask\s+import|import\s+flask)\b|\b(?:Flask|Blueprint)\s*\(/;

const FLASK_ROUTE_DECORATOR_RE = /^\s*@[\w.]+\.(route|get|post|put|patch|delete|options|head)\s*\(/;

export const flaskRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "flask-route",
  description:
    "Flask route decorators — Python web entry point coverage for AI review (weak candidate)",
  filePatterns: ["**/*.py"],
  match(content, filePath) {
    if (isPythonTestFile(filePath)) return [];
    if (!FLASK_CONTEXT_RE.test(content)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const methodMatch = lines[i].match(FLASK_ROUTE_DECORATOR_RE);
      if (!methodMatch) continue;

      const method = methodMatch[1].toUpperCase();
      const start = Math.max(0, i - 2);
      const end = Math.min(lines.length, i + 3);
      matches.push({
        vulnSlug: "flask-route",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern:
          method === "ROUTE"
            ? "Flask ROUTE decorator — Python HTTP entry point (weak candidate)"
            : `Flask ${method} route decorator — Python HTTP entry point (weak candidate)`,
      });
    }

    return matches;
  },
};
