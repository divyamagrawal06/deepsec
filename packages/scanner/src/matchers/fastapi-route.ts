import type { CandidateMatch } from "@deepsec/core";
import type { MatcherPlugin } from "../types.js";
import { isPythonTestFile } from "./python-utils.js";

const FASTAPI_CONTEXT_RE =
  /(?:^|\n)\s*(?:from\s+fastapi\s+import|import\s+fastapi)\b|\b(?:FastAPI|APIRouter)\s*\(/;

const FASTAPI_ROUTE_DECORATOR_RE =
  /^\s*@[\w.]+\.(get|post|put|patch|delete|options|head|trace|websocket|api_route)\s*\(/;

export const fastapiRouteMatcher: MatcherPlugin = {
  noiseTier: "noisy" as const,
  slug: "fastapi-route",
  description:
    "FastAPI route decorators — Python web entry point coverage for AI review (weak candidate)",
  filePatterns: ["**/*.py"],
  match(content, filePath) {
    if (isPythonTestFile(filePath)) return [];
    if (!FASTAPI_CONTEXT_RE.test(content)) return [];

    const matches: CandidateMatch[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const methodMatch = lines[i].match(FASTAPI_ROUTE_DECORATOR_RE);
      if (!methodMatch) continue;

      const method = methodMatch[1].toUpperCase();
      const start = Math.max(0, i - 2);
      const end = Math.min(lines.length, i + 3);
      matches.push({
        vulnSlug: "fastapi-route",
        lineNumbers: [i + 1],
        snippet: lines.slice(start, end).join("\n"),
        matchedPattern:
          method === "API_ROUTE"
            ? "FastAPI API route decorator — Python HTTP entry point (weak candidate)"
            : `FastAPI ${method} route decorator — Python HTTP entry point (weak candidate)`,
      });
    }

    return matches;
  },
};
