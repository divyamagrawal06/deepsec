import { findProject, getConfig } from "@deepsec/core";
import { BOLD, DIM, RESET } from "./formatters.js";

/**
 * Resolve --project-id: if omitted and the config has exactly one project, use it.
 * Exits with a clear error otherwise.
 */
export function resolveProjectId(projectId: string | undefined, command: string): string {
  if (projectId) return projectId;

  const config = getConfig();
  if (!config || config.projects.length === 0) {
    console.error(
      `error: --project-id is required (no deepsec.config found or it has no projects)`,
    );
    process.exit(1);
  }

  if (config.projects.length === 1) {
    const id = config.projects[0].id;
    console.log(`${DIM}Using project ${BOLD}${id}${RESET}${DIM} (only project in config)${RESET}`);
    return id;
  }

  const ids = config.projects.map((p) => p.id);
  console.error(
    `error: --project-id is required when config has multiple projects\n` +
      `  Available: ${ids.join(", ")}\n` +
      `  Example:   deepsec ${command} --project-id ${ids[0]}`,
  );
  process.exit(1);
}

/**
 * Resolve --root for the scan command: if omitted, read from the project's config declaration.
 * Falls back to "." if neither is available.
 */
export function resolveRoot(root: string | undefined, projectId: string): string {
  if (root) return root;

  const project = findProject(projectId);
  if (project?.root) {
    console.log(`${DIM}Using root ${BOLD}${project.root}${RESET}${DIM} (from config)${RESET}`);
    return project.root;
  }

  // No config root either — default to cwd
  console.log(`${DIM}Using root ${BOLD}.${RESET}${DIM} (default)${RESET}`);
  return ".";
}
