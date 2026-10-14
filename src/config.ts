import { readFile, writeFile, mkdir, access } from "node:fs/promises";
import { constants } from "node:fs";
import { parse, stringify } from "yaml";
import { ConfigSchema, type CsshConfig, type ProjectConfig, type ServerConfig } from "./schema.js";
import { CONFIG_DIR, CONFIG_FILE } from "./paths.js";

export async function configExists(): Promise<boolean> {
  try {
    await access(CONFIG_FILE, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function loadConfig(): Promise<CsshConfig> {
  const raw = await readFile(CONFIG_FILE, "utf8");
  const parsed = parse(raw);
  return ConfigSchema.parse(parsed);
}

export async function saveConfig(config: CsshConfig): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  const validated = ConfigSchema.parse(config);
  await writeFile(CONFIG_FILE, stringify(validated), "utf8");
}

export function findProject(
  config: CsshConfig,
  projectId: string
): ProjectConfig | undefined {
  return config.projects.find(
    (p) => p.id.toLowerCase() === projectId.toLowerCase()
  );
}

export function findServer(
  project: ProjectConfig,
  serverId: string
): ServerConfig | undefined {
  return project.servers.find(
    (s) => s.id.toLowerCase() === serverId.toLowerCase()
  );
}

export function createEmptyConfig(): CsshConfig {
  return {
    version: 1,
    security: { require_sudo: true, allow_non_interactive: true },
    projects: [],
  };
}

export function needsSudo(config: CsshConfig, nonInteractive = false): boolean {
  if (nonInteractive) return false;
  if (config.security.require_sudo !== undefined) {
    return config.security.require_sudo;
  }
  return config.security.require_password ?? true;
}

export function allowsNonInteractive(config: CsshConfig): boolean {
  return config.security.allow_non_interactive ?? true;
}

export const EXAMPLE_CONFIG = `version: 1
security:
  require_sudo: true
projects:
  - id: example
    name: Example Project
    servers:
      - id: web
        name: Production Web
        host: ec2-1-2-3-4.compute.amazonaws.com
        user: ubuntu
        group: production
        region: ap-southeast-1
        auth:
          type: pem
          secret: example-web-pem
      - id: api
        name: Production API
        host: ec2-5-6-7-8.compute.amazonaws.com
        user: ubuntu
        group: production
        region: ap-southeast-1
        auth:
          type: key
          secret: my-ed25519-key
`;
