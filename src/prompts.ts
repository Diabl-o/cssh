import * as p from "@clack/prompts";
import type { CsshConfig, ProjectConfig, ServerConfig } from "./schema.js";

const GROUP_ORDER = ["staging", "production", "legacy", "other"];

function cancelIfNeeded<T>(value: T | symbol): T {
  if (p.isCancel(value)) {
    p.cancel("Operation cancelled.");
    process.exit(0);
  }
  return value;
}

export async function selectProject(
  config: CsshConfig
): Promise<ProjectConfig> {
  const value = await p.select({
    message: "Select project",
    options: config.projects.map((project) => ({
      value: project.id,
      label: project.name,
      hint: `${project.servers.length} server(s)`,
    })),
  });

  const projectId = cancelIfNeeded(value);
  const project = config.projects.find((proj) => proj.id === projectId);
  if (!project) {
    throw new Error(`Project not found: ${projectId}`);
  }
  return project;
}

function groupServers(servers: ServerConfig[]): Map<string, ServerConfig[]> {
  const grouped = new Map<string, ServerConfig[]>();
  for (const server of servers) {
    const group = (server.group ?? "other").toLowerCase();
    const list = grouped.get(group) ?? [];
    list.push(server);
    grouped.set(group, list);
  }
  return grouped;
}

function orderedGroups(grouped: Map<string, ServerConfig[]>): string[] {
  const present = [...grouped.keys()];
  const ordered = GROUP_ORDER.filter((g) => present.includes(g));
  for (const g of present) {
    if (!ordered.includes(g)) ordered.push(g);
  }
  return ordered;
}

function formatGroupTitle(group: string): string {
  const titles: Record<string, string> = {
    staging: "Staging servers",
    production: "Production servers",
    legacy: "Legacy servers",
    other: "Other servers",
  };
  return titles[group] ?? `${group} servers`;
}

function serverOptionLabel(server: ServerConfig): string {
  return `${server.name.trim()}  ${server.user}@${server.host}`;
}

function groupBannerLines(group: string, servers: ServerConfig[]): string {
  const lines = [formatGroupTitle(group)];
  for (const server of servers) {
    lines.push(`  -- ${server.name.trim()}  ${server.user}@${server.host}`);
  }
  return lines.join("\n");
}

export async function selectServer(
  project: ProjectConfig
): Promise<ServerConfig> {
  if (project.servers.length === 0) {
    throw new Error(`Project "${project.id}" has no servers. Run: cssh config add-server`);
  }
  const grouped = groupServers(project.servers);
  const groups = orderedGroups(grouped);

  if (groups.length === 1) {
    return selectServerInGroup(project.name, groups[0], grouped.get(groups[0])!);
  }

  const groupValue = await p.select({
    message: `Select environment — ${project.name}`,
    options: groups.map((group) => {
      const inGroup = grouped.get(group)!;
      const roles = inGroup.map((s) => s.name.trim()).join(", ");
      return {
        value: group,
        label: formatGroupTitle(group),
        hint: roles,
      };
    }),
  });

  const group = cancelIfNeeded(groupValue) as string;
  return selectServerInGroup(project.name, group, grouped.get(group)!);
}

async function selectServerInGroup(
  _projectName: string,
  group: string,
  servers: ServerConfig[]
): Promise<ServerConfig> {
  if (servers.length === 1) {
    return servers[0];
  }

  p.note(groupBannerLines(group, servers), formatGroupTitle(group));

  const value = await p.select({
    message: `Select server — ${formatGroupTitle(group)}`,
    options: servers.map((server) => ({
      value: server.id,
      label: `${server.name.trim()} — ${server.user}@${server.host}`,
      hint: server.id,
    })),
  });

  const serverId = cancelIfNeeded(value);
  const server = servers.find((s) => s.id === serverId);
  if (!server) {
    throw new Error(`Server not found: ${serverId}`);
  }
  return server;
}

export async function promptText(
  message: string,
  placeholder?: string,
  validate?: (value: string) => string | undefined
): Promise<string> {
  const value = await p.text({ message, placeholder, validate });
  return cancelIfNeeded(value);
}

export async function promptOptionalText(
  message: string,
  placeholder?: string
): Promise<string | undefined> {
  const value = await p.text({
    message,
    placeholder,
    defaultValue: "",
  });
  const result = cancelIfNeeded(value);
  return result.trim() === "" ? undefined : result.trim();
}

export async function promptAuthType(): Promise<"key" | "pem" | "agent"> {
  const value = await p.select({
    message: "Authentication type",
    options: [
      { value: "pem", label: "PEM file", hint: "EC2 key pair" },
      { value: "key", label: "Private key", hint: "ed25519 / rsa" },
      { value: "agent", label: "SSH agent", hint: "Use running ssh-agent" },
    ],
  });
  return cancelIfNeeded(value) as "key" | "pem" | "agent";
}

export async function promptSecretId(): Promise<string> {
  return promptText("Secret id", "my-server-pem", (value) => {
    if (!/^[a-z0-9][a-z0-9_-]*$/i.test(value)) {
      return "Use alphanumeric id with dashes/underscores";
    }
    return undefined;
  });
}
