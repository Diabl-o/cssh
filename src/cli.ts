#!/usr/bin/env node

import { Command } from "commander";
import * as p from "@clack/prompts";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { stdin } from "node:process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  configExists,
  loadConfig,
  saveConfig,
  findProject,
  findServer,
  createEmptyConfig,
  EXAMPLE_CONFIG,
  needsSudo,
  allowsNonInteractive,
} from "./config.js";
import {
  secretsExist,
  initSecrets,
  setSecret,
  getSecret,
  listSecretIds,
  deleteSecret,
} from "./secrets.js";
import { ensureSudoAuthenticated } from "./sudo.js";
import {
  createVaultKey,
  loadVaultKey,
  vaultKeyExists,
} from "./vault-key.js";
import { connectSsh } from "./ssh.js";
import { isNonInteractive, fail, info } from "./non-interactive.js";
import {
  selectProject,
  selectServer,
  promptText,
  promptOptionalText,
  promptAuthType,
  promptSecretId,
} from "./prompts.js";
import type { CsshConfig, ServerConfig } from "./schema.js";
import { CONFIG_DIR, CONFIG_FILE } from "./paths.js";

const program = new Command();

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function requireAuth(
  config: CsshConfig,
  nonInteractive: boolean
): Promise<Buffer | null> {
  if (needsSudo(config, nonInteractive)) {
    await ensureSudoAuthenticated();
  }

  if (!(await vaultKeyExists())) {
    throw new Error("Secrets vault not initialized. Run: cssh secrets init");
  }

  return loadVaultKey();
}

async function connectToServer(
  server: ServerConfig,
  vaultKey: Buffer | null,
  remoteCommand: string[] = [],
  extraArgs: string[] = []
): Promise<number> {
  let secretContent: Buffer | null = null;

  if (server.auth.type === "agent") {
    secretContent = null;
  } else {
    if (!vaultKey) {
      throw new Error("Vault key required to decrypt secrets.");
    }
    if (!(await secretsExist())) {
      throw new Error("Secrets vault not initialized. Run: cssh secrets init");
    }
    secretContent = await getSecret(server.auth.secret, vaultKey);
  }

  return connectSsh({
    server,
    secretContent,
    remoteCommand,
    extraArgs,
  });
}

async function runConnect(
  projectId?: string,
  serverId?: string,
  remoteCommand: string[] = [],
  nonInteractive = false
): Promise<number> {
  if (!(await configExists())) {
    if (nonInteractive) {
      fail(`Config not found at ${CONFIG_FILE}. Run: cssh config init`, 1, true);
    }
    p.log.error(`Config not found at ${CONFIG_FILE}`);
    p.log.info("Run: cssh config init");
    return 1;
  }

  const config = await loadConfig();

  if (nonInteractive && !allowsNonInteractive(config)) {
    fail("Non-interactive mode is disabled in config (allow_non_interactive: false)", 1, true);
  }

  if (nonInteractive && (!projectId || !serverId)) {
    fail(
      "Non-interactive mode requires project and server: cssh -n <project> <server> [-- cmd...]",
      1,
      true
    );
  }

  const vaultKey = await requireAuth(config, nonInteractive);

  let project = projectId ? findProject(config, projectId) : undefined;
  if (projectId && !project) {
    if (nonInteractive) fail(`Project not found: ${projectId}`, 1, true);
    p.log.error(`Project not found: ${projectId}`);
    return 1;
  }

  if (!project) {
    if (config.projects.length === 0) {
      if (nonInteractive) fail("No projects configured.", 1, true);
      p.log.error("No projects configured. Run: cssh config add-project");
      return 1;
    }
    project = await selectProject(config);
  }

  let server = serverId ? findServer(project, serverId) : undefined;
  if (serverId && !server) {
    if (nonInteractive) fail(`Server not found: ${serverId}`, 1, true);
    p.log.error(`Server not found: ${serverId}`);
    return 1;
  }

  if (!server) {
    server = await selectServer(project);
  }

  if (nonInteractive) {
    info(`cssh: ${server.user}@${server.host}`, true);
  } else {
    p.log.info(`Connecting to ${server.name} (${server.user}@${server.host})`);
  }

  return connectToServer(server, vaultKey, remoteCommand);
}

function parseRemoteCommand(argv: string[]): string[] {
  const dashIndex = argv.indexOf("--");
  if (dashIndex === -1) return [];
  return argv.slice(dashIndex + 1);
}

program
  .name("cssh")
  .description("Configurable SSH client with encrypted secrets")
  .version("0.1.0")
  .option(
    "-n, --non-interactive",
    "Skip sudo and prompts (requires: cssh -n <project> <server>)"
  )
  .argument("[project]", "Project id")
  .argument("[server]", "Server id")
  .allowExcessArguments(true)
  .action(async (projectId?: string, serverId?: string, options?: { nonInteractive?: boolean }) => {
    const ni = isNonInteractive(options);
    const remoteCommand = parseRemoteCommand(process.argv);
    try {
      const code = await runConnect(projectId, serverId, remoteCommand, ni);
      process.exit(code);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (ni) fail(message, 1, true);
      p.log.error(message);
      process.exit(1);
    }
  });

const configCmd = program.command("config").description("Manage cssh configuration");

configCmd
  .command("init")
  .description("Initialize config directory and example config")
  .action(async () => {
    p.intro("cssh config init");
    await mkdir(CONFIG_DIR, { recursive: true });

    if (await configExists()) {
      const overwrite = await p.confirm({
        message: `${CONFIG_FILE} already exists. Overwrite?`,
        initialValue: false,
      });
      if (p.isCancel(overwrite) || !overwrite) {
        p.cancel("Skipped config write.");
        process.exit(0);
      }
    }

    const config = createEmptyConfig();
    await saveConfig(config);

    const examplePath = join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "config.example.yaml"
    );
    try {
      const example = await readFile(examplePath, "utf8");
      await writeFile(join(CONFIG_DIR, "config.example.yaml"), example, "utf8");
    } catch {
      await writeFile(join(CONFIG_DIR, "config.example.yaml"), EXAMPLE_CONFIG, "utf8");
    }

    p.outro(`Config initialized at ${CONFIG_DIR}`);
  });

configCmd
  .command("add-project")
  .description("Add a new project")
  .action(async () => {
    p.intro("cssh config add-project");
    const config = (await configExists()) ? await loadConfig() : createEmptyConfig();

    const id = await promptText("Project id", "my-project", (value) => {
      if (!/^[a-z0-9][a-z0-9_-]*$/i.test(value)) {
        return "Use alphanumeric id";
      }
      if (config.projects.some((proj) => proj.id === value)) {
        return "Project id already exists";
      }
      return undefined;
    });

    const name = await promptText("Project name", "My Project");

    config.projects.push({ id, name, servers: [] });
    await saveConfig(config);
    p.outro(`Project "${name}" (${id}) added.`);
  });

configCmd
  .command("add-server")
  .description("Add a server to a project")
  .action(async () => {
    p.intro("cssh config add-server");

    if (!(await configExists())) {
      p.log.error("Config not found. Run: cssh config init");
      process.exit(1);
    }

    const config = await loadConfig();
    if (config.projects.length === 0) {
      p.log.error("No projects. Run: cssh config add-project");
      process.exit(1);
    }

    const project = await selectProject(config);

    const id = await promptText("Server id", "web", (value) => {
      if (!/^[a-z0-9][a-z0-9_-]*$/i.test(value)) {
        return "Use alphanumeric id";
      }
      if (project.servers.some((srv) => srv.id === value)) {
        return "Server id already exists in this project";
      }
      return undefined;
    });

    const name = await promptText("Server display name", "Production CMS");
    const host = await promptText("Hostname or IP", "ec2-1-2-3-4.compute.amazonaws.com");
    const user = await promptText("SSH user", "ubuntu");
    const group = await promptOptionalText("Group (optional)", "production");
    const region = await promptOptionalText("Region (optional)", "ap-southeast-1");
    const authType = await promptAuthType();
    let secret = "";
    if (authType !== "agent") {
      secret = await promptSecretId();
    }

    project.servers.push({
      id,
      name,
      host,
      user,
      group,
      region,
      auth: authType === "agent" ? { type: "agent", secret: "ssh-agent" } : { type: authType, secret },
    });

    await saveConfig(config);
    p.outro(`Server "${name}" (${id}) added to ${project.name}.`);
  });

configCmd
  .command("list")
  .option("-n, --non-interactive", "Plain text output for scripts/agents")
  .description("List projects and servers")
  .action(async (options: { nonInteractive?: boolean }) => {
    const ni = isNonInteractive(options);

    if (!(await configExists())) {
      if (ni) fail("Config not found.", 1, true);
      p.log.error("Config not found. Run: cssh config init");
      process.exit(1);
    }

    const config = await loadConfig();
    for (const project of config.projects) {
      if (ni) {
        console.log(`${project.id}\t${project.name}`);
        for (const server of project.servers) {
          console.log(
            `${project.id}\t${server.id}\t${server.group ?? ""}\t${server.user}@${server.host}\t${server.name}`
          );
        }
      } else {
        p.log.info(`${project.name} (${project.id})`);
        for (const server of project.servers) {
          const group = server.group ? ` [${server.group}]` : "";
          const region = server.region ? ` {${server.region}}` : "";
          p.log.message(
            `  ${server.id}: ${server.name} — ${server.user}@${server.host}${group}${region} (${server.auth.type}:${server.auth.secret})`
          );
        }
      }
    }
  });

const secretsCmd = program.command("secrets").description("Manage encrypted secrets");

secretsCmd
  .command("init")
  .description("Initialize encrypted secrets vault (requires sudo)")
  .option("-f, --force", "Replace existing vault")
  .option("-n, --non-interactive", "Skip sudo (vault key only; for automated setup)")
  .action(async (options: { force?: boolean; nonInteractive?: boolean }) => {
    const ni = isNonInteractive(options);

    if (!ni) p.intro("cssh secrets init");

    if (await secretsExist() && !options.force) {
      if (ni) {
        console.log("secrets vault exists");
        return;
      }
      p.log.warn("Secrets vault already exists. Use --force to replace.");
      process.exit(0);
    }

    if (!ni) await ensureSudoAuthenticated();
    const vaultKey = await createVaultKey();
    await initSecrets(vaultKey);

    if (ni) console.log("secrets vault initialized");
    else p.outro(`Secrets vault created at ${CONFIG_DIR}`);
  });

secretsCmd
  .command("set <secretId>")
  .description("Store an encrypted secret from a file or stdin")
  .option("-f, --file <path>", "Path to PEM or private key file")
  .option("--stdin", "Read secret from stdin")
  .option("-n, --non-interactive", "Skip sudo; requires --file or --stdin")
  .action(async (
    secretId: string,
    options: { file?: string; stdin?: boolean; nonInteractive?: boolean }
  ) => {
    const ni = isNonInteractive(options);

    if (!ni) p.intro(`cssh secrets set ${secretId}`);

    if (!(await secretsExist())) {
      if (ni) fail("Secrets vault not initialized.", 1, true);
      p.log.error("Secrets vault not initialized. Run: cssh secrets init");
      process.exit(1);
    }

    if (!ni) await ensureSudoAuthenticated();
    const vaultKey = await loadVaultKey();
    let content: Buffer;

    if (options.stdin) {
      content = await readStdin();
    } else if (options.file) {
      content = await readFile(options.file);
    } else if (ni) {
      fail("Non-interactive mode requires --file or --stdin", 1, true);
    } else {
      const filePath = await promptText("Path to PEM or key file");
      content = await readFile(filePath);
    }

    if (content.length === 0) {
      if (ni) fail("Secret content is empty.", 1, true);
      p.log.error("Secret content is empty.");
      process.exit(1);
    }

    await setSecret(secretId, content, vaultKey);
    if (ni) console.log(`stored:${secretId}`);
    else p.outro(`Secret "${secretId}" stored.`);
  });

secretsCmd
  .command("list")
  .option("-n, --non-interactive", "Plain text output; skip sudo")
  .description("List secret ids in the vault")
  .action(async (options: { nonInteractive?: boolean }) => {
    const ni = isNonInteractive(options);

    if (!(await secretsExist())) {
      if (ni) fail("Secrets vault not initialized.", 1, true);
      p.log.error("Secrets vault not initialized. Run: cssh secrets init");
      process.exit(1);
    }

    if (!ni) await ensureSudoAuthenticated();
    const vaultKey = await loadVaultKey();
    const ids = await listSecretIds(vaultKey);

    if (ids.length === 0) {
      if (ni) return;
      p.log.info("No secrets stored.");
      return;
    }

    for (const id of ids) {
      if (ni) console.log(id);
      else p.log.message(`  ${id}`);
    }
  });

secretsCmd
  .command("verify")
  .option("-n, --non-interactive", "Skip sudo; plain output")
  .description("Verify vault access")
  .action(async (options: { nonInteractive?: boolean }) => {
    const ni = isNonInteractive(options);

    if (!(await secretsExist())) {
      if (ni) fail("Secrets vault not initialized.", 1, true);
      p.log.error("Secrets vault not initialized.");
      process.exit(1);
    }

    if (!ni) await ensureSudoAuthenticated();
    const vaultKey = await loadVaultKey();
    const ids = await listSecretIds(vaultKey);

    if (ni) {
      console.log(`ok ${ids.length} ${ids.join(",")}`);
    } else {
      p.outro(`Vault OK. ${ids.length} secret(s): ${ids.join(", ")}`);
    }
  });

secretsCmd
  .command("delete <secretId>")
  .option("-n, --non-interactive", "Skip sudo")
  .description("Delete a secret from the vault")
  .action(async (secretId: string, options: { nonInteractive?: boolean }) => {
    const ni = isNonInteractive(options);

    if (!(await secretsExist())) {
      if (ni) fail("Secrets vault not initialized.", 1, true);
      p.log.error("Secrets vault not initialized.");
      process.exit(1);
    }

    if (!ni) await ensureSudoAuthenticated();
    const vaultKey = await loadVaultKey();
    await deleteSecret(secretId, vaultKey);

    if (ni) console.log(`deleted:${secretId}`);
    else p.outro(`Secret "${secretId}" deleted.`);
  });

program.parseAsync(process.argv).catch((err: Error) => {
  const ni = isNonInteractive();
  if (ni) fail(err.message, 1, true);
  p.log.error(err.message);
  process.exit(1);
});
