import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ServerConfig } from "./schema.js";

export interface SshConnectOptions {
  server: ServerConfig;
  secretContent: Buffer | null;
  remoteCommand?: string[];
  extraArgs?: string[];
}

async function writeTempKey(content: Buffer): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "cssh-"));
  const keyPath = join(dir, "identity");
  await writeFile(keyPath, content, { mode: 0o600 });
  return keyPath;
}

export async function connectSsh(options: SshConnectOptions): Promise<number> {
  const { server, secretContent, remoteCommand = [], extraArgs = [] } = options;
  const args: string[] = [
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "IdentitiesOnly=yes",
  ];

  let tempKeyPath: string | null = null;
  let tempDir: string | null = null;

  if (secretContent && server.auth.type !== "agent") {
    tempKeyPath = await writeTempKey(secretContent);
    tempDir = join(tempKeyPath, "..");
    args.push("-i", tempKeyPath);
  }

  if (server.port) {
    args.push("-p", String(server.port));
  }

  args.push(...extraArgs);
  args.push(`${server.user}@${server.host}`);

  if (remoteCommand.length > 0) {
    args.push("--", ...remoteCommand);
  }

  return new Promise((resolve, reject) => {
    const child = spawn("ssh", args, {
      stdio: "inherit",
      shell: false,
    });

    const cleanup = async () => {
      if (tempDir) {
        try {
          await rm(tempDir, { recursive: true, force: true });
        } catch {
          // best effort
        }
      }
    };

    child.on("error", async (err) => {
      await cleanup();
      reject(err);
    });

    child.on("close", async (code) => {
      await cleanup();
      resolve(code ?? 1);
    });
  });
}
