import { spawn } from "node:child_process";

/** Run real `sudo` so the OS shows the standard `[sudo] password for user:` prompt. */
export async function ensureSudoAuthenticated(): Promise<void> {
  const code = await new Promise<number>((resolve, reject) => {
    const child = spawn("sudo", ["-k", "-v"], { stdio: "inherit" });
    child.on("error", reject);
    child.on("close", (exitCode) => resolve(exitCode ?? 1));
  });

  if (code !== 0) {
    throw new Error("sudo authentication failed");
  }
}
