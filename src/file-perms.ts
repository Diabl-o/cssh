import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Windows ignores POSIX file modes, so `mode: 0o600` has no effect there.
 * Strip inherited ACLs and grant only the current user access (like chmod 600),
 * which OpenSSH on Windows requires for private keys. No-op on other platforms.
 */
export async function restrictToCurrentUser(
  path: string,
  access: "R" | "F" = "F"
): Promise<void> {
  if (process.platform !== "win32") return;

  const user = process.env.USERNAME;
  if (!user) {
    throw new Error("Cannot restrict file permissions: USERNAME is not set");
  }

  const principal = process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${user}` : user;
  try {
    await execFileAsync("icacls", [path, "/inheritance:r", "/grant:r", `${principal}:${access}`]);
  } catch (err) {
    throw new Error(`Failed to restrict permissions on ${path}: ${(err as Error).message}`);
  }
}
