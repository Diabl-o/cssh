import { randomBytes } from "node:crypto";
import { readFile, writeFile, access } from "node:fs/promises";
import { constants } from "node:fs";
import { VAULT_KEY_FILE } from "./paths.js";
import { restrictToCurrentUser } from "./file-perms.js";

const KEY_LENGTH = 32;

export async function vaultKeyExists(): Promise<boolean> {
  try {
    await access(VAULT_KEY_FILE, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function loadVaultKey(): Promise<Buffer> {
  const key = await readFile(VAULT_KEY_FILE);
  if (key.length !== KEY_LENGTH) {
    throw new Error("Invalid vault key. Run: cssh secrets init");
  }
  return key;
}

export async function createVaultKey(): Promise<Buffer> {
  const key = randomBytes(KEY_LENGTH);
  await writeFile(VAULT_KEY_FILE, key, { mode: 0o600 });
  await restrictToCurrentUser(VAULT_KEY_FILE);
  return key;
}
