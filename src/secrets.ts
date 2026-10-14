import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import { readFile, writeFile, mkdir, access } from "node:fs/promises";
import { constants } from "node:fs";
import type { EncryptedSecret, SecretsMeta, SecretsVault } from "./schema.js";
import { SECRETS_FILE, SECRETS_META_FILE, CONFIG_DIR } from "./paths.js";

function encryptBuffer(plaintext: Buffer, vaultKey: Buffer): EncryptedSecret {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", vaultKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
  };
}

function decryptBuffer(secret: EncryptedSecret, vaultKey: Buffer): Buffer {
  const iv = Buffer.from(secret.iv, "base64");
  const tag = Buffer.from(secret.tag, "base64");
  const ciphertext = Buffer.from(secret.ciphertext, "base64");
  const decipher = createDecipheriv("aes-256-gcm", vaultKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export async function secretsExist(): Promise<boolean> {
  try {
    await access(SECRETS_META_FILE, constants.F_OK);
    await access(SECRETS_FILE, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function initSecrets(vaultKey: Buffer): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });

  const meta: SecretsMeta = {
    createdAt: new Date().toISOString(),
  };

  const emptyVault: SecretsVault = {};
  const encryptedVault = encryptBuffer(
    Buffer.from(JSON.stringify(emptyVault), "utf8"),
    vaultKey
  );

  await writeFile(SECRETS_META_FILE, JSON.stringify(meta, null, 2), "utf8");
  await writeFile(SECRETS_FILE, JSON.stringify(encryptedVault, null, 2), "utf8");
}

async function loadEncryptedVault(): Promise<EncryptedSecret> {
  const raw = await readFile(SECRETS_FILE, "utf8");
  return JSON.parse(raw) as EncryptedSecret;
}

async function saveVault(vault: SecretsVault, vaultKey: Buffer): Promise<void> {
  const encryptedVault = encryptBuffer(
    Buffer.from(JSON.stringify(vault), "utf8"),
    vaultKey
  );
  await writeFile(SECRETS_FILE, JSON.stringify(encryptedVault, null, 2), "utf8");
}

export async function unlockVault(vaultKey: Buffer): Promise<SecretsVault> {
  const encryptedVault = await loadEncryptedVault();
  try {
    const decrypted = decryptBuffer(encryptedVault, vaultKey);
    return JSON.parse(decrypted.toString("utf8")) as SecretsVault;
  } catch {
    throw new Error(
      "Cannot decrypt secrets vault. Run: cssh secrets init"
    );
  }
}

export async function listSecretIds(vaultKey: Buffer): Promise<string[]> {
  const vault = await unlockVault(vaultKey);
  return Object.keys(vault).sort();
}

export async function setSecret(
  secretId: string,
  content: Buffer,
  vaultKey: Buffer
): Promise<void> {
  const vault = await unlockVault(vaultKey);
  vault[secretId] = encryptBuffer(content, vaultKey);
  await saveVault(vault, vaultKey);
}

export async function getSecret(
  secretId: string,
  vaultKey: Buffer
): Promise<Buffer> {
  const vault = await unlockVault(vaultKey);
  const entry = vault[secretId];
  if (!entry) {
    throw new Error(`Secret not found: ${secretId}`);
  }
  try {
    return decryptBuffer(entry, vaultKey);
  } catch {
    throw new Error(`Failed to decrypt secret "${secretId}"`);
  }
}

export async function deleteSecret(
  secretId: string,
  vaultKey: Buffer
): Promise<void> {
  const vault = await unlockVault(vaultKey);
  if (!vault[secretId]) {
    throw new Error(`Secret not found: ${secretId}`);
  }
  delete vault[secretId];
  await saveVault(vault, vaultKey);
}
