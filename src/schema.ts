import { z } from "zod";

export const AuthSchema = z.object({
  type: z.enum(["key", "pem", "agent"]),
  secret: z.string().min(1),
});

export const ServerSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9_-]*$/i, "Server id must be alphanumeric"),
  name: z.string().min(1),
  host: z.string().min(1),
  user: z.string().default("ubuntu"),
  port: z.number().int().min(1).max(65535).optional(),
  group: z.string().optional(),
  region: z.string().optional(),
  auth: AuthSchema,
});

export const ProjectSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9_-]*$/i, "Project id must be alphanumeric"),
  name: z.string().min(1),
  servers: z.array(ServerSchema).default([]),
});

export const SecuritySchema = z.object({
  require_sudo: z.boolean().default(true),
  allow_non_interactive: z.boolean().default(true),
  /** @deprecated use require_sudo */
  require_password: z.boolean().optional(),
});

export const ConfigSchema = z.object({
  version: z.literal(1),
  security: SecuritySchema.default({ require_sudo: true }),
  projects: z.array(ProjectSchema).min(1),
});

export type AuthConfig = z.infer<typeof AuthSchema>;
export type ServerConfig = z.infer<typeof ServerSchema>;
export type ProjectConfig = z.infer<typeof ProjectSchema>;
export type CsshConfig = z.infer<typeof ConfigSchema>;

export interface SecretsMeta {
  createdAt: string;
}

export interface EncryptedSecret {
  iv: string;
  tag: string;
  ciphertext: string;
}

export interface SecretsVault {
  [secretId: string]: EncryptedSecret;
}
