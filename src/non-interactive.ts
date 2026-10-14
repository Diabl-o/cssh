export interface NonInteractiveOptions {
  nonInteractive?: boolean;
}

/** True when `-n` / `--non-interactive` or CSSH_NON_INTERACTIVE=1 */
export function isNonInteractive(options?: NonInteractiveOptions): boolean {
  if (options?.nonInteractive) return true;
  const env = process.env.CSSH_NON_INTERACTIVE;
  if (env === "1" || env === "true") return true;
  const argv = process.argv;
  return argv.includes("--non-interactive") || argv.includes("-n");
}

export function fail(message: string, code = 1, nonInteractive = false): never {
  if (nonInteractive) {
    console.error(message);
  } else {
    // eslint-disable-next-line no-console
    console.error(`Error: ${message}`);
  }
  process.exit(code);
}

export function info(message: string, nonInteractive = false): void {
  if (nonInteractive) {
    console.error(message);
  }
}
