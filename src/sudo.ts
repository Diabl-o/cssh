import { spawn } from "node:child_process";

const WINDOWS_MAX_ATTEMPTS = 3;

/**
 * Prompts for the current Windows account password in the terminal and
 * validates it against the OS. The password is read and checked entirely
 * inside PowerShell, so it never passes through Node.
 * Exit code 0 = verified, 1 = failed.
 */
const WINDOWS_PASSWORD_SCRIPT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$isLocal = $env:USERDOMAIN -eq $env:COMPUTERNAME
$type = if ($isLocal) { [System.DirectoryServices.AccountManagement.ContextType]::Machine } else { [System.DirectoryServices.AccountManagement.ContextType]::Domain }
$name = if ($isLocal) { $env:COMPUTERNAME } else { $env:USERDOMAIN }
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($type, $name)
for ($i = 0; $i -lt ${WINDOWS_MAX_ATTEMPTS}; $i++) {
  $secure = Read-Host "[cssh] password for $env:USERNAME" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ($ctx.ValidateCredentials($env:USERNAME, $plain)) { exit 0 }
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
  Write-Host "Sorry, try again."
}
exit 1
`;

function run(command: string, args: string[]): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit" });
    child.on("error", reject);
    child.on("close", (exitCode) => resolve(exitCode ?? 1));
  });
}

async function ensureWindowsPasswordAuthenticated(): Promise<void> {
  const encoded = Buffer.from(WINDOWS_PASSWORD_SCRIPT, "utf16le").toString("base64");
  const code = await run("powershell.exe", [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-EncodedCommand",
    encoded,
  ]);

  if (code !== 0) {
    throw new Error("Windows password authentication failed");
  }
}

/**
 * Gate access behind the OS's own authentication:
 * real `sudo` on Linux/macOS, a Windows account password check on Windows.
 */
export async function ensureSudoAuthenticated(): Promise<void> {
  if (process.platform === "win32") {
    await ensureWindowsPasswordAuthenticated();
    return;
  }

  const code = await run("sudo", ["-k", "-v"]);

  if (code !== 0) {
    throw new Error("sudo authentication failed");
  }
}
