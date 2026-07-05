import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function scriptPath() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'Protect-CertAcls.ps1');
}

export function protectWindowsPrivatePathAcls(paths) {
  if (process.platform !== 'win32') {
    return Promise.resolve();
  }

  const privatePaths = (Array.isArray(paths) ? paths : [paths]).filter(Boolean);
  if (privatePaths.length === 0) {
    return Promise.resolve();
  }

  const args = [
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    scriptPath(),
    '-CertDir',
    privatePaths[0],
  ];
  if (privatePaths.length > 1) {
    args.push('-PrivatePath', ...privatePaths.slice(1));
  }

  return new Promise((resolve, reject) => {
    execFile('powershell.exe', args, { windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`Private ACL protection failed: ${stderr || stdout || error.message}`));
        return;
      }
      resolve();
    });
  });
}
