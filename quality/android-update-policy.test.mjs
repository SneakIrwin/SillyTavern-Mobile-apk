import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('update identity policy handles active, replayed, stale and orphaned sessions', async () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const classes = await mkdtemp(path.join(tmpdir(), 'st-mobile-policy-test-'));
  const localJdk = path.join(root, '.tools', 'jdk-21', 'bin');
  const jdk = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin')
    : existsSync(localJdk) ? localJdk : '';
  const executable = (name) => path.join(jdk, name + (process.platform === 'win32' ? '.exe' : ''));
  try {
    execFileSync(executable('javac'), ['-d', classes,
      path.join(root, 'android/app/src/main/java/app/sillytavern/securemobile/UpdateSessionPolicy.java'),
      path.join(root, 'quality/UpdateSessionPolicyTest.java')], { windowsHide: true, timeout: 30_000 });
    execFileSync(executable('java'), ['-cp', classes,
      'app.sillytavern.securemobile.UpdateSessionPolicyTest'], { windowsHide: true, timeout: 30_000 });
  } finally {
    const [resolvedTemp, resolvedClasses] = await Promise.all([realpath(tmpdir()), realpath(classes)]);
    const relative = path.relative(resolvedTemp, resolvedClasses);
    if (!relative.startsWith('st-mobile-policy-test-') || relative.includes(path.sep) || path.isAbsolute(relative)) {
      throw new Error('Refusing to remove compilation output outside its temporary parent');
    }
    await rm(resolvedClasses, { recursive: true, force: true });
  }
});
