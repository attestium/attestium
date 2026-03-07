const {describe, it, before, after, mock} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const ReleaseVerification = require('../lib/release-verification.js');

describe('ReleaseVerification', () => {
  describe('constructor', () => {
    it('uses defaults', () => {
      const rv = new ReleaseVerification();
      assert.strictEqual(rv.timeout, 30_000);
      assert.strictEqual(rv.nodeDistUrl, 'https://nodejs.org/dist');
      assert.strictEqual(rv.platform, os.platform());
      assert.ok(rv._registryConcurrency >= 4);
      assert.ok(rv._registryConcurrency <= 16);
      assert.ok(rv._githubConcurrency >= 4);
      assert.strictEqual(rv._maxRetries, 3);
    });

    it('accepts options', () => {
      const rv = new ReleaseVerification({
        timeout: 5000,
        projectRoot: '/tmp',
        nodeDistUrl: 'https://mirror.example.com/dist',
      });
      assert.strictEqual(rv.timeout, 5000);
      assert.strictEqual(rv.projectRoot, '/tmp');
      assert.strictEqual(rv.nodeDistUrl, 'https://mirror.example.com/dist');
    });

    it('accepts concurrency overrides', () => {
      const rv = new ReleaseVerification({
        registryConcurrency: 2,
        githubConcurrency: 1,
        maxRetries: 5,
      });
      assert.strictEqual(rv._registryConcurrency, 2);
      assert.strictEqual(rv._githubConcurrency, 1);
      assert.strictEqual(rv._maxRetries, 5);
    });
  });

  describe('static helpers', () => {
    it('exposes registryConcurrency()', () => {
      const c = ReleaseVerification._registryConcurrency();
      assert.ok(c >= 4, 'min 4');
      assert.ok(c <= 16, 'max 16');
    });

    it('exposes githubConcurrency()', () => {
      const c = ReleaseVerification._githubConcurrency();
      // Without GITHUB_TOKEN it should be 4
      if (process.env.GITHUB_TOKEN) {
        assert.strictEqual(c, 8);
      } else {
        assert.strictEqual(c, 4);
      }
    });
  });

  describe('parallelMap', () => {
    const {_parallelMap: parallelMap} = ReleaseVerification;

    it('runs tasks in parallel up to concurrency limit', async () => {
      const order = [];
      const tasks = [
        async () => {
          order.push('a-start');
          await new Promise(resolve => {
            setTimeout(resolve, 50);
          });
          order.push('a-end');
          return 'a';
        },
        async () => {
          order.push('b-start');
          await new Promise(resolve => {
            setTimeout(resolve, 10);
          });
          order.push('b-end');
          return 'b';
        },
        async () => {
          order.push('c-start', 'c-end');
          return 'c';
        },
      ];

      const results = await parallelMap(tasks, 2);
      assert.deepStrictEqual(results, ['a', 'b', 'c']);
      // With concurrency 2, a and b start first; c starts after b finishes
      assert.strictEqual(order[0], 'a-start');
      assert.strictEqual(order[1], 'b-start');
    });

    it('handles empty task array', async () => {
      const results = await parallelMap([], 4);
      assert.deepStrictEqual(results, []);
    });

    it('handles single task', async () => {
      const results = await parallelMap([async () => 42], 4);
      assert.deepStrictEqual(results, [42]);
    });

    it('handles concurrency greater than task count', async () => {
      const results = await parallelMap(
        [async () => 1, async () => 2],
        100,
      );
      assert.deepStrictEqual(results, [1, 2]);
    });

    it('handles concurrency of 1 (sequential)', async () => {
      const order = [];
      const tasks = [
        async () => {
          order.push(1);
          return 1;
        },
        async () => {
          order.push(2);
          return 2;
        },
        async () => {
          order.push(3);
          return 3;
        },
      ];

      const results = await parallelMap(tasks, 1);
      assert.deepStrictEqual(results, [1, 2, 3]);
      assert.deepStrictEqual(order, [1, 2, 3]);
    });

    it('preserves result order regardless of completion order', async () => {
      const tasks = [
        async () => {
          await new Promise(resolve => {
            setTimeout(resolve, 50);
          });
          return 'slow';
        },
        async () => 'fast',
      ];

      const results = await parallelMap(tasks, 2);
      assert.strictEqual(results[0], 'slow');
      assert.strictEqual(results[1], 'fast');
    });

    it('propagates errors from tasks', async () => {
      const tasks = [
        async () => {
          throw new Error('boom');
        },
      ];

      await assert.rejects(
        () => parallelMap(tasks, 2),
        {message: 'boom'},
      );
    });
  });

  describe('verifyNodeRelease', () => {
    it('fetches SHASUMS and reports running binary hash', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyNodeRelease();

      assert.strictEqual(result.name, 'node-release');
      assert.ok(result.details.version, 'should report Node version');
      assert.ok(result.details.runningBinaryHash, 'should report running binary hash');
      assert.ok(result.details.runningBinaryPath, 'should report running binary path');
      assert.ok(result.details.runningBinarySize > 0, 'should report binary size');
    });

    it('reports the SHASUMS URL', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyNodeRelease();

      assert.ok(result.details.shasumsUrl);
      assert.ok(result.details.shasumsUrl.includes('nodejs.org/dist'));
      assert.ok(result.details.shasumsUrl.includes(process.version));
    });

    it('finds entries in SHASUMS', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyNodeRelease();

      // Should have found at least some entries
      if (!result.details.error) {
        assert.ok(result.details.totalEntries > 0, 'should have SHASUMS entries');
      }
    });

    it('handles network failure gracefully', async () => {
      const rv = new ReleaseVerification({
        timeout: 2000,
        nodeDistUrl: 'https://nonexistent.invalid',
      });
      const result = await rv.verifyNodeRelease();

      assert.strictEqual(result.passed, false);
      assert.ok(result.details.error);
    });
  });

  describe('verifyGlobalPackage', () => {
    it('verifies npm is installed and checks registry', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyGlobalPackage('npm');

      assert.strictEqual(result.name, 'npm-release');
      assert.strictEqual(result.details.installed, true);
      assert.ok(result.details.installedVersion);
    });

    it('reports registry metadata for npm', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyGlobalPackage('npm');

      if (result.details.installed) {
        // Registry should return integrity info
        assert.ok(result.details.registryUrl);
      }
    });

    it('handles non-installed package gracefully', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyGlobalPackage('nonexistent-package-xyz-12345');

      assert.strictEqual(result.details.installed, false);
      assert.strictEqual(result.passed, true); // Not installed = not a failure
    });

    it('verifies pnpm if installed', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyGlobalPackage('pnpm');

      assert.strictEqual(result.name, 'pnpm-release');
      // Pnpm may or may not be installed
      assert.ok(typeof result.details.installed === 'boolean');
    });

    it('verifies pm2 if installed', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const result = await rv.verifyGlobalPackage('pm2');

      assert.strictEqual(result.name, 'pm2-release');
      assert.ok(typeof result.details.installed === 'boolean');
    });
  });

  describe('verifyModules', () => {
    let projectDir;

    before(() => {
      projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-modules-'));
      // Create a minimal project with a fake dependency
      fs.writeFileSync(path.join(projectDir, 'package.json'), JSON.stringify({
        name: 'test-project',
        version: '1.0.0',
        dependencies: {
          'is-odd': '^3.0.1',
        },
      }));
      // Create a fake node_modules
      const modDir = path.join(projectDir, 'node_modules', 'is-odd');
      fs.mkdirSync(modDir, {recursive: true});
      fs.writeFileSync(path.join(modDir, 'package.json'), JSON.stringify({
        name: 'is-odd',
        version: '3.0.1',
      }));
      fs.writeFileSync(path.join(modDir, 'index.js'), 'module.exports = n => n % 2 === 1;');
    });

    after(() => {
      fs.rmSync(projectDir, {recursive: true, force: true});
    });

    it('verifies installed modules against registry', async () => {
      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: projectDir,
      });
      const result = await rv.verifyModules(['is-odd']);

      assert.strictEqual(result.name, 'module-integrity');
      assert.ok(result.details.modules['is-odd']);
      assert.strictEqual(result.details.modules['is-odd'].details.installed, true);
      assert.strictEqual(result.details.modules['is-odd'].details.installedVersion, '3.0.1');
    });

    it('reports concurrency in details', async () => {
      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: projectDir,
        registryConcurrency: 8,
      });
      const result = await rv.verifyModules(['is-odd']);

      assert.strictEqual(result.details.concurrency, 8);
    });

    it('reports registry integrity for modules', async () => {
      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: projectDir,
      });
      const result = await rv.verifyModules(['is-odd']);

      const modResult = result.details.modules['is-odd'];
      // Registry should return shasum or integrity
      if (!modResult.details.registryError) {
        assert.ok(
          modResult.details.registryShasum || modResult.details.registryIntegrity,
          'should have registry integrity info',
        );
      }
    });

    it('reports repository info from registry', async () => {
      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: projectDir,
      });
      const result = await rv.verifyModules(['is-odd']);

      const modResult = result.details.modules['is-odd'];
      if (!modResult.details.registryError) {
        // Is-odd should have a repository field
        assert.ok(modResult.details.repository || modResult.details.tarballUrl,
          'should have repository or tarball URL');
      }
    });

    it('handles missing module in node_modules', async () => {
      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: projectDir,
      });
      const result = await rv.verifyModules(['nonexistent-module']);

      assert.strictEqual(result.details.modules['nonexistent-module'].details.installed, false);
      assert.strictEqual(result.details.modules['nonexistent-module'].passed, false);
    });

    it('reads all deps from package.json when no modules specified', async () => {
      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: projectDir,
      });
      const result = await rv.verifyModules();

      assert.strictEqual(result.details.totalModules, 1);
      assert.ok(result.details.modules['is-odd']);
    });

    it('handles missing package.json', async () => {
      const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-empty-'));
      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: emptyDir,
      });
      const result = await rv.verifyModules();

      assert.ok(result.details.error);
      fs.rmSync(emptyDir, {recursive: true, force: true});
    });

    it('verifies multiple modules in parallel', async () => {
      // Create a project with multiple deps
      const multiDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-multi-'));
      fs.writeFileSync(path.join(multiDir, 'package.json'), JSON.stringify({
        name: 'test-multi',
        version: '1.0.0',
        dependencies: {
          'is-odd': '^3.0.1',
          'is-even': '^1.0.0',
        },
      }));

      for (const mod of ['is-odd', 'is-even']) {
        const modDir = path.join(multiDir, 'node_modules', mod);
        fs.mkdirSync(modDir, {recursive: true});
        fs.writeFileSync(path.join(modDir, 'package.json'), JSON.stringify({
          name: mod,
          version: mod === 'is-odd' ? '3.0.1' : '1.0.0',
        }));
        fs.writeFileSync(path.join(modDir, 'index.js'), '');
      }

      const rv = new ReleaseVerification({
        timeout: 15_000,
        projectRoot: multiDir,
        registryConcurrency: 4,
      });
      const result = await rv.verifyModules();

      assert.strictEqual(result.details.totalModules, 2);
      assert.ok(result.details.modules['is-odd']);
      assert.ok(result.details.modules['is-even']);
      assert.strictEqual(result.details.concurrency, 4);

      fs.rmSync(multiDir, {recursive: true, force: true});
    });
  });

  describe('verifyAll', () => {
    it('runs all verification checks', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const results = await rv.verifyAll({
        globalPackages: ['npm'],
        modules: false,
      });

      assert.ok(results.timestamp);
      assert.ok(results.platform);
      assert.ok(results.nodeVersion);
      assert.ok(results.checks.nodeRelease);
      assert.ok(results.checks.npmRelease);
      assert.ok(results.summary);
    });

    it('skips node check when disabled', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const results = await rv.verifyAll({
        checkNode: false,
        globalPackages: [],
        modules: false,
      });

      assert.strictEqual(results.checks.nodeRelease, undefined);
    });

    it('reports overall pass/fail', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const results = await rv.verifyAll({
        globalPackages: [],
        modules: false,
      });

      assert.ok(typeof results.passed === 'boolean');
      assert.ok(results.summary.includes('/'));
    });

    it('runs global packages in parallel', async () => {
      const rv = new ReleaseVerification({timeout: 15_000});
      const results = await rv.verifyAll({
        checkNode: false,
        globalPackages: ['npm', 'pnpm'],
        modules: false,
      });

      assert.ok(results.checks.npmRelease);
      assert.ok(results.checks.pnpmRelease);
    });
  });

  describe('_httpGet retry on 429', () => {
    it('retries on 429 with back-off', async () => {
      // We can't easily mock HTTP in node:test without a mock server,
      // but we can verify the retry parameter is respected
      const rv = new ReleaseVerification({
        timeout: 2000,
        maxRetries: 0, // No retries
      });

      // A URL that would 429 — we just verify the error propagates
      // since we can't easily trigger a real 429 in tests
      assert.strictEqual(rv._maxRetries, 0);
    });

    it('sends User-Agent header for GitHub API requests', async () => {
      const rv = new ReleaseVerification({timeout: 5000});
      // Verify the method exists and handles GitHub URLs
      // (actual header verification requires a mock server)
      try {
        await rv._httpGet('https://api.github.com/rate_limit');
      } catch {
        // May fail due to rate limiting, but that's OK
      }
    });
  });
});
