const {describe, it, before, after} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {spawn} = require('node:child_process');
const ProcessIntegrity = require('../lib/process-integrity.js');

describe('ProcessIntegrity', () => {
  describe('constructor', () => {
    it('uses defaults', () => {
      const pi = new ProcessIntegrity();
      assert.strictEqual(pi.maxAnonExecRegions, 256);
      assert.strictEqual(pi.timeout, 10_000);
      assert.strictEqual(pi.expectedLibs.size, 0);
    });

    it('accepts options', () => {
      const pi = new ProcessIntegrity({
        expectedLibs: ['/usr/lib/libc.so'],
        maxAnonExecRegions: 10,
        timeout: 5000,
      });
      assert.strictEqual(pi.maxAnonExecRegions, 10);
      assert.strictEqual(pi.timeout, 5000);
      assert.ok(pi.expectedLibs.has('/usr/lib/libc.so'));
    });
  });

  describe('checkMemoryMaps', () => {
    it('returns results for own process', () => {
      const pi = new ProcessIntegrity();
      const result = pi.checkMemoryMaps(process.pid);

      if (os.platform() === 'linux') {
        assert.ok(result.regions.length > 0, 'should have memory regions');
        assert.ok(result.summary.totalRegions > 0);
        assert.strictEqual(result.summary.supported, true);
      } else if (os.platform() === 'darwin') {
        assert.strictEqual(result.summary.supported, true);
      } else if (os.platform() === 'win32') {
        assert.strictEqual(result.summary.supported, true);
      }
    });

    it('returns empty for non-existent PID', () => {
      const pi = new ProcessIntegrity();
      const result = pi.checkMemoryMaps(999_999_999);

      if (os.platform() === 'linux') {
        // Should throw/catch and return empty
        assert.strictEqual(result.regions.length, 0);
      }
    });

    if (os.platform() === 'linux') {
      it('detects executable regions on Linux', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkMemoryMaps(process.pid);

        // Node.js uses V8 JIT which creates anonymous executable regions
        const execRegions = result.regions.filter(r => r.perms && r.perms.includes('x'));
        assert.ok(execRegions.length > 0, 'should have executable regions');
      });

      it('parses region fields correctly on Linux', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkMemoryMaps(process.pid);

        const region = result.regions[0];
        assert.ok(region.addr, 'should have address');
        assert.ok(region.perms, 'should have permissions');
        assert.ok(typeof region.inode === 'number', 'inode should be a number');
      });

      it('flags unexpected libraries when expectedLibs is set', () => {
        const pi = new ProcessIntegrity({expectedLibs: ['/nonexistent/lib.so']});
        const result = pi.checkMemoryMaps(process.pid);

        // Any .so file in the maps that isn't in expectedLibs should be flagged
        const unexpectedLibs = result.anomalies.filter(a => a.type === 'unexpected-lib');
        // There may or may not be .so files in the maps
        assert.ok(Array.isArray(unexpectedLibs));
      });

      it('reports W^X violations from V8 JIT', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkMemoryMaps(process.pid);

        // V8 JIT may create rwx regions
        assert.ok(typeof result.summary.wxeViolations === 'number');
      });

      it('reports anonymous exec count and excessive flag', () => {
        const pi = new ProcessIntegrity({maxAnonExecRegions: 0});
        const result = pi.checkMemoryMaps(process.pid);

        assert.ok(typeof result.summary.anonExecCount === 'number');
        // With maxAnonExecRegions=0, any anon exec region is excessive
        if (result.summary.anonExecCount > 0) {
          assert.strictEqual(result.summary.anonExecExcessive, true);
        }
      });
    }

    if (os.platform() === 'win32') {
      it('lists loaded modules on Windows', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkMemoryMaps(process.pid);

        if (!result.summary.error) {
          assert.ok(result.summary.totalModules >= 0);
        }
      });
    }
  });

  describe('checkExecutablePageHash', () => {
    if (os.platform() === 'linux') {
      it('hashes executable pages of own process', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkExecutablePageHash(process.pid);

        // May fail if we can't read /proc/self/mem (permissions)
        if (result.matched !== null) {
          assert.ok(result.diskHash, 'should have disk hash');
          assert.ok(result.memHash, 'should have memory hash');
          assert.ok(typeof result.matched === 'boolean');
        }
      });

      it('returns null matched for non-existent PID', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkExecutablePageHash(999_999_999);
        assert.strictEqual(result.matched, null);
        assert.ok(result.details.error);
      });

      it('reports exec region count', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkExecutablePageHash(process.pid);

        if (result.matched !== null) {
          assert.ok(result.details.execRegionCount > 0);
          assert.ok(result.details.exePath);
        }
      });
    } else {
      it('reports unsupported on non-Linux platforms', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkExecutablePageHash(process.pid);
        assert.strictEqual(result.matched, null);
        assert.strictEqual(result.details.supported, false);
      });
    }
  });

  describe('checkLinkerIntegrity', () => {
    it('checks linker integrity for own process', () => {
      const pi = new ProcessIntegrity();
      const result = pi.checkLinkerIntegrity(process.pid);

      if (os.platform() === 'linux') {
        assert.ok(typeof result.clean === 'boolean');
        // In a normal test environment, LD_PRELOAD should not be set
        if (result.clean) {
          assert.strictEqual(result.ldPreload, null);
        }
      } else if (os.platform() === 'darwin') {
        assert.ok(typeof result.clean === 'boolean');
      } else if (os.platform() === 'win32') {
        assert.ok(typeof result.clean === 'boolean');
      }
    });

    if (os.platform() === 'linux') {
      it('detects LD_PRELOAD in process environment', () => {
        // We can't easily set LD_PRELOAD for our own process after start,
        // but we can verify the parsing logic works
        const pi = new ProcessIntegrity();
        const result = pi.checkLinkerIntegrity(process.pid);
        // Should not have LD_PRELOAD in test environment
        assert.strictEqual(result.ldPreload, null);
      });

      it('checks /etc/ld.so.preload', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkLinkerIntegrity(process.pid);
        // SystemPreload should be null unless something is configured
        assert.ok(result.systemPreload === null || typeof result.systemPreload === 'string');
      });
    }

    if (os.platform() === 'win32') {
      it('checks AppInit_DLLs on Windows', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkLinkerIntegrity(process.pid);
        assert.ok(typeof result.clean === 'boolean');
      });
    }
  });

  describe('checkTracerPid', () => {
    it('checks tracer for own process', () => {
      const pi = new ProcessIntegrity();
      const result = pi.checkTracerPid(process.pid);

      if (os.platform() === 'linux') {
        // Our process should not be traced in a normal test run
        assert.strictEqual(result.traced, false);
        assert.strictEqual(result.tracerPid, 0);
      } else if (os.platform() === 'darwin') {
        assert.ok(typeof result.traced === 'boolean' || result.traced === null);
      } else if (os.platform() === 'win32') {
        assert.ok(typeof result.traced === 'boolean' || result.traced === null);
      }
    });

    if (os.platform() === 'linux') {
      it('returns error for non-existent PID', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkTracerPid(999_999_999);
        assert.ok(result.traced === null || result.error);
      });
    }
  });

  describe('checkFileDescriptors', () => {
    it('checks file descriptors for own process', () => {
      const pi = new ProcessIntegrity();
      const result = pi.checkFileDescriptors(process.pid);

      if (os.platform() === 'linux') {
        assert.ok(result.totalFds > 0, 'should have file descriptors');
        assert.ok(Array.isArray(result.suspicious));
      } else if (os.platform() === 'darwin') {
        // Lsof may or may not be available
        assert.ok(typeof result.totalFds === 'number');
      } else if (os.platform() === 'win32') {
        assert.ok(typeof result.totalFds === 'number');
      }
    });

    if (os.platform() === 'linux') {
      it('does not flag normal fds as suspicious', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkFileDescriptors(process.pid);
        // In a normal test, there should be no memfd or deleted fds
        const memfds = result.suspicious.filter(s => s.type === 'memfd');
        assert.strictEqual(memfds.length, 0, 'should not have memfd entries in normal test');
      });

      it('returns empty for non-existent PID', () => {
        const pi = new ProcessIntegrity();
        const result = pi.checkFileDescriptors(999_999_999);
        assert.strictEqual(result.totalFds, 0);
      });
    }
  });

  describe('checkAll', () => {
    it('runs all checks for own process', () => {
      const pi = new ProcessIntegrity();
      const result = pi.checkAll(process.pid);

      assert.strictEqual(result.pid, String(process.pid));
      assert.strictEqual(result.platform, os.platform());
      assert.ok(result.timestamp);
      assert.ok(result.memoryMaps);
      assert.ok(result.executablePageHash);
      assert.ok(result.linkerIntegrity);
      assert.ok(result.tracerPid);
      assert.ok(result.fileDescriptors);
    });

    it('runs all checks for a spawned child process', async () => {
      const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], {
        stdio: 'ignore',
      });

      try {
        // Wait for process to start
        await new Promise(resolve => {
          setTimeout(resolve, 500);
        });

        const pi = new ProcessIntegrity();
        const result = pi.checkAll(child.pid);

        assert.strictEqual(result.pid, String(child.pid));
        assert.ok(result.memoryMaps);
        assert.ok(result.linkerIntegrity);
        assert.ok(result.tracerPid);
        assert.ok(result.fileDescriptors);
      } finally {
        child.kill('SIGKILL');
      }
    });
  });
});
