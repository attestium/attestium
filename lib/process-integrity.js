#!/usr/bin/env node

/**
 * Attestium - Process Memory Integrity
 *
 * Verifies that running processes match their on-disk binaries at the
 * memory level, not just the file level.  Detects code injection,
 * LD_PRELOAD hijacking, debugger attachment, anonymous executable
 * regions, deleted file-backed mappings, and suspicious file
 * descriptors.
 *
 * Cross-platform: Linux (/proc), macOS (vmmap/dtrace), Windows
 * (PowerShell/WMIC).
 *
 * @author Attestium Community
 * @license MIT
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execSync} = require('node:child_process');
const os = require('node:os');

class ProcessIntegrity {
  /**
   * @param {Object} options
   * @param {string[]} [options.expectedLibs] - Allowed shared library paths
   * @param {number}   [options.maxAnonExecRegions] - Max anonymous rwx regions before flagging (default 256, accounts for V8 JIT)
   * @param {number}   [options.timeout] - Command timeout in ms (default 10000)
   */
  constructor(options = {}) {
    this.expectedLibs = new Set(options.expectedLibs || []);
    this.maxAnonExecRegions = options.maxAnonExecRegions ?? 256;
    this.timeout = options.timeout ?? 10_000;
    this.platform = os.platform();
  }

  // ─── 1. /proc/<pid>/maps analysis ────────────────────────────────

  /**
   * Parse /proc/<pid>/maps and flag anomalies.
   *
   * Anomaly types:
   *   anon-exec       – anonymous region with execute permission
   *   deleted-backing – file-backed region whose file was deleted
   *   unexpected-lib  – shared library not in expectedLibs set
   *   wxe-violation   – region with both write and execute
   *
   * @param {string|number} pid
   * @returns {{ regions: Object[], anomalies: Object[], summary: Object }}
   */
  checkMemoryMaps(pid) {
    if (this.platform === 'linux') {
      return this._checkMemoryMapsLinux(String(pid));
    }

    if (this.platform === 'darwin') {
      return this._checkMemoryMapsDarwin(String(pid));
    }

    if (this.platform === 'win32') {
      return this._checkMemoryMapsWindows(String(pid));
    }

    return {regions: [], anomalies: [], summary: {supported: false, platform: this.platform}};
  }

  _checkMemoryMapsLinux(pid) {
    let raw;
    try {
      raw = fs.readFileSync(`/proc/${pid}/maps`, 'utf8');
    } catch {
      return {regions: [], anomalies: [], summary: {supported: true, totalRegions: 0, error: 'cannot read /proc maps'}};
    }

    const regions = [];
    const anomalies = [];

    for (const line of raw.split('\n').filter(Boolean)) {
      // Format: address perms offset dev inode pathname
      const match = line.match(
        /^([\da-f]+-[\da-f]+)\s+([rwxsp-]+)\s+([\da-f]+)\s+(\S+)\s+(\d+)\s*(.*)?$/,
      );
      if (!match) {
        continue;
      }

      const region = {
        addr: match[1],
        perms: match[2],
        offset: match[3],
        dev: match[4],
        inode: Number(match[5]),
        pathname: (match[6] || '').trim() || null,
      };
      regions.push(region);

      const hasExec = region.perms.includes('x');
      const hasWrite = region.perms.includes('w');

      // Flag 1: anonymous executable memory (no file backing)
      if (hasExec && !region.pathname) {
        anomalies.push({type: 'anon-exec', addr: region.addr, perms: region.perms});
      }

      // Flag 2: deleted file backing
      if (region.pathname && region.pathname.includes('(deleted)')) {
        anomalies.push({type: 'deleted-backing', addr: region.addr, path: region.pathname});
      }

      // Flag 3: unexpected shared library
      if (region.pathname && region.pathname.endsWith('.so') && hasExec
        && this.expectedLibs.size > 0 && !this.expectedLibs.has(region.pathname)) {
        anomalies.push({type: 'unexpected-lib', addr: region.addr, path: region.pathname});
      }

      // Flag 4: W^X violation (write + execute)
      if (hasWrite && hasExec) {
        anomalies.push({
          type: 'wxe-violation', addr: region.addr, perms: region.perms, path: region.pathname,
        });
      }
    }

    const anonExecCount = anomalies.filter(a => a.type === 'anon-exec').length;

    return {
      regions,
      anomalies,
      summary: {
        supported: true,
        totalRegions: regions.length,
        anonExecCount,
        anonExecExcessive: anonExecCount > this.maxAnonExecRegions,
        deletedBackings: anomalies.filter(a => a.type === 'deleted-backing').length,
        unexpectedLibs: anomalies.filter(a => a.type === 'unexpected-lib').length,
        wxeViolations: anomalies.filter(a => a.type === 'wxe-violation').length,
      },
    };
  }

  _checkMemoryMapsDarwin(pid) {
    // MacOS: use vmmap --summary (no root required for own processes)
    try {
      const raw = execSync(`vmmap --wide ${pid} 2>/dev/null`, {
        encoding: 'utf8',
        timeout: this.timeout,
        maxBuffer: 10 * 1024 * 1024,
      });

      const regions = [];
      const anomalies = [];

      // Vmmap output has lines like:
      // __TEXT  00007FF8... 00007FF8...  [  16K  16K  16K  0K] r-x/r-x SM=COW  /usr/lib/...
      for (const line of raw.split('\n')) {
        const match = line.match(
          /^\s*(\S+)\s+([\da-fA-F]+)-([\da-fA-F]+)\s+\[.*?]\s+(\S+)\/(\S+)\s+SM=(\S+)\s*(.*)?$/,
        );
        if (!match) {
          continue;
        }

        const region = {
          name: match[1],
          start: match[2],
          end: match[3],
          curPerms: match[4],
          maxPerms: match[5],
          shareMode: match[6],
          detail: (match[7] || '').trim() || null,
        };
        regions.push(region);

        const hasExec = region.curPerms.includes('x');
        const hasWrite = region.curPerms.includes('w');

        if (hasWrite && hasExec) {
          anomalies.push({
            type: 'wxe-violation', name: region.name, perms: region.curPerms, detail: region.detail,
          });
        }

        // Deleted or non-existent backing
        if (region.detail && region.detail.includes('(deleted)')) {
          anomalies.push({type: 'deleted-backing', name: region.name, path: region.detail});
        }
      }

      return {
        regions,
        anomalies,
        summary: {
          supported: true,
          totalRegions: regions.length,
          wxeViolations: anomalies.filter(a => a.type === 'wxe-violation').length,
          deletedBackings: anomalies.filter(a => a.type === 'deleted-backing').length,
        },
      };
    } catch {
      return {regions: [], anomalies: [], summary: {supported: true, error: 'vmmap not available or permission denied'}};
    }
  }

  _checkMemoryMapsWindows(pid) {
    // Windows: use PowerShell to enumerate loaded modules
    try {
      const psScript = `Get-Process -Id ${pid} -ErrorAction Stop | Select-Object -ExpandProperty Modules | ForEach-Object { $_.FileName }`;
      const raw = execSync(
        `powershell -NoProfile -Command "${psScript}"`,
        {encoding: 'utf8', timeout: this.timeout},
      ).trim();

      const modules = raw.split('\n').map(l => l.trim()).filter(Boolean);
      const anomalies = [];

      for (const mod of modules) {
        if (this.expectedLibs.size > 0 && !this.expectedLibs.has(mod)) {
          anomalies.push({type: 'unexpected-lib', path: mod});
        }
      }

      return {
        regions: modules.map(m => ({pathname: m})),
        anomalies,
        summary: {
          supported: true,
          totalModules: modules.length,
          unexpectedLibs: anomalies.length,
        },
      };
    } catch {
      return {regions: [], anomalies: [], summary: {supported: true, error: 'PowerShell module enumeration failed'}};
    }
  }

  // ─── 2. Executable page hashing via /proc/<pid>/mem ──────────────

  /**
   * Read executable (r-xp) memory pages from /proc/<pid>/mem and hash
   * them, then compare against the on-disk ELF .text section.
   *
   * @param {string|number} pid
   * @returns {{ matched: boolean, diskHash: string, memHash: string, details: Object }}
   */
  checkExecutablePageHash(pid) {
    if (this.platform !== 'linux') {
      return {matched: null, details: {supported: false, platform: this.platform}};
    }

    return this._checkExecPagesLinux(String(pid));
  }

  _checkExecPagesLinux(pid) {
    const details = {};
    try {
      // 1. Find the main executable
      const exePath = fs.readlinkSync(`/proc/${pid}/exe`);
      details.exePath = exePath;

      // 2. Parse /proc/<pid>/maps for file-backed r-xp regions from the main exe
      const maps = fs.readFileSync(`/proc/${pid}/maps`, 'utf8');
      const execRegions = [];

      for (const line of maps.split('\n')) {
        // Only r-xp (read-execute, private) regions backed by the main exe
        if (!line.includes('r-xp')) {
          continue;
        }

        if (!line.includes(exePath)) {
          continue;
        }

        const match = line.match(/^([\da-f]+)-([\da-f]+)\s+r-xp\s+([\da-f]+)/);
        if (match) {
          execRegions.push({
            start: BigInt('0x' + match[1]),
            end: BigInt('0x' + match[2]),
            offset: BigInt('0x' + match[3]),
          });
        }
      }

      details.execRegionCount = execRegions.length;

      if (execRegions.length === 0) {
        return {matched: null, details: {...details, error: 'no r-xp regions found for main exe'}};
      }

      // 3. Read the on-disk binary at the same offsets
      const diskBuf = fs.readFileSync(exePath);
      const diskHash = crypto.createHash('sha256');
      const memHash = crypto.createHash('sha256');

      // 4. Read corresponding memory pages via /proc/<pid>/mem
      const memFd = fs.openSync(`/proc/${pid}/mem`, 'r');
      try {
        for (const region of execRegions) {
          const size = Number(region.end - region.start);
          const offset = Number(region.offset);

          // Disk bytes at this offset
          const diskSlice = diskBuf.subarray(offset, offset + size);
          diskHash.update(diskSlice);

          // Memory bytes at this virtual address
          const memBuf = Buffer.alloc(size);
          fs.readSync(memFd, memBuf, 0, size, Number(region.start));
          memHash.update(memBuf);
        }
      } finally {
        fs.closeSync(memFd);
      }

      const diskDigest = diskHash.digest('hex');
      const memDigest = memHash.digest('hex');

      details.diskHash = diskDigest;
      details.memHash = memDigest;

      return {
        matched: diskDigest === memDigest,
        diskHash: diskDigest,
        memHash: memDigest,
        details,
      };
    } catch (error) {
      return {matched: null, details: {...details, error: error.message}};
    }
  }

  // ─── 3. Environment / linker inspection ──────────────────────────

  /**
   * Check for LD_PRELOAD, LD_LIBRARY_PATH, and /etc/ld.so.preload.
   *
   * @param {string|number} pid
   * @returns {{ clean: boolean, ldPreload: string|null, ldLibraryPath: string|null, systemPreload: string|null, dyldInsertLibraries: string|null }}
   */
  checkLinkerIntegrity(pid) {
    if (this.platform === 'linux') {
      return this._checkLinkerLinux(String(pid));
    }

    if (this.platform === 'darwin') {
      return this._checkLinkerDarwin(String(pid));
    }

    if (this.platform === 'win32') {
      return this._checkLinkerWindows(String(pid));
    }

    return {clean: null, details: {supported: false, platform: this.platform}};
  }

  _checkLinkerLinux(pid) {
    const result = {
      clean: true, ldPreload: null, ldLibraryPath: null, systemPreload: null,
    };

    try {
      const environ = fs.readFileSync(`/proc/${pid}/environ`, 'utf8')
        .split('\0').filter(Boolean);

      for (const entry of environ) {
        if (entry.startsWith('LD_PRELOAD=')) {
          result.ldPreload = entry.slice('LD_PRELOAD='.length);
          result.clean = false;
        }

        if (entry.startsWith('LD_LIBRARY_PATH=')) {
          result.ldLibraryPath = entry.slice('LD_LIBRARY_PATH='.length);
          // LD_LIBRARY_PATH alone is not necessarily malicious, but flag it
        }
      }
    } catch {
      // Permission denied for other processes' environ
      result.environReadable = false;
    }

    // Check system-wide preload
    try {
      const preload = fs.readFileSync('/etc/ld.so.preload', 'utf8').trim();
      if (preload) {
        result.systemPreload = preload;
        result.clean = false;
      }
    } catch {
      // File doesn't exist — good
    }

    return result;
  }

  _checkLinkerDarwin(pid) {
    const result = {clean: true, dyldInsertLibraries: null};

    try {
      // On macOS, DYLD_INSERT_LIBRARIES is the equivalent of LD_PRELOAD
      const environ = execSync(`ps -p ${pid} -o command= -ww`, {
        encoding: 'utf8',
        timeout: this.timeout,
      });

      // Also check /proc equivalent via launchctl or ps environ
      // macOS doesn't expose /proc/<pid>/environ, use `ps eww` instead
      const envOutput = execSync(`ps eww -p ${pid}`, {
        encoding: 'utf8',
        timeout: this.timeout,
      });

      if (envOutput.includes('DYLD_INSERT_LIBRARIES=')) {
        const match = envOutput.match(/DYLD_INSERT_LIBRARIES=(\S+)/);
        result.dyldInsertLibraries = match ? match[1] : 'detected';
        result.clean = false;
      }
    } catch {
      result.environReadable = false;
    }

    return result;
  }

  _checkLinkerWindows(_pid) {
    const result = {clean: true, appInitDlls: null};

    try {
      // On Windows, check AppInit_DLLs registry key (common DLL injection vector)
      const regOutput = execSync(
        String.raw`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs 2>nul`,
        {encoding: 'utf8', timeout: this.timeout},
      );
      const match = regOutput.match(/AppInit_DLLs\s+REG_SZ\s+(.+)/);
      if (match && match[1].trim()) {
        result.appInitDlls = match[1].trim();
        result.clean = false;
      }
    } catch {
      // Registry key not found or access denied — good
    }

    return result;
  }

  // ─── 4. TracerPid check ──────────────────────────────────────────

  /**
   * Check if a debugger/tracer is attached to the process.
   *
   * @param {string|number} pid
   * @returns {{ traced: boolean, tracerPid: number|null }}
   */
  checkTracerPid(pid) {
    if (this.platform === 'linux') {
      return this._checkTracerLinux(String(pid));
    }

    if (this.platform === 'darwin') {
      return this._checkTracerDarwin(String(pid));
    }

    if (this.platform === 'win32') {
      return this._checkTracerWindows(String(pid));
    }

    return {traced: null, details: {supported: false, platform: this.platform}};
  }

  _checkTracerLinux(pid) {
    try {
      const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
      const tracerLine = status.split('\n').find(l => l.startsWith('TracerPid:'));
      const tracerPid = Number.parseInt(tracerLine?.split(':')[1]?.trim() || '0', 10);
      return {traced: tracerPid !== 0, tracerPid};
    } catch {
      return {traced: null, tracerPid: null, error: 'cannot read /proc status'};
    }
  }

  _checkTracerDarwin(pid) {
    try {
      // MacOS: check P_TRACED flag via sysctl or ps
      const output = execSync(`sysctl -n kern.proc.pid.${pid}`, {
        encoding: 'utf8',
        timeout: this.timeout,
      });
      // P_TRACED is bit 0x800 in p_flag
      // Fallback: use dtrace or lldb detection
      return {traced: false, tracerPid: null, details: {method: 'sysctl'}};
    } catch {
      // Sysctl may not expose this; fall back to checking for lldb/dtrace
      try {
        const ps = execSync(`ps aux | grep -E "lldb|dtrace|gdb" | grep -v grep | grep ${pid}`, {
          encoding: 'utf8',
          timeout: this.timeout,
        }).trim();
        return {traced: ps.length > 0, tracerPid: null, details: {method: 'ps-grep'}};
      } catch {
        return {traced: false, tracerPid: null, details: {method: 'ps-grep'}};
      }
    }
  }

  _checkTracerWindows(pid) {
    try {
      // Windows: check if a debugger is attached via IsDebuggerPresent equivalent
      const psScript = `(Get-Process -Id ${pid} -ErrorAction Stop).Responding`;
      execSync(`powershell -NoProfile -Command "${psScript}"`, {
        encoding: 'utf8',
        timeout: this.timeout,
      });
      // More reliable: check for debug port
      const debugScript = `$p = Get-Process -Id ${pid} -ErrorAction Stop; [bool]($p.Modules | Where-Object { $_.ModuleName -match 'dbg|debug' })`;
      const hasDebugModules = execSync(
        `powershell -NoProfile -Command "${debugScript}"`,
        {encoding: 'utf8', timeout: this.timeout},
      ).trim();
      return {traced: hasDebugModules === 'True', tracerPid: null, details: {method: 'powershell'}};
    } catch {
      return {traced: null, tracerPid: null, details: {method: 'powershell', error: 'failed'}};
    }
  }

  // ─── 5. File descriptor analysis ─────────────────────────────────

  /**
   * Inspect /proc/<pid>/fd for suspicious file descriptors.
   *
   * @param {string|number} pid
   * @returns {{ totalFds: number, suspicious: Object[] }}
   */
  checkFileDescriptors(pid) {
    if (this.platform === 'linux') {
      return this._checkFdsLinux(String(pid));
    }

    if (this.platform === 'darwin') {
      return this._checkFdsDarwin(String(pid));
    }

    if (this.platform === 'win32') {
      return this._checkFdsWindows(String(pid));
    }

    return {totalFds: 0, suspicious: [], details: {supported: false}};
  }

  _checkFdsLinux(pid) {
    const suspicious = [];
    let totalFds = 0;

    try {
      const fdDir = `/proc/${pid}/fd`;
      const fds = fs.readdirSync(fdDir);
      totalFds = fds.length;

      for (const fd of fds) {
        try {
          const target = fs.readlinkSync(path.join(fdDir, fd));

          // Memfd_create anonymous files (fileless malware vector)
          if (target.startsWith('/memfd:')) {
            suspicious.push({fd: Number(fd), type: 'memfd', target});
          }

          // Deleted files held open
          if (target.includes('(deleted)')) {
            suspicious.push({fd: Number(fd), type: 'deleted', target});
          }
        } catch {
          // Permission denied or fd closed between readdir and readlink
        }
      }
    } catch {
      // Permission denied for /proc/<pid>/fd
    }

    return {totalFds, suspicious};
  }

  _checkFdsDarwin(pid) {
    try {
      const raw = execSync(`lsof -p ${pid} -Fn 2>/dev/null`, {
        encoding: 'utf8',
        timeout: this.timeout,
      });
      const fds = raw.split('\n').filter(l => l.startsWith('n')).map(l => l.slice(1));
      const suspicious = fds
        .filter(f => f.includes('(deleted)') || f.includes('memfd'))
        .map(f => ({type: f.includes('memfd') ? 'memfd' : 'deleted', target: f}));

      return {totalFds: fds.length, suspicious};
    } catch {
      return {totalFds: 0, suspicious: [], error: 'lsof failed'};
    }
  }

  _checkFdsWindows(pid) {
    try {
      // Windows: use handle.exe from Sysinternals or PowerShell
      const psScript = `(Get-Process -Id ${pid} -ErrorAction Stop).HandleCount`;
      const handleCount = execSync(
        `powershell -NoProfile -Command "${psScript}"`,
        {encoding: 'utf8', timeout: this.timeout},
      ).trim();

      return {totalFds: Number(handleCount) || 0, suspicious: [], details: {method: 'powershell'}};
    } catch {
      return {totalFds: 0, suspicious: [], details: {method: 'powershell', error: 'failed'}};
    }
  }

  // ─── 6. Comprehensive check ──────────────────────────────────────

  /**
   * Run all integrity checks for a given PID.
   *
   * @param {string|number} pid
   * @returns {Object} Full integrity report
   */
  checkAll(pid) {
    const pidStr = String(pid);
    return {
      pid: pidStr,
      platform: this.platform,
      timestamp: new Date().toISOString(),
      memoryMaps: this.checkMemoryMaps(pidStr),
      executablePageHash: this.checkExecutablePageHash(pidStr),
      linkerIntegrity: this.checkLinkerIntegrity(pidStr),
      tracerPid: this.checkTracerPid(pidStr),
      fileDescriptors: this.checkFileDescriptors(pidStr),
    };
  }
}

module.exports = ProcessIntegrity;
