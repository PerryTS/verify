import * as child_process from 'child_process';
import * as fs from 'fs';
import { PlatformAdapter } from './adapter';
import { VerifyStep, Screenshot, AppManifest, UIElement, ElementQuery, AccessibilityNode } from '../api/types';

// Module-level state — avoids Perry class field NaN-boxing bugs
let _handleId: number = 0;
let _pid: number = 0;
let _logFile: string = '';

// Step result globals — avoids SEGV from returning objects from async functions
// Caller reads these after await completes
export let lastStepName: string = '';
export let lastStepStatus: string = '';
export let lastStepMethod: string = 'deterministic';
export let lastStepDurationMs: number = 0;
export let lastStepError: string = '';

function setResult(name: string, status: string, durationMs: number, error: string): void {
  lastStepName = name;
  lastStepStatus = status;
  lastStepMethod = 'deterministic';
  lastStepDurationMs = durationMs;
  lastStepError = error;
}

export class LinuxAdapter implements PlatformAdapter {
  constructor(jobId: string) {
    _handleId = 0;
    _pid = 0;
    _logFile = '';
  }

  async launch(binaryPath: string, env?: Record<string, string>): Promise<VerifyStep> {
    const start = Date.now();
    try {
      child_process.spawnSync('chmod', ['+x', binaryPath]);

      const jobDirEnd = binaryPath.length - '/binary'.length;
      const jobDirPath = binaryPath.substring(0, jobDirEnd);
      _logFile = jobDirPath + '/app.log';
      console.log('[linux.launch] logFile=' + _logFile);

      const envJson = '{"DISPLAY":":99"}';
      console.log('[linux.launch] calling spawnBackground');
      const handle = child_process.spawnBackground(binaryPath, [], _logFile, envJson);
      if (!handle) {
        setResult('launch', 'failed', Date.now() - start, 'Failed to spawn process');
        return null as any;
      }
      _pid = handle.pid;
      _handleId = handle.handleId;
      console.log('[linux.launch] pid=' + String(_pid) + ' handleId=' + String(_handleId));

      setResult('launch', 'passed', Date.now() - start, '');
      return null as any;
    } catch (err: any) {
      setResult('launch', 'failed', Date.now() - start, err.message || 'Launch failed');
      return null as any;
    }
  }

  async waitForReady(manifest: AppManifest): Promise<VerifyStep> {
    const start = Date.now();
    const timeoutMs = 30000;
    const pollMs = 500;

    if (manifest.appType === 'cli') {
      while (Date.now() - start < timeoutMs) {
        if (_handleId > 0) {
          const ps = child_process.getProcessStatus(_handleId);
          if (ps && !ps.alive) {
            const code = ps.exitCode;
            if (code === 0) {
              setResult('ready', 'passed', Date.now() - start, '');
              return null as any;
            }
            setResult('ready', 'failed', Date.now() - start, 'Process exited with code ' + String(code));
            return null as any;
          }
        }
        await sleep(pollMs);
      }
      setResult('ready', 'failed', Date.now() - start, 'CLI timed out');
      return null as any;
    }

    if (manifest.appType === 'server' && manifest.ports && manifest.ports.length > 0) {
      const port = manifest.ports[0];
      while (Date.now() - start < timeoutMs) {
        try {
          const r = child_process.spawnSync('nc', ['-z', '-w', '2', '127.0.0.1', String(port)]);
          if (r && r.status === 0) {
            console.log('[linux.ready] port ' + String(port) + ' is open');
            setResult('ready', 'passed', Date.now() - start, '');
            return null as any;
          }
        } catch (_) {}

        if (_handleId > 0) {
          const ps = child_process.getProcessStatus(_handleId);
          if (ps && !ps.alive) {
            setResult('ready', 'failed', Date.now() - start, 'Process exited before ready');
            return null as any;
          }
        }
        await sleep(pollMs);
      }
      setResult('ready', 'failed', Date.now() - start, 'Timed out waiting for port ' + String(port));
      return null as any;
    }

    // GUI app on Linux: just wait a bit and check process alive
    await sleep(2000);
    if (_handleId > 0) {
      const ps = child_process.getProcessStatus(_handleId);
      if (ps && !ps.alive) {
        setResult('ready', 'failed', Date.now() - start, 'Process exited');
        return null as any;
      }
    }
    setResult('ready', 'passed', Date.now() - start, '');
    return null as any;
  }

  async screenshot(savePath: string): Promise<Screenshot | null> {
    return null;
  }

  async findElement(_query: ElementQuery): Promise<UIElement | null> {
    return null;
  }

  async click(_element: UIElement): Promise<void> {}

  async type(_element: UIElement, _text: string): Promise<void> {}

  async getAccessibilityTree(): Promise<AccessibilityNode | null> {
    return null;
  }

  getLogs(): string {
    try {
      if (_logFile) {
        return fs.readFileSync(_logFile) || '';
      }
      return '';
    } catch (_) {
      return '';
    }
  }

  async kill(): Promise<void> {
    if (_handleId > 0) {
      child_process.killProcess(_handleId);
      _handleId = 0;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
