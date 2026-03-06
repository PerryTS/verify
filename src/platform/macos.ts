import * as child_process from 'child_process';
import * as fs from 'fs';
import { PlatformAdapter } from './adapter';
import { VerifyStep, Screenshot, AppManifest, UIElement, ElementQuery, AccessibilityNode } from '../api/types';
import { logFilePath } from '../storage/screenshots';

export class MacOSAdapter implements PlatformAdapter {
  private handleId: number;
  private pid: number;
  private logFile: string;
  private jobId: string;
  private geisterhandAvailable: boolean;

  constructor(jobId: string, geisterhandAvailable: boolean) {
    this.jobId = jobId;
    this.handleId = 0;
    this.pid = 0;
    this.logFile = logFilePath(jobId);
    this.geisterhandAvailable = geisterhandAvailable;
  }

  async launch(binaryPath: string, env?: Record<string, string>): Promise<VerifyStep> {
    const start = Date.now();
    try {
      child_process.spawnSync('chmod', ['+x', binaryPath]);

      const envJson = JSON.stringify(env || {});

      // Ensure log directory exists
      const logDir = this.logFile.split('/').slice(0, -1).join('/');
      try { fs.mkdirSync(logDir); } catch (e) { /* exists */ }

      const handle = child_process.spawnBackground(binaryPath, [], this.logFile, envJson);
      if (!handle) {
        return { name: 'launch', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: 'Failed to spawn process' };
      }

      this.pid = handle.pid;
      this.handleId = handle.handleId;

      return { name: 'launch', status: 'passed', method: 'deterministic', durationMs: Date.now() - start };
    } catch (err: any) {
      return { name: 'launch', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: err.message || 'Launch failed' };
    }
  }

  async waitForReady(manifest: AppManifest): Promise<VerifyStep> {
    const start = Date.now();
    const timeoutMs = 30000;
    const pollMs = 500;

    if (manifest.appType === 'server' && manifest.ports && manifest.ports.length > 0) {
      const port = manifest.ports[0];
      while (Date.now() - start < timeoutMs) {
        try {
          const r = child_process.spawnSync('nc', ['-z', '-w', '2', '127.0.0.1', String(port)]);
          if (r && r.status === 0) {
            return { name: 'ready', status: 'passed', method: 'deterministic', durationMs: Date.now() - start };
          }
        } catch (_) {}
        await sleep(pollMs);
        if (this.handleId > 0) {
          const ps = child_process.getProcessStatus(this.handleId);
          if (ps && !ps.alive) {
            return { name: 'ready', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: 'Process exited before ready' };
          }
        }
      }
      return { name: 'ready', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: 'Timed out waiting for TCP port ' + String(port) };
    }

    if (manifest.appType === 'cli') {
      while (Date.now() - start < timeoutMs) {
        if (this.handleId > 0) {
          const ps = child_process.getProcessStatus(this.handleId);
          if (ps && !ps.alive) {
            const code = ps.exitCode;
            if (code === 0) {
              return { name: 'ready', status: 'passed', method: 'deterministic', durationMs: Date.now() - start };
            }
            return { name: 'ready', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: 'Process exited with code ' + String(code) };
          }
        }
        await sleep(pollMs);
      }
      return { name: 'ready', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: 'CLI timed out' };
    }

    // GUI app: wait for a window to appear
    while (Date.now() - start < timeoutMs) {
      if (this.handleId > 0) {
        const ps = child_process.getProcessStatus(this.handleId);
        if (ps && !ps.alive) {
          return { name: 'ready', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: 'App crashed before window appeared' };
        }
      }

      if (this.geisterhandAvailable) {
        try {
          const r = child_process.spawnSync('geisterhand', ['ping']);
          if (r && r.status === 0) {
            return { name: 'ready', status: 'passed', method: 'deterministic', durationMs: Date.now() - start };
          }
        } catch (_) {}
      } else {
        if (Date.now() - start > 1000) {
          return { name: 'ready', status: 'passed', method: 'deterministic', durationMs: Date.now() - start };
        }
      }
      await sleep(pollMs);
    }

    return { name: 'ready', status: 'failed', method: 'deterministic', durationMs: Date.now() - start, error: 'Timed out after 30s' };
  }

  async screenshot(savePath: string): Promise<Screenshot | null> {
    try {
      const dir = savePath.split('/').slice(0, -1).join('/');
      try { fs.mkdirSync(dir); } catch (e) { /* exists */ }

      if (this.geisterhandAvailable) {
        const r = child_process.spawnSync('geisterhand', ['screenshot', savePath]);
        if (r && r.status === 0) {
          return { step: 'screenshot', path: savePath, timestamp: new Date().toISOString() };
        }
      }

      // Fallback: screencapture of entire screen
      const r = child_process.spawnSync('screencapture', ['-x', savePath]);
      if (r) {
        return { step: 'screenshot', path: savePath, timestamp: new Date().toISOString() };
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  async findElement(query: ElementQuery): Promise<UIElement | null> {
    if (!this.geisterhandAvailable) return null;

    try {
      const args: string[] = ['find'];
      if (query.label) { args.push('--label'); args.push(query.label); }
      if (query.role) { args.push('--role'); args.push(query.role); }
      if (query.text) { args.push('--text'); args.push(query.text); }

      const r = child_process.spawnSync('geisterhand', args);
      if (!r || r.status !== 0) return null;

      const stdout = r.stdout;
      if (!stdout) return null;
      const output = stdout.toString('utf-8');
      return JSON.parse(output);
    } catch (_) {
      return null;
    }
  }

  async click(element: UIElement): Promise<void> {
    if (!this.geisterhandAvailable) return;
    child_process.spawnSync('geisterhand', ['click', '--x', String(element.x), '--y', String(element.y)]);
  }

  async type(element: UIElement, text: string): Promise<void> {
    if (!this.geisterhandAvailable) return;
    child_process.spawnSync('geisterhand', ['click', '--x', String(element.x), '--y', String(element.y)]);
    child_process.spawnSync('geisterhand', ['type', '--text', text]);
  }

  async getAccessibilityTree(): Promise<AccessibilityNode | null> {
    if (!this.geisterhandAvailable) return null;
    try {
      const r = child_process.spawnSync('geisterhand', ['tree', '--format', 'json']);
      if (!r || r.status !== 0) return null;
      const stdout = r.stdout;
      if (!stdout) return null;
      const output = stdout.toString('utf-8');
      return JSON.parse(output);
    } catch (_) {
      return null;
    }
  }

  getLogs(): string {
    try {
      const content = fs.readFileSync(this.logFile);
      return content || '';
    } catch (_) {
      return '';
    }
  }

  async kill(): Promise<void> {
    if (this.handleId > 0) {
      child_process.killProcess(this.handleId);
      this.handleId = 0;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
