// perry-verify-worker: Platform-specific verification worker
// Connects to perry-verify manager via WebSocket, receives jobs, runs verification pipeline

import { WebSocket, sendToClient } from 'ws';
import * as fs from 'fs';
import * as os from 'os';
import * as child_process from 'child_process';
import { VerifyJob, VerifyConfig, AppManifest, TargetPlatform, VerifyStep, Screenshot } from './api/types';

// --- Configuration ---

const MANAGER_URL = process.env.PERRY_VERIFY_MANAGER_URL || 'ws://verify.perryts.com:7778';
const WORKER_NAME = process.env.PERRY_VERIFY_WORKER_NAME || 'worker-' + hostPlatform();
const WORK_DIR = process.env.PERRY_VERIFY_WORK_DIR || '/tmp/perry-verify-worker';
const RECONNECT_DELAY_MS = 5000;

try { fs.mkdirSync(WORK_DIR); } catch (e) { /* exists */ }

// --- Host platform detection ---

function hostPlatform(): string {
  const p = os.platform();
  const a = os.arch();
  if (p === 'darwin') return a === 'arm64' ? 'macos-arm64' : 'macos-x64';
  if (p === 'linux') return a === 'arm64' ? 'linux-arm64' : 'linux-x64';
  if (p === 'win32') return 'windows-x64';
  return p + '-' + a;
}

function detectCapabilities(): string[] {
  const p = os.platform();
  const caps: string[] = [];
  if (p === 'darwin') caps.push('macos');
  else if (p === 'linux') caps.push('linux');
  else if (p === 'win32') caps.push('windows');
  return caps;
}

// --- Job queue ---

let pendingWs: any = null;
let pendingJobId: string = '';
let pendingConfig: any = null;
let pendingManifest: any = null;
let pendingTarget: string = '';
let pendingBinaryUrl: string = '';
let hasPending: number = 0;

// --- Linux platform state ---

let _handleId: number = 0;
let _pid: number = 0;
let _logFile: string = '';

// Step result globals (avoids returning objects from async functions — Perry SEGV bug)
let _stepName: string = '';
let _stepStatus: string = '';
let _stepDurationMs: number = 0;
let _stepError: string = '';

function setStep(name: string, status: string, durationMs: number, error: string): void {
  _stepName = name;
  _stepStatus = status;
  _stepDurationMs = durationMs;
  _stepError = error;
}

// --- Binary decode ---

function decodeBinary(b64Path: string, outPath: string): void {
  console.log('[decodeBinary] decoding ' + b64Path + ' -> ' + outPath);
  const r = child_process.spawnSync('bash', ['-c', 'base64 -d ' + b64Path + ' > ' + outPath + ' && chmod +x ' + outPath]);
  if (r) {
    console.log('[decodeBinary] status=' + String(r.status));
  }
  console.log('[decodeBinary] file exists: ' + String(fs.existsSync(outPath)));
}

// --- Linux platform methods ---

async function linuxLaunch(binaryPath: string): Promise<void> {
  const start = Date.now();
  try {
    child_process.spawnSync('chmod', ['+x', binaryPath]);

    const jobDirEnd = binaryPath.length - '/binary'.length;
    const jobDirPath = binaryPath.substring(0, jobDirEnd);
    _logFile = jobDirPath + '/app.log';

    const envJson = '{"DISPLAY":":99"}';
    console.log('[launch] calling spawnBackground');
    const handle = child_process.spawnBackground(binaryPath, [], _logFile, envJson);
    if (!handle) {
      setStep('launch', 'failed', Date.now() - start, 'Failed to spawn process');
      return;
    }
    _pid = handle.pid;
    _handleId = handle.handleId;
    console.log('[launch] pid=' + String(_pid) + ' handleId=' + String(_handleId));
    setStep('launch', 'passed', Date.now() - start, '');
  } catch (err: any) {
    setStep('launch', 'failed', Date.now() - start, err.message || 'Launch failed');
  }
}

async function linuxWaitForReady(manifest: AppManifest): Promise<void> {
  const start = Date.now();
  const timeoutMs = 30000;
  const pollMs = 500;

  if (manifest.appType === 'server' && manifest.ports && manifest.ports.length > 0) {
    const port = manifest.ports[0];
    while (Date.now() - start < timeoutMs) {
      try {
        const r = child_process.spawnSync('nc', ['-z', '-w', '2', '127.0.0.1', String(port)]);
        if (r && r.status === 0) {
          console.log('[ready] port ' + String(port) + ' is open');
          setStep('ready', 'passed', Date.now() - start, '');
          return;
        }
      } catch (_) {}

      if (_handleId > 0) {
        const ps = child_process.getProcessStatus(_handleId);
        if (ps && !ps.alive) {
          setStep('ready', 'failed', Date.now() - start, 'Process exited before ready');
          return;
        }
      }
      await sleep(pollMs);
    }
    setStep('ready', 'failed', Date.now() - start, 'Timed out waiting for port ' + String(port));
    return;
  }

  if (manifest.appType === 'cli') {
    while (Date.now() - start < timeoutMs) {
      if (_handleId > 0) {
        const ps = child_process.getProcessStatus(_handleId);
        if (ps && !ps.alive) {
          const code = ps.exitCode;
          if (code === 0) {
            setStep('ready', 'passed', Date.now() - start, '');
            return;
          }
          setStep('ready', 'failed', Date.now() - start, 'Process exited with code ' + String(code));
          return;
        }
      }
      await sleep(pollMs);
    }
    setStep('ready', 'failed', Date.now() - start, 'CLI timed out');
    return;
  }

  // GUI: wait and check process alive
  await sleep(2000);
  if (_handleId > 0) {
    const ps = child_process.getProcessStatus(_handleId);
    if (ps && !ps.alive) {
      setStep('ready', 'failed', Date.now() - start, 'Process exited');
      return;
    }
  }
  setStep('ready', 'passed', Date.now() - start, '');
}

function linuxScreenshot(savePath: string): number {
  try {
    const r = child_process.spawnSync('bash', ['-c', 'DISPLAY=:99 scrot -o ' + savePath]);
    if (r && r.status === 0 && fs.existsSync(savePath)) {
      console.log('[screenshot] saved to ' + savePath);
      return 1;
    }
    console.log('[screenshot] scrot failed, status=' + String(r ? r.status : -1));
    return 0;
  } catch (err: any) {
    console.log('[screenshot] error: ' + (err.message || String(err)));
    return 0;
  }
}

function sendScreenshot(ws: any, jobId: string, stepName: string, pngPath: string): void {
  try {
    // base64 encode the PNG file
    const r = child_process.spawnSync('base64', ['-w', '0', pngPath]);
    if (r && r.stdout) {
      const b64Data = r.stdout;
      console.log('[screenshot] sending ' + stepName + ' (' + String(b64Data.length) + ' bytes b64)');
      // Use plain-text prefix format to avoid JSON.parse issues with large strings
      sendToClient(ws, 'SCREENSHOT:' + jobId + ':' + stepName + ':' + b64Data);
    }
  } catch (err: any) {
    console.log('[screenshot] send error: ' + (err.message || String(err)));
  }
}

function linuxKill(): void {
  if (_handleId > 0) {
    child_process.killProcess(_handleId);
    _handleId = 0;
  }
}

function linuxGetLogs(): string {
  try {
    if (_logFile) {
      return fs.readFileSync(_logFile) || '';
    }
    return '';
  } catch (_) {
    return '';
  }
}

// --- JSON helpers ---

function buildStepJson(name: string, status: string, method: string, durationMs: number, error: string): string {
  let j = '{"name":"' + name + '","status":"' + status + '","method":"' + method + '","durationMs":' + String(durationMs);
  if (error) j = j + ',"error":"' + error.replace(/"/g, '\\"') + '"';
  j = j + '}';
  return j;
}

function sendStepUpdate(ws: any, jobId: string, name: string, status: string, durationMs: number, error: string): void {
  const stepJson = buildStepJson(name, status, 'deterministic', durationMs, error);
  sendToClient(ws, '{"type":"step_update","job_id":"' + jobId + '","step":' + stepJson + '}');
}

function buildCompleteJson(jobId: string, success: number, logs: string, durationMs: number, costCents: number): string {
  const successStr = success === 1 ? 'true' : 'false';
  const escapedLogs = logs.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
  return '{"type":"job_complete","job_id":"' + jobId + '","success":' + successStr + ',"logs":"' + escapedLogs + '","durationMs":' + String(durationMs) + ',"costCents":' + String(costCents) + '}';
}

// --- Job execution ---

async function executeJob(ws: any, jobId: string, config: VerifyConfig, manifest: AppManifest, target: string, binaryUrl: string): Promise<void> {
  console.log('executeJob start: jobId=' + jobId + ' target=' + target);
  const jobDir = WORK_DIR + '/jobs/' + jobId;
  const screensDir = jobDir + '/screenshots';
  try { fs.mkdirSync(WORK_DIR + '/jobs'); } catch (e) {}
  try { fs.mkdirSync(jobDir); } catch (e) {}
  try { fs.mkdirSync(screensDir); } catch (e) {}

  const binPath = jobDir + '/binary';
  const startTime = Date.now();

  function sendLog(text: string): void {
    console.log('[job] ' + text);
    sendToClient(ws, '{"type":"log","job_id":"' + jobId + '","text":"' + text + '"}');
  }

  _handleId = 0;
  _pid = 0;
  _logFile = '';

  try {
    // Download binary
    sendLog('Downloading binary...');
    const resp = await fetch(binaryUrl);
    console.log('fetch status=' + String(resp.status));
    if (!resp.ok) {
      throw new Error('Failed to download binary: HTTP ' + String(resp.status));
    }
    const b64Data = await resp.text();
    console.log('b64Data length=' + String(b64Data.length));

    const b64Path = binPath + '.b64';
    fs.writeFileSync(b64Path, b64Data);
    decodeBinary(b64Path, binPath);

    if (!fs.existsSync(binPath)) {
      throw new Error('Binary decode failed');
    }
    sendLog('Binary downloaded and decoded');

    const isGui = manifest.appType === 'gui' || manifest.appType === 'desktop';
    let shotCount = 0;

    // Step 1: Launch
    console.log('Launching binary at ' + binPath);
    await linuxLaunch(binPath);
    const launchName = _stepName;
    const launchStatus = _stepStatus;
    const launchDuration = _stepDurationMs;
    const launchError = _stepError;
    console.log('Launch: ' + launchStatus);
    sendStepUpdate(ws, jobId, launchName, launchStatus, launchDuration, launchError);
    if (launchStatus === 'failed') {
      // Screenshot on failure (if GUI)
      if (isGui) {
        const shotPath = screensDir + '/launch-fail.png';
        if (linuxScreenshot(shotPath) === 1) {
          sendScreenshot(ws, jobId, 'launch-fail', shotPath);
        }
      }
      sendToClient(ws, buildCompleteJson(jobId, 0, linuxGetLogs(), Date.now() - startTime, 0));
      return;
    }

    // Step 2: Wait for ready
    console.log('Waiting for ready...');
    await linuxWaitForReady(manifest);
    const readyName = _stepName;
    const readyStatus = _stepStatus;
    const readyDuration = _stepDurationMs;
    const readyError = _stepError;
    console.log('Ready: ' + readyStatus);
    sendStepUpdate(ws, jobId, readyName, readyStatus, readyDuration, readyError);

    // Take screenshot after ready (GUI apps always, others on failure)
    if (isGui || readyStatus === 'failed') {
      const shotLabel = readyStatus === 'failed' ? 'ready-fail' : 'after-ready';
      const shotPath = screensDir + '/' + shotLabel + '.png';
      if (linuxScreenshot(shotPath) === 1) {
        sendScreenshot(ws, jobId, shotLabel, shotPath);
        shotCount = shotCount + 1;
      }
    }

    if (readyStatus === 'failed') {
      sendToClient(ws, buildCompleteJson(jobId, 0, linuxGetLogs(), Date.now() - startTime, 0));
      return;
    }

    // Step 3: Post-ready screenshot for GUI apps (give app a moment to render)
    if (isGui && shotCount === 0) {
      await sleep(1000);
      const shotPath = screensDir + '/post-ready.png';
      if (linuxScreenshot(shotPath) === 1) {
        sendScreenshot(ws, jobId, 'post-ready', shotPath);
      }
    }

    // All steps passed (auth/state-check/flows skipped for server apps with no auth)
    console.log('All steps passed!');
    sendToClient(ws, buildCompleteJson(jobId, 1, linuxGetLogs(), Date.now() - startTime, 0));

  } catch (err: any) {
    const errMsg = err.message || String(err);
    sendLog('Pipeline error: ' + errMsg);
    sendToClient(ws, buildCompleteJson(jobId, 0, linuxGetLogs() + '\nError: ' + errMsg, Date.now() - startTime, 0));
  } finally {
    linuxKill();
  }
}

// --- WebSocket connection ---

let currentWs: any = null;

async function connect(): Promise<void> {
  console.log('Connecting to manager at ' + MANAGER_URL + '...');
  try {
    const ws = await new WebSocket(MANAGER_URL);
    currentWs = ws;
    console.log('Connected to manager');

    const caps = detectCapabilities();
    let capsJson = '[';
    for (let ci = 0; ci < caps.length; ci++) {
      if (ci > 0) capsJson = capsJson + ',';
      capsJson = capsJson + '"' + caps[ci] + '"';
    }
    capsJson = capsJson + ']';
    const helloMsg = '{"type":"worker_hello","name":"' + WORKER_NAME + '","capabilities":' + capsJson + '}';
    sendToClient(ws, helloMsg);
    console.log('Registered as ' + WORKER_NAME + ' with capabilities: [' + caps.join(', ') + ']');

    ws.on('message', (data: any) => {
      let msg: any;
      try { msg = JSON.parse(data); } catch (e: any) { return; }

      if (msg.type === 'job_assign') {
        console.log('Queued job: ' + msg.job_id + ' target=' + msg.target);
        pendingWs = ws;
        pendingJobId = msg.job_id;
        pendingConfig = msg.config;
        pendingManifest = msg.manifest;
        pendingTarget = msg.target;
        pendingBinaryUrl = msg.binary_url;
        hasPending = 1;
      }
    });

    ws.on('close', () => {
      console.log('Disconnected. Reconnecting in ' + String(RECONNECT_DELAY_MS / 1000) + 's...');
      currentWs = null;
      setTimeout(connect, RECONNECT_DELAY_MS);
    });

    ws.on('error', (err: any) => {
      console.error('WebSocket error:', err);
    });
  } catch (err: any) {
    console.error('Connection failed: ' + (err.message || err));
    setTimeout(connect, RECONNECT_DELAY_MS);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms); });
}

// --- Start ---

async function main(): Promise<void> {
  console.log('perry-verify-worker starting');
  console.log('platform: ' + hostPlatform());
  console.log('work dir: ' + WORK_DIR);

  await connect();

  while (true) {
    if (hasPending === 1) {
      hasPending = 0;
      const ws = pendingWs;
      const jobId = pendingJobId;
      const config = pendingConfig;
      const manifest = pendingManifest;
      const target = pendingTarget;
      const binaryUrl = pendingBinaryUrl;
      console.log('Main loop picking up job: ' + jobId);

      try {
        await executeJob(ws, jobId, config, manifest, target, binaryUrl);
      } catch (err: any) {
        console.error('Job error: ' + (err.message || String(err)));
        try {
          sendToClient(ws, buildCompleteJson(jobId, 0, 'Worker error: ' + (err.message || String(err)), 0, 0));
        } catch (_) {}
      }
    }
    await sleep(200);
  }
}

main();
