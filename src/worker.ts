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

// --- Security ---
const AUTH_TOKEN = process.env.PERRY_VERIFY_AUTH_TOKEN || '';
const SANDBOX_ENABLED = process.env.PERRY_VERIFY_SANDBOX !== '0';
const JOB_TIMEOUT_SECONDS = parseInt(process.env.PERRY_VERIFY_JOB_TIMEOUT || '120', 10);

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
  if (p === 'darwin') {
    caps.push('macos');
    // Check for Xcode / iOS simulator support
    const xcrunCheck = child_process.spawnSync('which', ['xcrun']);
    if (xcrunCheck && xcrunCheck.status === 0) {
      caps.push('ios-simulator');
    }
  } else if (p === 'linux') {
    caps.push('linux');
  } else if (p === 'win32') {
    caps.push('windows');
  }
  // Check for Android SDK
  const adbCheck = child_process.spawnSync('which', ['adb']);
  if (adbCheck && adbCheck.status === 0) {
    caps.push('android-emulator');
  }
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

// --- Process state (shared across platforms) ---

let _handleId: number = 0;
let _pid: number = 0;
let _logFile: string = '';
let _bundleId: string = '';
let _packageName: string = '';
let _appPath: string = '';

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

async function linuxLaunch(binaryPath: string, manifest: AppManifest): Promise<void> {
  const start = Date.now();
  try {
    child_process.spawnSync('chmod', ['+x', binaryPath]);

    const jobDirEnd = binaryPath.length - '/binary'.length;
    const jobDirPath = binaryPath.substring(0, jobDirEnd);
    _logFile = jobDirPath + '/app.log';

    const appType = manifest.appType || 'cli';
    const wrapperPath = writeSandboxWrapper(jobDirPath, binaryPath, 'linux', appType);
    console.log('[launch] sandbox wrapper: ' + wrapperPath);
    const handle = child_process.spawnBackground('bash', [wrapperPath], _logFile, '{}');
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

// --- macOS platform methods ---

async function macosLaunch(binaryPath: string, manifest: AppManifest): Promise<void> {
  const start = Date.now();
  try {
    child_process.spawnSync('chmod', ['+x', binaryPath]);

    const jobDirEnd = binaryPath.length - '/binary'.length;
    const jobDirPath = binaryPath.substring(0, jobDirEnd);
    _logFile = jobDirPath + '/app.log';

    const appType = manifest.appType || 'cli';
    // Check if this is a .app bundle (extracted) or a plain binary
    if (_appPath && _appPath.indexOf('.app') >= 0) {
      // .app bundle — use open -W (macOS App Sandbox applies if signed)
      console.log('[macosLaunch] opening .app bundle: ' + _appPath);
      const handle = child_process.spawnBackground('open', ['-W', _appPath], _logFile, '{}');
      if (!handle) {
        setStep('launch', 'failed', Date.now() - start, 'Failed to open .app bundle');
        return;
      }
      _pid = handle.pid;
      _handleId = handle.handleId;
    } else {
      // Plain binary — wrap in sandbox
      console.log('[macosLaunch] launching binary: ' + binaryPath);
      const wrapperPath = writeSandboxWrapper(jobDirPath, binaryPath, 'macos', appType);
      console.log('[macosLaunch] sandbox wrapper: ' + wrapperPath);
      const handle = child_process.spawnBackground('bash', [wrapperPath], _logFile, '{}');
      if (!handle) {
        setStep('launch', 'failed', Date.now() - start, 'Failed to spawn process');
        return;
      }
      _pid = handle.pid;
      _handleId = handle.handleId;
    }
    console.log('[macosLaunch] pid=' + String(_pid) + ' handleId=' + String(_handleId));
    setStep('launch', 'passed', Date.now() - start, '');
  } catch (err: any) {
    setStep('launch', 'failed', Date.now() - start, err.message || 'Launch failed');
  }
}

async function macosWaitForReady(manifest: AppManifest): Promise<void> {
  // Same logic as linux — port check for servers, alive check for GUI
  const start = Date.now();
  const timeoutMs = 30000;
  const pollMs = 500;

  if (manifest.appType === 'server' && manifest.ports && manifest.ports.length > 0) {
    const port = manifest.ports[0];
    while (Date.now() - start < timeoutMs) {
      try {
        const r = child_process.spawnSync('nc', ['-z', '-w', '2', '127.0.0.1', String(port)]);
        if (r && r.status === 0) {
          console.log('[macosReady] port ' + String(port) + ' is open');
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

function macosScreenshot(savePath: string): number {
  try {
    const r = child_process.spawnSync('screencapture', ['-x', savePath]);
    if (r && r.status === 0 && fs.existsSync(savePath)) {
      console.log('[macosScreenshot] saved to ' + savePath);
      return 1;
    }
    console.log('[macosScreenshot] screencapture failed, status=' + String(r ? r.status : -1));
    return 0;
  } catch (err: any) {
    console.log('[macosScreenshot] error: ' + (err.message || String(err)));
    return 0;
  }
}

function macosKill(): void {
  if (_handleId > 0) {
    child_process.killProcess(_handleId);
    _handleId = 0;
  }
}

function macosGetLogs(): string {
  return linuxGetLogs(); // Same file-based logging
}

// --- iOS Simulator platform methods ---

async function iosLaunch(binaryPath: string, manifest: AppManifest): Promise<void> {
  const start = Date.now();
  try {
    // Determine bundle ID from manifest or default
    _bundleId = '';
    if (manifest && (manifest as any).bundleId) {
      _bundleId = (manifest as any).bundleId;
    }

    // Boot simulator
    console.log('[iosLaunch] booting simulator...');
    const bootResult = child_process.spawnSync('xcrun', ['simctl', 'boot', 'iPhone 16']);
    if (bootResult) {
      console.log('[iosLaunch] boot status=' + String(bootResult.status));
      // status != 0 is OK if already booted
    }

    // Wait a moment for boot
    await sleep(2000);

    // Install the .app
    if (!_appPath) {
      setStep('launch', 'failed', Date.now() - start, 'No .app bundle found for iOS simulator');
      return;
    }
    console.log('[iosLaunch] installing app: ' + _appPath);
    const installResult = child_process.spawnSync('xcrun', ['simctl', 'install', 'booted', _appPath]);
    if (installResult && installResult.status !== 0) {
      const errOut = installResult.stderr || '';
      setStep('launch', 'failed', Date.now() - start, 'Install failed: ' + errOut);
      return;
    }

    // Try to extract bundle ID from Info.plist if not in manifest
    if (!_bundleId) {
      const plistPath = _appPath + '/Info.plist';
      const plistResult = child_process.spawnSync('bash', ['-c', '/usr/libexec/PlistBuddy -c "Print CFBundleIdentifier" ' + plistPath]);
      if (plistResult && plistResult.stdout) {
        _bundleId = plistResult.stdout.replace(/\n/g, '').replace(/\r/g, '');
      }
    }

    if (!_bundleId) {
      setStep('launch', 'failed', Date.now() - start, 'Could not determine bundle ID');
      return;
    }

    // Launch app
    console.log('[iosLaunch] launching bundle: ' + _bundleId);
    const launchResult = child_process.spawnSync('xcrun', ['simctl', 'launch', 'booted', _bundleId]);
    if (launchResult && launchResult.status !== 0) {
      const errOut = launchResult.stderr || '';
      setStep('launch', 'failed', Date.now() - start, 'Launch failed: ' + errOut);
      return;
    }

    console.log('[iosLaunch] app launched');
    setStep('launch', 'passed', Date.now() - start, '');
  } catch (err: any) {
    setStep('launch', 'failed', Date.now() - start, err.message || 'iOS launch failed');
  }
}

async function iosWaitForReady(manifest: AppManifest): Promise<void> {
  const start = Date.now();
  const timeoutMs = 30000;
  const pollMs = 1000;

  // Wait and check the app is still running
  await sleep(3000);

  while (Date.now() - start < timeoutMs) {
    if (_bundleId) {
      // Check app container exists (means it's installed and was launched)
      const checkResult = child_process.spawnSync('xcrun', ['simctl', 'get_app_container', 'booted', _bundleId]);
      if (checkResult && checkResult.status === 0) {
        setStep('ready', 'passed', Date.now() - start, '');
        return;
      }
    }
    await sleep(pollMs);
  }
  setStep('ready', 'failed', Date.now() - start, 'iOS app did not become ready');
}

function iosScreenshot(savePath: string): number {
  try {
    const r = child_process.spawnSync('xcrun', ['simctl', 'io', 'booted', 'screenshot', savePath]);
    if (r && r.status === 0 && fs.existsSync(savePath)) {
      console.log('[iosScreenshot] saved to ' + savePath);
      return 1;
    }
    console.log('[iosScreenshot] failed, status=' + String(r ? r.status : -1));
    return 0;
  } catch (err: any) {
    console.log('[iosScreenshot] error: ' + (err.message || String(err)));
    return 0;
  }
}

function iosKill(): void {
  if (_bundleId) {
    try {
      child_process.spawnSync('xcrun', ['simctl', 'terminate', 'booted', _bundleId]);
    } catch (_) {}
  }
  // Don't shutdown the simulator — other jobs may use it
}

function iosGetLogs(): string {
  if (!_bundleId) return '';
  try {
    const r = child_process.spawnSync('xcrun', ['simctl', 'spawn', 'booted', 'log', 'show', '--last', '30s', '--style', 'compact']);
    if (r && r.stdout) {
      return r.stdout;
    }
    return '';
  } catch (_) {
    return '';
  }
}

// --- Android Emulator platform methods ---

async function androidLaunch(binaryPath: string, manifest: AppManifest): Promise<void> {
  const start = Date.now();
  try {
    // Determine package name from manifest
    _packageName = '';
    if (manifest && (manifest as any).packageName) {
      _packageName = (manifest as any).packageName;
    }

    // Check if emulator is running, start if not
    console.log('[androidLaunch] checking for running emulator...');
    const devicesResult = child_process.spawnSync('adb', ['devices']);
    let emulatorRunning = false;
    if (devicesResult && devicesResult.stdout) {
      const output = devicesResult.stdout;
      if (output.indexOf('emulator') >= 0) {
        emulatorRunning = true;
        console.log('[androidLaunch] emulator already running');
      }
    }

    if (!emulatorRunning) {
      // Start emulator in background
      console.log('[androidLaunch] starting emulator...');
      const jobDirEnd = binaryPath.length - '/binary'.length;
      const jobDirPath = binaryPath.substring(0, jobDirEnd);
      const emuLog = jobDirPath + '/emulator.log';
      child_process.spawnBackground('emulator', ['-avd', 'perry_test', '-no-window', '-no-audio', '-no-boot-anim'], emuLog, '{}');

      // Wait for device
      console.log('[androidLaunch] waiting for device...');
      const waitResult = child_process.spawnSync('adb', ['wait-for-device']);
      if (waitResult) {
        console.log('[androidLaunch] device connected');
      }

      // Wait for boot
      let bootComplete = false;
      const bootStart = Date.now();
      while (Date.now() - bootStart < 60000) {
        const propResult = child_process.spawnSync('adb', ['shell', 'getprop', 'sys.boot_completed']);
        if (propResult && propResult.stdout) {
          const val = propResult.stdout.replace(/\n/g, '').replace(/\r/g, '');
          if (val === '1') {
            bootComplete = true;
            break;
          }
        }
        await sleep(2000);
      }

      if (!bootComplete) {
        setStep('launch', 'failed', Date.now() - start, 'Emulator boot timed out');
        return;
      }
      console.log('[androidLaunch] emulator booted');
    }

    // Install APK — binary was renamed to .apk in artifact handling
    const apkPath = _appPath || binaryPath;
    console.log('[androidLaunch] installing APK: ' + apkPath);
    const installResult = child_process.spawnSync('adb', ['install', '-r', apkPath]);
    if (installResult && installResult.status !== 0) {
      const errOut = installResult.stderr || '';
      setStep('launch', 'failed', Date.now() - start, 'Install failed: ' + errOut);
      return;
    }

    // Extract package name from APK if not in manifest
    if (!_packageName) {
      const aapt = child_process.spawnSync('aapt', ['dump', 'badging', apkPath]);
      if (aapt && aapt.stdout) {
        const output = aapt.stdout;
        const pkgIdx = output.indexOf("package: name='");
        if (pkgIdx >= 0) {
          const nameStart = pkgIdx + "package: name='".length;
          const nameEnd = output.indexOf("'", nameStart);
          if (nameEnd > nameStart) {
            _packageName = output.substring(nameStart, nameEnd);
          }
        }
      }
    }

    if (!_packageName) {
      setStep('launch', 'failed', Date.now() - start, 'Could not determine package name');
      return;
    }

    // Launch the main activity
    console.log('[androidLaunch] launching package: ' + _packageName);
    const launchCmd = _packageName + '/.MainActivity';
    if (manifest && (manifest as any).activity) {
      // Use custom activity if specified
    }
    const launchResult = child_process.spawnSync('adb', ['shell', 'am', 'start', '-n', launchCmd]);
    if (launchResult && launchResult.status !== 0) {
      // Try with monkey (fallback — launches default activity)
      const monkeyResult = child_process.spawnSync('adb', ['shell', 'monkey', '-p', _packageName, '-c', 'android.intent.category.LAUNCHER', '1']);
      if (monkeyResult && monkeyResult.status !== 0) {
        const errOut = monkeyResult.stderr || '';
        setStep('launch', 'failed', Date.now() - start, 'Launch failed: ' + errOut);
        return;
      }
    }

    console.log('[androidLaunch] app launched');
    setStep('launch', 'passed', Date.now() - start, '');
  } catch (err: any) {
    setStep('launch', 'failed', Date.now() - start, err.message || 'Android launch failed');
  }
}

async function androidWaitForReady(manifest: AppManifest): Promise<void> {
  const start = Date.now();
  const timeoutMs = 30000;
  const pollMs = 1000;

  await sleep(3000);

  while (Date.now() - start < timeoutMs) {
    if (_packageName) {
      const pidResult = child_process.spawnSync('adb', ['shell', 'pidof', _packageName]);
      if (pidResult && pidResult.stdout) {
        const pid = pidResult.stdout.replace(/\n/g, '').replace(/\r/g, '');
        if (pid.length > 0) {
          console.log('[androidReady] app running, pid=' + pid);
          setStep('ready', 'passed', Date.now() - start, '');
          return;
        }
      }
    }
    await sleep(pollMs);
  }
  setStep('ready', 'failed', Date.now() - start, 'Android app did not become ready');
}

function androidScreenshot(savePath: string): number {
  try {
    // Capture screenshot from device and pull to local path
    const r = child_process.spawnSync('bash', ['-c', 'adb exec-out screencap -p > ' + savePath]);
    if (r && r.status === 0 && fs.existsSync(savePath)) {
      console.log('[androidScreenshot] saved to ' + savePath);
      return 1;
    }
    console.log('[androidScreenshot] failed, status=' + String(r ? r.status : -1));
    return 0;
  } catch (err: any) {
    console.log('[androidScreenshot] error: ' + (err.message || String(err)));
    return 0;
  }
}

function androidKill(): void {
  if (_packageName) {
    try {
      child_process.spawnSync('adb', ['shell', 'am', 'force-stop', _packageName]);
    } catch (_) {}
  }
}

function androidGetLogs(): string {
  if (!_packageName) return '';
  try {
    const r = child_process.spawnSync('adb', ['logcat', '-d', '-s', _packageName]);
    if (r && r.stdout) {
      return r.stdout;
    }
    return '';
  } catch (_) {
    return '';
  }
}

// --- Shared helpers ---

function sendScreenshot(ws: any, jobId: string, stepName: string, pngPath: string): void {
  try {
    // base64 encode the PNG file — use -w 0 on Linux, no flag needed on macOS
    const p = os.platform();
    let args: string[];
    if (p === 'linux') {
      args = ['-w', '0', pngPath];
    } else {
      args = [pngPath];
    }
    const r = child_process.spawnSync('base64', args);
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

// --- Platform-specific artifact handling ---

function handleArtifactFormat(binPath: string, jobDir: string, target: string): string {
  const isIos = target.indexOf('ios') >= 0 || target.indexOf('ipados') >= 0;
  const isMacos = target.indexOf('macos') >= 0;
  const isAndroid = target.indexOf('android') >= 0;

  if (isMacos || isIos) {
    // Check if it's a tar.gz (compressed .app bundle)
    const fileResult = child_process.spawnSync('file', [binPath]);
    let isArchive = false;
    if (fileResult && fileResult.stdout) {
      const output = fileResult.stdout;
      if (output.indexOf('gzip') >= 0 || output.indexOf('tar') >= 0 || output.indexOf('Zip') >= 0) {
        isArchive = true;
      }
    }

    if (isArchive) {
      console.log('[artifact] extracting archive for ' + target);
      const extractDir = jobDir + '/app';
      try { fs.mkdirSync(extractDir); } catch (e) {}
      child_process.spawnSync('tar', ['-xzf', binPath, '-C', extractDir]);

      // Find the .app directory inside
      const lsResult = child_process.spawnSync('bash', ['-c', 'find ' + extractDir + ' -name "*.app" -type d -maxdepth 3']);
      if (lsResult && lsResult.stdout) {
        const appDirs = lsResult.stdout.replace(/\r/g, '');
        const firstLine = appDirs.indexOf('\n') >= 0 ? appDirs.substring(0, appDirs.indexOf('\n')) : appDirs;
        if (firstLine.length > 0) {
          _appPath = firstLine;
          console.log('[artifact] found .app: ' + _appPath);
          return _appPath;
        }
      }
    }
    _appPath = binPath;
    return binPath;
  }

  if (isAndroid) {
    // Rename to .apk for adb install
    const apkPath = binPath + '.apk';
    child_process.spawnSync('mv', [binPath, apkPath]);
    _appPath = apkPath;
    console.log('[artifact] renamed to APK: ' + apkPath);
    return apkPath;
  }

  // Linux / default — binary is ready as-is
  _appPath = '';
  return binPath;
}

// --- Platform dispatch helpers ---

function platformLaunch(target: string, binPath: string, manifest: AppManifest): Promise<void> {
  const isLinux = target.indexOf('linux') >= 0;
  const isMacos = target.indexOf('macos') >= 0;
  const isIos = target.indexOf('ios') >= 0 || target.indexOf('ipados') >= 0;
  const isAndroid = target.indexOf('android') >= 0;

  if (isLinux) return linuxLaunch(binPath, manifest);
  if (isMacos) return macosLaunch(binPath, manifest);
  if (isIos) return iosLaunch(binPath, manifest);
  if (isAndroid) return androidLaunch(binPath, manifest);
  // Fallback to linux
  return linuxLaunch(binPath);
}

function platformWaitForReady(target: string, manifest: AppManifest): Promise<void> {
  const isLinux = target.indexOf('linux') >= 0;
  const isMacos = target.indexOf('macos') >= 0;
  const isIos = target.indexOf('ios') >= 0 || target.indexOf('ipados') >= 0;
  const isAndroid = target.indexOf('android') >= 0;

  if (isLinux) return linuxWaitForReady(manifest);
  if (isMacos) return macosWaitForReady(manifest);
  if (isIos) return iosWaitForReady(manifest);
  if (isAndroid) return androidWaitForReady(manifest);
  return linuxWaitForReady(manifest);
}

function platformScreenshot(target: string, savePath: string): number {
  const isLinux = target.indexOf('linux') >= 0;
  const isMacos = target.indexOf('macos') >= 0;
  const isIos = target.indexOf('ios') >= 0 || target.indexOf('ipados') >= 0;
  const isAndroid = target.indexOf('android') >= 0;

  if (isLinux) return linuxScreenshot(savePath);
  if (isMacos) return macosScreenshot(savePath);
  if (isIos) return iosScreenshot(savePath);
  if (isAndroid) return androidScreenshot(savePath);
  return linuxScreenshot(savePath);
}

function platformKill(target: string): void {
  const isLinux = target.indexOf('linux') >= 0;
  const isMacos = target.indexOf('macos') >= 0;
  const isIos = target.indexOf('ios') >= 0 || target.indexOf('ipados') >= 0;
  const isAndroid = target.indexOf('android') >= 0;

  if (isLinux) { linuxKill(); return; }
  if (isMacos) { macosKill(); return; }
  if (isIos) { iosKill(); return; }
  if (isAndroid) { androidKill(); return; }
  linuxKill();
}

function platformGetLogs(target: string): string {
  const isLinux = target.indexOf('linux') >= 0;
  const isMacos = target.indexOf('macos') >= 0;
  const isIos = target.indexOf('ios') >= 0 || target.indexOf('ipados') >= 0;
  const isAndroid = target.indexOf('android') >= 0;

  if (isLinux) return linuxGetLogs();
  if (isMacos) return macosGetLogs();
  if (isIos) return iosGetLogs();
  if (isAndroid) return androidGetLogs();
  return linuxGetLogs();
}

// --- Sandbox & cleanup ---

function writeSandboxWrapper(jobDir: string, binaryPath: string, target: string, appType: string): string {
  const scriptPath = jobDir + '/sandbox-run.sh';
  let script = '#!/bin/bash\nset -e\n';
  const isLinux = target.indexOf('linux') >= 0;
  const isMacos = target.indexOf('macos') >= 0;
  const isCli = appType === 'cli';
  const isGui = appType === 'gui' || appType === 'desktop';

  if (isLinux) {
    const relBinPath = binaryPath.substring(jobDir.length);
    if (SANDBOX_ENABLED) {
      script += 'if command -v bwrap &>/dev/null; then\n';
      script += '  exec timeout ' + String(JOB_TIMEOUT_SECONDS) + ' bwrap \\\n';
      script += '    --ro-bind /usr /usr \\\n';
      script += '    --ro-bind /bin /bin \\\n';
      script += '    --ro-bind /sbin /sbin \\\n';
      script += '    --ro-bind /lib /lib \\\n';
      script += '    $([ -d /lib64 ] && echo "--ro-bind /lib64 /lib64") \\\n';
      script += '    --proc /proc \\\n';
      script += '    --dev /dev \\\n';
      script += '    --tmpfs /tmp \\\n';
      if (isGui) {
        script += '    --bind /tmp/.X11-unix /tmp/.X11-unix \\\n';
        script += '    --setenv DISPLAY :99 \\\n';
      }
      script += '    --bind ' + jobDir + ' /workspace \\\n';
      script += '    --chdir /workspace \\\n';
      if (isCli) {
        script += '    --unshare-net \\\n';
      }
      script += '    --unshare-pid \\\n';
      script += '    --unshare-ipc \\\n';
      script += '    --die-with-parent \\\n';
      script += '    --new-session \\\n';
      script += '    -- /workspace' + relBinPath + '\n';
      script += 'else\n';
      script += '  echo "WARNING: bwrap not installed, running without sandbox" >&2\n';
      if (isGui) {
        script += '  export DISPLAY=:99\n';
      }
      script += '  exec timeout ' + String(JOB_TIMEOUT_SECONDS) + ' ' + binaryPath + '\n';
      script += 'fi\n';
    } else {
      if (isGui) {
        script += 'export DISPLAY=:99\n';
      }
      script += 'exec timeout ' + String(JOB_TIMEOUT_SECONDS) + ' ' + binaryPath + '\n';
    }
  } else if (isMacos) {
    if (SANDBOX_ENABLED) {
      const profilePath = jobDir + '/sandbox.sb';
      let profile = '(version 1)\n';
      profile += '(allow default)\n';
      if (isCli) {
        profile += '(deny network*)\n';
      } else {
        profile += '(deny network-outbound)\n';
      }
      fs.writeFileSync(profilePath, profile);

      script += 'MYPID=$$\n';
      script += '(sleep ' + String(JOB_TIMEOUT_SECONDS) + ' && kill -9 $MYPID 2>/dev/null) &\n';
      script += 'exec sandbox-exec -f ' + profilePath + ' ' + binaryPath + '\n';
    } else {
      script += 'MYPID=$$\n';
      script += '(sleep ' + String(JOB_TIMEOUT_SECONDS) + ' && kill -9 $MYPID 2>/dev/null) &\n';
      script += 'exec ' + binaryPath + '\n';
    }
  } else {
    // Windows or unknown — no sandbox, timeout only
    script += 'exec ' + binaryPath + '\n';
  }

  fs.writeFileSync(scriptPath, script);
  child_process.spawnSync('chmod', ['+x', scriptPath]);
  return scriptPath;
}

function cleanupJobDir(dirPath: string): void {
  try {
    child_process.spawnSync('rm', ['-rf', dirPath]);
    console.log('[cleanup] removed ' + dirPath);
  } catch (e) {
    console.log('[cleanup] failed to remove job dir');
  }
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
  _bundleId = '';
  _packageName = '';
  _appPath = '';

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

    // Handle platform-specific artifact formats
    const effectiveBinPath = handleArtifactFormat(binPath, jobDir, target);
    sendLog('Artifact prepared for ' + target);

    const isGui = manifest.appType === 'gui' || manifest.appType === 'desktop';
    let shotCount = 0;

    // Step 1: Launch
    console.log('Launching binary at ' + effectiveBinPath);
    await platformLaunch(target, effectiveBinPath, manifest);
    const launchName = _stepName;
    const launchStatus = _stepStatus;
    const launchDuration = _stepDurationMs;
    const launchError = _stepError;
    console.log('Launch: ' + launchStatus);
    sendStepUpdate(ws, jobId, launchName, launchStatus, launchDuration, launchError);
    if (launchStatus === 'failed') {
      if (isGui) {
        const shotPath = screensDir + '/launch-fail.png';
        if (platformScreenshot(target, shotPath) === 1) {
          sendScreenshot(ws, jobId, 'launch-fail', shotPath);
        }
      }
      sendToClient(ws, buildCompleteJson(jobId, 0, platformGetLogs(target), Date.now() - startTime, 0));
      return;
    }

    // Step 2: Wait for ready
    console.log('Waiting for ready...');
    await platformWaitForReady(target, manifest);
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
      if (platformScreenshot(target, shotPath) === 1) {
        sendScreenshot(ws, jobId, shotLabel, shotPath);
        shotCount = shotCount + 1;
      }
    }

    if (readyStatus === 'failed') {
      sendToClient(ws, buildCompleteJson(jobId, 0, platformGetLogs(target), Date.now() - startTime, 0));
      return;
    }

    // Step 3: Post-ready screenshot for GUI apps (give app a moment to render)
    if (isGui && shotCount === 0) {
      await sleep(1000);
      const shotPath = screensDir + '/post-ready.png';
      if (platformScreenshot(target, shotPath) === 1) {
        sendScreenshot(ws, jobId, 'post-ready', shotPath);
      }
    }

    // All steps passed
    console.log('All steps passed!');
    sendToClient(ws, buildCompleteJson(jobId, 1, platformGetLogs(target), Date.now() - startTime, 0));

  } catch (err: any) {
    const errMsg = err.message || String(err);
    sendLog('Pipeline error: ' + errMsg);
    sendToClient(ws, buildCompleteJson(jobId, 0, platformGetLogs(target) + '\nError: ' + errMsg, Date.now() - startTime, 0));
  } finally {
    platformKill(target);
    cleanupJobDir(jobDir);
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
    const helloMsg = '{"type":"worker_hello","name":"' + WORKER_NAME + '","capabilities":' + capsJson + ',"token":"' + AUTH_TOKEN + '"}';
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
  console.log('sandbox: ' + (SANDBOX_ENABLED ? 'enabled' : 'DISABLED'));
  console.log('auth: ' + (AUTH_TOKEN ? 'configured' : 'NONE (set PERRY_VERIFY_AUTH_TOKEN)'));
  const whoamiResult = child_process.spawnSync('whoami', []);
  if (whoamiResult && whoamiResult.stdout) {
    const user = whoamiResult.stdout.replace(/\n/g, '');
    console.log('user: ' + user);
    if (user === 'root') {
      console.log('WARNING: Running as root is not recommended. Create a dedicated user: useradd -r -s /bin/false perry-verify');
    }
  }

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
