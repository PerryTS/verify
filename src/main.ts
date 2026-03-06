// perry-verify: Verification manager / coordinator
// Receives verify requests via HTTP, dispatches to platform workers via WebSocket

import Fastify from 'fastify';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as child_process from 'child_process';
import * as os from 'os';
import { WebSocketServer, sendToClient, closeClient } from 'ws';
import { VerifyJob, VerifyConfig, AppManifest, TargetPlatform, JobStatusResponse, VerifyStep, Screenshot } from './api/types';
import { storeJob, getJob, updateJob } from './storage/results';
import { jobDir, binaryPath } from './storage/screenshots';
import { AuditConfig, AuditResult } from './audit/types';
import { runAudit, parseSourceInput, filterTestFiles, computeGrade, computeGradeExplanation } from './audit/scanner';
import { runDeepScan, getDeepFindings, getDeepFindingCount, getLastAiCostCents } from './audit/deep-scan';
import { buildHtmlReport } from './audit/report';

// --- Configuration ---

const HTTP_PORT = parseInt(process.env.PERRY_VERIFY_PORT || '7777', 10);
const WS_PORT = parseInt(process.env.PERRY_VERIFY_WS_PORT || '7778', 10);
const TEMP_DIR = process.env.PERRY_VERIFY_TEMP_DIR || '/tmp/perry-verify';

try { fs.mkdirSync(TEMP_DIR); } catch (e) { /* exists */ }

function getPublicUrl(): string {
  return process.env.PERRY_VERIFY_PUBLIC_URL || 'https://verify.perryts.com';
}

// --- Types ---

interface WorkerInfo {
  clientHandle: any;
  capabilities: string[];  // e.g. ['macos-arm64', 'ios-simulator', 'android-emulator']
  name: string;
  busy: boolean;
  currentJobId: string | null;
}

// --- In-memory stores ---

const jobQueue: string[] = [];  // job IDs waiting for dispatch
const workerList: WorkerInfo[] = [];
const counters = { workers: 0, queueLen: 0 };

// --- Audit result store (1hr TTL) ---

const auditResultStore: Record<string, AuditResult> = {};
const auditCreatedAt: Record<string, number> = {};
const auditIds: string[] = [];
let auditIdCount = 0;

function storeAuditResult(result: AuditResult): void {
  auditResultStore[result.auditId] = result;
  auditCreatedAt[result.auditId] = Date.now();
  auditIds[auditIdCount] = result.auditId;
  auditIdCount++;
}

function getAuditResult(auditId: string): AuditResult | null {
  return auditResultStore[auditId] || null;
}

function evictOldAudits(): void {
  const now = Date.now();
  const oneHourMs = 60 * 60 * 1000;
  let writeIdx = 0;
  for (let i = 0; i < auditIdCount; i++) {
    const id = auditIds[i];
    const ts = auditCreatedAt[id];
    if (ts && now - ts > oneHourMs) {
      delete auditResultStore[id];
      delete auditCreatedAt[id];
    } else {
      auditIds[writeIdx] = id;
      writeIdx++;
    }
  }
  auditIdCount = writeIdx;
}

setInterval(evictOldAudits, 5 * 60 * 1000);

// Client tracking maps (keyed by 'h'+handle to avoid NaN issues)
const clientIdentified = new Map<string, boolean>();
const clientRole = new Map<string, string>();
const clientWorkerIdx = new Map<string, number>();

function handleKey(handle: any): string {
  return 'h' + String(handle);
}

function registerClient(handle: any): void {
  clientIdentified.set(handleKey(handle), false);
}

function isClientIdentified(handle: any): boolean {
  return clientIdentified.get(handleKey(handle)) || false;
}

function setClientIdentified(handle: any): void {
  clientIdentified.set(handleKey(handle), true);
}

function setClientRole(handle: any, role: string): void {
  clientRole.set(handleKey(handle), role);
}

function getClientRole(handle: any): string {
  return clientRole.get(handleKey(handle)) || '';
}

function setClientWorkerIdx(handle: any, idx: number): void {
  clientWorkerIdx.set(handleKey(handle), idx);
}

function getClientWorkerIdx(handle: any): number {
  const v = clientWorkerIdx.get(handleKey(handle));
  if (v === undefined) return -1;
  return v;
}

function removeClient(handle: any): void {
  const key = handleKey(handle);
  clientIdentified.delete(key);
  clientRole.delete(key);
  clientWorkerIdx.delete(key);
}

// --- Worker pool ---

function targetToCapability(target: string): string {
  // Map target platform to a capability string workers register
  if (target === 'macos-arm64' || target === 'macos-x64') return 'macos';
  if (target === 'linux-x64' || target === 'linux-arm64') return 'linux';
  if (target === 'windows-x64') return 'windows';
  if (target === 'ios-simulator' || target === 'ipados-simulator') return 'ios-simulator';
  if (target === 'android-emulator' || target === 'android-tablet-emulator') return 'android-emulator';
  return target;
}

function getAvailableWorker(target: string): WorkerInfo | null {
  const needed = targetToCapability(target);
  for (let wi = 0; wi < counters.workers; wi++) {
    const worker = workerList[wi];
    if (!worker.busy) {
      for (let ci = 0; ci < worker.capabilities.length; ci++) {
        if (worker.capabilities[ci] === needed) {
          return worker;
        }
      }
    }
  }
  return null;
}

function dispatchJob(job: VerifyJob): boolean {
  const worker = getAvailableWorker(job.target);
  if (!worker) return false;

  worker.busy = true;
  worker.currentJobId = job.id;
  job.status = 'running';
  updateJob(job);

  try {
    sendToClient(worker.clientHandle, JSON.stringify({
      type: 'job_assign',
      job_id: job.id,
      config: job.config,
      manifest: job.manifest,
      target: job.target,
      binary_url: getPublicUrl() + '/internal/binary/' + job.id,
    }));
  } catch (e) {
    worker.busy = false;
    worker.currentJobId = null;
    job.status = 'pending';
    updateJob(job);
    return false;
  }

  console.log('Dispatched job ' + job.id + ' to worker ' + worker.name);
  return true;
}

function tryDispatchNext(): void {
  while (counters.queueLen > 0) {
    const jobId = jobQueue.shift()!;
    counters.queueLen--;
    const job = getJob(jobId);
    if (job && job.status === 'pending') {
      if (!dispatchJob(job)) {
        // Re-enqueue if no worker available
        jobQueue.unshift(jobId);
        counters.queueLen++;
        return;
      }
    }
  }
}

function enqueueJob(jobId: string): void {
  jobQueue.push(jobId);
  counters.queueLen++;
  tryDispatchNext();
}

// --- Multipart parser ---

interface MultipartPart {
  name: string;
  filename?: string;
  content_type?: string;
  data: string;
  size: number;
}

function parseMultipart(body: string, contentType: string): MultipartPart[] {
  const boundaryMatch = contentType.match(/boundary=([^\s;]+)/);
  if (!boundaryMatch) return [];
  const boundary = boundaryMatch[1].replace(/^"(.*)"$/, '$1');

  const delimiter = '--' + boundary;
  const parts: MultipartPart[] = [];
  const segments = body.split(delimiter);

  for (let i = 1; i < segments.length; i++) {
    const segment = segments[i];
    if (segment.startsWith('--')) break;

    const headerEnd = segment.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;

    const headerSection = segment.substring(0, headerEnd);
    let data = segment.substring(headerEnd + 4);

    if (data.endsWith('\r\n')) {
      data = data.substring(0, data.length - 2);
    }

    let name: string | null = null;
    let filename: string | undefined;
    let partContentType: string | undefined;

    const lines = headerSection.split('\r\n');
    for (let li = 0; li < lines.length; li++) {
      const line = lines[li];
      const trimmed = line.trim();
      if (!trimmed) continue;

      const lower = trimmed.toLowerCase();
      if (lower.startsWith('content-disposition:')) {
        const dispValue = trimmed.substring('content-disposition:'.length).trim();
        const nameMatch = dispValue.match(/name="([^"]+)"/);
        if (nameMatch) name = nameMatch[1];
        const fileMatch = dispValue.match(/filename="([^"]+)"/);
        if (fileMatch) filename = fileMatch[1];
      } else if (lower.startsWith('content-type:')) {
        partContentType = trimmed.substring('content-type:'.length).trim();
      }
    }

    if (name) {
      parts.push({ name, filename, content_type: partContentType, data, size: data.length });
    }
  }

  return parts;
}

// --- Host platform detection ---

function hostPlatform(): string {
  const p = os.platform();
  const a = os.arch();
  if (p === 'darwin') return a === 'arm64' ? 'macos-arm64' : 'macos-x64';
  if (p === 'linux') return a === 'arm64' ? 'linux-arm64' : 'linux-x64';
  if (p === 'win32') return 'windows-x64';
  return p + '-' + a;
}

// --- Worker message handler ---

function handleScreenshotMessage(clientHandle: any, dataStr: string): void {
  // Format: SCREENSHOT:<jobId>:<step>:<base64data>
  // Find the colons to split
  const firstColon = dataStr.indexOf(':', 11); // after "SCREENSHOT:"
  if (firstColon < 0) return;
  const secondColon = dataStr.indexOf(':', firstColon + 1);
  if (secondColon < 0) return;

  const shotJobId = dataStr.substring(11, firstColon);
  const shotStep = dataStr.substring(firstColon + 1, secondColon);
  const b64Data = dataStr.substring(secondColon + 1);

  console.log('[screenshot] job=' + shotJobId + ' step=' + shotStep + ' b64len=' + String(b64Data.length));

  const job = getJob(shotJobId);
  if (!job) {
    console.log('[screenshot] job not found: ' + shotJobId);
    return;
  }

  const shotDir = jobDir(shotJobId) + '/screenshots';
  const shotPath = shotDir + '/' + shotStep + '.png';
  try { fs.mkdirSync(shotDir); } catch (e) { /* exists */ }

  // Save both base64 and decoded PNG
  const b64Path = shotPath + '.b64';
  fs.writeFileSync(b64Path, b64Data);
  try {
    child_process.execSync('base64 -d ' + b64Path + ' > ' + shotPath);
  } catch (decErr: any) {
    console.log('[screenshot] decode error: ' + (decErr.message || String(decErr)));
  }
  const exists = fs.existsSync(shotPath);
  console.log('[screenshot] saved ' + shotStep + ' exists=' + String(exists));
  const screenshot: Screenshot = { step: shotStep, path: shotPath, timestamp: new Date().toISOString() };
  job.screenshots.push(screenshot);
  updateJob(job);
}

function handleWorkerMessage(msg: any, worker: WorkerInfo): void {
  const msgType = msg.type;
  const jobId = msg.job_id || worker.currentJobId;
  console.log('[ws-msg] type=' + msgType + ' job=' + jobId);
  if (!jobId) return;

  const job = getJob(jobId);
  if (!job) return;

  if (msgType === 'step_update') {
    const step: VerifyStep = {
      name: msg.step.name || '',
      status: msg.step.status || 'failed',
      method: msg.step.method || 'deterministic',
      durationMs: msg.step.durationMs || 0,
      error: msg.step.error,
      aiCostCents: msg.step.aiCostCents,
      screenshotPath: msg.step.screenshotPath,
    };
    job.steps.push(step);
    updateJob(job);
  } else if (msgType === 'job_complete') {
    job.status = msg.success ? 'passed' : 'failed';
    job.logs = msg.logs || '';
    job.durationMs = msg.durationMs || 0;
    job.costCents = msg.costCents || 0;
    job.completedAt = new Date().toISOString();
    updateJob(job);

    worker.busy = false;
    worker.currentJobId = null;
    console.log('Job ' + jobId + ' completed: ' + job.status);
    tryDispatchNext();
  } else if (msgType === 'log') {
    job.logs = job.logs + (msg.text || '') + '\n';
    updateJob(job);
  }
}

// --- Fastify HTTP server ---

const app = Fastify({ bodyLimit: 500 * 1024 * 1024 });

// POST /verify — submit a verification job
app.post('/verify', async (request: any, reply: any) => {
  reply.header('Content-Type', 'application/json');
  console.log('[POST /verify] received request');

  const hdrs = request.headers;
  const contentType = hdrs['content-type'] || '';
  if (!contentType.includes('multipart/form-data')) {
    reply.status(400);
    return JSON.stringify({ error: 'Expected multipart/form-data' });
  }

  const rawBody = request.text;
  let parts: MultipartPart[];
  try {
    parts = parseMultipart(rawBody, contentType);
  } catch (e: any) {
    reply.status(400);
    return JSON.stringify({ error: 'Failed to parse multipart body: ' + (e.message || e) });
  }

  let configPart: MultipartPart | null = null;
  let manifestPart: MultipartPart | null = null;
  let targetPart: MultipartPart | null = null;
  let binaryB64Part: MultipartPart | null = null;
  for (let pi = 0; pi < parts.length; pi++) {
    const p = parts[pi];
    if (p.name === 'config') configPart = p;
    else if (p.name === 'manifest') manifestPart = p;
    else if (p.name === 'target') targetPart = p;
    else if (p.name === 'binary_b64') binaryB64Part = p;
  }

  if (!configPart) { reply.status(400); return JSON.stringify({ error: "Missing 'config' field" }); }
  if (!manifestPart) { reply.status(400); return JSON.stringify({ error: "Missing 'manifest' field" }); }
  if (!targetPart) { reply.status(400); return JSON.stringify({ error: "Missing 'target' field" }); }
  if (!binaryB64Part) { reply.status(400); return JSON.stringify({ error: "Missing 'binary_b64' field" }); }

  let config: VerifyConfig;
  let manifest: AppManifest;
  try {
    config = JSON.parse(configPart.data);
    manifest = JSON.parse(manifestPart.data);
  } catch (_) {
    reply.status(400);
    return JSON.stringify({ error: 'Invalid JSON in config or manifest' });
  }

  const target = targetPart.data.trim() as TargetPlatform;
  const jobId = 'v_' + crypto.randomUUID().replace(/-/g, '').substring(0, 8);
  const dir = jobDir(jobId);

  try { fs.mkdirSync(dir); } catch (e) { /* exists */ }
  try { fs.mkdirSync(dir + '/screenshots'); } catch (e) { /* exists */ }

  // Save base64 binary — worker will download via HTTP
  const binPath = binaryPath(jobId);
  const b64Path = binPath + '.b64';
  fs.writeFileSync(b64Path, binaryB64Part.data);

  const now = new Date().toISOString();
  const job: VerifyJob = {
    id: jobId,
    status: 'pending',
    target,
    config,
    manifest,
    binaryPath: b64Path,
    jobDir: dir,
    steps: [],
    screenshots: [],
    logs: '',
    durationMs: 0,
    costCents: 0,
    createdAt: now,
    completedAt: null,
  };

  storeJob(job);
  enqueueJob(jobId);

  reply.status(202);
  return '{"jobId":"' + jobId + '","status":"pending"}';
});

// GET /verify/:jobId — get job status
app.get('/verify/:jobId', async (request: any, reply: any) => {
  reply.header('Content-Type', 'application/json');
  const jobId = request.params.jobId;
  const job = getJob(jobId);
  if (!job) {
    reply.status(404);
    return JSON.stringify({ error: 'Job not found' });
  }

  const screenshotUrls: string[] = [];
  for (let i = 0; i < job.screenshots.length; i++) {
    const shot = job.screenshots[i];
    const filename = shot.path.split('/').pop() || shot.path;
    screenshotUrls[i] = '/verify/' + jobId + '/screenshots/' + filename;
  }

  // Build steps JSON array manually (JSON.stringify crashes on complex objects)
  let stepsJson = '[';
  for (let si = 0; si < job.steps.length; si++) {
    if (si > 0) stepsJson = stepsJson + ',';
    const s = job.steps[si];
    stepsJson = stepsJson + '{"name":"' + (s.name || '') + '","status":"' + s.status + '","method":"' + s.method + '","durationMs":' + String(s.durationMs);
    if (s.error) stepsJson = stepsJson + ',"error":"' + s.error.replace(/"/g, '\\"') + '"';
    if (s.aiCostCents) stepsJson = stepsJson + ',"aiCostCents":' + String(s.aiCostCents);
    stepsJson = stepsJson + '}';
  }
  stepsJson = stepsJson + ']';

  let shotsJson = '[';
  for (let si = 0; si < screenshotUrls.length; si++) {
    if (si > 0) shotsJson = shotsJson + ',';
    shotsJson = shotsJson + '"' + screenshotUrls[si] + '"';
  }
  shotsJson = shotsJson + ']';

  const completedAtJson = job.completedAt ? '"' + job.completedAt + '"' : 'null';
  return '{"jobId":"' + job.id + '","status":"' + job.status + '","steps":' + stepsJson + ',"screenshots":' + shotsJson + ',"logs":' + JSON.stringify(job.logs) + ',"durationMs":' + String(job.durationMs) + ',"costCents":' + String(job.costCents) + ',"createdAt":"' + job.createdAt + '","completedAt":' + completedAtJson + '}';
});

// GET /verify/:jobId/screenshots/:filename — serve screenshot PNG
app.get('/verify/:jobId/screenshots/:filename', async (request: any, reply: any) => {
  const jobId = request.params.jobId;
  const filename = request.params.filename;
  const job = getJob(jobId);
  if (!job) {
    reply.status(404);
    reply.header('Content-Type', 'application/json');
    return JSON.stringify({ error: 'Job not found' });
  }

  const filePath = jobDir(jobId) + '/screenshots/' + filename;
  if (!fs.existsSync(filePath)) {
    reply.status(404);
    reply.header('Content-Type', 'application/json');
    return JSON.stringify({ error: 'Screenshot not found' });
  }

  // Wrap PNG in HTML page with embedded base64 data URI for browser viewing
  const b64Path = filePath + '.b64';
  if (fs.existsSync(b64Path)) {
    const b64Data = fs.readFileSync(b64Path);
    if (b64Data) {
      reply.header('Content-Type', 'text/html');
      return '<html><body style="margin:0;background:#111"><img src="data:image/png;base64,' + b64Data + '" style="max-width:100%;height:auto"></body></html>';
    }
  }
  reply.status(404);
  reply.header('Content-Type', 'application/json');
  return JSON.stringify({ error: 'Screenshot not available' });
});

// GET /internal/binary/:jobId — workers download base64 binary
app.get('/internal/binary/:jobId', async (request: any, reply: any) => {
  const jobId = request.params.jobId;
  const job = getJob(jobId);
  if (!job) {
    reply.status(404);
    reply.header('Content-Type', 'application/json');
    return JSON.stringify({ error: 'Job not found' });
  }

  try {
    const data = fs.readFileSync(job.binaryPath);
    reply.header('Content-Type', 'text/plain');
    return data;
  } catch (e: any) {
    reply.status(500);
    reply.header('Content-Type', 'application/json');
    return JSON.stringify({ error: 'Binary not found' });
  }
});

// GET /health
app.get('/health', async (_request: any, reply: any) => {
  reply.header('Content-Type', 'application/json');
  return '{"status":"ok","platform":"' + hostPlatform() + '","version":"0.1.0","workers":' + String(counters.workers) + ',"queueLength":' + String(counters.queueLen) + '}';
});

// --- Audit routes ---

// POST /audit — run security scan on source code
app.post('/audit', async (request: any, reply: any) => {
  reply.header('Content-Type', 'application/json');
  console.log('[POST /audit] received request');

  const hdrs = request.headers;
  const contentType = hdrs['content-type'] || '';
  if (!contentType.includes('multipart/form-data')) {
    reply.status(400);
    return '{"error":"Expected multipart/form-data"}';
  }

  const rawBody = request.text;
  let parts: MultipartPart[];
  try {
    parts = parseMultipart(rawBody, contentType);
  } catch (e: any) {
    reply.status(400);
    return '{"error":"Failed to parse multipart body"}';
  }

  let sourcePart: MultipartPart | null = null;
  let configPart: MultipartPart | null = null;
  for (let pi = 0; pi < parts.length; pi++) {
    const p = parts[pi];
    if (p.name === 'source') sourcePart = p;
    else if (p.name === 'config') configPart = p;
  }

  if (!sourcePart) {
    reply.status(400);
    return '{"error":"Missing source field"}';
  }

  // Parse config with defaults
  let appType = 'server';
  let severity = 'all';
  let ignoreList: string[] = [];
  let deepScan = false;

  if (configPart) {
    try {
      const cfg = JSON.parse(configPart.data);
      if (cfg.appType) appType = cfg.appType;
      if (cfg.severity) severity = cfg.severity;
      if (cfg.ignore) {
        const arr = cfg.ignore;
        for (let i = 0; i < arr.length; i++) {
          ignoreList[i] = arr[i];
        }
      }
      if (cfg.deepScan === true) deepScan = true;
    } catch (e) {
      // Use defaults
    }
  }

  const auditConfig: AuditConfig = {
    appType: appType,
    severity: severity,
    ignore: ignoreList,
    deepScan: deepScan,
  };

  // Run synchronous regex scan
  const result = runAudit(sourcePart.data, auditConfig);

  // Deep scan: call AI, then merge findings from module globals
  if (deepScan) {
    const files = filterTestFiles(parseSourceInput(sourcePart.data));
    await runDeepScan(files, appType);
    const aiFindings = getDeepFindings();
    const aiCount = getDeepFindingCount();
    let totalFindings = result.findings.length;
    for (let i = 0; i < aiCount; i++) {
      result.findings[totalFindings] = aiFindings[i];
      totalFindings++;
    }
    result.summary.aiCostCents = getLastAiCostCents();
    // Recount severities
    let cr = 0;
    let hi = 0;
    let me = 0;
    let lo = 0;
    for (let i = 0; i < result.findings.length; i++) {
      const sev = result.findings[i].severity;
      if (sev === 'critical') cr++;
      else if (sev === 'high') hi++;
      else if (sev === 'medium') me++;
      else lo++;
    }
    result.summary.critical = cr;
    result.summary.high = hi;
    result.summary.medium = me;
    result.summary.low = lo;
    result.summary.durationMs = Date.now() - (new Date(result.createdAt).getTime());
    result.grade = computeGrade(cr, hi, me);
    result.gradeExplanation = computeGradeExplanation(result.grade, cr, hi, me);
  }

  storeAuditResult(result);

  // Build JSON response manually (avoid JSON.stringify crash on complex objects)
  let findingsJson = '[';
  for (let i = 0; i < result.findings.length; i++) {
    if (i > 0) findingsJson = findingsJson + ',';
    const f = result.findings[i];
    findingsJson = findingsJson + '{"id":"' + f.id + '"';
    findingsJson = findingsJson + ',"severity":"' + f.severity + '"';
    findingsJson = findingsJson + ',"title":"' + escapeJsonStr(f.title) + '"';
    findingsJson = findingsJson + ',"file":"' + escapeJsonStr(f.file) + '"';
    findingsJson = findingsJson + ',"line":' + String(f.line);
    findingsJson = findingsJson + ',"snippet":"' + escapeJsonStr(f.snippet) + '"';
    findingsJson = findingsJson + ',"what":"' + escapeJsonStr(f.what) + '"';
    findingsJson = findingsJson + ',"risk":"' + escapeJsonStr(f.risk) + '"';
    findingsJson = findingsJson + ',"fix":"' + escapeJsonStr(f.fix) + '"';
    findingsJson = findingsJson + ',"fixCode":"' + escapeJsonStr(f.fixCode) + '"';
    findingsJson = findingsJson + '}';
  }
  findingsJson = findingsJson + ']';

  const s = result.summary;
  let json = '{"auditId":"' + result.auditId + '"';
  json = json + ',"summary":{"critical":' + String(s.critical) + ',"high":' + String(s.high) + ',"medium":' + String(s.medium) + ',"low":' + String(s.low) + ',"totalFiles":' + String(s.totalFiles) + ',"durationMs":' + String(s.durationMs) + ',"aiCostCents":' + String(s.aiCostCents) + '}';
  json = json + ',"grade":"' + result.grade + '"';
  json = json + ',"gradeExplanation":"' + escapeJsonStr(result.gradeExplanation) + '"';
  json = json + ',"findings":' + findingsJson;
  json = json + '}';

  return json;
});

// GET /audit/:auditId — retrieve previous audit result
app.get('/audit/:auditId', async (request: any, reply: any) => {
  reply.header('Content-Type', 'application/json');
  const auditId = request.params.auditId;
  const result = getAuditResult(auditId);
  if (!result) {
    reply.status(404);
    return '{"error":"Audit not found"}';
  }

  // Build same JSON as POST /audit response
  let findingsJson = '[';
  for (let i = 0; i < result.findings.length; i++) {
    if (i > 0) findingsJson = findingsJson + ',';
    const f = result.findings[i];
    findingsJson = findingsJson + '{"id":"' + f.id + '"';
    findingsJson = findingsJson + ',"severity":"' + f.severity + '"';
    findingsJson = findingsJson + ',"title":"' + escapeJsonStr(f.title) + '"';
    findingsJson = findingsJson + ',"file":"' + escapeJsonStr(f.file) + '"';
    findingsJson = findingsJson + ',"line":' + String(f.line);
    findingsJson = findingsJson + ',"snippet":"' + escapeJsonStr(f.snippet) + '"';
    findingsJson = findingsJson + ',"what":"' + escapeJsonStr(f.what) + '"';
    findingsJson = findingsJson + ',"risk":"' + escapeJsonStr(f.risk) + '"';
    findingsJson = findingsJson + ',"fix":"' + escapeJsonStr(f.fix) + '"';
    findingsJson = findingsJson + ',"fixCode":"' + escapeJsonStr(f.fixCode) + '"';
    findingsJson = findingsJson + '}';
  }
  findingsJson = findingsJson + ']';

  const s = result.summary;
  let json = '{"auditId":"' + result.auditId + '"';
  json = json + ',"summary":{"critical":' + String(s.critical) + ',"high":' + String(s.high) + ',"medium":' + String(s.medium) + ',"low":' + String(s.low) + ',"totalFiles":' + String(s.totalFiles) + ',"durationMs":' + String(s.durationMs) + ',"aiCostCents":' + String(s.aiCostCents) + '}';
  json = json + ',"grade":"' + result.grade + '"';
  json = json + ',"gradeExplanation":"' + escapeJsonStr(result.gradeExplanation) + '"';
  json = json + ',"findings":' + findingsJson;
  json = json + '}';

  return json;
});

// GET /audit/:auditId/html — HTML report
app.get('/audit/:auditId/html', async (request: any, reply: any) => {
  const auditId = request.params.auditId;
  const result = getAuditResult(auditId);
  if (!result) {
    reply.status(404);
    reply.header('Content-Type', 'application/json');
    return '{"error":"Audit not found"}';
  }

  reply.header('Content-Type', 'text/html');
  return buildHtmlReport(result);
});

// --- Helper: escape string for manual JSON building ---

function escapeJsonStr(s: string): string {
  let result = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (c === '"') result = result + '\\"';
    else if (c === '\\') result = result + '\\\\';
    else if (c === '\n') result = result + '\\n';
    else if (c === '\r') result = result + '\\r';
    else if (c === '\t') result = result + '\\t';
    else result = result + c;
  }
  return result;
}

// --- WebSocket server for workers ---

const wss = new WebSocketServer({ port: WS_PORT });

wss.on('connection', (clientHandle: any) => {
  registerClient(clientHandle);
});

wss.on('message', (clientHandle: any, data: any) => {
  const dataStr = String(data);

  // Handle screenshot data (non-JSON format to avoid large-string parsing issues)
  if (dataStr.substring(0, 11) === 'SCREENSHOT:') {
    handleScreenshotMessage(clientHandle, dataStr);
    return;
  }

  let msg: any;
  try {
    msg = JSON.parse(dataStr);
  } catch (e: any) {
    return;
  }

  if (!isClientIdentified(clientHandle)) {
    setClientIdentified(clientHandle);

    if (msg.type === 'worker_hello') {
      setClientRole(clientHandle, 'worker');
      const workerInfo: WorkerInfo = {
        clientHandle,
        capabilities: msg.capabilities || [],
        name: msg.name || 'worker-' + String(counters.workers + 1),
        busy: false,
        currentJobId: null,
      };
      workerList[counters.workers] = workerInfo;
      setClientWorkerIdx(clientHandle, counters.workers);
      counters.workers++;
      console.log('Worker connected: ' + workerInfo.name + ' capabilities=[' + workerInfo.capabilities.join(',') + ']');
      tryDispatchNext();
      return;
    }

    // Unknown first message
    closeClient(clientHandle);
    return;
  }

  const role = getClientRole(clientHandle);
  if (role === 'worker') {
    const wIdx = getClientWorkerIdx(clientHandle);
    if (wIdx >= 0 && wIdx < counters.workers) {
      handleWorkerMessage(msg, workerList[wIdx]);
    }
  }
});

wss.on('close', (clientHandle: any) => {
  const role = getClientRole(clientHandle);
  if (role === 'worker') {
    const wIdx = getClientWorkerIdx(clientHandle);
    if (wIdx >= 0 && wIdx < counters.workers) {
      const workerInfo = workerList[wIdx];
      console.log('Worker disconnected: ' + workerInfo.name);

      // If worker was running a job, mark it as error
      if (workerInfo.busy && workerInfo.currentJobId) {
        const job = getJob(workerInfo.currentJobId);
        if (job && job.status === 'running') {
          job.status = 'error';
          job.logs = job.logs + '\nWorker disconnected during verification';
          job.completedAt = new Date().toISOString();
          updateJob(job);
        }
      }

      // Remove worker — shift down (avoid splice)
      counters.workers--;
      for (let wi = wIdx; wi < counters.workers; wi++) {
        workerList[wi] = workerList[wi + 1];
        setClientWorkerIdx(workerList[wi].clientHandle, wi);
      }
    }
  }
  removeClient(clientHandle);
});

wss.on('error', (err: any) => {
  console.error('WebSocket server error:', err);
});

// --- Event loop heartbeat (needed for WS event dispatch) ---
setInterval(() => {
  // Process any pending WebSocket events
}, 500);

// --- Start servers ---

wss.on('listening', () => {
  console.log('perry-verify WebSocket server listening on port ' + String(WS_PORT));
});

app.listen({ port: HTTP_PORT, host: '0.0.0.0' }, (err: any, address: string) => {
  if (err) {
    console.error('Failed to start perry-verify:', err);
    process.exit(1);
  }
  console.log('perry-verify HTTP server listening at ' + address);
  console.log('platform: ' + hostPlatform());
  console.log('temp dir: ' + TEMP_DIR);
});
