import * as fs from 'fs';
import * as crypto from 'crypto';
import * as child_process from 'child_process';
import { VerifyJob, VerifyConfig, AppManifest, TargetPlatform, JobStatusResponse } from './types';
import { storeJob, getJob, updateJob } from '../storage/results';
import { jobDir, binaryPath, screenshotPath } from '../storage/screenshots';
import { executePipeline } from '../executor/pipeline';
import { createAdapter, hostPlatform } from '../executor/launcher';

// --- Multipart parser (pure TypeScript, matches perry-hub pattern) ---

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

// ---

export function registerRoutes(app: any): void {
  // POST /verify — submit a verification job
  app.post('/verify', async (request: any, reply: any) => {
    reply.header('Content-Type', 'application/json');

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

    // Extract fields using index loop (not .find()) per Perry quirks
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

    // Create job directories
    try { fs.mkdirSync(dir); } catch (e) { /* exists */ }
    try { fs.mkdirSync(dir + '/screenshots'); } catch (e) { /* exists */ }

    // Decode base64 binary and write to disk
    const binPath = binaryPath(jobId);
    const b64Path = binPath + '.b64';
    fs.writeFileSync(b64Path, binaryB64Part.data);
    try {
      child_process.execSync('base64 -d < ' + b64Path + ' > ' + binPath);
      fs.unlinkSync(b64Path);
    } catch (e: any) {
      reply.status(400);
      return JSON.stringify({ error: 'Failed to decode binary: ' + (e.message || e) });
    }

    // If tar.gz, extract
    if (binaryB64Part.filename && binaryB64Part.filename.endsWith('.tar.gz')) {
      try {
        child_process.execSync('tar -xzf ' + binPath + ' -C ' + dir);
      } catch (_) {}
    }

    const now = new Date().toISOString();
    const job: VerifyJob = {
      id: jobId,
      status: 'pending',
      target,
      config,
      manifest,
      binaryPath: binPath,
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

    // Fire-and-forget pipeline
    const adapter = createAdapter(job);
    executePipeline(job, adapter).catch((err: any) => {
      job.status = 'error';
      job.logs = job.logs + '\nUnhandled error: ' + (err.message || String(err));
      job.completedAt = new Date().toISOString();
      updateJob(job);
    });

    reply.status(202);
    return JSON.stringify({ jobId, status: 'pending' });
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

    const response: JobStatusResponse = {
      jobId: job.id,
      status: job.status,
      steps: job.steps,
      screenshots: screenshotUrls,
      logs: job.logs,
      durationMs: job.durationMs,
      costCents: job.costCents,
      createdAt: job.createdAt,
      completedAt: job.completedAt,
    };
    return JSON.stringify(response);
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

    const data = fs.readFileSync(filePath);
    reply.header('Content-Type', 'image/png');
    return data;
  });

  // GET /health
  app.get('/health', async (_request: any, reply: any) => {
    reply.header('Content-Type', 'application/json');
    let geisterhandAvailable = false;
    try {
      const r = child_process.spawnSync('which', ['geisterhand']);
      if (r) {
        geisterhandAvailable = r.status === 0;
      }
    } catch (_) {}

    return JSON.stringify({
      status: 'ok',
      platform: hostPlatform(),
      geisterhand: geisterhandAvailable,
      version: '0.1.0',
    });
  });
}
