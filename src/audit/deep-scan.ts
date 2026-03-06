// AI deep scan — calls Claude Haiku for advanced security analysis
// Uses module-level globals to avoid returning objects from async (Perry SEGV)

import { AuditFinding, AuditSeverity, AuditConfig, SourceFile } from './types';
import { parseJsonSafe } from '../ai/client';

// Module-level results (Perry: cannot return objects from async functions)
let _deepFindings: AuditFinding[] = [];
let _deepFindingCount = 0;
let _lastAiCostCents = 0;

export function getDeepFindings(): AuditFinding[] { return _deepFindings; }
export function getDeepFindingCount(): number { return _deepFindingCount; }
export function getLastAiCostCents(): number { return _lastAiCostCents; }

// Cost per million tokens (in cents) - Haiku
const HAIKU_INPUT_CPM = 80;
const HAIKU_OUTPUT_CPM = 400;

const SYSTEM_PROMPT = 'You are a security auditor for TypeScript web applications. Analyze the source code for security vulnerabilities that regex-based scanners cannot catch. Focus on:\n\n1. Business logic flaws: auth checks that can be bypassed, IDOR patterns, privilege escalation\n2. Data flow: tracking user input through transformations to dangerous sinks\n3. Auth issues: JWT not verified, sessions not invalidated, missing CSRF protection\n4. API design: mass assignment, excessive data exposure, broken object-level authorization\n5. Context-aware secrets: values that look like real credentials based on surrounding code\n\nReturn a JSON array of findings. Each finding must have these exact fields:\n- id: string (rule identifier like "auth-bypass", "idor", "jwt-unverified")\n- severity: "critical" | "high" | "medium"\n- title: string (short description)\n- file: string (file path)\n- line: number (approximate line number)\n- snippet: string (relevant code snippet, max 100 chars)\n- what: string (what the issue is)\n- risk: string (what could go wrong)\n- fix: string (how to fix it)\n- fixCode: string (example fix code, or empty string)\n\nReturn ONLY the JSON array, no markdown fences, no explanation. If no issues found, return [].';

// Build the source context string for the AI prompt
function buildSourceContext(files: SourceFile[]): string {
  let sourceContext = '';
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    sourceContext = sourceContext + '=== File: ' + file.path + ' ===\n';
    if (file.content.length > 4000) {
      sourceContext = sourceContext + file.content.substring(0, 4000) + '\n[...truncated]\n';
    } else {
      sourceContext = sourceContext + file.content + '\n';
    }
    sourceContext = sourceContext + '\n';
  }
  return sourceContext;
}

// Parse AI response text into findings, storing in module globals
function parseDeepFindings(responseText: string): void {
  _deepFindings = [];
  _deepFindingCount = 0;

  if (!responseText || responseText.length === 0) return;

  const parsed = parseJsonSafe(responseText);
  if (!parsed) return;

  const arr = parsed as any[];
  if (!arr || !arr.length) return;

  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];
    if (!item || !item.id || !item.severity || !item.title) continue;

    const sev = item.severity;
    if (sev !== 'critical' && sev !== 'high' && sev !== 'medium' && sev !== 'low') continue;

    _deepFindings[_deepFindingCount] = {
      id: item.id || 'ai-finding',
      severity: sev as AuditSeverity,
      title: item.title || '',
      file: item.file || 'unknown',
      line: item.line || 0,
      snippet: item.snippet || '',
      what: item.what || '',
      risk: item.risk || '',
      fix: item.fix || '',
      fixCode: item.fixCode || '',
    };
    _deepFindingCount++;
  }
}

// Run deep scan — stores results in module globals, returns null (Perry async safety)
export async function runDeepScan(files: SourceFile[], appType: string): Promise<null> {
  _deepFindings = [];
  _deepFindingCount = 0;
  _lastAiCostCents = 0;

  const apiKey = process.env.ANTHROPIC_API_KEY || '';
  if (!apiKey) {
    return null as any;
  }

  const sourceContext = buildSourceContext(files);
  const userPrompt = 'Analyze this ' + appType + ' application for security vulnerabilities:\n\n' + sourceContext;

  const body = JSON.stringify({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 2048,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: [{ type: 'text', text: userPrompt }] }],
  });

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: body,
    });

    const responseText = await response.text();
    const data = JSON.parse(responseText) as any;

    let text = '';
    if (data.content && data.content.length > 0) {
      const firstBlock = data.content[0];
      if (firstBlock.text) {
        text = firstBlock.text;
      }
    }

    const inputTokens = data.usage ? data.usage.input_tokens : 0;
    const outputTokens = data.usage ? data.usage.output_tokens : 0;
    _lastAiCostCents = (inputTokens * HAIKU_INPUT_CPM + outputTokens * HAIKU_OUTPUT_CPM) / 1000000;

    parseDeepFindings(text);
  } catch (err) {
    console.log('[deep-scan] AI call failed: ' + String(err));
  }

  return null as any;
}
