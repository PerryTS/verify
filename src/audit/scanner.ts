// Audit scanner — entry point for running audits

import * as crypto from 'crypto';
import { AuditConfig, AuditResult, SourceFile } from './types';
import { runAllRules } from './rules';
import { isTestFile } from './patterns';

export function parseSourceInput(source: string): SourceFile[] {
  const files: SourceFile[] = [];

  // Try to parse as JSON map {"path": "content", ...}
  const trimmed = source.trim();
  if (trimmed.length > 0 && trimmed[0] === '{') {
    try {
      const parsed = JSON.parse(trimmed);
      const keys = Object.keys(parsed);
      let fileCount = 0;
      for (let i = 0; i < keys.length; i++) {
        const path = keys[i];
        const content = parsed[path];
        if (typeof content === 'string') {
          files[fileCount] = {
            path: path,
            content: content,
            lines: content.split('\n'),
          };
          fileCount++;
        }
      }
      if (fileCount > 0) return files;
    } catch (e) {
      // Not JSON, treat as single file
    }
  }

  // Single file source
  files[0] = {
    path: 'source.ts',
    content: source,
    lines: source.split('\n'),
  };
  return files;
}

export function filterTestFiles(files: SourceFile[]): SourceFile[] {
  const result: SourceFile[] = [];
  let count = 0;
  for (let i = 0; i < files.length; i++) {
    if (!isTestFile(files[i].path)) {
      result[count] = files[i];
      count++;
    }
  }
  return result;
}

export function computeGrade(critical: number, high: number, medium: number): string {
  if (critical > 0) {
    if (critical >= 3) return 'F';
    return high > 0 ? 'D' : 'C';
  }
  if (high > 0) {
    if (high >= 3) return 'C';
    return 'B';
  }
  if (medium > 0) {
    if (medium >= 5) return 'B';
    return 'A-';
  }
  return 'A';
}

export function computeGradeExplanation(grade: string, critical: number, high: number, medium: number): string {
  if (grade === 'A') return 'No security issues found. Your code looks clean.';
  if (grade === 'A-') return String(medium) + ' minor issues found. Good overall security.';
  if (grade === 'B') return String(high) + ' high-severity issues to address before publishing.';
  if (grade === 'C') return String(critical) + ' critical issues. Fix hardcoded secrets before publishing.';
  if (grade === 'D') return String(critical) + ' critical and ' + String(high) + ' high-severity issues. Significant security risks.';
  return String(critical) + ' critical issues found. Do not publish without fixing these.';
}

// Run synchronous regex-based audit. Returns AuditResult (safe: not async).
export function runAudit(source: string, config: AuditConfig): AuditResult {
  const startTime = Date.now();

  let files = parseSourceInput(source);
  files = filterTestFiles(files);

  const findings = runAllRules(files, config);

  // Count by severity
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  for (let i = 0; i < findings.length; i++) {
    const sev = findings[i].severity;
    if (sev === 'critical') critical++;
    else if (sev === 'high') high++;
    else if (sev === 'medium') medium++;
    else low++;
  }

  const durationMs = Date.now() - startTime;
  const auditId = 'a_' + crypto.randomUUID().replace(/-/g, '').substring(0, 12);

  const grade = computeGrade(critical, high, medium);

  const result: AuditResult = {
    auditId: auditId,
    summary: {
      critical: critical,
      high: high,
      medium: medium,
      low: low,
      totalFiles: files.length,
      durationMs: durationMs,
      aiCostCents: 0,
    },
    grade: grade,
    gradeExplanation: computeGradeExplanation(grade, critical, high, medium),
    findings: findings,
    createdAt: new Date().toISOString(),
  };

  return result;
}
