// Audit types — all shared types for the security scanner

export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface AuditConfig {
  appType: string;       // 'server' | 'gui' | 'cli'
  severity: string;      // 'all' | 'critical' | 'high'
  ignore: string[];      // rule IDs to suppress
  deepScan: boolean;     // enable AI-powered analysis
}

export interface AuditFinding {
  id: string;
  severity: AuditSeverity;
  title: string;
  file: string;
  line: number;
  snippet: string;
  what: string;
  risk: string;
  fix: string;
  fixCode: string;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  totalFiles: number;
  durationMs: number;
  aiCostCents: number;
}

export interface AuditResult {
  auditId: string;
  summary: AuditSummary;
  grade: string;
  gradeExplanation: string;
  findings: AuditFinding[];
  createdAt: string;
}

export interface SourceFile {
  path: string;
  content: string;
  lines: string[];
}
