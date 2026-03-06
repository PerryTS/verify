// HTML report builder for audit results

import { AuditResult, AuditFinding } from './types';

function escapeHtml(s: string): string {
  let result = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (c === '<') result = result + '&lt;';
    else if (c === '>') result = result + '&gt;';
    else if (c === '&') result = result + '&amp;';
    else if (c === '"') result = result + '&quot;';
    else if (c === "'") result = result + '&#39;';
    else result = result + c;
  }
  return result;
}

function severityColor(severity: string): string {
  if (severity === 'critical') return '#dc2626';
  if (severity === 'high') return '#ea580c';
  if (severity === 'medium') return '#ca8a04';
  return '#65a30d';
}

function severityBg(severity: string): string {
  if (severity === 'critical') return '#fef2f2';
  if (severity === 'high') return '#fff7ed';
  if (severity === 'medium') return '#fefce8';
  return '#f7fee7';
}

function gradeColor(grade: string): string {
  if (grade === 'A' || grade === 'A-') return '#16a34a';
  if (grade === 'B') return '#ca8a04';
  if (grade === 'C') return '#ea580c';
  return '#dc2626';
}

function buildFindingHtml(finding: AuditFinding, index: number): string {
  const sColor = severityColor(finding.severity);
  const sBg = severityBg(finding.severity);

  let html = '<div style="border:1px solid #e5e7eb;border-left:4px solid ' + sColor + ';border-radius:8px;padding:16px;margin-bottom:12px;background:' + sBg + '">';
  html = html + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
  html = html + '<span style="font-weight:600;font-size:15px">' + escapeHtml(finding.title) + '</span>';
  html = html + '<span style="background:' + sColor + ';color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;text-transform:uppercase">' + escapeHtml(finding.severity) + '</span>';
  html = html + '</div>';

  html = html + '<div style="font-size:13px;color:#6b7280;margin-bottom:8px">' + escapeHtml(finding.file) + ':' + String(finding.line) + ' &middot; <code style="background:#f3f4f6;padding:1px 4px;border-radius:3px;font-size:12px">' + escapeHtml(finding.id) + '</code></div>';

  if (finding.snippet) {
    html = html + '<pre style="background:#1e293b;color:#e2e8f0;padding:10px 12px;border-radius:6px;font-size:13px;overflow-x:auto;margin:8px 0">' + escapeHtml(finding.snippet) + '</pre>';
  }

  html = html + '<div style="margin:8px 0"><strong>What:</strong> ' + escapeHtml(finding.what) + '</div>';
  html = html + '<div style="margin:8px 0"><strong>Risk:</strong> ' + escapeHtml(finding.risk) + '</div>';
  html = html + '<div style="margin:8px 0"><strong>Fix:</strong> ' + escapeHtml(finding.fix) + '</div>';

  if (finding.fixCode) {
    html = html + '<pre style="background:#f0fdf4;color:#166534;padding:10px 12px;border-radius:6px;font-size:13px;border:1px solid #bbf7d0;overflow-x:auto;margin:8px 0">' + escapeHtml(finding.fixCode) + '</pre>';
  }

  html = html + '</div>';
  return html;
}

export function buildHtmlReport(result: AuditResult): string {
  const gc = gradeColor(result.grade);
  const s = result.summary;

  let html = '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Audit Report</title></head>';
  html = html + '<body style="font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;max-width:800px;margin:0 auto;padding:24px;background:#f9fafb;color:#111827">';

  // Header
  html = html + '<div style="text-align:center;margin-bottom:32px">';
  html = html + '<h1 style="font-size:28px;margin-bottom:8px">Security Audit Report</h1>';
  html = html + '<div style="color:#6b7280;font-size:14px">' + escapeHtml(result.auditId) + ' &middot; ' + escapeHtml(result.createdAt) + '</div>';
  html = html + '</div>';

  // Grade card
  html = html + '<div style="text-align:center;background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,0.1)">';
  html = html + '<div style="font-size:72px;font-weight:700;color:' + gc + ';line-height:1">' + escapeHtml(result.grade) + '</div>';
  html = html + '<div style="font-size:16px;color:#4b5563;margin-top:8px">' + escapeHtml(result.gradeExplanation) + '</div>';
  html = html + '</div>';

  // Summary stats
  html = html + '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px">';

  html = html + '<div style="background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,0.05)">';
  html = html + '<div style="font-size:28px;font-weight:700;color:#dc2626">' + String(s.critical) + '</div>';
  html = html + '<div style="font-size:12px;color:#6b7280;text-transform:uppercase">Critical</div></div>';

  html = html + '<div style="background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,0.05)">';
  html = html + '<div style="font-size:28px;font-weight:700;color:#ea580c">' + String(s.high) + '</div>';
  html = html + '<div style="font-size:12px;color:#6b7280;text-transform:uppercase">High</div></div>';

  html = html + '<div style="background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,0.05)">';
  html = html + '<div style="font-size:28px;font-weight:700;color:#ca8a04">' + String(s.medium) + '</div>';
  html = html + '<div style="font-size:12px;color:#6b7280;text-transform:uppercase">Medium</div></div>';

  html = html + '<div style="background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,0.05)">';
  html = html + '<div style="font-size:28px;font-weight:700;color:#111827">' + String(s.totalFiles) + '</div>';
  html = html + '<div style="font-size:12px;color:#6b7280;text-transform:uppercase">Files</div></div>';

  html = html + '</div>';

  // Duration & cost
  html = html + '<div style="text-align:center;color:#6b7280;font-size:13px;margin-bottom:24px">';
  html = html + 'Scanned in ' + String(s.durationMs) + 'ms';
  if (s.aiCostCents > 0) {
    html = html + ' &middot; AI cost: $' + (s.aiCostCents / 100).toFixed(4);
  }
  html = html + '</div>';

  // Findings
  if (result.findings.length === 0) {
    html = html + '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:24px;text-align:center;color:#166534;font-size:16px">No security issues found. Great job!</div>';
  } else {
    html = html + '<h2 style="font-size:20px;margin-bottom:16px">Findings (' + String(result.findings.length) + ')</h2>';
    for (let i = 0; i < result.findings.length; i++) {
      html = html + buildFindingHtml(result.findings[i], i);
    }
  }

  // Footer
  html = html + '<div style="text-align:center;color:#9ca3af;font-size:12px;margin-top:32px;padding-top:16px;border-top:1px solid #e5e7eb">';
  html = html + 'Perry Audit &middot; Security Scanner for Vibe-Coders';
  html = html + '</div>';

  html = html + '</body></html>';
  return html;
}
