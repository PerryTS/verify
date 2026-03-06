// Audit rules — all security rule functions

import {
  AuditFinding, AuditSeverity, AuditConfig, SourceFile,
} from './types';
import {
  SECRET_PATTERNS, SECRET_VAR_NAMES, PLACEHOLDER_VALUES,
  UNSAFE_EXEC_PATTERNS, SQL_QUERY_METHODS,
  SENSITIVE_ROUTES, WEAK_HASH_PATTERNS, MATH_RANDOM_SECRET,
  shannonEntropy, isCommentLine, isPlaceholder, isProcessEnvRef,
  getLineNumber, getLineAt, truncateSnippet,
} from './patterns';

// --- Tier 1: Critical ---

export function checkHardcodedSecrets(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // Check known secret patterns
  for (let pi = 0; pi < SECRET_PATTERNS.length; pi++) {
    const pattern = SECRET_PATTERNS[pi][0];
    const desc = SECRET_PATTERNS[pi][1];
    const regex = new RegExp(pattern, 'g');
    let match = regex.exec(content);
    while (match !== null) {
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText) && !isPlaceholder(match[0])) {
        findings[findCount] = {
          id: 'hardcoded-secret',
          severity: 'critical' as AuditSeverity,
          title: 'Hardcoded ' + desc,
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(lineText, 120),
          what: 'A ' + desc + ' is embedded in your source code.',
          risk: 'Anyone who sees your code can use this credential.',
          fix: 'Use an environment variable instead.',
          fixCode: 'process.env.YOUR_SECRET_NAME',
        };
        findCount++;
      }
      match = regex.exec(content);
    }
  }

  // Check variable assignments with secret-like names + high-entropy values
  for (let vi = 0; vi < SECRET_VAR_NAMES.length; vi++) {
    const varName = SECRET_VAR_NAMES[vi];
    // Match: const/let/var secretName = 'value' or "value"
    const pat = new RegExp('(?:const|let|var)\\s+\\w*' + varName + '\\w*\\s*=\\s*["\']([^"\']{8,})["\']', 'gi');
    let match = pat.exec(content);
    while (match !== null) {
      const value = match[1];
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText) && !isPlaceholder(value) && !isProcessEnvRef(lineText)) {
        const entropy = shannonEntropy(value);
        if (entropy > 4.0) {
          findings[findCount] = {
            id: 'hardcoded-secret',
            severity: 'critical' as AuditSeverity,
            title: 'Hardcoded secret in variable',
            file: file.path,
            line: lineNum,
            snippet: truncateSnippet(lineText, 120),
            what: 'A high-entropy string is assigned to a secret-named variable.',
            risk: 'This looks like a real credential embedded in source code.',
            fix: 'Use an environment variable: process.env.' + varName.toUpperCase(),
            fixCode: 'const ' + varName + ' = process.env.' + varName.toUpperCase() + ' || \'\'',
          };
          findCount++;
        }
      }
      match = pat.exec(content);
    }
  }

  return findings;
}

export function checkUnsafeExecution(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // Check eval, new Function, etc.
  for (let pi = 0; pi < UNSAFE_EXEC_PATTERNS.length; pi++) {
    const pattern = UNSAFE_EXEC_PATTERNS[pi];
    const regex = new RegExp(pattern, 'g');
    let match = regex.exec(content);
    while (match !== null) {
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText)) {
        findings[findCount] = {
          id: 'unsafe-exec',
          severity: 'critical' as AuditSeverity,
          title: 'Unsafe code execution',
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(lineText, 120),
          what: 'Dynamic code execution detected.',
          risk: 'If user input reaches this, attackers can run arbitrary code.',
          fix: 'Avoid eval/new Function. Use safer alternatives like JSON.parse for data.',
          fixCode: '',
        };
        findCount++;
      }
      match = regex.exec(content);
    }
  }

  // Check execSync/exec with string interpolation from potential user input
  const execInterp = new RegExp('(?:execSync|exec|spawnSync)\\s*\\(\\s*`[^`]*\\$\\{', 'g');
  let execMatch = execInterp.exec(content);
  while (execMatch !== null) {
    const lineNum = getLineNumber(content, execMatch.index);
    const lineText = getLineAt(lines, lineNum);

    if (!isCommentLine(lineText)) {
      findings[findCount] = {
        id: 'unsafe-exec',
        severity: 'critical' as AuditSeverity,
        title: 'Command injection risk',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(lineText, 120),
        what: 'Shell command built with string interpolation.',
        risk: 'If user input is interpolated, attackers can inject shell commands.',
        fix: 'Use spawnSync with an args array instead of shell string interpolation.',
        fixCode: 'child_process.spawnSync(cmd, [arg1, arg2])',
      };
      findCount++;
    }
    execMatch = execInterp.exec(content);
  }

  // Check dynamic require/import
  const dynReq = new RegExp('(?:require|import)\\s*\\(\\s*(?![\'"]).', 'g');
  let dynMatch = dynReq.exec(content);
  while (dynMatch !== null) {
    const lineNum = getLineNumber(content, dynMatch.index);
    const lineText = getLineAt(lines, lineNum);

    if (!isCommentLine(lineText)) {
      findings[findCount] = {
        id: 'unsafe-exec',
        severity: 'critical' as AuditSeverity,
        title: 'Dynamic module loading',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(lineText, 120),
        what: 'Module loaded with a dynamic (non-literal) path.',
        risk: 'If user input controls the path, attackers can load arbitrary modules.',
        fix: 'Use static import paths.',
        fixCode: '',
      };
      findCount++;
    }
    dynMatch = dynReq.exec(content);
  }

  return findings;
}

export function checkSqlInjection(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // Check .query/.execute with template literals
  for (let mi = 0; mi < SQL_QUERY_METHODS.length; mi++) {
    const method = SQL_QUERY_METHODS[mi];
    // Template literal: .query(`...${...}...`)
    const tplPat = new RegExp('\\' + method + '\\s*\\(\\s*`[^`]*\\$\\{', 'g');
    let match = tplPat.exec(content);
    while (match !== null) {
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText)) {
        findings[findCount] = {
          id: 'sql-injection',
          severity: 'critical' as AuditSeverity,
          title: 'SQL injection risk',
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(lineText, 120),
          what: 'SQL query built with template literal interpolation.',
          risk: 'User input in the query can modify SQL logic, exposing or deleting data.',
          fix: 'Use parameterized queries with placeholders.',
          fixCode: 'db.query(\'SELECT * FROM users WHERE id = $1\', [userId])',
        };
        findCount++;
      }
      match = tplPat.exec(content);
    }

    // String concatenation: .query('...' + variable)
    const concatPat = new RegExp('\\' + method + '\\s*\\(\\s*["\'][^"\']*["\']\\s*\\+', 'g');
    let concatMatch = concatPat.exec(content);
    while (concatMatch !== null) {
      const lineNum = getLineNumber(content, concatMatch.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText)) {
        findings[findCount] = {
          id: 'sql-injection',
          severity: 'critical' as AuditSeverity,
          title: 'SQL injection risk',
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(lineText, 120),
          what: 'SQL query built with string concatenation.',
          risk: 'User input concatenated into SQL can modify query logic.',
          fix: 'Use parameterized queries with placeholders.',
          fixCode: 'db.query(\'SELECT * FROM users WHERE id = $1\', [userId])',
        };
        findCount++;
      }
      concatMatch = concatPat.exec(content);
    }
  }

  return findings;
}

// --- Tier 2: High (server apps) ---

export function checkUnprotectedRoutes(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  for (let ri = 0; ri < SENSITIVE_ROUTES.length; ri++) {
    const route = SENSITIVE_ROUTES[ri];
    // Match: .get('/admin' or .post('/admin' etc.
    const pat = new RegExp('\\.(get|post|put|delete|patch)\\s*\\(\\s*["\']' + escapeRegex(route) + '["\'/]', 'g');
    let match = pat.exec(content);
    while (match !== null) {
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText)) {
        // Check if there's auth middleware nearby (within 5 lines above or in same line)
        let hasAuth = false;
        const startLine = lineNum > 5 ? lineNum - 5 : 1;
        for (let li = startLine; li <= lineNum; li++) {
          const checkLine = getLineAt(lines, li);
          if (checkLine.indexOf('preHandler') >= 0 ||
              checkLine.indexOf('auth') >= 0 ||
              checkLine.indexOf('authenticate') >= 0 ||
              checkLine.indexOf('middleware') >= 0 ||
              checkLine.indexOf('requireAuth') >= 0 ||
              checkLine.indexOf('isAdmin') >= 0 ||
              checkLine.indexOf('verifyToken') >= 0) {
            hasAuth = true;
            break;
          }
        }

        if (!hasAuth) {
          findings[findCount] = {
            id: 'unprotected-routes',
            severity: 'high' as AuditSeverity,
            title: 'Unprotected sensitive route: ' + route,
            file: file.path,
            line: lineNum,
            snippet: truncateSnippet(lineText, 120),
            what: 'The route ' + route + ' appears to lack authentication.',
            risk: 'Unauthenticated users may access admin or sensitive functionality.',
            fix: 'Add authentication middleware (preHandler) to this route.',
            fixCode: '{ preHandler: [authenticateUser] }',
          };
          findCount++;
        }
      }
      match = pat.exec(content);
    }
  }

  return findings;
}

export function checkMissingSecurityHeaders(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // Check CORS wildcard
  const corsStar = new RegExp('cors\\s*\\(\\s*\\{[^}]*origin\\s*:\\s*["\']\\*["\']', 'g');
  let corsMatch = corsStar.exec(content);
  while (corsMatch !== null) {
    const lineNum = getLineNumber(content, corsMatch.index);
    const lineText = getLineAt(lines, lineNum);

    if (!isCommentLine(lineText)) {
      findings[findCount] = {
        id: 'missing-security',
        severity: 'high' as AuditSeverity,
        title: 'CORS allows all origins',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(lineText, 120),
        what: 'CORS is configured to allow requests from any origin.',
        risk: 'Any website can make authenticated requests to your API.',
        fix: 'Restrict CORS to specific trusted origins.',
        fixCode: 'origin: [\'https://yourdomain.com\']',
      };
      findCount++;
    }
    corsMatch = corsStar.exec(content);
  }

  // Also check Access-Control-Allow-Origin: *
  const acoStar = new RegExp('Access-Control-Allow-Origin["\']\\s*,\\s*["\']\\*["\']', 'g');
  let acoMatch = acoStar.exec(content);
  while (acoMatch !== null) {
    const lineNum = getLineNumber(content, acoMatch.index);
    const lineText = getLineAt(lines, lineNum);

    if (!isCommentLine(lineText)) {
      findings[findCount] = {
        id: 'missing-security',
        severity: 'high' as AuditSeverity,
        title: 'CORS allows all origins',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(lineText, 120),
        what: 'Access-Control-Allow-Origin is set to wildcard.',
        risk: 'Any website can make requests to your API.',
        fix: 'Restrict to specific trusted origins.',
        fixCode: 'reply.header(\'Access-Control-Allow-Origin\', \'https://yourdomain.com\')',
      };
      findCount++;
    }
    acoMatch = acoStar.exec(content);
  }

  return findings;
}

export function checkInsecureCrypto(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // Weak hash functions
  for (let wi = 0; wi < WEAK_HASH_PATTERNS.length; wi++) {
    const pattern = WEAK_HASH_PATTERNS[wi];
    const regex = new RegExp(pattern, 'g');
    let match = regex.exec(content);
    while (match !== null) {
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText)) {
        // Check if used for password hashing (look for 'password' nearby)
        let isPasswordRelated = false;
        const startLine = lineNum > 3 ? lineNum - 3 : 1;
        const endLine = lineNum + 3 < lines.length ? lineNum + 3 : lines.length;
        for (let li = startLine; li <= endLine; li++) {
          const checkLine = getLineAt(lines, li).toLowerCase();
          if (checkLine.indexOf('password') >= 0 || checkLine.indexOf('passwd') >= 0) {
            isPasswordRelated = true;
            break;
          }
        }

        findings[findCount] = {
          id: 'insecure-crypto',
          severity: 'high' as AuditSeverity,
          title: isPasswordRelated ? 'Weak hash for passwords' : 'Weak hash algorithm',
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(lineText, 120),
          what: isPasswordRelated ? 'MD5/SHA1 used for password hashing.' : 'MD5/SHA1 hash detected.',
          risk: isPasswordRelated ? 'MD5/SHA1 are broken for passwords. Attackers can crack them easily.' : 'MD5/SHA1 are cryptographically weak.',
          fix: isPasswordRelated ? 'Use bcrypt or argon2 for password hashing.' : 'Use SHA-256 or SHA-512.',
          fixCode: isPasswordRelated ? 'import bcrypt from \'bcrypt\'; bcrypt.hash(password, 10)' : 'crypto.createHash(\'sha256\')',
        };
        findCount++;
      }
      match = regex.exec(content);
    }
  }

  // Math.random for secrets/tokens
  for (let mi = 0; mi < MATH_RANDOM_SECRET.length; mi++) {
    const pattern = MATH_RANDOM_SECRET[mi];
    const regex = new RegExp(pattern, 'g');
    let match = regex.exec(content);
    while (match !== null) {
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);
      const lower = lineText.toLowerCase();

      if (!isCommentLine(lineText)) {
        // Only flag if used for token/secret/id generation
        if (lower.indexOf('token') >= 0 || lower.indexOf('secret') >= 0 ||
            lower.indexOf('key') >= 0 || lower.indexOf('session') >= 0 ||
            lower.indexOf('nonce') >= 0 || lower.indexOf('salt') >= 0) {
          findings[findCount] = {
            id: 'insecure-crypto',
            severity: 'high' as AuditSeverity,
            title: 'Math.random() used for security',
            file: file.path,
            line: lineNum,
            snippet: truncateSnippet(lineText, 120),
            what: 'Math.random() is not cryptographically secure.',
            risk: 'Tokens generated with Math.random() are predictable.',
            fix: 'Use crypto.randomUUID() or crypto.randomBytes().',
            fixCode: 'crypto.randomUUID()',
          };
          findCount++;
        }
      }
      match = regex.exec(content);
    }
  }

  return findings;
}

// --- Tier 3: Medium ---

export function checkPathTraversal(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // fs operations with potential user input (template literal or concat)
  const fsOps = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync',
    'readdir', 'readdirSync', 'unlink', 'unlinkSync', 'stat', 'statSync'];

  for (let fi = 0; fi < fsOps.length; fi++) {
    const op = fsOps[fi];
    // Template literal: fs.readFile(`...${...}`)
    const tplPat = new RegExp(op + '\\s*\\(\\s*`[^`]*\\$\\{', 'g');
    let match = tplPat.exec(content);
    while (match !== null) {
      const lineNum = getLineNumber(content, match.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText)) {
        // Check for path validation nearby
        let hasValidation = false;
        const startLine = lineNum > 5 ? lineNum - 5 : 1;
        for (let li = startLine; li <= lineNum; li++) {
          const checkLine = getLineAt(lines, li);
          if (checkLine.indexOf('path.resolve') >= 0 ||
              checkLine.indexOf('path.normalize') >= 0 ||
              checkLine.indexOf('startsWith') >= 0 ||
              checkLine.indexOf('sanitize') >= 0 ||
              checkLine.indexOf('..') >= 0) {
            hasValidation = true;
            break;
          }
        }

        if (!hasValidation) {
          findings[findCount] = {
            id: 'path-traversal',
            severity: 'medium' as AuditSeverity,
            title: 'Path traversal risk in ' + op,
            file: file.path,
            line: lineNum,
            snippet: truncateSnippet(lineText, 120),
            what: 'File system operation uses dynamic path without validation.',
            risk: 'User input like "../../../etc/passwd" can access arbitrary files.',
            fix: 'Validate and normalize the path. Ensure it stays within expected directory.',
            fixCode: 'const safePath = path.resolve(baseDir, userInput); if (!safePath.startsWith(baseDir)) throw new Error(\'invalid path\');',
          };
          findCount++;
        }
      }
      match = tplPat.exec(content);
    }

    // Concatenation: fs.readFile(dir + userInput)
    const concatPat = new RegExp(op + '\\s*\\([^)]*\\+', 'g');
    let concatMatch = concatPat.exec(content);
    while (concatMatch !== null) {
      const lineNum = getLineNumber(content, concatMatch.index);
      const lineText = getLineAt(lines, lineNum);

      if (!isCommentLine(lineText)) {
        let hasValidation = false;
        const startLine = lineNum > 5 ? lineNum - 5 : 1;
        for (let li = startLine; li <= lineNum; li++) {
          const checkLine = getLineAt(lines, li);
          if (checkLine.indexOf('path.resolve') >= 0 ||
              checkLine.indexOf('path.normalize') >= 0 ||
              checkLine.indexOf('startsWith') >= 0 ||
              checkLine.indexOf('sanitize') >= 0) {
            hasValidation = true;
            break;
          }
        }

        if (!hasValidation) {
          findings[findCount] = {
            id: 'path-traversal',
            severity: 'medium' as AuditSeverity,
            title: 'Path traversal risk in ' + op,
            file: file.path,
            line: lineNum,
            snippet: truncateSnippet(lineText, 120),
            what: 'File system operation uses concatenated path.',
            risk: 'If user input is part of the path, directory traversal is possible.',
            fix: 'Use path.resolve() and validate the result stays within the base directory.',
            fixCode: 'const safePath = path.resolve(baseDir, userInput); if (!safePath.startsWith(baseDir)) throw new Error(\'invalid path\');',
          };
          findCount++;
        }
      }
      concatMatch = concatPat.exec(content);
    }
  }

  return findings;
}

export function checkInformationDisclosure(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // console.log of secrets
  const consoleSecretPat = new RegExp('console\\.log\\s*\\([^)]*(?:password|secret|token|apiKey|api_key|private_key)[^)]*\\)', 'gi');
  let csMatch = consoleSecretPat.exec(content);
  while (csMatch !== null) {
    const lineNum = getLineNumber(content, csMatch.index);
    const lineText = getLineAt(lines, lineNum);

    if (!isCommentLine(lineText)) {
      findings[findCount] = {
        id: 'info-disclosure',
        severity: 'medium' as AuditSeverity,
        title: 'Sensitive data logged',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(lineText, 120),
        what: 'Sensitive data (password/secret/token) is being logged.',
        risk: 'Secrets in logs can be accessed by anyone with log access.',
        fix: 'Remove console.log of sensitive values, or mask them.',
        fixCode: 'console.log(\'auth: [REDACTED]\')',
      };
      findCount++;
    }
    csMatch = consoleSecretPat.exec(content);
  }

  // Stack traces in error responses
  const stackPat = new RegExp('(?:return|send|reply)\\s*[^;]*(?:err\\.stack|error\\.stack|e\\.stack)', 'g');
  let stackMatch = stackPat.exec(content);
  while (stackMatch !== null) {
    const lineNum = getLineNumber(content, stackMatch.index);
    const lineText = getLineAt(lines, lineNum);

    if (!isCommentLine(lineText)) {
      findings[findCount] = {
        id: 'info-disclosure',
        severity: 'medium' as AuditSeverity,
        title: 'Stack trace in response',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(lineText, 120),
        what: 'Error stack trace may be sent to the client.',
        risk: 'Stack traces reveal internal paths and code structure to attackers.',
        fix: 'Return a generic error message to clients. Log details server-side.',
        fixCode: 'return \'{"error":"Internal server error"}\'',
      };
      findCount++;
    }
    stackMatch = stackPat.exec(content);
  }

  return findings;
}

export function checkInsecurePermissions(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const content = file.content;
  const lines = file.lines;

  // chmod 777 or 0o777
  const chmodPat = new RegExp('chmod(?:Sync)?\\s*\\([^)]*(?:0?o?777|0777|["\']777["\'])', 'g');
  let match = chmodPat.exec(content);
  while (match !== null) {
    const lineNum = getLineNumber(content, match.index);
    const lineText = getLineAt(lines, lineNum);

    if (!isCommentLine(lineText)) {
      findings[findCount] = {
        id: 'insecure-perms',
        severity: 'medium' as AuditSeverity,
        title: 'World-writable file permissions',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(lineText, 120),
        what: 'File permissions set to 777 (world-readable, writable, executable).',
        risk: 'Any user on the system can read, modify, or execute this file.',
        fix: 'Use restrictive permissions like 0o755 (dirs) or 0o644 (files).',
        fixCode: 'fs.chmodSync(path, 0o644)',
      };
      findCount++;
    }
    match = chmodPat.exec(content);
  }

  return findings;
}

// --- Orchestrator ---

export function runAllRules(files: SourceFile[], config: AuditConfig): AuditFinding[] {
  const allFindings: AuditFinding[] = [];
  let totalCount = 0;

  const ignoredRules = config.ignore;
  const severityFilter = config.severity || 'all';
  const isServer = config.appType === 'server';

  for (let fi = 0; fi < files.length; fi++) {
    const file = files[fi];

    // Tier 1 — Critical (always run)
    if (!isIgnored('hardcoded-secret', ignoredRules)) {
      const secrets = checkHardcodedSecrets(file);
      for (let i = 0; i < secrets.length; i++) {
        allFindings[totalCount] = secrets[i];
        totalCount++;
      }
    }

    if (!isIgnored('unsafe-exec', ignoredRules)) {
      const execs = checkUnsafeExecution(file);
      for (let i = 0; i < execs.length; i++) {
        allFindings[totalCount] = execs[i];
        totalCount++;
      }
    }

    if (!isIgnored('sql-injection', ignoredRules)) {
      const sqli = checkSqlInjection(file);
      for (let i = 0; i < sqli.length; i++) {
        allFindings[totalCount] = sqli[i];
        totalCount++;
      }
    }

    // Tier 2 — High (server apps only, unless severity=all)
    if (isServer || severityFilter === 'all') {
      if (!isIgnored('unprotected-routes', ignoredRules)) {
        const routes = checkUnprotectedRoutes(file);
        for (let i = 0; i < routes.length; i++) {
          allFindings[totalCount] = routes[i];
          totalCount++;
        }
      }

      if (!isIgnored('missing-security', ignoredRules)) {
        const headers = checkMissingSecurityHeaders(file);
        for (let i = 0; i < headers.length; i++) {
          allFindings[totalCount] = headers[i];
          totalCount++;
        }
      }

      if (!isIgnored('insecure-crypto', ignoredRules)) {
        const crypto = checkInsecureCrypto(file);
        for (let i = 0; i < crypto.length; i++) {
          allFindings[totalCount] = crypto[i];
          totalCount++;
        }
      }
    }

    // Tier 3 — Medium (always run unless filtered)
    if (severityFilter === 'all' || severityFilter === 'high') {
      if (!isIgnored('path-traversal', ignoredRules)) {
        const paths = checkPathTraversal(file);
        for (let i = 0; i < paths.length; i++) {
          allFindings[totalCount] = paths[i];
          totalCount++;
        }
      }

      if (!isIgnored('info-disclosure', ignoredRules)) {
        const info = checkInformationDisclosure(file);
        for (let i = 0; i < info.length; i++) {
          allFindings[totalCount] = info[i];
          totalCount++;
        }
      }

      if (!isIgnored('insecure-perms', ignoredRules)) {
        const perms = checkInsecurePermissions(file);
        for (let i = 0; i < perms.length; i++) {
          allFindings[totalCount] = perms[i];
          totalCount++;
        }
      }
    }
  }

  // Filter by severity if needed
  if (severityFilter === 'critical') {
    return filterBySeverity(allFindings, 'critical');
  }
  if (severityFilter === 'high') {
    return filterBySeverityMinimum(allFindings, 'high');
  }

  return allFindings;
}

function isIgnored(ruleId: string, ignoreList: string[]): boolean {
  for (let i = 0; i < ignoreList.length; i++) {
    if (ignoreList[i] === ruleId) return true;
  }
  return false;
}

function filterBySeverity(findings: AuditFinding[], severity: string): AuditFinding[] {
  const result: AuditFinding[] = [];
  let count = 0;
  for (let i = 0; i < findings.length; i++) {
    if (findings[i].severity === severity) {
      result[count] = findings[i];
      count++;
    }
  }
  return result;
}

function filterBySeverityMinimum(findings: AuditFinding[], minSeverity: string): AuditFinding[] {
  const result: AuditFinding[] = [];
  let count = 0;
  for (let i = 0; i < findings.length; i++) {
    const sev = findings[i].severity;
    if (minSeverity === 'high') {
      if (sev === 'critical' || sev === 'high') {
        result[count] = findings[i];
        count++;
      }
    } else if (minSeverity === 'critical') {
      if (sev === 'critical') {
        result[count] = findings[i];
        count++;
      }
    } else {
      result[count] = findings[i];
      count++;
    }
  }
  return result;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
