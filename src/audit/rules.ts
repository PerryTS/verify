// Audit rules — all security rule functions
// Uses ONLY indexOf() for pattern matching (Perry doesn't support new RegExp())

import {
  AuditFinding, AuditSeverity, AuditConfig, SourceFile,
} from './types';
import {
  shannonEntropy, isCommentLine, isPlaceholder, isProcessEnvRef,
  getLineAt, truncateSnippet,
} from './patterns';

// --- Tier 1: Critical ---

// Secret prefix patterns: [prefix, description]
const SECRET_PREFIXES: string[][] = [
  ['sk_live_', 'Stripe secret key'],
  ['sk_test_', 'Stripe test key'],
  ['pk_live_', 'Stripe publishable key'],
  ['AKIA', 'AWS access key'],
  ['ghp_', 'GitHub personal access token'],
  ['gho_', 'GitHub OAuth token'],
  ['ghs_', 'GitHub app token'],
  ['github_pat_', 'GitHub fine-grained token'],
  ['glpat-', 'GitLab personal access token'],
  ['xoxb-', 'Slack bot token'],
  ['xoxp-', 'Slack user token'],
  ['xapp-', 'Slack app token'],
  ['-----BEGIN PRIVATE KEY-----', 'Private key'],
  ['-----BEGIN RSA PRIVATE KEY-----', 'RSA private key'],
  ['-----BEGIN EC PRIVATE KEY-----', 'EC private key'],
  ['-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH private key'],
];

// DB connection string patterns
const DB_PREFIXES: string[] = [
  'mysql://', 'postgres://', 'postgresql://', 'mongodb://', 'redis://',
];

// Secret variable name fragments
const SECRET_VAR_FRAGMENTS: string[] = [
  'api_key', 'apikey', 'api_secret', 'apisecret',
  'secret_key', 'secretkey', 'private_key', 'privatekey',
  'access_token', 'accesstoken', 'auth_token', 'authtoken',
  'client_secret', 'clientsecret', 'password', 'passwd',
  'db_password', 'database_password', 'connection_string',
  'encryption_key', 'signing_key', 'master_key',
];

// Placeholder values to skip
const SKIP_VALUES: string[] = [
  'your-key-here', 'your_key_here', 'your-api-key',
  'replace_me', 'todo', 'xxx', 'changeme', 'placeholder',
  'example', 'test', 'dummy', 'fake', 'sample',
  'insert-key-here', 'your-secret-here',
];

function isSkipValue(value: string): boolean {
  const lower = value.toLowerCase();
  for (let i = 0; i < SKIP_VALUES.length; i++) {
    if (lower.indexOf(SKIP_VALUES[i]) >= 0) return true;
  }
  return false;
}

// Extract string value from assignment line: const x = 'value' or "value"
function extractAssignedString(line: string): string {
  // Find = followed by quote
  const eqIdx = line.indexOf('=');
  if (eqIdx < 0) return '';
  const afterEq = line.substring(eqIdx + 1).trim();
  if (afterEq.length < 3) return '';
  const quote = afterEq.charAt(0);
  if (quote !== '\'' && quote !== '"') return '';
  const endQuote = afterEq.indexOf(quote, 1);
  if (endQuote < 0) return '';
  return afterEq.substring(1, endQuote);
}

export function checkHardcodedSecrets(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;

    // Check secret prefixes
    for (let pi = 0; pi < SECRET_PREFIXES.length; pi++) {
      const prefix = SECRET_PREFIXES[pi][0];
      const desc = SECRET_PREFIXES[pi][1];

      if (line.indexOf(prefix) >= 0) {
        findings[findCount] = {
          id: 'hardcoded-secret',
          severity: 'critical' as AuditSeverity,
          title: 'Hardcoded ' + desc,
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(line, 120),
          what: 'A ' + desc + ' is embedded in your source code.',
          risk: 'Anyone who sees your code can use this credential.',
          fix: 'Use an environment variable instead.',
          fixCode: 'process.env.YOUR_SECRET_NAME',
        };
        findCount++;
        break; // one finding per line for prefixes
      }
    }

    // Check DB connection strings with passwords (contains :// and @ with password)
    for (let di = 0; di < DB_PREFIXES.length; di++) {
      const dbPfx = DB_PREFIXES[di];
      const dbIdx = line.indexOf(dbPfx);
      if (dbIdx >= 0) {
        const afterProto = line.substring(dbIdx + dbPfx.length);
        // Look for user:pass@host pattern
        if (afterProto.indexOf(':') >= 0 && afterProto.indexOf('@') >= 0) {
          const colonIdx = afterProto.indexOf(':');
          const atIdx = afterProto.indexOf('@');
          if (colonIdx < atIdx) {
            // There's a password between : and @
            findings[findCount] = {
              id: 'hardcoded-secret',
              severity: 'critical' as AuditSeverity,
              title: 'Database connection string with password',
              file: file.path,
              line: lineNum,
              snippet: truncateSnippet(line, 120),
              what: 'A database connection string with embedded password found.',
              risk: 'Anyone who sees your code can access your database.',
              fix: 'Use environment variables for database credentials.',
              fixCode: 'process.env.DATABASE_URL',
            };
            findCount++;
            break;
          }
        }
      }
    }

    // Check secret-named variable assignments with high-entropy values
    if (isProcessEnvRef(line)) continue;
    if (line.indexOf('=') < 0) continue;

    const lineLower = line.toLowerCase();
    for (let vi = 0; vi < SECRET_VAR_FRAGMENTS.length; vi++) {
      const varFrag = SECRET_VAR_FRAGMENTS[vi];
      // Check if the variable name part (before =) contains the fragment
      const eqIdx = line.indexOf('=');
      if (eqIdx < 0) continue;
      const beforeEq = lineLower.substring(0, eqIdx);
      if (beforeEq.indexOf(varFrag) < 0) continue;

      // Must be an assignment (const/let/var)
      if (lineLower.indexOf('const ') < 0 && lineLower.indexOf('let ') < 0 && lineLower.indexOf('var ') < 0) continue;

      const value = extractAssignedString(line);
      if (value.length < 8) continue;
      if (isSkipValue(value)) continue;

      const entropy = shannonEntropy(value);
      if (entropy > 4.0) {
        findings[findCount] = {
          id: 'hardcoded-secret',
          severity: 'critical' as AuditSeverity,
          title: 'Hardcoded secret in variable',
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(line, 120),
          what: 'A high-entropy string assigned to a secret-named variable.',
          risk: 'This looks like a real credential embedded in source code.',
          fix: 'Use an environment variable instead.',
          fixCode: 'process.env.' + varFrag.toUpperCase(),
        };
        findCount++;
        break; // one finding per line
      }
    }
  }

  return findings;
}

export function checkUnsafeExecution(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;
    const trimmed = line.trim();

    if (isCommentLine(line)) continue;

    // eval()
    if (line.indexOf('eval(') >= 0 || line.indexOf('eval (') >= 0) {
      findings[findCount] = {
        id: 'unsafe-exec',
        severity: 'critical' as AuditSeverity,
        title: 'Unsafe eval() call',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(line, 120),
        what: 'eval() executes arbitrary code.',
        risk: 'If user input reaches eval, attackers can run arbitrary code.',
        fix: 'Avoid eval. Use JSON.parse for data, or safer alternatives.',
        fixCode: '',
      };
      findCount++;
    }

    // new Function()
    if (line.indexOf('new Function(') >= 0 || line.indexOf('new Function (') >= 0) {
      findings[findCount] = {
        id: 'unsafe-exec',
        severity: 'critical' as AuditSeverity,
        title: 'Unsafe new Function() call',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(line, 120),
        what: 'new Function() creates code from strings.',
        risk: 'If user input reaches this, attackers can run arbitrary code.',
        fix: 'Avoid new Function. Use safer alternatives.',
        fixCode: '',
      };
      findCount++;
    }

    // execSync/exec with template literal interpolation
    if ((line.indexOf('execSync') >= 0 || line.indexOf('exec(') >= 0 || line.indexOf('spawnSync') >= 0) &&
        line.indexOf('`') >= 0 && line.indexOf('${') >= 0) {
      findings[findCount] = {
        id: 'unsafe-exec',
        severity: 'critical' as AuditSeverity,
        title: 'Command injection risk',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(line, 120),
        what: 'Shell command built with string interpolation.',
        risk: 'If user input is interpolated, attackers can inject shell commands.',
        fix: 'Use spawnSync with an args array instead.',
        fixCode: 'child_process.spawnSync(cmd, [arg1, arg2])',
      };
      findCount++;
    }
  }

  return findings;
}

function hasSqlKeyword(line: string): boolean {
  const upper = line.toUpperCase();
  if (upper.indexOf('SELECT') >= 0) return true;
  if (upper.indexOf('INSERT') >= 0) return true;
  if (upper.indexOf('UPDATE') >= 0) return true;
  if (upper.indexOf('DELETE FROM') >= 0) return true;
  if (upper.indexOf('DROP') >= 0) return true;
  if (upper.indexOf('ALTER') >= 0) return true;
  if (upper.indexOf('WHERE') >= 0) return true;
  return false;
}

export function checkSqlInjection(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;

    // Must have a SQL query method
    let methodIdx = -1;
    let methodLen = 0;

    if (line.indexOf('.query(') >= 0) {
      methodIdx = line.indexOf('.query(');
      methodLen = 7;
    } else if (line.indexOf('.execute(') >= 0) {
      methodIdx = line.indexOf('.execute(');
      methodLen = 9;
    }

    if (methodIdx < 0) continue;

    const afterMethod = line.substring(methodIdx + methodLen);

    // Must have string concatenation or interpolation
    let hasConcat = false;
    if (afterMethod.indexOf('`') >= 0 && afterMethod.indexOf('${') >= 0) hasConcat = true;
    if (afterMethod.indexOf('+') >= 0) hasConcat = true;

    if (!hasConcat) continue;

    // Must have SQL keywords somewhere on the line
    if (!hasSqlKeyword(line)) continue;

    findings[findCount] = {
      id: 'sql-injection',
      severity: 'critical' as AuditSeverity,
      title: 'SQL injection risk',
      file: file.path,
      line: lineNum,
      snippet: truncateSnippet(line, 120),
      what: 'SQL query built with string concatenation or interpolation.',
      risk: 'User input in the query can modify SQL logic, exposing or deleting data.',
      fix: 'Use parameterized queries with placeholders.',
      fixCode: 'db.query(\'SELECT * FROM users WHERE id = $1\', [userId])',
    };
    findCount++;
  }

  return findings;
}

// --- Tier 2: High (server apps) ---

function isSensitiveRoute(line: string): string {
  // Return the matched route name, or empty string if none
  if (line.indexOf('/admin') >= 0) return '/admin';
  if (line.indexOf('/delete') >= 0) return '/delete';
  if (line.indexOf('/internal') >= 0) return '/internal';
  if (line.indexOf('/debug') >= 0) return '/debug';
  if (line.indexOf('/management') >= 0) return '/management';
  if (line.indexOf('/dashboard') >= 0) return '/dashboard';
  if (line.indexOf('/config') >= 0) return '/config';
  if (line.indexOf('/settings') >= 0) return '/settings';
  return '';
}

function isRouteDef(line: string): boolean {
  if (line.indexOf('.get(') >= 0) return true;
  if (line.indexOf('.post(') >= 0) return true;
  if (line.indexOf('.put(') >= 0) return true;
  if (line.indexOf('.delete(') >= 0) return true;
  if (line.indexOf('.patch(') >= 0) return true;
  return false;
}

export function checkUnprotectedRoutes(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;
    if (!isRouteDef(line)) continue;

    const route = isSensitiveRoute(line);
    if (route.length === 0) continue;

    // Check if there's auth middleware nearby (within 5 lines above or same line)
    let hasAuth = false;
    const startLine = lineNum > 5 ? lineNum - 5 : 1;
    for (let li = startLine; li <= lineNum; li++) {
      const checkLine = getLineAt(lines, li);
      if (checkLine.indexOf('preHandler') >= 0 ||
          checkLine.indexOf('authenticate') >= 0 ||
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
        snippet: truncateSnippet(line, 120),
        what: 'The route ' + route + ' appears to lack authentication.',
        risk: 'Unauthenticated users may access admin or sensitive functionality.',
        fix: 'Add authentication middleware (preHandler) to this route.',
        fixCode: '{ preHandler: [authenticateUser] }',
      };
      findCount++;
    }
  }

  return findings;
}

export function checkMissingSecurityHeaders(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;

    // CORS wildcard
    if (line.indexOf('Access-Control-Allow-Origin') >= 0 && line.indexOf('*') >= 0) {
      findings[findCount] = {
        id: 'missing-security',
        severity: 'high' as AuditSeverity,
        title: 'CORS allows all origins',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(line, 120),
        what: 'Access-Control-Allow-Origin is set to wildcard.',
        risk: 'Any website can make requests to your API.',
        fix: 'Restrict to specific trusted origins.',
        fixCode: 'reply.header(\'Access-Control-Allow-Origin\', \'https://yourdomain.com\')',
      };
      findCount++;
    }

    // origin: '*' in CORS config
    if (line.indexOf('origin') >= 0 && line.indexOf("'*'") >= 0) {
      findings[findCount] = {
        id: 'missing-security',
        severity: 'high' as AuditSeverity,
        title: 'CORS allows all origins',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(line, 120),
        what: 'CORS origin set to wildcard.',
        risk: 'Any website can make authenticated requests to your API.',
        fix: 'Restrict CORS to specific trusted origins.',
        fixCode: 'origin: [\'https://yourdomain.com\']',
      };
      findCount++;
    }
  }

  return findings;
}

export function checkInsecureCrypto(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;

    // Weak hash: createHash('md5') or createHash("md5")
    if (line.indexOf('createHash') >= 0 &&
        (line.indexOf("'md5'") >= 0 || line.indexOf('"md5"') >= 0 ||
         line.indexOf("'sha1'") >= 0 || line.indexOf('"sha1"') >= 0)) {
      // Check if related to password
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
        snippet: truncateSnippet(line, 120),
        what: isPasswordRelated ? 'MD5/SHA1 used for password hashing.' : 'MD5/SHA1 hash detected.',
        risk: isPasswordRelated ? 'These are broken for passwords. Attackers can crack them easily.' : 'MD5/SHA1 are cryptographically weak.',
        fix: isPasswordRelated ? 'Use bcrypt or argon2 for password hashing.' : 'Use SHA-256 or SHA-512.',
        fixCode: isPasswordRelated ? 'bcrypt.hash(password, 10)' : 'crypto.createHash(\'sha256\')',
      };
      findCount++;
    }

    // Math.random for security-sensitive context
    if (line.indexOf('Math.random') >= 0) {
      const lower = line.toLowerCase();
      if (lower.indexOf('token') >= 0 || lower.indexOf('secret') >= 0 ||
          lower.indexOf('session') >= 0 || lower.indexOf('nonce') >= 0 ||
          lower.indexOf('salt') >= 0) {
        findings[findCount] = {
          id: 'insecure-crypto',
          severity: 'high' as AuditSeverity,
          title: 'Math.random() used for security',
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(line, 120),
          what: 'Math.random() is not cryptographically secure.',
          risk: 'Tokens generated with Math.random() are predictable.',
          fix: 'Use crypto.randomUUID() or crypto.randomBytes().',
          fixCode: 'crypto.randomUUID()',
        };
        findCount++;
      }
    }
  }

  return findings;
}

// --- Tier 3: Medium ---

function findFsOp(line: string): string {
  // Return the fs operation name found, or empty if none
  // Check longer names first to avoid partial matches
  if (line.indexOf('readFileSync(') >= 0) return 'readFileSync';
  if (line.indexOf('writeFileSync(') >= 0) return 'writeFileSync';
  if (line.indexOf('readdirSync(') >= 0) return 'readdirSync';
  if (line.indexOf('unlinkSync(') >= 0) return 'unlinkSync';
  if (line.indexOf('readFile(') >= 0) return 'readFile';
  if (line.indexOf('writeFile(') >= 0) return 'writeFile';
  if (line.indexOf('readdir(') >= 0) return 'readdir';
  if (line.indexOf('unlink(') >= 0) return 'unlink';
  return '';
}

export function checkPathTraversal(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;

    const op = findFsOp(line);
    if (op.length === 0) continue;

    // Check for dynamic path (template literal or concat) after the fs op
    const opIdx = line.indexOf(op);
    const afterOp = line.substring(opIdx);

    let isDynamic = false;
    if (afterOp.indexOf('`') >= 0 && afterOp.indexOf('${') >= 0) isDynamic = true;
    if (afterOp.indexOf('+') >= 0) isDynamic = true;

    if (!isDynamic) continue;

    // Check for path validation nearby
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
        snippet: truncateSnippet(line, 120),
        what: 'File system operation uses dynamic path without validation.',
        risk: 'User input like "../../../etc/passwd" can access arbitrary files.',
        fix: 'Validate and normalize the path.',
        fixCode: 'const safePath = path.resolve(baseDir, input); if (!safePath.startsWith(baseDir)) throw new Error(\'bad path\');',
      };
      findCount++;
    }
  }

  return findings;
}

export function checkInformationDisclosure(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;

    // console.log of secrets
    if (line.indexOf('console.log') >= 0) {
      const lower = line.toLowerCase();
      if (lower.indexOf('password') >= 0 || lower.indexOf('secret') >= 0 ||
          lower.indexOf('token') >= 0 || lower.indexOf('apikey') >= 0 ||
          lower.indexOf('api_key') >= 0 || lower.indexOf('private_key') >= 0) {
        findings[findCount] = {
          id: 'info-disclosure',
          severity: 'medium' as AuditSeverity,
          title: 'Sensitive data logged',
          file: file.path,
          line: lineNum,
          snippet: truncateSnippet(line, 120),
          what: 'Sensitive data (password/secret/token) is being logged.',
          risk: 'Secrets in logs can be accessed by anyone with log access.',
          fix: 'Remove console.log of sensitive values, or mask them.',
          fixCode: 'console.log(\'auth: [REDACTED]\')',
        };
        findCount++;
      }
    }

    // Stack traces in error responses
    if (line.indexOf('.stack') >= 0 &&
        (line.indexOf('return') >= 0 || line.indexOf('send') >= 0 || line.indexOf('reply') >= 0)) {
      findings[findCount] = {
        id: 'info-disclosure',
        severity: 'medium' as AuditSeverity,
        title: 'Stack trace in response',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(line, 120),
        what: 'Error stack trace may be sent to the client.',
        risk: 'Stack traces reveal internal paths and code structure to attackers.',
        fix: 'Return a generic error message to clients.',
        fixCode: 'return \'{"error":"Internal server error"}\'',
      };
      findCount++;
    }
  }

  return findings;
}

export function checkInsecurePermissions(file: SourceFile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  let findCount = 0;
  const lines = file.lines;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    if (isCommentLine(line)) continue;

    if (line.indexOf('777') >= 0 && line.indexOf('chmod') >= 0) {
      findings[findCount] = {
        id: 'insecure-perms',
        severity: 'medium' as AuditSeverity,
        title: 'World-writable file permissions',
        file: file.path,
        line: lineNum,
        snippet: truncateSnippet(line, 120),
        what: 'File permissions set to 777.',
        risk: 'Any user on the system can read, modify, or execute this file.',
        fix: 'Use restrictive permissions like 0o755 or 0o644.',
        fixCode: 'fs.chmodSync(path, 0o644)',
      };
      findCount++;
    }
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
        const cryptoFindings = checkInsecureCrypto(file);
        for (let i = 0; i < cryptoFindings.length; i++) {
          allFindings[totalCount] = cryptoFindings[i];
          totalCount++;
        }
      }
    }

    // Tier 3 — Medium (always run unless filtered to critical only)
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
