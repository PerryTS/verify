// Audit patterns — regex patterns, entropy calculation, helper functions

// --- Secret patterns ---
// Each entry: [regex, description]
// These match common API key formats

export const SECRET_PATTERNS: string[][] = [
  // Stripe
  ['sk_live_[a-zA-Z0-9]{20,}', 'Stripe secret key'],
  ['sk_test_[a-zA-Z0-9]{20,}', 'Stripe test key'],
  ['pk_live_[a-zA-Z0-9]{20,}', 'Stripe publishable key'],
  // AWS
  ['AKIA[0-9A-Z]{16}', 'AWS access key'],
  ['aws_secret_access_key\\s*[=:]\\s*["\'][A-Za-z0-9/+=]{40}', 'AWS secret key'],
  // GitHub
  ['ghp_[a-zA-Z0-9]{36}', 'GitHub personal access token'],
  ['gho_[a-zA-Z0-9]{36}', 'GitHub OAuth token'],
  ['ghs_[a-zA-Z0-9]{36}', 'GitHub app token'],
  ['github_pat_[a-zA-Z0-9_]{22,}', 'GitHub fine-grained token'],
  // GitLab
  ['glpat-[a-zA-Z0-9_\\-]{20,}', 'GitLab personal access token'],
  // Slack
  ['xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}', 'Slack bot token'],
  ['xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}', 'Slack user token'],
  ['xapp-[0-9]{1}-[A-Z0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{30,}', 'Slack app token'],
  // Private keys
  ['-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private key'],
  // Database connection strings with passwords
  ['(mysql|postgres|postgresql|mongodb|redis)://[^\\s:]+:[^\\s@]+@', 'Database connection string with password'],
  // Generic API key patterns
  ['api[_-]?key\\s*[=:]\\s*["\'][a-zA-Z0-9_\\-]{20,}["\']', 'API key assignment'],
  ['api[_-]?secret\\s*[=:]\\s*["\'][a-zA-Z0-9_\\-]{20,}["\']', 'API secret assignment'],
  // JWT
  ['eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}', 'JWT token'],
];

// Variable names that suggest secrets
export const SECRET_VAR_NAMES: string[] = [
  'api_key', 'apikey', 'api_secret', 'apisecret',
  'secret_key', 'secretkey', 'private_key', 'privatekey',
  'access_token', 'accesstoken', 'auth_token', 'authtoken',
  'client_secret', 'clientsecret', 'password', 'passwd',
  'db_password', 'database_password', 'connection_string',
  'encryption_key', 'signing_key', 'master_key',
];

// Placeholder values to skip (false positives)
export const PLACEHOLDER_VALUES: string[] = [
  'your-key-here', 'your_key_here', 'your-api-key',
  'YOUR_API_KEY', 'REPLACE_ME', 'TODO', 'xxx', 'XXX',
  'changeme', 'CHANGEME', 'placeholder', 'PLACEHOLDER',
  'example', 'EXAMPLE', 'test', 'TEST', 'dummy', 'DUMMY',
  'insert-key-here', 'your-secret-here', 'sk_test_',
  'pk_test_', 'fake', 'FAKE', 'sample', 'SAMPLE',
];

// --- Unsafe execution patterns ---
export const UNSAFE_EXEC_PATTERNS: string[] = [
  'eval\\s*\\(',
  'new\\s+Function\\s*\\(',
  'setTimeout\\s*\\(\\s*["\']',
  'setInterval\\s*\\(\\s*["\']',
];

// --- SQL injection patterns ---
// Template literal or concat with user-influenced variable in query
export const SQL_QUERY_METHODS: string[] = [
  '.query', '.execute', '.raw', '.prepare',
];

// --- Sensitive route paths ---
export const SENSITIVE_ROUTES: string[] = [
  '/admin', '/users', '/delete', '/config', '/settings',
  '/api/admin', '/api/users', '/api/config', '/api/settings',
  '/internal', '/debug', '/management', '/dashboard',
];

// --- Insecure crypto ---
export const WEAK_HASH_PATTERNS: string[] = [
  'createHash\\s*\\(\\s*["\']md5["\']\\s*\\)',
  'createHash\\s*\\(\\s*["\']sha1["\']\\s*\\)',
];

export const MATH_RANDOM_SECRET: string[] = [
  'Math\\.random\\s*\\(\\s*\\)',
];

// --- Shannon entropy ---
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: number[] = [];
  const chars: string[] = [];
  let numChars = 0;

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    let found = false;
    for (let j = 0; j < numChars; j++) {
      if (chars[j] === c) {
        freq[j] = freq[j] + 1;
        found = true;
        break;
      }
    }
    if (!found) {
      chars[numChars] = c;
      freq[numChars] = 1;
      numChars++;
    }
  }

  let entropy = 0;
  for (let i = 0; i < numChars; i++) {
    const p = freq[i] / s.length;
    if (p > 0) {
      entropy = entropy - p * (Math.log(p) / Math.log(2));
    }
  }
  return entropy;
}

// --- Helper functions ---

export function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
}

export function isPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  for (let i = 0; i < PLACEHOLDER_VALUES.length; i++) {
    if (lower.indexOf(PLACEHOLDER_VALUES[i].toLowerCase()) >= 0) {
      return true;
    }
  }
  return false;
}

export function isTestFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.indexOf('.test.') >= 0 ||
    lower.indexOf('.spec.') >= 0 ||
    lower.indexOf('__test') >= 0 ||
    lower.indexOf('__mock') >= 0;
}

export function isProcessEnvRef(value: string): boolean {
  return value.indexOf('process.env') >= 0;
}

export function getLineNumber(content: string, charIndex: number): number {
  let line = 1;
  for (let i = 0; i < charIndex && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

export function getLineAt(lines: string[], lineNum: number): string {
  if (lineNum < 1 || lineNum > lines.length) return '';
  return lines[lineNum - 1];
}

export function truncateSnippet(line: string, maxLen: number): string {
  const trimmed = line.trim();
  if (trimmed.length <= maxLen) return trimmed;
  return trimmed.substring(0, maxLen - 3) + '...';
}
