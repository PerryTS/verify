import { PlatformAdapter } from '../platform/adapter'
import { AuthConfig, AppManifest, VerifyStep, UIElement } from '../api/types'
import { askHaiku, parseJsonSafe } from '../ai/client'
import { authSystemPrompt } from '../ai/prompts'

const EMAIL_LABELS = ['email', 'username', 'user', 'login', 'e-mail']
const PASS_LABELS = ['password', 'pass', 'passphrase', 'secret']
const SUBMIT_LABELS = ['sign in', 'signin', 'log in', 'login', 'submit', 'continue', 'enter']

function labelMatchesAny(label: string, keywords: string[]): boolean {
  const l = label.toLowerCase()
  for (let i = 0; i < keywords.length; i++) {
    if (l.includes(keywords[i])) return true
  }
  return false
}

function findInTree(tree: object | null, role: string, labelKeywords: string[]): UIElement | null {
  if (!tree) return null
  const node = tree as { role?: string; label?: string; x?: number; y?: number; width?: number; height?: number; children?: object[] }

  if (node.role === role && node.label && labelMatchesAny(node.label, labelKeywords)) {
    return {
      label: node.label || '',
      role: node.role || '',
      x: node.x || 0,
      y: node.y || 0,
      width: node.width || 0,
      height: node.height || 0,
    }
  }

  const children = node.children || []
  for (let i = 0; i < children.length; i++) {
    const found = findInTree(children[i], role, labelKeywords)
    if (found) return found
  }
  return null
}

async function deterministicAuth(
  platform: PlatformAdapter,
  credentials: { username?: string; password?: string },
): Promise<VerifyStep | null> {
  const start = Date.now()

  const tree = await platform.getAccessibilityTree()
  if (!tree) return null

  const usernameField = findInTree(tree, 'textField', EMAIL_LABELS)
  const passwordField = findInTree(tree, 'secureTextField', PASS_LABELS)
  const submitButton = findInTree(tree, 'button', SUBMIT_LABELS)

  // Use truthiness checks (not !== null) per Perry quirks
  if (!usernameField || !passwordField || !submitButton) return null

  await platform.click(usernameField)
  await platform.type(usernameField, credentials.username || '')
  await platform.click(passwordField)
  await platform.type(passwordField, credentials.password || '')
  await platform.click(submitButton)

  // Wait for auth to complete
  await sleep(5000)

  return {
    name: 'auth',
    status: 'passed',
    method: 'deterministic',
    durationMs: Date.now() - start,
  }
}

async function aiAuth(
  platform: PlatformAdapter,
  credentials: { username?: string; password?: string },
  screenshotPath: string,
): Promise<VerifyStep> {
  const start = Date.now()

  const screenshot = await platform.screenshot(screenshotPath)
  const tree = await platform.getAccessibilityTree()
  const treeStr = tree ? JSON.stringify(tree) : 'unavailable'

  const imagePath = screenshot ? screenshot.path : undefined
  const userContent = `Accessibility tree:\n${treeStr}\n\nIdentify the username field, password field, and submit button.`

  const resp = await askHaiku(authSystemPrompt(), userContent, imagePath)

  if (!resp.text) {
    return {
      name: 'auth',
      status: 'failed',
      method: 'ai-fallback',
      durationMs: Date.now() - start,
      error: 'AI service unavailable',
      aiCostCents: 0,
    }
  }

  const parsed = parseJsonSafe(resp.text) as { usernameField?: UIElement | null; passwordField?: UIElement | null; submitButton?: UIElement | null } | null
  if (!parsed) {
    return {
      name: 'auth',
      status: 'failed',
      method: 'ai-fallback',
      durationMs: Date.now() - start,
      error: 'AI response could not be parsed',
      aiCostCents: resp.costCents,
    }
  }

  const usernameField = parsed.usernameField
  const passwordField = parsed.passwordField
  const submitButton = parsed.submitButton

  if (!usernameField || !passwordField || !submitButton) {
    return {
      name: 'auth',
      status: 'failed',
      method: 'ai-fallback',
      durationMs: Date.now() - start,
      error: 'Could not identify login form elements',
      aiCostCents: resp.costCents,
    }
  }

  await platform.click(usernameField)
  await platform.type(usernameField, credentials.username || '')
  await platform.click(passwordField)
  await platform.type(passwordField, credentials.password || '')
  await platform.click(submitButton)
  await sleep(5000)

  return {
    name: 'auth',
    status: 'passed',
    method: 'ai-fallback',
    durationMs: Date.now() - start,
    aiCostCents: resp.costCents,
  }
}

export async function executeAuth(
  platform: PlatformAdapter,
  authConfig: AuthConfig,
  _manifest: AppManifest,
  screenshotDir: string,
): Promise<VerifyStep> {
  const strategy = authConfig.strategy
  const start = Date.now()

  if (strategy === 'none' || strategy === 'skip') {
    return { name: 'auth', status: 'skipped', method: 'deterministic', durationMs: 0 }
  }

  if (strategy === 'test-mode' || strategy === 'api-key') {
    // Env vars already injected at launch, app should handle auth automatically
    return { name: 'auth', status: 'passed', method: 'deterministic', durationMs: Date.now() - start }
  }

  if (strategy === 'oauth-mock') {
    return { name: 'auth', status: 'skipped', method: 'deterministic', durationMs: 0, error: 'OAuth mock not implemented in v1' }
  }

  if (strategy === 'login-form') {
    const credentials = authConfig.credentials || {}

    // Phase 1: deterministic
    const deterministicResult = await deterministicAuth(platform, credentials)
    if (deterministicResult) return deterministicResult

    // Phase 2: AI fallback
    return aiAuth(platform, credentials, screenshotDir + '/auth-ai-attempt.png')
  }

  return { name: 'auth', status: 'failed', method: 'deterministic', durationMs: 0, error: 'Unknown auth strategy: ' + strategy }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms) })
}
