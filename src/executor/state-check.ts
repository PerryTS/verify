import { PlatformAdapter } from '../platform/adapter'
import { AppManifest, VerifyStep } from '../api/types'
import { askHaiku, parseJsonSafe } from '../ai/client'
import { stateCheckSystemPrompt, stateCheckUserPrompt } from '../ai/prompts'

function treeContainsText(node: object | null, text: string): boolean {
  if (!node) return false
  const n = node as { label?: string; value?: string; role?: string; children?: object[] }
  const lowerText = text.toLowerCase()
  if (n.label && n.label.toLowerCase().includes(lowerText)) return true
  if (n.value && n.value.toLowerCase().includes(lowerText)) return true
  const children = n.children || []
  for (let i = 0; i < children.length; i++) {
    if (treeContainsText(children[i], text)) return true
  }
  return false
}

export async function executeStateCheck(
  platform: PlatformAdapter,
  expectedState: string | null | undefined,
  _manifest: AppManifest,
  screenshotPath: string,
): Promise<VerifyStep> {
  const start = Date.now()

  // If no expected state, just verify app is still running
  if (!expectedState) {
    return { name: 'state-check', status: 'passed', method: 'deterministic', durationMs: Date.now() - start }
  }

  // Phase 1: Deterministic - search accessibility tree
  const tree = await platform.getAccessibilityTree()
  if (tree && treeContainsText(tree, expectedState)) {
    return { name: 'state-check', status: 'passed', method: 'deterministic', durationMs: Date.now() - start }
  }

  // Phase 2: AI fallback
  const screenshot = await platform.screenshot(screenshotPath)
  const imagePath = screenshot ? screenshot.path : undefined

  const resp = await askHaiku(
    stateCheckSystemPrompt(),
    stateCheckUserPrompt(expectedState),
    imagePath,
  )

  if (!resp.text) {
    // AI unavailable - if no tree found, skip state check rather than fail
    return { name: 'state-check', status: 'skipped', method: 'ai-fallback', durationMs: Date.now() - start, error: 'AI service unavailable', aiCostCents: 0 }
  }

  const parsed = parseJsonSafe(resp.text) as { matches?: boolean; confidence?: number; reason?: string } | null
  if (!parsed) {
    return { name: 'state-check', status: 'failed', method: 'ai-fallback', durationMs: Date.now() - start, error: 'AI response could not be parsed', aiCostCents: resp.costCents }
  }

  const matches = parsed.matches === true
  const confidence = parsed.confidence || 0
  const reason = parsed.reason || ''

  if (matches && confidence >= 0.7) {
    return { name: 'state-check', status: 'passed', method: 'ai-fallback', durationMs: Date.now() - start, aiCostCents: resp.costCents }
  }

  return { name: 'state-check', status: 'failed', method: 'ai-fallback', durationMs: Date.now() - start, error: reason || 'Screen does not match expected state', aiCostCents: resp.costCents }
}
