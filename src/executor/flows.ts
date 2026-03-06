import { PlatformAdapter } from '../platform/adapter'
import { VerifyStep } from '../api/types'
import { askSonnet, parseJsonSafe } from '../ai/client'
import { flowSystemPrompt, flowUserPrompt } from '../ai/prompts'

const MAX_ITERATIONS = 10

export async function executeFlow(
  platform: PlatformAdapter,
  flowInstruction: string,
  screenshotPath: string,
): Promise<VerifyStep> {
  const start = Date.now()

  // v1 stub: return skipped
  // Uncomment the implementation below for Phase 2
  return { name: flowInstruction, status: 'skipped', method: 'ai-fallback', durationMs: Date.now() - start, error: 'Critical flows not implemented in v1' }

  /*
  for (let i = 0; i < MAX_ITERATIONS; i++) {
    const tree = await platform.getAccessibilityTree()
    const treeStr = tree ? JSON.stringify(tree) : 'unavailable'
    const screenshot = await platform.screenshot(screenshotPath + '-' + String(i) + '.png')
    const imagePath = screenshot ? screenshot.path : undefined

    const resp = await askSonnet(
      flowSystemPrompt(),
      flowUserPrompt(flowInstruction, treeStr),
      imagePath,
    )

    if (!resp.text) {
      return { name: flowInstruction, status: 'failed', method: 'ai-fallback', durationMs: Date.now() - start, error: 'AI service unavailable' }
    }

    const parsed = parseJsonSafe(resp.text) as { completed?: boolean; action?: string; target?: { label?: string; role?: string }; typeText?: string } | null
    if (!parsed) {
      return { name: flowInstruction, status: 'failed', method: 'ai-fallback', durationMs: Date.now() - start, error: 'AI response unparseable' }
    }

    if (parsed.completed === true) {
      return { name: flowInstruction, status: 'passed', method: 'ai-fallback', durationMs: Date.now() - start }
    }

    const action = parsed.action || ''
    const target = parsed.target || {}
    const element = await platform.findElement({ label: target.label, role: target.role })

    if (action === 'click' && element) {
      await platform.click(element)
    } else if (action === 'type' && element) {
      await platform.type(element, parsed.typeText || '')
    }

    await sleep(1000)
  }

  return { name: flowInstruction, status: 'failed', method: 'ai-fallback', durationMs: Date.now() - start, error: 'Could not complete flow in ' + String(MAX_ITERATIONS) + ' actions' }
  */
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms) })
}
