import { PlatformAdapter } from '../platform/adapter'
import { VerifyJob, VerifyStep } from '../api/types'
import { updateJob } from '../storage/results'
import { screenshotPath, slugify } from '../storage/screenshots'
import { executeAuth } from './auth'
import { executeStateCheck } from './state-check'
import { executeFlow } from './flows'

const STEP_TIMEOUT_MS = 30000
const PIPELINE_TIMEOUT_MS = 5 * 60 * 1000

async function withTimeout<T>(promise: Promise<T>, ms: number, errorMsg: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(errorMsg))
    }, ms)
    promise.then((v) => {
      clearTimeout(timer)
      resolve(v)
    }).catch((e) => {
      clearTimeout(timer)
      reject(e)
    })
  })
}

export async function executePipeline(job: VerifyJob, platform: PlatformAdapter): Promise<void> {
  job.status = 'running'
  updateJob(job)
  const startTime = Date.now()

  const screensDir = job.jobDir + '/screenshots'

  async function addStep(step: VerifyStep): Promise<void> {
    job.steps.push(step)
    updateJob(job)
  }

  const pipelineWork = async () => {
    // Step 1: Launch
    const launchStep = await withTimeout(
      platform.launch(job.binaryPath, job.config.env),
      STEP_TIMEOUT_MS,
      'Launch timed out after 30s',
    )
    await addStep(launchStep)
    if (launchStep.status === 'failed') {
      job.status = 'failed'
      return
    }

    // Step 2: Wait for ready
    const readyStep = await withTimeout(
      platform.waitForReady(job.manifest),
      STEP_TIMEOUT_MS,
      'Wait for ready timed out after 30s',
    )
    await addStep(readyStep)
    if (readyStep.status === 'failed') {
      job.status = 'failed'
      // Take failure screenshot
      await platform.screenshot(screenshotPath(job.id, 'ready-failed'))
      return
    }

    // Step 3: Initial screenshot
    const shotPath = screenshotPath(job.id, 'initial')
    const initialShot = await platform.screenshot(shotPath)
    if (initialShot) {
      job.screenshots.push(initialShot)
    }

    // Step 4: Auth (if needed)
    const authConfig = job.config.auth
    if (job.manifest.hasAuthGate && authConfig && authConfig.strategy !== 'none' && authConfig.strategy !== 'skip') {
      const authStep = await withTimeout(
        executeAuth(platform, authConfig, job.manifest, screensDir),
        STEP_TIMEOUT_MS,
        'Auth timed out after 30s',
      )
      await addStep(authStep)
      if (authStep.status === 'failed') {
        await platform.screenshot(screenshotPath(job.id, 'auth-failed'))
        job.status = 'failed'
        return
      }
      const postAuthShot = await platform.screenshot(screenshotPath(job.id, 'post-auth'))
      if (postAuthShot) {
        job.screenshots.push(postAuthShot)
      }
    }

    // Step 5: State check
    const expectedState = (job.config.auth && job.config.auth.afterAuth) ? job.config.auth.afterAuth : job.manifest.entryScreen
    const stateStep = await withTimeout(
      executeStateCheck(platform, expectedState, job.manifest, screenshotPath(job.id, 'state-check')),
      STEP_TIMEOUT_MS,
      'State check timed out after 30s',
    )
    await addStep(stateStep)
    if (stateStep.status === 'failed') {
      job.status = 'failed'
      return
    }

    // Step 6: Critical flows
    const flows = job.config.criticalFlows
    if (flows && flows.length > 0) {
      for (let i = 0; i < flows.length; i++) {
        const instruction = flows[i]
        const flowStep = await withTimeout(
          executeFlow(platform, instruction, screenshotPath(job.id, slugify(instruction))),
          STEP_TIMEOUT_MS,
          'Flow timed out after 30s',
        )
        await addStep(flowStep)
        const flowShot = await platform.screenshot(screenshotPath(job.id, slugify(instruction)))
        if (flowShot) {
          job.screenshots.push(flowShot)
        }
        if (flowStep.status === 'failed') {
          job.status = 'failed'
          return
        }
      }
    }

    job.status = 'passed'
  }

  try {
    await withTimeout(pipelineWork(), PIPELINE_TIMEOUT_MS, 'Pipeline timed out after 5 minutes')
  } catch (err: any) {
    job.status = 'error'
    job.logs = job.logs + '\nPipeline error: ' + (err.message || String(err))
    // Try to take a failure screenshot
    try {
      await platform.screenshot(screenshotPath(job.id, 'error'))
    } catch (_) {}
  } finally {
    // Always kill the app
    try {
      await platform.kill()
    } catch (_) {}

    job.durationMs = Date.now() - startTime
    job.completedAt = new Date().toISOString()

    // Accumulate AI costs
    let totalCost = 0
    for (let i = 0; i < job.steps.length; i++) {
      totalCost = totalCost + (job.steps[i].aiCostCents || 0)
    }
    job.costCents = totalCost
    job.logs = job.logs + platform.getLogs()
    updateJob(job)
  }
}
