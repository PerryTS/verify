// All shared types for perry-verify. Single source of truth.

export type TargetPlatform =
  | "macos-arm64"
  | "macos-x64"
  | "windows-x64"
  | "linux-x64"
  | "linux-arm64"
  | "ios-simulator"
  | "ipados-simulator"
  | "android-emulator"
  | "android-tablet-emulator"

export type JobStatus = "pending" | "running" | "passed" | "failed" | "error"
export type StepStatus = "passed" | "failed" | "skipped"
export type StepMethod = "deterministic" | "ai-fallback"
export type AppType = "gui" | "server" | "cli"
export type AuthStrategy = "login-form" | "oauth-mock" | "api-key" | "test-mode" | "skip" | "none"

export interface VerifyJob {
  id: string
  status: JobStatus
  target: TargetPlatform
  config: VerifyConfig
  manifest: AppManifest
  binaryPath: string
  jobDir: string
  steps: VerifyStep[]
  screenshots: Screenshot[]
  logs: string
  durationMs: number
  costCents: number
  createdAt: string
  completedAt: string | null
}

export interface VerifyConfig {
  auth?: AuthConfig
  criticalFlows?: string[]
  env?: Record<string, string>
}

export interface AuthConfig {
  strategy: AuthStrategy
  credentials?: {
    username?: string
    password?: string
    apiKey?: string
  }
  afterAuth?: string
}

export interface AppManifest {
  appType: AppType
  entryScreen?: string
  hasAuthGate: boolean
  screens?: string[]
  ports?: number[]
  accessibilityHints?: Record<string, string>
}

export interface VerifyStep {
  name: string
  status: StepStatus
  method: StepMethod
  screenshotPath?: string
  durationMs: number
  aiCostCents?: number
  error?: string
}

export interface Screenshot {
  step: string
  path: string
  timestamp: string
}

export interface VerifyRequest {
  config: VerifyConfig
  manifest: AppManifest
  target: TargetPlatform
}

export interface VerifyResponse {
  jobId: string
  status: JobStatus
}

export interface JobStatusResponse {
  jobId: string
  status: JobStatus
  steps: VerifyStep[]
  screenshots: string[]
  logs: string
  durationMs: number
  costCents: number
  createdAt: string
  completedAt: string | null
}

export interface UIElement {
  label: string
  role: string
  x: number
  y: number
  width: number
  height: number
}

export interface ElementQuery {
  label?: string
  role?: string
  text?: string
}

export interface AccessibilityNode {
  role: string
  label?: string
  value?: string
  children: AccessibilityNode[]
}
