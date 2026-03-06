# Perry Verify — Standalone Verification Service

## Spec for Claude Code

**Version:** 0.1.0
**Language:** TypeScript (compiled with Perry to native binary)
**Date:** March 2026

---

## 1. What This Is

Perry Verify is a standalone HTTP service that accepts a compiled application binary + configuration, runs a verification pipeline against it on the host machine, and returns structured results (pass/fail, screenshots, logs, step details).

It is architecturally independent — not tied to Perry Publish, Perry CLI, or any other system. It is a simple API: **provide config + binary → wait → get result.**

The service runs locally on whatever platform it's deployed to. If you run it on macOS, it verifies macOS binaries. If you run it on Linux, it verifies Linux binaries. The caller decides which machine to send the job to. There is no multi-target orchestration, no queue, no fan-out — that is the responsibility of the caller (Perry Publish, later).

---

## 2. Project Structure

```
perry-verify/
├── src/
│   ├── main.ts                     # HTTP server entry point
│   ├── api/
│   │   ├── routes.ts               # POST /verify, GET /verify/:id, GET /verify/:id/screenshots/:step
│   │   └── types.ts                # All shared types/interfaces
│   ├── executor/
│   │   ├── pipeline.ts             # Main verification pipeline orchestrator
│   │   ├── launcher.ts             # Step: launch binary, wait for ready
│   │   ├── auth.ts                 # Step: authentication (deterministic + AI fallback)
│   │   ├── state-check.ts          # Step: verify app reached expected state
│   │   └── flows.ts                # Step: critical flows via AI (phase 2, stub for now)
│   ├── platform/
│   │   ├── adapter.ts              # PlatformAdapter interface definition
│   │   ├── macos.ts                # macOS implementation (Geisterhand integration)
│   │   ├── linux.ts                # Linux implementation (process management, AT-SPI)
│   │   ├── windows.ts              # Windows implementation (stub for v1)
│   │   ├── ios-simulator.ts        # iOS Simulator via xcrun simctl (stub for v1)
│   │   └── android-emulator.ts     # Android Emulator via adb (stub for v1)
│   ├── ai/
│   │   ├── client.ts               # Anthropic API client (Claude Haiku/Sonnet)
│   │   └── prompts.ts              # Structured prompts for auth fallback, state check, flow execution
│   └── storage/
│       ├── screenshots.ts          # Save/retrieve screenshots to local disk
│       └── results.ts              # In-memory job state (upgradeable to Postgres later)
├── perry.toml                      # Perry build configuration
└── README.md
```

---

## 3. Core Types

All types live in `src/api/types.ts`. This is the single source of truth for all data structures.

```typescript
// === Job Types ===

type TargetPlatform =
  | "macos-arm64"
  | "macos-x64"
  | "windows-x64"
  | "linux-x64"
  | "linux-arm64"
  | "ios-simulator"
  | "ipados-simulator"
  | "android-emulator"
  | "android-tablet-emulator"

type JobStatus = "pending" | "running" | "passed" | "failed" | "error"
type StepStatus = "passed" | "failed" | "skipped"
type StepMethod = "deterministic" | "ai-fallback"
type AppType = "gui" | "server" | "cli"
type AuthStrategy = "login-form" | "oauth-mock" | "api-key" | "test-mode" | "skip" | "none"

interface VerifyJob {
  id: string
  status: JobStatus
  target: TargetPlatform
  config: VerifyConfig
  manifest: AppManifest
  binaryPath: string              // local path to saved binary
  steps: VerifyStep[]
  screenshots: Screenshot[]
  logs: string
  durationMs: number
  costCents: number               // accumulated AI spend
  createdAt: string               // ISO timestamp
  completedAt: string | null
}

interface VerifyConfig {
  auth?: AuthConfig
  criticalFlows?: string[]        // natural language instructions
  env?: Record<string, string>    // environment variables injected into the app
}

interface AuthConfig {
  strategy: AuthStrategy
  credentials?: {
    username?: string
    password?: string
    apiKey?: string
  }
  afterAuth?: string              // expected screen name or visible text after auth
}

interface AppManifest {
  appType: AppType
  entryScreen?: string            // name of the first screen (from compiler)
  hasAuthGate: boolean            // whether app requires auth before main UI
  screens?: string[]              // known screen names (from compiler)
  ports?: number[]                // for server apps: expected listening ports
  accessibilityHints?: Record<string, string>  // element labels the compiler knows about
}

interface VerifyStep {
  name: string                    // "launch" | "ready" | "auth" | "state-check" | flow name
  status: StepStatus
  method: StepMethod
  screenshotPath?: string         // relative path to screenshot taken at this step
  durationMs: number
  aiCostCents?: number
  error?: string                  // human-readable error description if failed
}

interface Screenshot {
  step: string
  path: string                    // relative path on disk
  timestamp: string
}

// === API Request/Response Types ===

interface VerifyRequest {
  // binary: sent as multipart file upload
  config: VerifyConfig
  manifest: AppManifest
  target: TargetPlatform
}

interface VerifyResponse {
  jobId: string
  status: JobStatus
}

interface JobStatusResponse {
  jobId: string
  status: JobStatus
  steps: VerifyStep[]
  screenshots: string[]           // URLs/paths to screenshot files
  logs: string
  durationMs: number
  costCents: number
  createdAt: string
  completedAt: string | null
}

// === Platform Adapter Types ===

interface UIElement {
  label: string
  role: string                    // "button" | "textField" | "secureTextField" | "staticText" | etc.
  x: number
  y: number
  width: number
  height: number
}

interface ElementQuery {
  label?: string                  // accessibility label
  role?: string                   // element role
  text?: string                   // visible text content
}

interface AccessibilityNode {
  role: string
  label?: string
  value?: string
  children: AccessibilityNode[]
}
```

---

## 4. Platform Adapter Interface

Defined in `src/platform/adapter.ts`. Every platform implements this interface.

```typescript
interface PlatformAdapter {
  // Launch the binary. Set up environment variables from config.
  // For GUI apps: launch the .app / executable
  // For server apps: launch the binary and wait for process to start
  // Returns a step result indicating success/failure
  launch(binaryPath: string, env?: Record<string, string>): Promise<VerifyStep>

  // Wait for the app to signal readiness.
  // For GUI apps: a window appeared (check via OS API, not AI)
  // For server apps: a port is responding (TCP connect or HTTP GET)
  // For CLI apps: process exited with code 0
  // Timeout: 30 seconds
  waitForReady(manifest: AppManifest): Promise<VerifyStep>

  // Capture a screenshot of the current app state.
  // For GUI apps: screenshot of the app window
  // For server apps: not applicable, return null
  screenshot(savePath: string): Promise<Screenshot | null>

  // Find a UI element by label, role, or visible text.
  // Uses accessibility APIs (not AI) as first attempt.
  // Returns null if not found.
  findElement(query: ElementQuery): Promise<UIElement | null>

  // Click on a UI element.
  click(element: UIElement): Promise<void>

  // Type text into a focused or specified element.
  type(element: UIElement, text: string): Promise<void>

  // Get the full accessibility tree of the current app window.
  // Used for deterministic element lookups and as context for AI fallback.
  getAccessibilityTree(): Promise<AccessibilityNode | null>

  // Get any stdout/stderr logs from the running app process.
  getLogs(): string

  // Kill the app process and clean up any temp files.
  kill(): Promise<void>
}
```

### 4.1 macOS Implementation (`src/platform/macos.ts`)

- **launch()**: Use `child_process.spawn` (or Perry equivalent) to launch the .app bundle or binary. Pass env vars via process environment.
- **waitForReady()**: For GUI apps, shell out to Geisterhand CLI or use macOS Accessibility API to check if a window with the app's bundle ID exists. Poll every 500ms, timeout at 30s. For server apps, attempt TCP connection to expected port(s) from manifest.
- **screenshot()**: Shell out to `screencapture -l <windowId> <path>` or use Geisterhand's screenshot endpoint.
- **findElement()**: Shell out to Geisterhand CLI: `geisterhand find --label "Email" --role textField`. Geisterhand uses macOS Accessibility API under the hood. Parse JSON response.
- **click()**: `geisterhand click --x <x> --y <y>` or `geisterhand click --label "Sign In"`
- **type()**: `geisterhand type --text "test@example.com"` (types into focused element) or `geisterhand type --element <id> --text "..."`
- **getAccessibilityTree()**: `geisterhand tree --format json` — returns the full accessibility tree of the frontmost app.
- **kill()**: `kill <pid>` or `osascript -e 'quit app "AppName"'`

**Geisterhand dependency**: The macOS adapter assumes Geisterhand is installed on the host (`brew install --cask geisterhand-io/tap/geisterhand`). If not found, fall back to basic process management only (launch + screenshot via screencapture, no UI interaction).

### 4.2 Linux Implementation (`src/platform/linux.ts`)

- **launch()**: `child_process.spawn` the binary with env vars. For GUI apps on Linux with a display server, set DISPLAY or WAYLAND_DISPLAY.
- **waitForReady()**: For server apps, TCP connect to port. For GUI apps, check if process is running and optionally use `xdotool` to check for window existence. For CLI apps, wait for process exit.
- **screenshot()**: For GUI apps: `import` (ImageMagick) or `xdotool`+`scrot`. For headless server apps: skip.
- **findElement()**: Use AT-SPI2 via D-Bus if available, otherwise not supported (AI fallback required). For v1: return null (Linux UI interaction is lower priority).
- **click()/type()**: `xdotool` for basic input. AT-SPI2 for accessibility-aware interaction. For v1: basic xdotool only.
- **getAccessibilityTree()**: AT-SPI2 via `accerciser` or direct D-Bus calls. For v1: return null.
- **kill()**: `kill <pid>`

### 4.3 Stubs for v1

`windows.ts`, `ios-simulator.ts`, and `android-emulator.ts` should exist as files but throw a "not yet implemented" error. This keeps the architecture clean for future expansion.

```typescript
// Example stub
class WindowsAdapter implements PlatformAdapter {
  async launch(): Promise<VerifyStep> {
    throw new Error("Windows platform adapter not yet implemented")
  }
  // ... all methods throw
}
```

---

## 5. Verification Pipeline

Defined in `src/executor/pipeline.ts`. This is the core orchestration logic.

```
Pipeline Flow:
                                    
  launch() ──► waitForReady() ──► screenshot("initial") 
                                       │
                                       ▼
                               has auth gate?
                              /              \
                            yes               no
                            │                  │
                            ▼                  │
                     executeAuth()             │
                         │                     │
                         ▼                     │
                  screenshot("post-auth")      │
                         │                     │
                         └──────┬──────────────┘
                                │
                                ▼
                       executeStateCheck()
                                │
                                ▼
                     has critical flows?
                    /                    \
                  yes                     no
                   │                       │
                   ▼                       │
            for each flow:                 │
              executeFlow()                │
              screenshot(flow-name)        │
                   │                       │
                   └──────┬────────────────┘
                          │
                          ▼
                       kill()
                          │
                          ▼
                    return result
```

### Pipeline Rules

1. **Fail fast**: If any step fails, skip remaining steps and return immediately with collected results so far.
2. **Always screenshot**: Take a screenshot after every major step, even on failure (the failure screenshot is the most valuable one).
3. **Always kill**: The app process must be killed in a finally block, even if the pipeline throws.
4. **Track method**: Every step records whether it was resolved deterministically or via AI fallback.
5. **Track cost**: Every step that uses AI records the API cost in cents.
6. **Timeout**: Each individual step has a 30-second timeout. The entire pipeline has a 5-minute timeout.

### Pipeline Implementation Pseudocode

```typescript
async function executePipeline(job: VerifyJob, platform: PlatformAdapter): Promise<VerifyJob> {
  job.status = "running"
  const startTime = Date.now()

  try {
    // Step 1: Launch
    const launchStep = await platform.launch(job.binaryPath, job.config.env)
    job.steps.push(launchStep)
    if (launchStep.status === "failed") {
      job.status = "failed"
      return job
    }

    // Step 2: Wait for ready
    const readyStep = await platform.waitForReady(job.manifest)
    job.steps.push(readyStep)
    if (readyStep.status === "failed") {
      job.status = "failed"
      return job
    }

    // Step 3: Initial screenshot
    const initialShot = await platform.screenshot(screenshotPath(job.id, "initial"))
    if (initialShot) job.screenshots.push(initialShot)

    // Step 4: Auth (if needed)
    if (job.manifest.hasAuthGate && job.config.auth && job.config.auth.strategy !== "none") {
      const authStep = await executeAuth(platform, job.config.auth, job.manifest)
      job.steps.push(authStep)
      if (authStep.status === "failed") {
        // Screenshot the failure state
        await platform.screenshot(screenshotPath(job.id, "auth-failed"))
        job.status = "failed"
        return job
      }
      const postAuthShot = await platform.screenshot(screenshotPath(job.id, "post-auth"))
      if (postAuthShot) job.screenshots.push(postAuthShot)
    }

    // Step 5: State check
    const expectedState = job.config.auth?.afterAuth ?? job.manifest.entryScreen
    const stateStep = await executeStateCheck(platform, expectedState, job.manifest)
    job.steps.push(stateStep)
    if (stateStep.status === "failed") {
      job.status = "failed"
      return job
    }

    // Step 6: Critical flows (if configured)
    if (job.config.criticalFlows && job.config.criticalFlows.length > 0) {
      for (const flowInstruction of job.config.criticalFlows) {
        const flowStep = await executeFlow(platform, flowInstruction)
        job.steps.push(flowStep)
        const flowShot = await platform.screenshot(screenshotPath(job.id, slugify(flowInstruction)))
        if (flowShot) job.screenshots.push(flowShot)
        if (flowStep.status === "failed") {
          job.status = "failed"
          return job
        }
      }
    }

    // All passed
    job.status = "passed"
    return job

  } catch (err) {
    job.status = "error"
    job.logs += "\nPipeline error: " + err.message
    return job
  } finally {
    await platform.kill()
    job.durationMs = Date.now() - startTime
    job.completedAt = new Date().toISOString()
    job.costCents = job.steps.reduce((sum, s) => sum + (s.aiCostCents ?? 0), 0)
  }
}
```

---

## 6. Executor Step Details

### 6.1 Auth Step (`src/executor/auth.ts`)

```
Input: PlatformAdapter, AuthConfig, AppManifest
Output: VerifyStep

Logic by strategy:

  "none" / "skip":
    → return { status: "skipped", method: "deterministic" }

  "test-mode":
    → env var PERRY_TEST_MODE=true was already injected at launch
    → app should skip auth automatically
    → return { status: "passed", method: "deterministic" }

  "api-key":
    → env var was injected at launch (e.g., API_KEY=xxx)
    → app should authenticate via the key automatically
    → return { status: "passed", method: "deterministic" }

  "login-form":
    → This is the interesting one. Two-phase approach:
    
    Phase 1 — Deterministic (try first):
      1. Get accessibility tree from platform
      2. Search tree for elements matching common login patterns:
         - role: "textField" with label containing "email" / "username" / "user" / "login"
         - role: "secureTextField" with label containing "password" / "pass"  
         - role: "button" with label containing "sign in" / "log in" / "login" / "submit"
      3. If all three found:
         - platform.click(usernameField)
         - platform.type(usernameField, credentials.username)
         - platform.click(passwordField)
         - platform.type(passwordField, credentials.password)
         - platform.click(submitButton)
         - Wait 5 seconds for auth to complete
         - return { status: "passed", method: "deterministic" }
      4. If not all found → go to Phase 2

    Phase 2 — AI Fallback:
      1. Take screenshot
      2. Get accessibility tree (may be partial)
      3. Send to Claude Haiku:
         System: "You are a UI automation assistant. Given a screenshot and 
                  accessibility tree of a login screen, identify the username field,
                  password field, and submit button. Return JSON only."
         User: [screenshot image] + [accessibility tree text]
         Expected response: {
           "usernameField": { "label": "...", "role": "...", "x": N, "y": N },
           "passwordField": { "label": "...", "role": "...", "x": N, "y": N },
           "submitButton": { "label": "...", "role": "...", "x": N, "y": N }
         }
      4. Use returned coordinates/labels to interact
      5. return { status: "passed", method: "ai-fallback", aiCostCents: <actual> }

  "oauth-mock":
    → For v1: not implemented, return skipped
    → Future: Perry compiler injects mock OAuth token at build time
```

### 6.2 State Check (`src/executor/state-check.ts`)

```
Input: PlatformAdapter, expectedState (string | undefined), AppManifest
Output: VerifyStep

Logic:

  If no expectedState provided:
    → Just verify app is still running (process alive, window exists)
    → return { status: "passed", method: "deterministic" }

  Phase 1 — Deterministic:
    1. Get accessibility tree
    2. Search tree for any node where:
       - label contains expectedState (case-insensitive)
       - OR value contains expectedState
       - OR any staticText child contains expectedState
    3. If found → return { status: "passed", method: "deterministic" }

  Phase 2 — AI Fallback:
    1. Take screenshot
    2. Send to Claude Haiku:
       System: "You are verifying a UI state. Answer with JSON only."
       User: "Does this screen appear to show: '{expectedState}'? 
              Respond: { \"matches\": true/false, \"confidence\": 0.0-1.0, \"reason\": \"...\" }"
       + [screenshot image]
    3. If matches === true and confidence >= 0.7:
       → return { status: "passed", method: "ai-fallback" }
    4. Else:
       → return { status: "failed", method: "ai-fallback", error: reason }
```

### 6.3 Critical Flows (`src/executor/flows.ts`)

```
Input: PlatformAdapter, flowInstruction (string, natural language)
Output: VerifyStep

This is the most AI-intensive step. For v1, this can be a stub that returns "skipped".
When implemented:

Logic:
  Max iterations per flow: 10 actions
  Max retries per action: 3

  Loop:
    1. Capture current state (accessibility tree + screenshot)
    2. Send to Claude Sonnet:
       System: "You are a UI testing agent. Given the current screen state and an 
                instruction, determine the next action to take. If the instruction
                has been completed, say so.
                
                Respond with JSON only:
                { 
                  \"completed\": true/false,
                  \"action\": \"click\" | \"type\" | \"scroll\" | \"wait\",
                  \"target\": { \"label\": \"...\", \"role\": \"...\" },
                  \"typeText\": \"...\" (if action is type),
                  \"reasoning\": \"...\"
                }"
       User: "Instruction: '{flowInstruction}'
              Current accessibility tree: {tree}
              [screenshot image]"
    3. If completed === true → return { status: "passed" }
    4. Execute the action via platform adapter
    5. Wait 1 second for UI to settle
    6. Repeat from step 1
    
  If max iterations reached without completion:
    → return { status: "failed", error: "Could not complete flow in 10 actions" }

Model: Claude Sonnet (claude-sonnet-4-5-20250929)
Cost: ~$0.01-0.03 per action (screenshot + tree as input, structured JSON output)
```

---

## 7. AI Client

Defined in `src/ai/client.ts`.

```
Configuration:
  - API Key: read from ANTHROPIC_API_KEY environment variable
  - Base URL: https://api.anthropic.com/v1/messages
  - Default timeout: 30 seconds

Two methods:

  askHaiku(systemPrompt: string, userContent: Content[]): Promise<string>
    → model: "claude-haiku-4-5-20251001"
    → max_tokens: 1024
    → Used for: auth fallback (identify form fields), state check (yes/no screen match)
    → Content can include text and base64 images

  askSonnet(systemPrompt: string, userContent: Content[]): Promise<string>
    → model: "claude-sonnet-4-5-20250929"
    → max_tokens: 1024
    → Used for: critical flow action planning
    → Content can include text and base64 images

Both methods:
  - Parse response to extract text content
  - Track token usage and calculate cost:
    - Haiku input: $0.80/MTok, output: $4/MTok
    - Sonnet input: $3/MTok, output: $15/MTok
  - Return both the response text and cost in cents
  - Handle errors gracefully (timeout, rate limit, API error) → return error, don't crash
```

---

## 8. HTTP API

Defined in `src/api/routes.ts`. Minimal HTTP server, no framework dependency.

### POST /verify

```
Content-Type: multipart/form-data

Fields:
  - binary (file): The compiled application binary or .app bundle (as .tar.gz for bundles)
  - config (text/json): VerifyConfig as JSON string
  - manifest (text/json): AppManifest as JSON string  
  - target (text): TargetPlatform string

Response (202 Accepted):
{
  "jobId": "v_a1b2c3d4",
  "status": "pending"
}

Behavior:
  1. Generate job ID (random, prefixed with "v_")
  2. Save binary to /tmp/perry-verify/jobs/<jobId>/binary (extract .tar.gz if bundle)
  3. Create VerifyJob in memory store
  4. Start pipeline execution asynchronously (don't block the response)
  5. Return job ID immediately
```

### GET /verify/:jobId

```
Response (200 OK):
{
  "jobId": "v_a1b2c3d4",
  "status": "running",          // or "pending" | "passed" | "failed" | "error"
  "steps": [
    {
      "name": "launch",
      "status": "passed",
      "method": "deterministic",
      "durationMs": 1200
    },
    {
      "name": "auth",
      "status": "passed",
      "method": "ai-fallback",
      "durationMs": 3400,
      "aiCostCents": 0.5
    }
  ],
  "screenshots": [
    "/verify/v_a1b2c3d4/screenshots/initial.png",
    "/verify/v_a1b2c3d4/screenshots/post-auth.png"
  ],
  "logs": "App launched with PID 12345\n...",
  "durationMs": 8700,
  "costCents": 0.5,
  "createdAt": "2026-03-01T10:00:00Z",
  "completedAt": "2026-03-01T10:00:08Z"
}

Response (404):
{ "error": "Job not found" }
```

### GET /verify/:jobId/screenshots/:filename

```
Serves the screenshot PNG file from disk.
Content-Type: image/png

Response (404) if file not found.
```

### GET /health

```
Response (200):
{
  "status": "ok",
  "platform": "macos-arm64",     // detected host platform
  "geisterhand": true,           // whether Geisterhand CLI is available
  "version": "0.1.0"
}
```

---

## 9. Storage (v1 — Local Only)

### Job Store (`src/storage/results.ts`)

In-memory Map for v1. No database.

```typescript
// Simple in-memory store
// Map<jobId, VerifyJob>
// 
// Jobs are kept in memory for 1 hour after completion, then evicted.
// This is a standalone service — if it restarts, jobs are lost. That's fine for v1.
```

### File Storage (`src/storage/screenshots.ts`)

```
Base directory: /tmp/perry-verify/jobs/

Per job:
  /tmp/perry-verify/jobs/<jobId>/
    ├── binary              # or binary/ directory for .app bundles
    ├── screenshots/
    │   ├── initial.png
    │   ├── post-auth.png
    │   ├── state-check.png
    │   └── navigate-to-settings.png
    └── logs.txt

Cleanup: Delete job directory 1 hour after job completion.
```

---

## 10. Configuration & Environment Variables

The service itself is configured via environment variables:

```
PERRY_VERIFY_PORT=7777              # HTTP server port (default: 7777)
PERRY_VERIFY_HOST=0.0.0.0          # Bind address (default: 0.0.0.0)
PERRY_VERIFY_TEMP_DIR=/tmp/perry-verify   # Base temp directory
ANTHROPIC_API_KEY=sk-ant-...        # Required for AI fallback steps
PERRY_VERIFY_LOG_LEVEL=info         # debug | info | warn | error
```

---

## 11. Build & Run

```bash
# Build with Perry
perry build src/main.ts --target macos-arm64 --release --output perry-verify

# Run
ANTHROPIC_API_KEY=sk-ant-xxx ./perry-verify

# Or with custom port
PERRY_VERIFY_PORT=9000 ./perry-verify
```

---

## 12. Example Usage

### Minimal: verify a GUI app with no auth launches successfully

```bash
curl -X POST http://localhost:7777/verify \
  -F binary=@./my-app \
  -F config='{"auth":{"strategy":"none"}}' \
  -F manifest='{"appType":"gui","hasAuthGate":false}' \
  -F target=macos-arm64

# → { "jobId": "v_abc123", "status": "pending" }

curl http://localhost:7777/verify/v_abc123

# → { "status": "passed", "steps": [
#      { "name": "launch", "status": "passed", ... },
#      { "name": "ready", "status": "passed", ... },
#      { "name": "state-check", "status": "passed", ... }
#    ], "screenshots": ["/verify/v_abc123/screenshots/initial.png"] }
```

### With auth: verify app can log in

```bash
curl -X POST http://localhost:7777/verify \
  -F binary=@./my-app.tar.gz \
  -F config='{
    "auth": {
      "strategy": "login-form",
      "credentials": {
        "username": "test@example.com",
        "password": "testpass123"
      },
      "afterAuth": "Dashboard"
    }
  }' \
  -F manifest='{
    "appType": "gui",
    "hasAuthGate": true,
    "entryScreen": "Login",
    "screens": ["Login", "Dashboard", "Settings"]
  }' \
  -F target=macos-arm64
```

### Server app: verify it starts and listens

```bash
curl -X POST http://localhost:7777/verify \
  -F binary=@./my-server \
  -F config='{}' \
  -F manifest='{
    "appType": "server",
    "hasAuthGate": false,
    "ports": [3000]
  }' \
  -F target=linux-x64
```

### With critical flows (phase 2)

```bash
curl -X POST http://localhost:7777/verify \
  -F binary=@./my-app \
  -F config='{
    "auth": { "strategy": "test-mode" },
    "criticalFlows": [
      "Navigate to Settings",
      "Change display name to Test User",
      "Go back to Dashboard and verify name changed"
    ]
  }' \
  -F manifest='{
    "appType": "gui",
    "hasAuthGate": true,
    "screens": ["Dashboard", "Settings", "Profile"]
  }' \
  -F target=macos-arm64
```

---

## 13. Error Handling

### Pipeline-Level Errors

- **Binary not found / corrupt**: Return step "launch" as failed with error message.
- **Platform not supported**: Return job status "error" with message "Target {target} not supported on this host (running {hostPlatform})".
- **Geisterhand not available**: Degrade gracefully. Launch and screenshot still work. Auth and flows that need UI interaction return "skipped" with a note.
- **AI API unavailable**: Deterministic steps still work. AI-dependent steps return "skipped" with error "AI service unavailable". Never fail the entire job because AI is down — just skip the AI-dependent steps.

### Step-Level Errors

- **Timeout (30s per step)**: Mark step as failed with error "Timed out after 30 seconds".
- **App crashed during verification**: Detect via process exit. Capture whatever logs/stderr exist. Mark current step as failed with crash info.
- **AI returned unparseable response**: Retry once. If still unparseable, mark step as failed with "AI response could not be parsed".

### HTTP-Level Errors

- **Missing required fields**: 400 Bad Request with specific field name.
- **Job not found**: 404 Not Found.
- **Server error**: 500 Internal Server Error with message (never expose stack traces).

---

## 14. Implementation Order

### Week 1: Core Loop

**Day 1-2: Skeleton**
- [ ] HTTP server with POST /verify, GET /verify/:id, GET /health
- [ ] Multipart file upload parsing (save binary to temp dir)
- [ ] In-memory job store
- [ ] Type definitions (all of types.ts)
- [ ] PlatformAdapter interface

**Day 3-4: macOS Adapter (basic)**
- [ ] launch(): spawn process, capture PID
- [ ] waitForReady(): poll for window existence (via `osascript` or Geisterhand)
- [ ] screenshot(): via `screencapture` command
- [ ] kill(): kill process
- [ ] Skip findElement/click/type for now

**Day 5: Pipeline v1**
- [ ] Pipeline executor: launch → waitForReady → screenshot → kill
- [ ] Wire into API: POST /verify triggers pipeline async, GET returns status
- [ ] Test with a real Perry-compiled GUI app
- **Milestone: submit a binary via curl, get back pass/fail + screenshot**

### Week 2: Auth & State Check

**Day 6-7: Geisterhand Integration**
- [ ] findElement() via Geisterhand CLI
- [ ] click() and type() via Geisterhand CLI
- [ ] getAccessibilityTree() via Geisterhand CLI

**Day 8-9: Auth Step**
- [ ] Deterministic auth (find fields by accessibility, fill, submit)
- [ ] AI fallback (screenshot + tree → Claude Haiku → field locations)
- [ ] AI client with cost tracking

**Day 10: State Check**
- [ ] Deterministic state check (search accessibility tree for expected text)
- [ ] AI fallback (screenshot → Claude Haiku → yes/no match)
- **Milestone: submit an app with login, verify it authenticates and reaches expected screen**

### Week 3: Linux + Polish

**Day 11-12: Linux Adapter**
- [ ] launch(), waitForReady() for server apps (process + TCP port check)
- [ ] launch(), waitForReady() for CLI apps (run and check exit code)
- [ ] screenshot() via xdotool/scrot for GUI apps (nice-to-have)

**Day 13-14: Polish & Robustness**
- [ ] Timeout handling on all steps
- [ ] Crash detection (process exit during pipeline)
- [ ] Job cleanup (evict old jobs from memory, delete temp files)
- [ ] Logging throughout
- [ ] Error messages that are actually helpful
- **Milestone: working service for macOS GUI apps + Linux server apps**

### Future (not v1)

- [ ] Critical flows via Claude Sonnet (Phase 2)
- [ ] Windows adapter
- [ ] iOS Simulator adapter (xcrun simctl)
- [ ] Android Emulator adapter (adb)
- [ ] WebSocket streaming for live progress
- [ ] Integration with Perry Publish API
- [ ] Persistent storage (Postgres)
- [ ] Cost budgets (max AI spend per job)
