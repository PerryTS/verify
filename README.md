# Perry Verify

Standalone verification service for the [Perry](https://github.com/PerryTS/perry) ecosystem. Accepts compiled application binaries, runs automated verification pipelines (launch, auth, UI interaction, state checks), and returns structured results with screenshots.

## How It Works

```
POST /verify ──► Manager ──WebSocket──► Worker
  (binary +        │                      │
   config)         │                      ├─ launch binary
                   │                      ├─ wait for ready
                   │                      ├─ screenshot
                   │                      ├─ authenticate (deterministic or AI)
                   │                      ├─ verify state
                   │                      └─ run critical flows (AI)
                   │                      │
GET /verify/:id ◄──── results + screenshots
```

1. Submit a compiled binary with config and manifest via HTTP
2. The worker launches the app, waits for it to be ready, and takes a screenshot
3. If the app has an auth gate, the worker fills in credentials (via accessibility APIs, with AI fallback)
4. State checks verify the app reached the expected screen
5. Optional critical flows use AI to navigate and test specific user journeys
6. Results include pass/fail per step, screenshots, logs, and AI cost tracking

## Architecture

- **Manager** (`src/main.ts`) — HTTP API + WebSocket server for coordinating workers
- **Worker** (`src/worker.ts`) — Connects to manager, executes verification jobs on the host platform
- **Platform adapters** — macOS (via Geisterhand), Linux (via xdotool/AT-SPI), with stubs for Windows, iOS Simulator, and Android Emulator
- **AI client** — Claude Haiku/Sonnet for UI element identification and critical flow execution
- **Audit scanner** — Static analysis of source code for security vulnerabilities

## Tech Stack

- **TypeScript** compiled to native binary by the [Perry compiler](https://github.com/PerryTS/perry)
- HTTP: Fastify
- WebSocket: ws
- AI: Anthropic API (Claude)

## Building

```sh
perry compile src/main.ts -o dist/perry-verify
perry compile src/worker.ts -o dist/perry-verify-worker
```

## Running

```sh
# Start the manager
PERRY_VERIFY_PORT=7777 \
PERRY_VERIFY_WS_PORT=7778 \
./dist/perry-verify

# Start a worker (on same or different machine)
PERRY_VERIFY_MANAGER_URL=ws://localhost:7778 \
ANTHROPIC_API_KEY=sk-ant-... \
./dist/perry-verify-worker
```

## Configuration

### Manager

| Variable | Default | Description |
|---|---|---|
| `PERRY_VERIFY_PORT` | `7777` | HTTP server port |
| `PERRY_VERIFY_WS_PORT` | `7778` | WebSocket server port |
| `PERRY_VERIFY_PUBLIC_URL` | `https://verify.perryts.com` | Public URL for download links |
| `PERRY_VERIFY_AUTH_TOKEN` | *(empty)* | Auth token for worker connections |
| `PERRY_VERIFY_TEMP_DIR` | `/tmp/perry-verify` | Temp directory for job files |

### Worker

| Variable | Default | Description |
|---|---|---|
| `PERRY_VERIFY_MANAGER_URL` | `ws://verify.perryts.com:7778` | Manager WebSocket URL |
| `PERRY_VERIFY_AUTH_TOKEN` | *(empty)* | Auth token for manager connection |
| `PERRY_VERIFY_WORKER_NAME` | hostname | Worker display name |
| `PERRY_VERIFY_WORK_DIR` | `/tmp/perry-verify-worker` | Working directory for builds |
| `PERRY_VERIFY_SANDBOX` | `true` | Enable sandboxed execution |
| `PERRY_VERIFY_JOB_TIMEOUT` | `120` | Job timeout in seconds |
| `ANTHROPIC_API_KEY` | *(empty)* | Anthropic API key for AI-powered steps |

## API

### `POST /verify`

Submit a binary for verification (multipart/form-data):
- `binary` — compiled application binary or `.tar.gz` bundle
- `config` — JSON with auth strategy, credentials, critical flows
- `manifest` — JSON with app type, screens, ports
- `target` — target platform (e.g. `macos-arm64`, `linux-x64`)

### `GET /verify/:jobId`

Poll for job status, steps, screenshots, logs, and AI cost.

### `GET /verify/:jobId/screenshots/:filename`

Download a screenshot taken during verification.

### `POST /audit`

Submit source code for static security analysis.

### `GET /health`

Service health check with platform and capability info.

## Verification Steps

| Step | Method | Description |
|---|---|---|
| **Launch** | Deterministic | Spawn the binary, set up environment |
| **Ready** | Deterministic | Wait for window (GUI) or port (server) |
| **Auth** | Deterministic + AI fallback | Fill login forms via accessibility APIs or Claude |
| **State Check** | Deterministic + AI fallback | Verify expected screen reached |
| **Critical Flows** | AI (Claude Sonnet) | Navigate and test user journeys |

## Platform Support

| Platform | Status | UI Automation |
|---|---|---|
| macOS | Supported | Geisterhand + Accessibility API |
| Linux | Supported | xdotool + AT-SPI |
| Windows | Stub | — |
| iOS Simulator | Stub | — |
| Android Emulator | Stub | — |

## Related Repos

- [perry](https://github.com/PerryTS/perry) — The Perry compiler and CLI
- [hub](https://github.com/PerryTS/hub) — Central build server
- [builder-macos](https://github.com/PerryTS/builder-macos) — macOS build worker
- [builder-linux](https://github.com/PerryTS/builder-linux) — Linux build worker
- [builder-windows](https://github.com/PerryTS/builder-windows) — Windows build worker

## License

MIT
