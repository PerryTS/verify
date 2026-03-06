// Launcher helper: select appropriate adapter and start pipeline
import { VerifyJob } from '../api/types'
import { PlatformAdapter } from '../platform/adapter'
import { MacOSAdapter } from '../platform/macos'
import { LinuxAdapter } from '../platform/linux'
import { WindowsAdapter } from '../platform/windows'
import { IOSSimulatorAdapter } from '../platform/ios-simulator'
import { AndroidEmulatorAdapter } from '../platform/android-emulator'
import * as child_process from 'child_process'
import * as os from 'os'

export function createAdapter(job: VerifyJob): PlatformAdapter {
  const target = job.target
  const platform = os.platform()

  if (target === 'macos-arm64' || target === 'macos-x64') {
    // Check if geisterhand is available
    let geisterhandAvailable = false
    try {
      const r = child_process.spawnSync('which', ['geisterhand'])
      if (r) {
        geisterhandAvailable = r.status === 0
      }
    } catch (_) {}
    return new MacOSAdapter(job.id, geisterhandAvailable)
  }

  if (target === 'linux-x64' || target === 'linux-arm64') {
    return new LinuxAdapter(job.id)
  }

  if (target === 'windows-x64') {
    return new WindowsAdapter()
  }

  if (target === 'ios-simulator' || target === 'ipados-simulator') {
    return new IOSSimulatorAdapter()
  }

  if (target === 'android-emulator' || target === 'android-tablet-emulator') {
    return new AndroidEmulatorAdapter()
  }

  throw new Error('Unsupported target platform: ' + target)
}

export function hostPlatform(): string {
  const p = os.platform()
  const a = os.arch()
  if (p === 'darwin') {
    return a === 'arm64' ? 'macos-arm64' : 'macos-x64'
  }
  if (p === 'linux') {
    return a === 'arm64' ? 'linux-arm64' : 'linux-x64'
  }
  if (p === 'win32') {
    return 'windows-x64'
  }
  return p + '-' + a
}
