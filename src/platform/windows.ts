import { PlatformAdapter } from './adapter'
import { VerifyStep, Screenshot, AppManifest, UIElement, ElementQuery, AccessibilityNode } from '../api/types'

export class WindowsAdapter implements PlatformAdapter {
  async launch(): Promise<VerifyStep> {
    throw new Error('Windows platform adapter not yet implemented')
  }
  async waitForReady(): Promise<VerifyStep> {
    throw new Error('Windows platform adapter not yet implemented')
  }
  async screenshot(): Promise<Screenshot | null> {
    throw new Error('Windows platform adapter not yet implemented')
  }
  async findElement(): Promise<UIElement | null> {
    throw new Error('Windows platform adapter not yet implemented')
  }
  async click(): Promise<void> {
    throw new Error('Windows platform adapter not yet implemented')
  }
  async type(): Promise<void> {
    throw new Error('Windows platform adapter not yet implemented')
  }
  async getAccessibilityTree(): Promise<AccessibilityNode | null> {
    throw new Error('Windows platform adapter not yet implemented')
  }
  getLogs(): string {
    throw new Error('Windows platform adapter not yet implemented')
  }
  async kill(): Promise<void> {
    throw new Error('Windows platform adapter not yet implemented')
  }
}
