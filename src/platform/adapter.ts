import { VerifyStep, Screenshot, AppManifest, UIElement, ElementQuery, AccessibilityNode } from '../api/types'

export interface PlatformAdapter {
  launch(binaryPath: string, env?: Record<string, string>): Promise<VerifyStep>
  waitForReady(manifest: AppManifest): Promise<VerifyStep>
  screenshot(savePath: string): Promise<Screenshot | null>
  findElement(query: ElementQuery): Promise<UIElement | null>
  click(element: UIElement): Promise<void>
  type(element: UIElement, text: string): Promise<void>
  getAccessibilityTree(): Promise<AccessibilityNode | null>
  getLogs(): string
  kill(): Promise<void>
}
