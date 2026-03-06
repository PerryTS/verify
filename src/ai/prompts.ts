// Structured prompts for perry-verify AI steps
// Perry cannot export const strings across modules — use functions instead

export function authSystemPrompt(): string {
  return 'You are a UI automation assistant. Given a screenshot and accessibility tree of a login screen, identify the username field, password field, and submit button.\n\nReturn JSON only, no explanation. Format:\n{\n  "usernameField": { "label": "...", "role": "...", "x": 0, "y": 0, "width": 0, "height": 0 },\n  "passwordField": { "label": "...", "role": "...", "x": 0, "y": 0, "width": 0, "height": 0 },\n  "submitButton": { "label": "...", "role": "...", "x": 0, "y": 0, "width": 0, "height": 0 }\n}\n\nIf any element cannot be found, set it to null.';
}

export function stateCheckSystemPrompt(): string {
  return 'You are verifying a UI state. Answer with JSON only, no explanation.';
}

export function flowSystemPrompt(): string {
  return 'You are a UI testing agent. Given the current screen state and an instruction, determine the next action to take.\n\nReturn JSON only:\n{\n  "completed": false,\n  "action": "click" | "type" | "scroll" | "wait",\n  "target": { "label": "...", "role": "..." },\n  "typeText": "...",\n  "reasoning": "..."\n}\n\nIf the instruction has been completed, set "completed" to true.';
}

export function stateCheckUserPrompt(expectedState: string): string {
  return 'Does this screen appear to show: \'' + expectedState + '\'?\nRespond with: { "matches": true/false, "confidence": 0.0-1.0, "reason": "..." }';
}

export function flowUserPrompt(instruction: string, treeJson: string): string {
  return 'Instruction: \'' + instruction + '\'\nCurrent accessibility tree: ' + treeJson + '\n\nWhat is the next action to take?';
}
