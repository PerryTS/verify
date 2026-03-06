import * as fs from 'fs';
import * as child_process from 'child_process';

// Cost per million tokens (in cents)
const HAIKU_INPUT_CPM = 80;   // $0.80/MTok
const HAIKU_OUTPUT_CPM = 400; // $4/MTok
const SONNET_INPUT_CPM = 300;  // $3/MTok
const SONNET_OUTPUT_CPM = 1500; // $15/MTok

export interface AIResponse {
  text: string;
  costCents: number;
}

function getApiKey(): string {
  return process.env.ANTHROPIC_API_KEY || '';
}

async function callAnthropic(
  model: string,
  systemPrompt: string,
  userContent: string,
  imageBase64?: string,
  inputCpm: number = HAIKU_INPUT_CPM,
  outputCpm: number = HAIKU_OUTPUT_CPM,
): Promise<AIResponse> {
  const apiKey = getApiKey();
  if (!apiKey) {
    return { text: '', costCents: 0 };
  }

  let userContentArr: object[];
  if (imageBase64) {
    userContentArr = [
      {
        type: 'image',
        source: {
          type: 'base64',
          media_type: 'image/png',
          data: imageBase64,
        },
      },
      {
        type: 'text',
        text: userContent,
      },
    ];
  } else {
    userContentArr = [{ type: 'text', text: userContent }];
  }

  const body = JSON.stringify({
    model: model,
    max_tokens: 1024,
    system: systemPrompt,
    messages: [
      {
        role: 'user',
        content: userContentArr,
      },
    ],
  });

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: body,
    });

    const responseText = await response.text();
    const data = JSON.parse(responseText) as any;
    let text = '';
    if (data.content && data.content.length > 0) {
      const firstBlock = data.content[0];
      if (firstBlock.text) {
        text = firstBlock.text;
      }
    }

    const inputTokens = data.usage ? data.usage.input_tokens : 0;
    const outputTokens = data.usage ? data.usage.output_tokens : 0;
    const costCents = (inputTokens * inputCpm + outputTokens * outputCpm) / 1_000_000;

    return { text, costCents };
  } catch (err) {
    return { text: '', costCents: 0 };
  }
}

export async function askHaiku(
  systemPrompt: string,
  userContent: string,
  imagePath?: string,
): Promise<AIResponse> {
  let imageBase64: string | undefined;
  if (imagePath) {
    imageBase64 = readImageBase64(imagePath);
  }
  return callAnthropic(
    'claude-haiku-4-5-20251001',
    systemPrompt,
    userContent,
    imageBase64,
    HAIKU_INPUT_CPM,
    HAIKU_OUTPUT_CPM,
  );
}

export async function askSonnet(
  systemPrompt: string,
  userContent: string,
  imagePath?: string,
): Promise<AIResponse> {
  let imageBase64: string | undefined;
  if (imagePath) {
    imageBase64 = readImageBase64(imagePath);
  }
  return callAnthropic(
    'claude-sonnet-4-5-20250929',
    systemPrompt,
    userContent,
    imageBase64,
    SONNET_INPUT_CPM,
    SONNET_OUTPUT_CPM,
  );
}

function readImageBase64(imagePath: string): string {
  try {
    // Read binary file then encode to base64 via CLI
    // Perry's readFileSync returns string; use base64 CLI for binary encoding
    const result = child_process.execSync('base64 < ' + imagePath);
    if (!result) return '';
    return result.trim();
  } catch (_) {
    return '';
  }
}

export function parseJsonSafe(text: string): object | null {
  try {
    let cleaned = text.trim();
    if (cleaned.startsWith('```')) {
      const endFence = cleaned.lastIndexOf('```');
      cleaned = cleaned.slice(cleaned.indexOf('\n') + 1, endFence).trim();
    }
    return JSON.parse(cleaned);
  } catch (_) {
    return null;
  }
}
