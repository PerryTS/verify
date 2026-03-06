import * as path from 'path'

const BASE_DIR = process.env['PERRY_VERIFY_TEMP_DIR'] || '/tmp/perry-verify'

export function jobDir(jobId: string): string {
  return path.join(BASE_DIR, 'jobs', jobId)
}

export function screenshotPath(jobId: string, stepName: string): string {
  return path.join(jobDir(jobId), 'screenshots', slugify(stepName) + '.png')
}

export function logFilePath(jobId: string): string {
  return path.join(jobDir(jobId), 'app.log')
}

export function binaryPath(jobId: string): string {
  return path.join(jobDir(jobId), 'binary')
}

export function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
}
