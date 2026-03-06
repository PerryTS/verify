import { VerifyJob } from '../api/types';
import * as fs from 'fs';

// In-memory job store. Jobs evicted 1 hour after completion.
const jobs: Record<string, VerifyJob> = {};

export function storeJob(job: VerifyJob): void {
  jobs[job.id] = job;
}

export function getJob(jobId: string): VerifyJob | null {
  return jobs[jobId] || null;
}

export function updateJob(job: VerifyJob): void {
  jobs[job.id] = job;
}

// Evict completed jobs older than 1 hour and clean up their temp dirs
function evictOldJobs(): void {
  const now = Date.now();
  const oneHourMs = 60 * 60 * 1000;
  const ids = Object.keys(jobs);
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    const job = jobs[id];
    if (job.completedAt) {
      const completedTime = new Date(job.completedAt).getTime();
      if (now - completedTime > oneHourMs) {
        // Clean up temp directory
        if (job.jobDir) {
          fs.rmRecursive(job.jobDir);
        }
        delete jobs[id];
      }
    }
  }
}

// Run eviction every 5 minutes
setInterval(evictOldJobs, 5 * 60 * 1000);
