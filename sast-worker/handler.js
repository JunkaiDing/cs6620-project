// handler.js — SAST worker Lambda
//
// Triggered by the secureci-sast-jobs SQS queue. For each job message:
//   1. parse Junkai's job schema  { job_id, repo, pr_number, commit_sha, job_type, ... }
//   2. download the repo at commit_sha from GitHub (tarball, no git binary needed)
//   3. run the regex scanner over the extracted source
//   4. write the full JSON report to S3
//   5. update the job row in DynamoDB (status + summary + S3 key)
//
// Failure handling: if the handler throws, the SQS message is NOT deleted, so it
// is retried. After maxReceiveCount (3) it lands in secureci-sast-dlq automatically.
// That redrive is configured on the QUEUE in CloudFormation — nothing to do here.

import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { pipeline } from 'node:stream/promises';
import { createWriteStream } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanDirectory } from './scanner.js';

const REGION = process.env.AWS_REGION || 'us-east-1';
const REPORTS_BUCKET = process.env.REPORTS_BUCKET;          // your own S3 bucket
const JOBS_TABLE = process.env.DYNAMODB_TABLE || 'secureci-jobs'; // Junkai's shared table
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';         // optional, for private repos / rate limit

const s3 = new S3Client({ region: REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: REGION }));

const nowIso = () => new Date().toISOString();

async function updateJob(jobId, fields) {
  const names = {};
  const values = {};
  const sets = [];
  for (const [k, v] of Object.entries(fields)) {
    names[`#${k}`] = k;
    values[`:${k}`] = v;
    sets.push(`#${k} = :${k}`);
  }
  await ddb.send(new UpdateCommand({
    TableName: JOBS_TABLE,
    Key: { job_id: jobId },
    UpdateExpression: `SET ${sets.join(', ')}`,
    ExpressionAttributeNames: names,
    ExpressionAttributeValues: values,
  }));
}

// Download + extract a GitHub repo at a commit into a temp dir. Returns the dir path.
async function fetchRepo(repo, commitSha) {
  const workdir = await mkdtemp(join(tmpdir(), 'sast-'));
  const tarPath = join(workdir, 'repo.tar.gz');

  // codeload serves a tarball for any ref without needing git
  const url = `https://codeload.github.com/${repo}/tar.gz/${commitSha}`;
  const headers = GITHUB_TOKEN ? { Authorization: `token ${GITHUB_TOKEN}` } : {};
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`GitHub download failed: ${res.status} ${url}`);

  await pipeline(res.body, createWriteStream(tarPath));
  // tar is available in the Lambda Node runtime image
  execFileSync('tar', ['-xzf', tarPath, '-C', workdir]);
  return workdir; // scanDirectory skips node_modules / dotfiles on its own
}

export const handler = async (event) => {
  // SQS can deliver a batch; process each record independently.
  for (const record of event.Records) {
    let job;
    try {
      job = JSON.parse(record.body);
    } catch {
      console.error('Unparseable message body, skipping:', record.body);
      continue; // bad JSON will never succeed; don't poison the queue
    }

    // Safety net: only handle SAST jobs even if a pentest message slips in.
    if (job.job_type && job.job_type !== 'sast') {
      console.log(`Skipping non-sast job ${job.job_id} (${job.job_type})`);
      continue;
    }

    const jobId = job.job_id;
    let workdir;
    try {
      await updateJob(jobId, { status: 'running', updated_at: nowIso() });

      workdir = await fetchRepo(job.repo, job.commit_sha);
      const results = scanDirectory(workdir);

      const all = Object.values(results).flat();
      const summary = {
        filesScanned: Object.keys(results).length,
        totalVulnerabilities: all.length,
        high: all.filter(v => v.severity === 'HIGH').length,
        medium: all.filter(v => v.severity === 'MEDIUM').length,
        low: all.filter(v => v.severity === 'LOW').length,
      };

      const report = {
        job_id: jobId,
        repo: job.repo,
        pr_number: job.pr_number,
        commit_sha: job.commit_sha,
        scannedAt: nowIso(),
        summary,
        results,
      };

      const s3Key = `reports/${jobId}.json`;
      await s3.send(new PutObjectCommand({
        Bucket: REPORTS_BUCKET,
        Key: s3Key,
        Body: JSON.stringify(report, null, 2),
        ContentType: 'application/json',
      }));

      await updateJob(jobId, {
        status: 'completed',
        updated_at: nowIso(),
        report_s3_key: s3Key,
        summary,
      });

      console.log(`Job ${jobId} done: ${summary.totalVulnerabilities} findings`);
    } catch (err) {
      console.error(`Job ${jobId} failed:`, err);
      // Mark failed for visibility, then rethrow so SQS retries / dead-letters.
      try { await updateJob(jobId, { status: 'failed', updated_at: nowIso(), error: String(err.message || err) }); }
      catch (e2) { console.error('Could not write failed status:', e2); }
      throw err;
    } finally {
      if (workdir) await rm(workdir, { recursive: true, force: true }).catch(() => {});
    }
  }

  return { ok: true };
};