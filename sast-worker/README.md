# SecureCI — SAST Worker slice

My slice of SecureCI: an SQS-triggered Lambda that runs a static scanner over the
code in a GitHub PR, writes a JSON report to S3, and updates the job row in the
shared DynamoDB table. Failed jobs are retried and dead-lettered automatically.

```
GitHub PR ─▶ Junkai's API ─▶ secureci-sast-jobs (SQS)
                                     │
                                     ▼
                            secureci-sast-worker (Lambda)
                              • download repo @ commit
                              • run scanner.js
                              • write report ─▶ S3 (secureci-sast-reports-<acct>)
                              • update status ─▶ DynamoDB (secureci-jobs, shared)
                                     │ (on repeated failure)
                                     ▼
                            secureci-sast-dlq (SQS)
```

## Files
- `scanner.js`   — scanning brain, copied unchanged from `cs6620/sast/backend`. (Express `server.js` was NOT copied; Lambda is triggered by SQS, not HTTP.)
- `handler.js`   — Lambda handler: parse SQS msg → fetch repo → scan → S3 + DynamoDB.
- `cloudformation.yaml` — SAST queue + DLQ, S3 reports bucket, Lambda, event mapping. Uses `LabRole`.
- `local-test.js` — run the scanner locally with no AWS.
- `NOTE-FOR-JUNKAI.md` — the one-line queue-routing change his API needs.

## Local test (no AWS)
```bash
npm install
node local-test.js /path/to/some/js/project
```

## Deploy (Learner Lab)
```bash
# 1. zip the Lambda package
npm install --omit=dev
zip -r sast-worker.zip handler.js scanner.js node_modules package.json

# 2. upload the zip to any S3 bucket you can write to
aws s3 cp sast-worker.zip s3://<your-code-bucket>/sast-worker.zip

# 3. deploy the stack
aws cloudformation deploy \
  --template-file cloudformation.yaml \
  --stack-name secureci-sast \
  --parameter-overrides \
      LambdaCodeBucket=<your-code-bucket> \
      LambdaCodeKey=sast-worker.zip

# 4. take the SastQueueURL output and give it to Junkai's API as SAST_QUEUE_URL
aws cloudformation describe-stacks --stack-name secureci-sast \
  --query "Stacks[0].Outputs"
```

## Notes / constraints
- Uses `LabRole` (Learner Lab can't create custom IAM roles).
- Lambda timeout 120s; queue VisibilityTimeout 180s (must be ≥ timeout).
- Repo download uses the codeload tarball — public repos work as-is; private repos need `GitHubToken`.
- Retry/DLQ is configured on the queue (`maxReceiveCount: 3`), so the handler just throws on failure and SQS handles the rest.