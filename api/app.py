import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone

import boto3
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="SecureCI API")

# ─── AWS Clients ──────────────────────────────────────────────────────
REGION = os.getenv("AWS_REGION", "us-east-1")
DYNAMODB_TABLE = os.getenv("DYNAMODB_TABLE", "secureci-jobs")
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
SSM_WEBHOOK_SECRET = os.getenv("SSM_WEBHOOK_SECRET", "/secureci/webhook-secret")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sqs = boto3.client("sqs", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
table = dynamodb.Table(DYNAMODB_TABLE)


def get_webhook_secret() -> str:
    """Fetch webhook secret from Parameter Store."""
    resp = ssm.get_parameter(Name=SSM_WEBHOOK_SECRET, WithDecryption=False)
    return resp["Parameter"]["Value"]


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub HMAC-SHA256 webhook signature."""
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def create_job(job_id: str, repo: str, pr_number: int, commit_sha: str, job_type: str) -> dict:
    """Write a new job record to DynamoDB."""
    now = datetime.now(timezone.utc).isoformat()
    # TTL: 90 days from now
    ttl = int(datetime.now(timezone.utc).timestamp()) + 90 * 24 * 3600

    item = {
        "job_id": job_id,
        "repo": repo,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "job_type": job_type,
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "ttl": ttl,
    }
    table.put_item(Item=item)
    return item


def enqueue_job(job: dict):
    """Push job to SQS."""
    sqs.send_message(
        QueueUrl=SQS_QUEUE_URL,
        MessageBody=json.dumps(job),
        MessageAttributes={
            "job_type": {
                "StringValue": job["job_type"],
                "DataType": "String",
            }
        },
    )


def post_pr_comment(repo: str, pr_number: int, job_id: str, job_type: str):
    """Post an acknowledgement comment to the GitHub PR."""
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return  # skip if no token configured yet

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    body = (
        f"🔍 **SecureCI** — `{job_type.upper()}` scan queued.\n\n"
        f"- Job ID: `{job_id}`\n"
        f"- Status: `queued`\n\n"
        f"Results will be posted here when the scan completes."
    )
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    requests.post(url, json={"body": body}, headers=headers, timeout=10)


# ─── Routes ───────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "secureci-api"}


@app.post("/webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    payload = await request.body()

    # 1. Verify signature
    if not x_hub_signature_256:
        raise HTTPException(status_code=400, detail="Missing signature header")

    secret = get_webhook_secret()
    if not verify_signature(payload, x_hub_signature_256, secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 2. Only handle pull_request events
    if x_github_event != "pull_request":
        return JSONResponse({"message": f"Ignored event: {x_github_event}"})

    data = json.loads(payload)
    action = data.get("action")

    # Only trigger on opened / synchronize (new commits pushed to PR)
    if action not in ("opened", "synchronize"):
        return JSONResponse({"message": f"Ignored action: {action}"})

    # 3. Extract PR info
    repo = data["repository"]["full_name"]
    pr_number = data["pull_request"]["number"]
    commit_sha = data["pull_request"]["head"]["sha"]

    # 4. Create job + enqueue
    job_id = str(uuid.uuid4())
    job = create_job(job_id, repo, pr_number, commit_sha, job_type="sast")
    enqueue_job(job)

    # 5. Post acknowledgement comment to PR
    post_pr_comment(repo, pr_number, job_id, job_type="sast")

    return JSONResponse({
        "message": "Job queued",
        "job_id": job_id,
        "repo": repo,
        "pr_number": pr_number,
    })


@app.post("/scans")
async def trigger_pentest(request: Request):
    """Manually trigger a pentest job (called from dashboard or curl)."""
    data = await request.json()
    target_url = data.get("target_url")
    repo = data.get("repo", "manual")
    pr_number = data.get("pr_number", 0)

    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")

    job_id = str(uuid.uuid4())
    job = create_job(job_id, repo, pr_number, commit_sha="manual", job_type="pentest")
    job["target_url"] = target_url
    enqueue_job(job)

    return JSONResponse({
        "message": "Pentest job queued",
        "job_id": job_id,
        "target_url": target_url,
    })


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    """Check status of a specific job."""
    resp = table.get_item(Key={"job_id": job_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Job not found")
    return item


@app.get("/jobs")
def list_jobs(limit: int = 20):
    """List recent jobs."""
    resp = table.scan(Limit=limit)
    return {"jobs": resp.get("Items", []), "count": resp.get("Count", 0)}
