# Hybrid XAI pilot on AWS

Branch: `codex/hybrid-xai-aws`. It deploys a **separate** ECS service and ECR
repository, and serves `/api/v1/analyze/hybrid`. The existing
`aws-fargate-deployment` service and `/api/v1/analyze` remain independent.

## Model artifact (one-time setup)

The 470 MB encoder is intentionally excluded from Git and the Docker image.
The locally packaged inference-only ZIP is
`artifacts/hybrid/upload/multilingual-candidate-v3-curated-inference.zip`.
For the ZIP generated on this branch, SHA-256 is
`7319227028657087f33546423ad3d49d52d9d57842269bdce7c02ad17bf8daa6`.
Confirm it with `Get-FileHash` before upload. To regenerate the ZIP:

```powershell
python -m scripts.package_hybrid --model artifacts/hybrid/multilingual-candidate-v3-curated --output artifacts/hybrid/upload/multilingual-candidate-v3-curated-inference.zip
```

You can reuse the same private S3 bucket as the `audit` Fargate task
(`phisharg-models-668281913895-us-east-1-an`). The current SLM object is
`qwen2.5-3b-instruct-q4_k_m.gguf`; the Hybrid ZIP is a **different object**.
Upload the **exact ZIP** to that versioned S3 bucket, using key
`hybrid/multilingual-candidate-v3-curated/v1/model.zip`. Record the returned
`VersionId` and the ZIP SHA-256. Never use a bucket with public access. The
ECS task role must be able to `s3:GetObjectVersion` for this object; a narrow
example is in `task-role-policy-hybrid.json`.

For example, with AWS CLI credentials authorized to upload to the existing
bucket:

```powershell
aws s3api put-object --bucket phisharg-models-668281913895-us-east-1-an --key hybrid/multilingual-candidate-v3-curated/v1/model.zip --body artifacts/hybrid/upload/multilingual-candidate-v3-curated-inference.zip --region us-east-1
```

The command returns the `VersionId` to put in GitHub Actions. Recalculate
`HYBRID_MODEL_SHA256` if you regenerate the ZIP; ZIP metadata can change its
hash even when the model files remain the same.

## One-time AWS and GitHub configuration

An AWS administrator creates ECR repository `phisharg-hybrid`, an ECS cluster
or uses an existing cluster, and a **separate** ECS service named for the
Hybrid pilot, using the existing VPC, ALB routing and port 8080. Create the
CloudWatch log group `/ecs/phisharg-hybrid`. The task has 2 vCPU, 8 GiB RAM,
and 30 GiB ephemeral storage as a starting point. Measure memory and p95
latency before increasing traffic.

The task execution role must read the two Secrets Manager values below and
pull ECR images. The task role needs the S3 permission above. Use an API key
of at least 32 characters and a separate token signing key of at least 32
characters. If browser tokens are used across multiple tasks, configure a
shared replay table; the current in-memory replay check is appropriate only
for a one-task pilot.

Create a GitHub Actions OIDC role scoped to this repository and branch, with
permissions to read the pinned S3 object, push this ECR repository, register
task revisions, update/describe the **pilot** ECS service, and pass its task
roles. Add these repository variables in GitHub Actions:

| Variable | Value |
|---|---|
| `HYBRID_AWS_DEPLOY_ROLE_ARN` | Pilot-only GitHub OIDC deploy role |
| `ECS_EXECUTION_ROLE_ARN` | Existing or pilot execution role |
| `HYBRID_TASK_ROLE_ARN` | Pilot task role with versioned S3 read |
| `API_KEY_SECRET_ARN` | Secrets Manager ARN for `API_KEY` |
| `TOKEN_KEY_SECRET_ARN` | Secrets Manager ARN for `PHISHARG_TOKEN_KEY` |
| `HYBRID_MODEL_BUCKET` | Private S3 bucket |
| `HYBRID_MODEL_VERSION_ID` | Version ID from exact ZIP upload |
| `HYBRID_MODEL_SHA256` | Lowercase SHA-256 of exact ZIP |
| `SLM_MODEL_S3_BUCKET` | Private bucket used by the existing audit Qwen task |
| `SLM_MODEL_S3_KEY` | `qwen2.5-3b-instruct-q4_k_m.gguf` |
| `SLM_MODEL_S3_VERSION_ID` | Version ID of the existing Qwen object |
| `SLM_MODEL_SHA256` | SHA-256 of that GGUF version |
| `HYBRID_ECS_CLUSTER` | ECS cluster name |
| `HYBRID_ECS_SERVICE` | Separate pilot service name |
| `HYBRID_PUBLIC_URL` | Optional HTTPS base URL for readiness check |

Run the `Deploy Hybrid XAI pilot` workflow manually after uploading the model.
Publishing this branch does not deploy ECS. The workflow downloads and verifies the
pinned ZIP, builds the image, runs three classifier smoke cases inside the
image, pushes a commit-SHA image to ECR, updates the **pilot** ECS service,
waits for stability, and optionally checks its public readiness endpoint.

The add-in branch `codex/hybrid-xai-addin` calls this pilot's Hybrid route.
For its Vercel deployment, set `API_BASE_URL` to the pilot HTTPS URL and
`PHISHARG_TOKEN_KEY` to the **same value** held by the ECS token secret.
Its token endpoint also requires `PHISHARG_RATE_LIMIT_ID` in Vercel. Do not
point the main add-in at the pilot until the new service and authentication
are tested.

## Promotion decision

The local model gave low raw scores on shortened benign meeting and Microsoft
terms examples, but this does not establish accuracy on the original messages
or an independent deployment dataset. A credential-theft example scored
0.8294, below the model threshold 0.8901; content rules must detect it.
Before promotion, evaluate a blinded set of real benign and malicious mail,
especially account notices, newsletters, internal summaries and credential
requests. Measure false positives, false negatives, startup time, p95 quick
verdict latency, full XAI latency, and memory. The saved candidate report
notes possible data leakage and uncalibrated probabilities.

## Security-rule release (21 October 2026)

This branch includes the shared bilingual rules from audit, credential and
MFA reformulations, gift-card/payment diversion checks, and offline URL-label
versus HTML destination comparison. The image smoke gate runs the three
original model cases plus 36 contrastive rule cases; malicious cases also
exercise the final quick verdict. Benign rule cases do not override known
model false positives. See `docs/SECURITY_RULES_IMPROVEMENTS.md` for results
and remaining limitations. No classifier weights or model ZIP changed.

The temporary `.hybrid-model/` download used by GitHub Actions is excluded
from the Docker context. The running task still obtains the pinned, verified
artifact from S3. Local environments are also excluded from the image.

This remains a separate Hybrid pilot. Required repository variables, S3
version/hash and pilot ECS infrastructure must be configured as described
above. This task now downloads and verifies the same versioned Qwen GGUF as
audit and preloads it before readiness. `llama-cpp-python` executes Qwen on
CPU; it is not a different language model. The audit task definition records
version `tCL4aY4DPIHhTK_l5OL97o5VnWNsXiam` and SHA-256
`c3ba6d838a8615e9048c9d37642c5009ed0195fd8783eb04384102ffecd75cc5`.
Check these against the live bucket before deployment. Full phishing
explanations invoke Qwen, with deterministic fallback on failure. Deployments
start only when the GitHub Actions workflow is run manually.
