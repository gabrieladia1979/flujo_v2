# Automatic ECS deployment

The workflow in `.github/workflows/deploy-aws-fargate.yml` builds the image on
every push to `aws-fargate-deployment` and on manual dispatch. It checks the
packaged classifier on a benign and a phishing example before pushing the image
to ECR or updating ECS. The image tag is the Git commit SHA.

One-time setup for the AWS/GitHub administrator:

1. Create an AWS IAM role assumable by GitHub Actions through OIDC. Limit its
   trust policy to `gabrieladia1979/flujo_v2` on branch
   `aws-fargate-deployment`. Grant only the permissions needed to push to ECR
   repository `phisharg-api`, register and update this ECS service, describe
   deployment state, and pass the two existing roles in `task-definition.json`.
2. Add these GitHub **repository variables** in Settings → Secrets and
   variables → Actions: `AWS_DEPLOY_ROLE_ARN`, `ECS_CLUSTER`, `ECS_SERVICE`.
3. Run the `Deploy AWS Fargate` workflow manually once. Later pushes to the
   branch deploy automatically.

The workflow currently uses AWS region `us-east-1`, ECR repository
`phisharg-api`, and the existing ECS task definition. It waits for ECS service
stability and checks that the public API loaded its classifier. The local
classifier smoke check catches the inverted class probability seen in the old
container image. It does not replace a live end-to-end analysis check.

## Security-rule release (21 October 2026)

This branch includes the bilingual content rules from `audit`, gift-card and
payment diversion checks, and offline comparison of displayed URLs with HTML
link destinations. The existing image smoke step now also executes 36 fixed
contrastive rule cases and checks final attack verdicts before publishing to
ECR or updating ECS. These are development regressions, not independent
accuracy measurements. See `docs/SECURITY_RULES_IMPROVEMENTS.md` for remaining
false negatives and model limitations.

The model pickle, SLM download configuration, task roles and API endpoint are
unchanged. The rules ship in the application image; there is no new model
upload or model retraining in this release. Pushing this branch triggers the
existing deployment workflow. A local commit alone does not update AWS.
