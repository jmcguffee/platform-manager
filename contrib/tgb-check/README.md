# tgb-check

A CI check for a GitOps repo (like platform-apps) that renders every Kustomize
overlay and verifies each TargetGroupBinding. It needs no cluster access.

Offline, it checks that each binding:
- names a target group (`targetGroupName` or `targetGroupARN`),
- keeps the target group name within 32 characters,
- points `serviceRef` at a Service and port that exist in the same build, and
- isn't the second binding on the same target group (unless both set `multiClusterTargetGroup`).

With `--aws` (a read-only role via GitHub OIDC), it also checks that the target
group exists, that its target type matches, and that a load balancer is attached.

| File | Goes in the GitOps repo at |
|---|---|
| `check_tgb.py` | `.github/scripts/check_tgb.py` |
| `tgb-check.yml` | `.github/workflows/tgb-check.yml` |
| `iam.tf` | your Terraform, once per account. Put the output ARN in the `TGB_CHECK_ROLE_<ENV>` repo variable |

Run it locally with `python check_tgb.py --discover .` (add `--aws` when you have credentials).
