#!/usr/bin/env bash
set -euo pipefail

# Configure GitHub branch protection on `main` using GitHub CLI (`gh`).
# Usage: ./scripts/setup_github_branch_protection.sh ianloe/aegis-harness

REPO="${1:-ianloe/aegis-harness}"
BRANCH="${2:-main}"

echo "Applying branch protection to ${REPO} (${BRANCH})..."

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/${REPO}/branches/${BRANCH}/protection" \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["harness-gates"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  "/repos/${REPO}/branches/${BRANCH}/protection/required_signatures"

echo "Branch protection and signed-commit enforcement enabled for ${REPO}:${BRANCH}."
