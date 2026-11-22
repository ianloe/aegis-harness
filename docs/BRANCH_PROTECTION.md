# Branch Protection Guidance (GitHub and GitLab)

To ensure Harness check-in gates cannot be bypassed locally, configure server-side branch protection on `main`.

## GitHub

1. Run the provided setup script (requires `gh auth login` with repo admin rights):
   ```bash
   ./scripts/setup_github_branch_protection.sh ianloe/aegis-harness main
   ```
2. Verify in **Settings > Branches > Branch protection rules**:
   - Require a pull request before merging (minimum 1 approval; 2 approvals for high-risk repositories).
   - Dismiss stale pull request approvals when new commits are pushed.
   - Require status checks to pass (`harness-gates`).
   - Require signed commits.
   - Do not allow force pushes or deletions.
   - Include administrators (`enforce_admins: true`).

## GitLab Equivalents

In **Settings > Repository > Protected branches** and **Merge requests**:
1. Protect `main`: **Allowed to merge**: Maintainers; **Allowed to push and merge**: No one (force merges via Merge Requests).
2. Enable **Pipelines must succeed** under **Settings > Merge requests > Merge checks** and run the Harness gate job in `.gitlab-ci.yml`.
3. Under **Settings > Repository > Push rules**, enable **Reject unsigned commits** (`reject_unsigned_commits: true`) and **Prevent pushing secret files**.
4. Set **Merge request approvals** to require at least 1 approval (2 for high-risk), enable **Prevent approval by author**, and **Reset approvals on push**.
