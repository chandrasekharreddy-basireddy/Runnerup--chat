# Activating CI

`github-actions-ci.yml` is the pipeline. It is parked here because the token used for
the initial push did not carry the `workflow` scope, and GitHub refuses workflow files
from such a token through both git push and the contents API.

To enable it:

    mkdir -p .github/workflows
    git mv ci/github-actions-ci.yml .github/workflows/ci.yml
    git commit -m "Enable CI" && git push

Do that from a local clone authenticated with `gh auth login`, or commit the file
through the GitHub web editor, which is not subject to the scope restriction.

The pipeline gates every other job behind `no-ai-check.sh`, applies the schema against a
real Postgres service container before running tests, and scans full history with
gitleaks so a credential cannot land in a commit unnoticed.
