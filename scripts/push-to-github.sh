#!/usr/bin/env bash
# One-shot: create the repo on your account and push this tree to it.
# Requires the GitHub CLI, already authenticated:  gh auth login
set -euo pipefail

REPO_NAME="${1:-secure-chat-platform}"
VISIBILITY="${2:-private}"

command -v gh >/dev/null || { echo "install the GitHub CLI first: https://cli.github.com"; exit 1; }

git init -q 2>/dev/null || true
git add -A
git -c user.email="${GIT_EMAIL:-$(git config user.email)}" \
    -c user.name="${GIT_NAME:-$(git config user.name)}" \
    commit -qm "Secure real-time chat platform: schema, authorization core, infrastructure" || true
git branch -M main

gh repo create "$REPO_NAME" --"$VISIBILITY" --source=. --remote=origin --push

echo
echo "Pushed. Next:"
echo "  Render:  New > Blueprint, point at this repo, it reads render.yaml"
echo "  Vercel:  New Project > this repo, root directory 'frontend'"
