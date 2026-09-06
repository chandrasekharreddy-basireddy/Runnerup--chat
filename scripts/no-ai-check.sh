#!/usr/bin/env bash
# Fails the build if an AI/LLM dependency or model endpoint is introduced anywhere.
# This product has no AI surface by design. See docs/no-ai-policy.md.
set -uo pipefail

BANNED_IMPORTS='@anthropic-ai/|[^a-z]openai|langchain|llamaindex|@huggingface|onnxruntime|@tensorflow|vercel/ai|ai-sdk|cohere|replicate|sentence-transformers|pgvector'
BANNED_HOSTS='api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.cohere\.ai'

fail=0
scan() {
  if grep -rInE "$1" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.py' \
       --include='package.json' --include='requirements.txt' \
       --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=scripts . ; then
    echo "^^ blocked: $2" >&2; fail=1
  fi
}
scan "$BANNED_IMPORTS" "AI/ML dependency"
scan "$BANNED_HOSTS" "model provider endpoint"
[ $fail -eq 0 ] && echo "no-ai check passed"
exit $fail
