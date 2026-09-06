# No-AI policy

The product surface contains no AI or ML components. Concretely, none of the following
exist in this codebase and none may be added without changing this document first:

- suggested/smart replies, autocomplete of message text, tone rewriting
- thread or conversation summarization
- AI search, semantic search, embeddings, vector columns or vector indexes
- automated moderation classifiers acting on message content
- assistant/bot participants in conversations
- any outbound call to a model provider

Search is PostgreSQL full-text (`tsvector` + GIN), filtered by membership before the
index is consulted. Moderation is human review of user reports, backed by an audit log.
Spam controls are deterministic counters and thresholds, not classifiers.

Enforcement: `scripts/no-ai-check.sh` runs in CI and fails the build on any banned
import or model endpoint string.
