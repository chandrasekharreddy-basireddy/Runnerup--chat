#!/usr/bin/env bash
# Generates a real .env with cryptographically random secrets and brings the stack up.
# Idempotent: an existing .env is never overwritten, so re-running will not rotate your
# keys out from under a running database.
set -euo pipefail
cd "$(dirname "$0")/.."

rand() { openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-48; }

if [ -f .env ]; then
  echo ".env already exists — leaving it alone."
else
  echo "Generating .env with fresh secrets..."
  DB_PW=$(rand); REDIS_PW=$(rand); S3_KEY=$(rand); S3_SECRET=$(rand)
  cat > .env <<EOF
ENVIRONMENT=development
LOG_LEVEL=INFO

JWT_SIGNING_KEY=$(rand)
OTP_PEPPER=$(rand)
COOKIE_SIGNING_KEY=$(rand)

ACCESS_TOKEN_TTL_SECONDS=600
REFRESH_TOKEN_TTL_SECONDS=2592000
OTP_TTL_SECONDS=300
OTP_MAX_ATTEMPTS=5

POSTGRES_DB=chat
POSTGRES_USER=chat_app
POSTGRES_PASSWORD=${DB_PW}
POSTGRES_SUPERUSER_PASSWORD=$(rand)
DATABASE_URL=postgresql://chat_app:${DB_PW}@postgres:5432/chat

REDIS_PASSWORD=${REDIS_PW}
REDIS_URL=redis://:${REDIS_PW}@redis:6379/0

S3_ENDPOINT=http://minio:9000
S3_REGION=us-east-1
S3_BUCKET=chat-media
S3_ACCESS_KEY=${S3_KEY}
S3_SECRET_KEY=${S3_SECRET}
MAX_UPLOAD_BYTES=52428800

SMS_PROVIDER=console
ALLOWED_ORIGINS=http://localhost:3000,https://localhost
PUBLIC_WEB_ORIGIN=http://localhost:3000
EOF
  chmod 600 .env
  echo "  .env written (mode 600). It is gitignored; do not commit it."
fi

# 0002 ships with a placeholder instead of a password. Render it with the real one at
# startup rather than storing a credential in a tracked file.
set -a; . ./.env; set +a
mkdir -p .runtime/initdb
cp backend/migrations/0001_init.sql .runtime/initdb/01_schema.sql
sed "s/REPLACE_ME_FROM_SECRET_STORE/${POSTGRES_PASSWORD}/" \
  backend/migrations/0002_roles.sql > .runtime/initdb/02_roles.sql
chmod 600 .runtime/initdb/02_roles.sql

if ! command -v docker >/dev/null; then
  echo "Docker not found. Install Docker Desktop, then re-run this script."
  exit 1
fi

echo "Starting services..."
docker compose up --build -d
echo
echo "Waiting for the API to become healthy..."
for i in $(seq 1 60); do
  if curl -sf http://localhost/api/v1/health >/dev/null 2>&1; then
    echo "  API is up."
    break
  fi
  sleep 2
done

cat <<'EOF'

Ready.

  Web        http://localhost:3000
  API        http://localhost/api/v1/health
  MinIO      http://localhost:9001

To sign in: enter any phone number, then read the six-digit code out of the API log —
the development SMS provider prints it instead of sending a text:

  docker compose logs -f api | grep dev-sms

That provider refuses to start when ENVIRONMENT=production, so it cannot leak a real
code into a real log pipeline.
EOF
