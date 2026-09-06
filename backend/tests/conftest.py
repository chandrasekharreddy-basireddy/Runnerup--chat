import os

# Test-only values. Real deployments get these from the platform secret store; the
# config validator rejects anything shorter than 32 chars or the literal placeholder.
os.environ.setdefault("JWT_SIGNING_KEY", "t" * 48)
os.environ.setdefault("OTP_PEPPER", "p" * 48)
os.environ.setdefault("COOKIE_SIGNING_KEY", "c" * 48)
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:ci@localhost:5432/chat_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("S3_ENDPOINT", "http://localhost:9000")
os.environ.setdefault("S3_BUCKET", "test")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")
