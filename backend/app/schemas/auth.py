from pydantic import BaseModel, Field, field_validator



class OtpRequestIn(BaseModel):
    phone: str = Field(min_length=5, max_length=24)
    region: str | None = Field(default=None, max_length=2)

    @field_validator("phone")
    @classmethod
    def _shape(cls, v: str) -> str:
        # Full normalization happens in the route (it needs the region); this only
        # rejects obvious junk before it reaches the rate limiter.
        if not all(c.isdigit() or c in "+ -()" for c in v):
            raise ValueError("invalid characters")
        return v


class OtpRequestOut(BaseModel):
    # Deliberately identical whether or not the number has an account.
    challenge_id: str
    expires_in: int


class OtpVerifyIn(BaseModel):
    challenge_id: str
    code: str = Field(min_length=4, max_length=8)
    phone: str
    region: str | None = None
    platform: str = "WEB"

    @field_validator("code")
    @classmethod
    def _digits(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("invalid code")
        return v


class SessionOut(BaseModel):
    access_token: str
    expires_in: int
    user_id: str
    display_name: str
    is_new_account: bool


class DeviceOut(BaseModel):
    id: str
    platform: str
    label: str
    created_at: str
    last_active_at: str
    is_current: bool
