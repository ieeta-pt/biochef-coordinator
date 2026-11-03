"""Settings, read from the environment or from a .env file.

Every variable starts with COORDINATOR_. example.env lists them.
"""

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ASYNC_DRIVER = "postgresql+psycopg://"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="COORDINATOR_",
        env_file=".env",
        # .env also holds the POSTGRES_ variables that Docker Compose reads.
        extra="ignore",
    )

    database_url: str = Field(
        description="Where Postgres is, as postgresql+psycopg://user:password@host:5432/database.",
    )

    @field_validator("database_url")
    @classmethod
    def _uses_the_async_driver(cls, url: str) -> str:
        # Plain postgresql:// makes SQLAlchemy pick a synchronous driver, which
        # fails on the first query rather than at startup.
        if not url.startswith(ASYNC_DRIVER):
            raise ValueError(f"must start with {ASYNC_DRIVER}")
        return url
