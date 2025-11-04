import os
from datetime import timedelta


class Config:
    JWT_SECRET_KEY = "change-this-in-production"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_TOKEN_LOCATION = ["headers"]
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    _icn = os.getenv("INSTANCE_CONNECTION_NAME")
    _db_user = os.getenv("DB_USER", "postgres")
    _db_pass = os.getenv("DB_PASS", "")
    _db_name = os.getenv("DB_NAME", "web3jobs")

    if os.getenv("GAE_ENV") or os.getenv("K_SERVICE"):  # running on GCP (Run/AppEngine)
        SQLALCHEMY_DATABASE_URI = (
            f"postgresql+pg8000://{_db_user}:{_db_pass}"
            f"@/{_db_name}?unix_sock=/cloudsql/{_icn}/.s.PGSQL.5432"
        )
    else:
        # Local dev (adjust host/port)
        SQLALCHEMY_DATABASE_URI = os.getenv(
            "SQLALCHEMY_DATABASE_URI",
            f"postgresql+pg8000://{_db_user}:{_db_pass}@127.0.0.1:5432/{_db_name}"
        )