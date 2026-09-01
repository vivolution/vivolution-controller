import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from django.core.exceptions import ImproperlyConfigured

from .edge_release import SUPPORTED_EDGE_ENROLLMENT_RELEASE_DIGEST

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ImproperlyConfigured(f"{name} must be a boolean value")


def env_list(name, default=()):
    value = os.environ.get(name)
    if value is None:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


def env_int(name, default, *, minimum=None, maximum=None):
    value = os.environ.get(name, str(default))
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured(f"{name} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise ImproperlyConfigured(f"{name} must be at least {minimum}")
    if maximum is not None and parsed > maximum:
        raise ImproperlyConfigured(f"{name} must be at most {maximum}")
    return parsed


def env_release_id(name="VIVOLUTION_RELEASE_ID", default="unversioned"):
    value = os.environ.get(name, default).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", value):
        raise ImproperlyConfigured(
            f"{name} must be a safe release identifier of at most 128 characters"
        )
    return value


def env_controller_origin(name="VIVOLUTION_CONTROLLER_ORIGIN"):
    value = os.environ.get(name, "https://controller.example.test" if TESTING else "").strip()
    if not value:
        raise ImproperlyConfigured(f"{name} is required")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} contains an invalid port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise ImproperlyConfigured(
            f"{name} must be one HTTPS origin on port 443 with no path, query, or fragment"
        )
    hostname = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ImproperlyConfigured(f"{name} must use a DNS hostname, not an IP address")
    if not re.fullmatch(
        r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?",
        hostname,
    ):
        raise ImproperlyConfigured(f"{name} must contain a valid ASCII DNS hostname")
    return f"https://{hostname}"


def env_session_engine(name="DJANGO_SESSION_ENGINE", default="file"):
    value = os.environ.get(name, default)
    engines = {
        "db": "django.contrib.sessions.backends.db",
        "file": "django.contrib.sessions.backends.file",
        "signed_cookies": "django.contrib.sessions.backends.signed_cookies",
    }
    try:
        return engines[value]
    except KeyError as exc:
        raise ImproperlyConfigured(
            f"{name} must be exactly db, file, or signed_cookies"
        ) from exc


def database_config(database_url):
    parsed = urlparse(database_url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ImproperlyConfigured("DATABASE_URL must use postgres:// or postgresql://")
    if not parsed.hostname or not parsed.path.lstrip("/"):
        raise ImproperlyConfigured("DATABASE_URL must include a host and database name")

    query = parse_qs(parsed.query, keep_blank_values=False)
    allowed_options = {"sslmode", "sslrootcert", "sslcert", "sslkey", "target_session_attrs"}
    options = {
        key: values[-1]
        for key, values in query.items()
        if key in allowed_options and values
    }

    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": unquote(parsed.path.lstrip("/")),
        "USER": unquote(parsed.username or ""),
        "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname,
        "PORT": str(parsed.port or 5432),
        "CONN_MAX_AGE": int(os.environ.get("DB_CONN_MAX_AGE", "60")),
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": options,
    }


TESTING = env_bool("DJANGO_TESTING", False)
DEBUG = env_bool("DJANGO_DEBUG", False)
VIVOLUTION_RELEASE_ID = env_release_id()
VIVOLUTION_CONTROLLER_ORIGIN = env_controller_origin()

EDGE_ENROLLMENT_TOKEN_PEPPER = os.environ.get(
    "EDGE_ENROLLMENT_TOKEN_PEPPER",
    "00" * 32 if TESTING else "",
)
if not re.fullmatch(r"[0-9a-f]{64}", EDGE_ENROLLMENT_TOKEN_PEPPER):
    raise ImproperlyConfigured(
        "EDGE_ENROLLMENT_TOKEN_PEPPER must be an independent 32-byte key encoded as "
        "64 lowercase hex characters"
    )
EDGE_API_MAX_BODY_BYTES = env_int(
    "EDGE_API_MAX_BODY_BYTES", 16384, minimum=4096, maximum=65536
)
DATA_UPLOAD_MAX_MEMORY_SIZE = EDGE_API_MAX_BODY_BYTES
EDGE_CHALLENGE_TTL_SECONDS = 60
EDGE_ENROLLMENT_RELEASE_DIGEST = SUPPORTED_EDGE_ENROLLMENT_RELEASE_DIGEST

RLS_CONTEXT_SIGNING_KEY = os.environ.get("RLS_CONTEXT_SIGNING_KEY", "")
if RLS_CONTEXT_SIGNING_KEY:
    if not re.fullmatch(r"[0-9a-f]{64}", RLS_CONTEXT_SIGNING_KEY):
        raise ImproperlyConfigured(
            "RLS_CONTEXT_SIGNING_KEY must be exactly 64 lowercase hex characters"
        )
elif not TESTING:
    raise ImproperlyConfigured("RLS_CONTEXT_SIGNING_KEY is required")
RLS_CONTEXT_TTL_SECONDS = env_int(
    "RLS_CONTEXT_TTL_SECONDS", 60, minimum=5, maximum=300
)

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if TESTING:
        SECRET_KEY = "test-only-not-for-deployment"
    else:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY is required")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", ["testserver"] if TESTING else [])
if not ALLOWED_HOSTS and not DEBUG:
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS is required when debug is disabled")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core.apps.CoreConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "core.middleware.OperatorRLSMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "cp1.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # This project-owned directory takes precedence over Django's bundled
        # templates so the operator console can carry product branding and a
        # documentation link without adding a separate frontend toolchain.
        "DIRS": [BASE_DIR / "core" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "cp1.wsgi.application"

if TESTING:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
else:
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise ImproperlyConfigured("DATABASE_URL is required")
    DATABASES = {"default": database_config(database_url)}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
CSRF_COOKIE_SECURE = env_bool("DJANGO_CSRF_COOKIE_SECURE", not DEBUG and not TESTING)
SESSION_COOKIE_SECURE = env_bool("DJANGO_SESSION_COOKIE_SECURE", not DEBUG and not TESTING)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
# Keep the application and reusable deployment role backward-compatible with
# node-local file sessions. The Ubuntu turnkey playbook explicitly selects the
# database backend because it also provisions the matching PostgreSQL ACL.
# Signed cookies remain an explicitly selected stateless alternative.
SESSION_ENGINE = env_session_engine()
SESSION_FILE_PATH = "/tmp"
SESSION_COOKIE_AGE = env_int(
    "DJANGO_SESSION_COOKIE_AGE_SECONDS",
    3600,
    minimum=300,
    maximum=28800,
)
# Do not slide the signed cookie's expiry on every request. This preserves an
# absolute upper bound even for a continuously active operator session.
SESSION_SAVE_EVERY_REQUEST = False
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", False)
# The application listener is loopback-only. These probes must remain usable by
# systemd/Podman without pretending that an untrusted public request was HTTPS.
SECURE_REDIRECT_EXEMPT = [r"^health/"]
SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_SECURE_HSTS_SECONDS", "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("DJANGO_SECURE_HSTS_PRELOAD", False)

if env_bool("DJANGO_TRUST_X_FORWARDED_PROTO", False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "{asctime} {levelname} {name} {message}", "style": "{"}
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "standard"}},
    "root": {"handlers": ["console"], "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO")},
}
