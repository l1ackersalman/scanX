"""
scanX Django Settings

For production, ensure DEBUG=False and set a strong SECRET_KEY.
All secrets should come from environment variables via .env file.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: don't run with debug turned on in production!
# Off by default: the app is public, and DEBUG pages show code and settings.
# Set DEBUG=True in .env while developing.
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1", "yes")


def _load_secret_key() -> str:
    """
    SECRET_KEY from the environment, else a random key generated once and kept
    in BASE_DIR/.secret_key (gitignored). Never a hard-coded public value.
    """
    key = os.environ.get("SECRET_KEY", "").strip()
    if key:
        return key
    key_file = BASE_DIR / ".secret_key"
    try:
        return key_file.read_text().strip()
    except FileNotFoundError:
        from django.core.management.utils import get_random_secret_key
        key = get_random_secret_key()
        key_file.write_text(key)
        key_file.chmod(0o600)
        return key


SECRET_KEY = _load_secret_key()

ALLOWED_HOSTS = [
    h.strip() for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()
]

# Public URL(s) the site is opened from, e.g. "https://scanx.example.com,http://203.0.113.7:8000".
# Needed for forms to pass Django's CSRF check behind a domain or HTTPS proxy.
CSRF_TRUSTED_ORIGINS = [
    o.strip() for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()
]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    # Local apps
    "scanner",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # Serves CSS/JS even with DEBUG off (runserver stops doing it then)
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # No-cache middleware: prevent browsers from caching pages
    "core.middleware.NoCacheMiddleware",
]

ROOT_URLCONF = "scanx.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "scanx.wsgi.application"

# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases
import dj_database_url

DATABASES = {
    "default": dj_database_url.config(
        default=os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}"),
        conn_max_age=600,
    )
}

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Dhaka"
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [
    BASE_DIR / "static",
]
# Serve straight from static/ so CSS/JS edits don't need collectstatic
WHITENOISE_USE_FINDERS = True

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# =====================================================================
# scanX Custom Settings
# =====================================================================

# Directory where scan outputs are stored
# Can be overridden by SCANX_DATA_DIR environment variable
SCANX_DATA_DIR = Path(os.environ.get("SCANX_DATA_DIR", BASE_DIR / "scan_data")).resolve()

# Scanner script path (relative to BASE_DIR)
SCANNER_SCRIPT_PATH = BASE_DIR / "scanner" / "scanx.sh"

# Chaos API key (injected into scanner environment)
CHAOS_API_KEY = os.environ.get("CHAOS_API_KEY", "")

# Additional PATH entries for external tools (colon-separated)
TOOLS_PATH = os.environ.get("TOOLS_PATH", "")

# Maximum scan execution time in seconds
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "3600"))

# ---------------------------------------------------------------------
# Built-in AI analysis ("Generate AI report" button)
# The API key is read by the provider SDK from the environment:
#   ANTHROPIC_API_KEY (Claude) or OPENAI_API_KEY (OpenAI).
# AI_PROVIDER: "anthropic", "openai", or empty = whichever key is set
# (Anthropic first). No key set = the button is shown as unavailable.
# ---------------------------------------------------------------------
AI_PROVIDER = os.environ.get("AI_PROVIDER", "").strip().lower()  # anthropic | openai | nvidia
AI_MODEL_ANTHROPIC = os.environ.get("AI_MODEL_ANTHROPIC", "claude-opus-5-5")
AI_MODEL_OPENAI = os.environ.get("AI_MODEL_OPENAI", "gpt-5")
# NVIDIA NIM (OpenAI-compatible API), e.g. Nemotron. Key: NVIDIA_API_KEY (nvapi-...).
# Copy the exact model id from the model's page on build.nvidia.com.
AI_MODEL_NVIDIA = os.environ.get("AI_MODEL_NVIDIA", "nvidia/nemotron-3-ultra-550b-a55b")
NVIDIA_BASE_URL = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
AI_DAILY_LIMIT = int(os.environ.get("AI_DAILY_LIMIT", "30"))             # built-in reports per day, all users
AI_SCAN_COOLDOWN_MINUTES = int(os.environ.get("AI_SCAN_COOLDOWN_MINUTES", "10"))  # per scan
AI_MAX_TURNS = int(os.environ.get("AI_MAX_TURNS", "25"))                 # tool-call rounds per report
AI_QUESTION_DAILY_LIMIT = int(os.environ.get("AI_QUESTION_DAILY_LIMIT", "100"))  # "Ask the report" per day
AI_QUESTIONS_PER_REPORT = int(os.environ.get("AI_QUESTIONS_PER_REPORT", "20"))
AI_JOB_TIMEOUT = int(os.environ.get("AI_JOB_TIMEOUT", "600"))            # seconds per report

# Maximum scans waiting in the queue. The app is public, so this stops one
# visitor from filling the queue and blocking everyone else's scans.
SCAN_QUEUE_LIMIT = int(os.environ.get("SCAN_QUEUE_LIMIT", "5"))

# Ensure scan data directory exists
SCANX_DATA_DIR.mkdir(parents=True, exist_ok=True)

# Logging configuration
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
        "file": {
            # Rotates at 5 MB, keeps 3 old files, so the log can't fill the disk
            "class": "logging.handlers.RotatingFileHandler",
            "filename": BASE_DIR / "scanx.log",
            "maxBytes": 5_000_000,
            "backupCount": 3,
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "scanner": {
            # Test runs log fake scans/errors; keep them out of the real scanx.log
            "handlers": ["console"] if "test" in sys.argv[1:2] else ["console", "file"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}