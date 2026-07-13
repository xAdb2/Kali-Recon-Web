"""Django settings for KaliRecon Web.

All security-relevant defaults are safe for a local, single-user,
SSH-tunnelled deployment. Secrets come from the environment only.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .env import env_bool, env_int, env_list, env_str

BASE_DIR = Path(__file__).resolve().parent.parent

RUNNING_TESTS = "pytest" in sys.modules or "test" in sys.argv

# --- Core security -----------------------------------------------------------
SECRET_KEY = env_str("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if RUNNING_TESTS or env_bool("DJANGO_ALLOW_INSECURE_SECRET", False):
        SECRET_KEY = "insecure-test-only-key-do-not-use-in-production"  # noqa: S105
    else:
        raise RuntimeError(
            "DJANGO_SECRET_KEY is not set. Generate one and place it in .env "
            "(scripts/install.sh does this automatically)."
        )

DEBUG = env_bool("DJANGO_DEBUG", False)

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS", ["127.0.0.1", "localhost", "web", "testserver"]
)
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", [])

# --- Applications ------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "recon",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "recon" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "recon.context_processors.site_flags",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# --- Database ----------------------------------------------------------------
_use_sqlite = env_bool("USE_SQLITE", False) or (
    RUNNING_TESTS and not env_str("POSTGRES_HOST")
)
if _use_sqlite:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env_str("POSTGRES_DB", "kalirecon"),
            "USER": env_str("POSTGRES_USER", "kalirecon"),
            "PASSWORD": env_str("POSTGRES_PASSWORD", ""),
            "HOST": env_str("POSTGRES_HOST", "db"),
            "PORT": env_str("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": env_int("DB_CONN_MAX_AGE", 60),
        }
    }

# --- Auth --------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

# --- I18N / L10N -------------------------------------------------------------
LANGUAGE_CODE = "zh-hant"
TIME_ZONE = env_str("DJANGO_TIME_ZONE", "Asia/Taipei")
USE_I18N = True
USE_TZ = True

# --- Static ------------------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
# recon/static is collected via the app-directories finder; no STATICFILES_DIRS.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
    },
}
# Manifest storage requires collectstatic; relax during tests/dev runserver.
if RUNNING_TESTS or DEBUG:
    STORAGES["staticfiles"] = {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
    }

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Celery ------------------------------------------------------------------
REDIS_URL = env_str("REDIS_URL", "redis://redis:6379/0")
CELERY_BROKER_URL = env_str("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = env_str("CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", RUNNING_TESTS)
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_WORKER_CONCURRENCY = env_int("CELERY_WORKER_CONCURRENCY", 1)
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

# --- KaliRecon runtime configuration ----------------------------------------
KALIRECON = {
    "WORKSPACE_VOLUME": env_str("WORKSPACE_VOLUME", "kalirecon_workspaces"),
    "WORKSPACE_ROOT": env_str("WORKSPACE_ROOT", "/workspace"),
    "SCANNER_IMAGE": env_str("SCANNER_IMAGE", "kalirecon-scanner:local"),
    "SCANNER_NETWORK": env_str("SCANNER_NETWORK", ""),
    "SCANNER_CPU": env_str("SCANNER_CPU", "1.0"),
    "SCANNER_MEMORY": env_str("SCANNER_MEMORY", "1g"),
    "SCANNER_PIDS_LIMIT": env_int("SCANNER_PIDS_LIMIT", 256),
    "DOCKER_HOST": env_str("DOCKER_HOST", ""),
    "STEP_TIMEOUT_DEFAULT": env_int("STEP_TIMEOUT_DEFAULT", 900),
    "TASK_TIMEOUT_DEFAULT": env_int("TASK_TIMEOUT_DEFAULT", 3600),
    "MAX_ACTIVE_TASKS": env_int("MAX_ACTIVE_TASKS", 3),
    "MAX_THREADS": env_int("MAX_THREADS", 20),
    "MAX_RATE": env_int("MAX_RATE", 200),
    "ENABLE_EXPERT_COMMANDS": env_bool("ENABLE_EXPERT_COMMANDS", True),
    "NUCLEI_TEMPLATE_VERSION": env_str("NUCLEI_TEMPLATE_VERSION", "bundled"),
}

ENABLE_EXPERT_COMMANDS = KALIRECON["ENABLE_EXPERT_COMMANDS"]

# --- Security headers (safe for local Django) --------------------------------
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
# Cookies are not marked Secure by default because the app is served over a
# plain-HTTP SSH tunnel on localhost. Set these true behind TLS.
SESSION_COOKIE_SECURE = env_bool("DJANGO_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("DJANGO_COOKIE_SECURE", False)

DATA_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024

# --- Logging -----------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
    },
    "root": {"handlers": ["console"], "level": env_str("LOG_LEVEL", "INFO")},
    "loggers": {
        "recon": {
            "handlers": ["console"],
            "level": env_str("LOG_LEVEL", "INFO"),
            "propagate": False,
        },
    },
}
