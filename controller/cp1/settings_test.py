import os


os.environ.setdefault("DJANGO_TESTING", "1")
os.environ.setdefault("DJANGO_ALLOWED_HOSTS", "testserver")

from .settings import *  # noqa: E402,F403

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
STORAGES["staticfiles"] = {
    "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
}
