"""
WSGI config for scanX project.
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "scanx.settings")

application = get_wsgi_application()