"""
scanX Scanner URL Patterns
"""
from django.urls import path

from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("history/", views.scan_history, name="history"),
    path("start/", views.start_scan, name="start_scan"),
    path("scan/<uuid:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scan/<uuid:scan_id>/logs/", views.scan_logs, name="scan_logs"),
    path(
        "scan/<uuid:scan_id>/download/<str:artifact_name>/",
        views.download_artifact,
        name="download_artifact",
    ),
]