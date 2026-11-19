"""
scanX Scanner URL Patterns
"""
from django.urls import path
from django.views.generic import RedirectView

from . import views

app_name = "scanner"

urlpatterns = [
    path("", RedirectView.as_view(url="dashboard/", permanent=False)),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("history/", views.scan_history, name="history"),
    path("start/", views.start_scan, name="start_scan"),
    path("scan/<uuid:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scan/<uuid:scan_id>/logs/", views.scan_logs, name="scan_logs"),
    path("scan/<uuid:scan_id>/cancel/", views.stop_scan, name="stop_scan"),
    path("programs/", views.programs, name="programs"),
    path("programs/add/", views.create_program, name="programs_add"),
    path("programs/edit/<int:program_id>/", views.edit_program, name="programs_edit"),
    path("programs/delete/<int:program_id>/", views.delete_program, name="programs_delete"),
    path("programs/<int:program_id>/", views.program_detail, name="program_detail"),
    path("assets/", views.assets, name="assets"),
    path("assets/tech/", views.technology_detail, name="technology_detail"),
]