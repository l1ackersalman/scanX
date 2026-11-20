"""
scanX Scanner URL Patterns
"""
from django.urls import path
from django.views.generic import RedirectView

from . import views

app_name = "scanner"

urlpatterns = [
    path("", RedirectView.as_view(url="overview/", permanent=False)),
    path("overview/", views.dashboard, name="overview"),
    path("history/", views.scan_history, name="history"),
    path("start/", views.start_scan, name="start_scan"),
    path("scan/<uuid:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scan/<uuid:scan_id>/logs/", views.scan_logs, name="scan_logs"),
    path("scan/<uuid:scan_id>/cancel/", views.stop_scan, name="stop_scan"),
    path("organizations/", views.programs, name="organizations"),
    path("organizations/add/", views.create_program, name="organizations_add"),
    path("organizations/edit/<int:organization_id>/", views.edit_program, name="organizations_edit"),
    path("organizations/delete/<int:organization_id>/", views.delete_program, name="organizations_delete"),
    path("organizations/<int:organization_id>/", views.program_detail, name="organization_detail"),
    path("assets/", views.assets, name="assets"),
    path("assets/tech/", views.technology_detail, name="technology_detail"),
    # Reports (MCP Analysis)
    path("reports/", views.reports_list, name="reports"),
    path("reports/<uuid:report_id>/", views.report_detail, name="report_detail"),
    path("reports/<uuid:report_id>/download/", views.report_download, name="report_download"),
    # MCP Guide
    path("mcp/", views.mcp_guide, name="mcp_guide"),
    # MCP HTTP Server
    path("mcp/status/", views.mcp_http_status, name="mcp_http_status"),
    path("mcp/start/", views.mcp_http_start, name="mcp_http_start"),
]