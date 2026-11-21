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
    path("scan/<uuid:scan_id>/download/", views.scan_download_all, name="scan_download_all"),
    path("scan/<uuid:scan_id>/download/<str:name>", views.scan_download, name="scan_download"),
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
    # MCP: Connect page + user guide, and the endpoint AI agents talk to
    path("mcp/", views.mcp_guide, name="mcp_guide"),
    path("mcp/connect/", views.mcp_connect, name="mcp_connect"),
    path("mcp/connections/<int:token_id>/revoke/", views.mcp_revoke, name="mcp_revoke"),
    # REST API: same tools, plain HTTPS + JSON, same Connect token
    path("api/v1/tools", views.api_tools, name="api_tools"),
    path("api/v1/tools/<str:name>", views.api_tool_call, name="api_tool_call"),
    path("api/v1/openapi.json", views.api_openapi, name="api_openapi"),
    # Built-in AI
    path("reports/ai/", views.ai_report_create, name="ai_report_create"),
    path("reports/<uuid:report_id>/status/", views.report_status, name="report_status"),
    path("reports/<uuid:report_id>/ask/", views.report_ask, name="report_ask"),
    path("api/mcp", views.mcp_endpoint, name="mcp_endpoint"),
    path("api/mcp/", views.mcp_endpoint),  # some clients add a trailing slash
]