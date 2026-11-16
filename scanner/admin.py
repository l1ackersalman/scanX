"""
scanX Scanner Admin Configuration
"""
from django.contrib import admin

from .models import Scan


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "domain",
        "status",
        "created_at",
        "started_at",
        "completed_at",
        "authorized",
        "authorized_by",
    ]
    list_filter = ["status", "authorized", "created_at"]
    search_fields = ["domain", "id", "authorized_by"]
    readonly_fields = [
        "id",
        "created_at",
        "started_at",
        "completed_at",
        "output_dir",
        "error_message",
        "total_subdomains",
        "live_subdomains",
        "http_success",
        "http_failed",
    ]
    ordering = ["-created_at"]
    list_per_page = 25

    fieldsets = (
        ("Target", {"fields": ("domain",)}),
        ("Status", {"fields": ("status", "error_message")}),
        ("Authorization", {"fields": ("authorized", "authorized_by")}),
        ("Output", {"fields": ("output_dir",)}),
        ("Timestamps", {"fields": ("created_at", "started_at", "completed_at")}),
        (
            "Statistics",
            {
                "fields": (
                    "total_subdomains",
                    "live_subdomains",
                    "http_success",
                    "http_failed",
                )
            },
        ),
    )