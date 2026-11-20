"""
scanX Scanner Models

Defines the Scan model for tracking reconnaissance scans.
"""
import uuid
from django.db import models
from django.utils import timezone

from core.validators import validate_domain


class Scan(models.Model):
    """
    Represents a single reconnaissance scan of a target domain.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.CharField(max_length=253, validators=[validate_domain])
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )

    # Output directory relative to SCANX_DATA_DIR
    output_dir = models.CharField(max_length=512, blank=True, default="")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Error tracking
    error_message = models.TextField(blank=True, default="")

    # Authorization tracking
    authorized = models.BooleanField(default=False)
    authorized_by = models.CharField(max_length=255, blank=True, default="")

    # Program association
    program = models.ForeignKey(
        'scanner.Program',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='scans',
    )

    # Scan metadata (populated after completion)
    total_subdomains = models.IntegerField(null=True, blank=True)
    live_subdomains = models.IntegerField(null=True, blank=True)
    http_success = models.IntegerField(null=True, blank=True)
    http_failed = models.IntegerField(null=True, blank=True)
    httpx_results = models.JSONField(null=True, blank=True, default=None)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["domain", "-created_at"]),
        ]

    def __str__(self):
        return f"Scan({self.domain[:50]} - {self.status})"

    @property
    def is_terminal(self) -> bool:
        """Check if scan is in a terminal state."""
        return self.status in (self.Status.COMPLETED, self.Status.FAILED, self.Status.CANCELLED)

    @property
    def duration_seconds(self) -> int | None:
        """Get scan duration in seconds if completed."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None

    @property
    def duration_display(self) -> str:
        """Get human-readable duration (s/m/h)."""
        seconds = self.duration_seconds
        if not seconds:
            return "—"
        if seconds >= 3600:
            return f"{seconds // 3600}h"
        if seconds >= 60:
            return f"{seconds // 60}m"
        return f"{seconds}s"

    @property
    def output_path(self):
        """Get absolute path to scan output directory."""
        from django.conf import settings
        if self.output_dir:
            return settings.SCANX_DATA_DIR / self.output_dir
        return None

    def get_artifact_path(self, filename: str):
        """Get path to a specific artifact file."""
        if self.output_path:
            return self.output_path / self.domain / filename
        return None

    def mark_running(self, output_dir: str = ""):
        """Mark scan as running."""
        self.status = self.Status.RUNNING
        self.started_at = timezone.now()
        if output_dir:
            self.output_dir = output_dir
        self.save(update_fields=["status", "started_at", "output_dir"])

    def mark_completed(self, **stats):
        """Mark scan as completed with optional statistics."""
        self.status = self.Status.COMPLETED
        self.completed_at = timezone.now()
        for key, value in stats.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.save()

    def mark_failed(self, error: str):
        """Mark scan as failed with error message."""
        self.status = self.Status.FAILED
        self.completed_at = timezone.now()
        self.error_message = error
        self.save(update_fields=["status", "completed_at", "error_message"])

    def mark_cancelled(self):
        """Mark scan as cancelled."""
        self.status = self.Status.CANCELLED
        self.completed_at = timezone.now()
        self.error_message = "Scan cancelled by user"
        self.save(update_fields=["status", "completed_at", "error_message"])

class Program(models.Model):
    """
    Authorized target organization for reconnaissance.
    """

    class OrganizationType(models.TextChoices):
        FINTECH = "fintech", "Fintech"
        AGRICULTURE = "agriculture", "Agriculture"
        RESEARCH = "research", "Research"
        EDUCATION = "education", "Education"
        HEALTHCARE = "healthcare", "Healthcare"
        GOVERNMENT = "government", "Government"
        RETAIL = "retail", "Retail"
        MANUFACTURING = "manufacturing", "Manufacturing"
        TECHNOLOGY = "technology", "Technology"
        ENERGY = "energy", "Energy"
        TELECOMMUNICATIONS = "telecommunications", "Telecommunications"
        TRANSPORTATION = "transportation", "Transportation"
        MEDIA = "media", "Media"
        HOSPITALITY = "hospitality", "Hospitality"
        REAL_ESTATE = "real_estate", "Real Estate"
        CONSULTING = "consulting", "Consulting"
        NON_PROFIT = "non_profit", "Non-Profit"
        OTHER = "other", "Other"

    name = models.CharField(max_length=255, help_text="Authorized target domain or organization name")
    description = models.TextField(blank=True, default="", help_text="Organization description (e.g. Let it empty for future)")
    organization_type = models.CharField(max_length=50, choices=OrganizationType.choices, default=OrganizationType.OTHER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization_type"]),
        ]

    def __str__(self):
        return f"{self.name}"


class Report(models.Model):
    """
    AI-generated analysis reports for scans.
    """
    
    class ReportType(models.TextChoices):
        ATTACK_SURFACE = "attack_surface", "Attack Surface Analysis"
        VULNERABILITY = "vulnerability", "Vulnerability Assessment"
        TECHNOLOGY_EXPOSURE = "technology_exposure", "Technology Exposure"
        ATTACK_VECTOR = "attack_vector", "Attack Vector Analysis"
        CUSTOM = "custom", "Custom Analysis"
    
    class Status(models.TextChoices):
        GENERATING = "generating", "Generating"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='reports',
    )
    report_type = models.CharField(
        max_length=50,
        choices=ReportType.choices,
        default=ReportType.ATTACK_SURFACE,
    )
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True, default="")
    content = models.TextField(blank=True, default="")  # Markdown content
    findings = models.JSONField(default=dict, blank=True)  # Structured findings
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.GENERATING,
        db_index=True,
    )
    generated_by = models.CharField(max_length=100, default="MCP Agent")  # AI agent identifier
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scan", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.get_report_type_display()})"
    
    def mark_completed(self, content: str, findings: dict = None):
        self.status = self.Status.COMPLETED
        self.completed_at = timezone.now()
        self.content = content
        if findings:
            self.findings = findings
        self.save()
    
    def mark_failed(self, error: str):
        self.status = self.Status.FAILED
        self.content = f"Generation failed: {error}"
        self.save()
