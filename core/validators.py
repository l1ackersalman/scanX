"""
Domain validation utilities for scanX.

Validates domains per RFC 1035 / RFC 1123 with additional safety checks
to prevent shell injection and path traversal.
"""
import re
from pathlib import Path
from urllib.parse import urlsplit
from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible


# RFC 1035 / RFC 1123 hostname regex
# - Each label: 1-63 chars, alphanumeric + hyphen (not at start/end)
# - Total length: max 253 chars
# - TLD: at least 2 chars, letters only
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Characters that could be dangerous in shell context
SHELL_METACHARACTERS = re.compile(r"[;&|$`(){}\[\]<>\\'\"\s]")


@deconstructible
class DomainValidator:
    """
    Validates that a value is a valid domain name and safe for shell usage.
    """

    message = "Enter a valid domain name."
    code = "invalid_domain"

    def __call__(self, value: str) -> None:
        if not value:
            raise ValidationError(self.message, code=self.code)

        value = value.strip().lower()

        # Check for shell metacharacters
        if SHELL_METACHARACTERS.search(value):
            raise ValidationError(
                "Domain contains invalid characters.", code="invalid_characters"
            )

        # Check for path traversal attempts
        if ".." in value or "/" in value or "\\" in value:
            raise ValidationError(
                "Domain contains path traversal sequences.", code="path_traversal"
            )

        # Validate RFC 1035 format
        if not DOMAIN_REGEX.match(value):
            raise ValidationError(self.message, code=self.code)

        # Additional safety: reject localhost and internal domains in production
        # (can be configured via settings if needed)
        blocked = {"localhost", "localhost.localdomain", "broadcasthost"}
        if value in blocked:
            raise ValidationError(
                "This domain is not allowed for scanning.", code="blocked_domain"
            )

    def __eq__(self, other):
        return isinstance(other, DomainValidator)


validate_domain = DomainValidator()


def normalize_domain(value: str) -> str:
    """
    Reduce user input to a bare hostname so pasted URLs are accepted.
    e.g. "https://user@Example.com:8443/path?q=1#x" -> "example.com".
    Returns the trimmed input unchanged if no hostname can be extracted,
    so the validator still reports the real problem.
    """
    value = (value or "").strip()
    if not value:
        return value
    try:
        host = urlsplit(value if "://" in value else f"//{value}").hostname
    except ValueError:
        return value
    return host.rstrip(".") if host else value


def sanitize_domain(domain: str) -> str:
    """
    Sanitize domain for safe use in filesystem paths and shell commands.
    Returns lowercase, stripped domain.
    """
    return domain.strip().lower()


def get_scan_output_dir(base_dir, scan_id: str) -> Path:
    """
    Get the output directory for a specific scan.
    Creates the directory if it doesn't exist.
    """
    scan_dir = Path(base_dir) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir