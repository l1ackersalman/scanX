"""
scanX Tool Check Command

Verifies that all required external tools are installed and available in PATH.
Run on startup/deploy to catch missing dependencies early.
"""
import os
import shutil
import subprocess
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Check that all required reconnaissance tools are installed"

    # Tools required by scanx.sh
    REQUIRED_TOOLS = [
        ("figlet", "ASCII banner"),
        ("subfinder", "Subdomain enumeration (projectdiscovery)"),
        ("assetfinder", "Subdomain enumeration (tomnomnom)"),
        ("chaos", "Chaos dataset client (projectdiscovery)"),
        ("crt", "Certificate transparency logs"),
        ("dnsx", "DNS resolution (projectdiscovery)"),
        ("httpx", "HTTP probing (projectdiscovery)"),
    ]

    def add_arguments(self, parser):
        parser.add_argument(
            "--install-hints",
            action="store_true",
            help="Show installation hints for missing tools",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Output results as JSON",
        )

    def handle(self, *args, **options):
        results = []
        all_ok = True

        # Build PATH with TOOLS_PATH if configured
        env_path = os.environ.get("PATH", "")
        if settings.TOOLS_PATH:
            env_path = f"{settings.TOOLS_PATH}:{env_path}"

        for tool_name, description in self.REQUIRED_TOOLS:
            # Special handling for httpx which might be in ~/go/bin
            paths_to_check = [env_path]
            if tool_name == "httpx":
                go_bin = os.path.expanduser("~/go/bin")
                paths_to_check.insert(0, go_bin)

            found = False
            found_path = None
            for p in paths_to_check:
                full_path = shutil.which(tool_name, path=p)
                if full_path:
                    found = True
                    found_path = full_path
                    break

            # Also try direct check for httpx at common Go locations
            if not found and tool_name == "httpx":
                for candidate in [
                    os.path.expanduser("~/go/bin/httpx"),
                    "/usr/local/go/bin/httpx",
                    "/opt/go/bin/httpx",
                ]:
                    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                        found = True
                        found_path = candidate
                        break

            if found:
                # Try to get version
                version = self._get_version(tool_name, found_path)
                results.append(
                    {
                        "tool": tool_name,
                        "description": description,
                        "status": "ok",
                        "path": found_path,
                        "version": version,
                    }
                )
                self.stdout.write(
                    self.style.SUCCESS(f"  ✓ {tool_name} - {found_path} {version}")
                )
            else:
                all_ok = False
                results.append(
                    {
                        "tool": tool_name,
                        "description": description,
                        "status": "missing",
                        "path": None,
                        "version": None,
                    }
                )
                self.stdout.write(
                    self.style.ERROR(f"  ✗ {tool_name} - NOT FOUND ({description})")
                )

        # Check Chaos API key
        if not settings.CHAOS_API_KEY or settings.CHAOS_API_KEY == "your_chaos_api_key_here":
            self.stdout.write(
                self.style.WARNING(
                    "  ⚠ CHAOS_API_KEY not configured (chaos tool will fail)"
                )
            )
        else:
            self.stdout.write(self.style.SUCCESS("  ✓ CHAOS_API_KEY configured"))

        # Check scanner script
        if settings.SCANNER_SCRIPT_PATH.exists():
            self.stdout.write(
                self.style.SUCCESS(f"  ✓ Scanner script: {settings.SCANNER_SCRIPT_PATH}")
            )
        else:
            all_ok = False
            self.stdout.write(
                self.style.ERROR(
                    f"  ✗ Scanner script not found: {settings.SCANNER_SCRIPT_PATH}"
                )
            )

        # Check scan data directory
        if settings.SCANX_DATA_DIR.exists():
            self.stdout.write(
                self.style.SUCCESS(f"  ✓ Scan data dir: {settings.SCANX_DATA_DIR}")
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"  ⚠ Scan data dir will be created: {settings.SCANX_DATA_DIR}"
                )
            )

        if options["json"]:
            self.stdout.write(json.dumps(results, indent=2))

        if not all_ok:
            if options["install_hints"]:
                self._print_install_hints()
            raise CommandError("One or more required tools are missing")

        self.stdout.write(self.style.SUCCESS("\nAll required tools are available!"))

    def _get_version(self, tool_name: str, tool_path: str) -> str:
        """Try to get version string from tool."""
        version_args = {
            "figlet": ["-v"],
            "subfinder": ["-version"],
            "assetfinder": ["-version"],
            "chaos": ["-version"],
            "crt": ["-version"],
            "dnsx": ["-version"],
            "httpx": ["-version"],
        }
        args = version_args.get(tool_name, ["--version"])
        try:
            result = subprocess.run(
                [tool_path] + args,
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout or result.stderr
            # Extract first line as version
            version_line = output.strip().split("\n")[0] if output else "unknown"
            return f"({version_line})"
        except Exception:
            return "(version unknown)"

    def _print_install_hints(self):
        """Print installation hints for missing tools."""
        self.stdout.write("\nInstallation hints:")
        self.stdout.write("  Go tools (subfinder, assetfinder, chaos, dnsx, httpx, crt):")
        self.stdout.write("    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        self.stdout.write("    go install -v github.com/tomnomnom/assetfinder@latest")
        self.stdout.write("    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest")
        self.stdout.write("    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        self.stdout.write("    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        self.stdout.write("    go install -v github.com/projectdiscovery/crt/cmd/crt@latest")
        self.stdout.write("  figlet:")
        self.stdout.write("    apt install figlet  # Debian/Ubuntu")
        self.stdout.write("    brew install figlet  # macOS")
        self.stdout.write("")
        self.stdout.write("  Ensure Go bin directory is in PATH or set TOOLS_PATH in .env")
        self.stdout.write("    export PATH=$PATH:$(go env GOPATH)/bin")