"""
Django management command to run MCP server over HTTP/SSE (Streamable HTTP).
Run with: python manage.py mcp_server_http
"""
import asyncio
import os
import sys
from pathlib import Path

from django.core.management.base import BaseCommand

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scanx.settings')

import django
django.setup()

import uvicorn
from scanner.mcp_server import app


class Command(BaseCommand):
    help = "Run MCP server over HTTP/SSE (Streamable HTTP transport)"

    def add_arguments(self, parser):
        parser.add_argument(
            '--host',
            default='0.0.0.0',
            help='Host to bind to (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8001,
            help='Port to bind to (default: 8001)'
        )

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']

        self.stdout.write(f"Starting ScanX MCP HTTP Server on {host}:{port}")
        self.stdout.write(f"MCP endpoint: http://<your-vps-ip>:8001/mcp")
        self.stdout.write("Press Ctrl+C to stop")

        try:
            # Create Starlette app from MCP server
            starlette_app = app.streamable_http_app(
                streamable_http_path="/mcp",
                json_response=False,
                stateless_http=False,
            )
            uvicorn.run(starlette_app, host=host, port=port, log_level="info")
        except KeyboardInterrupt:
            self.stdout.write(self.style.SUCCESS("\nMCP HTTP server stopped"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error: {e}"))
            sys.exit(1)