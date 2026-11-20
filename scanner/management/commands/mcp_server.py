from django.core.management.base import BaseCommand
from scanner.mcp_server import main
import asyncio

class Command(BaseCommand):
    help = "Run the ScanX MCP server"
    
    def handle(self, *args, **options):
        self.stdout.write("Starting ScanX MCP Server...")
        asyncio.run(main())