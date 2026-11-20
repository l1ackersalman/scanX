"""
MCP Server for ScanX - Exposes reconnaissance data and tools to AI agents.
Run with: python manage.py mcp_server
"""
import json
import asyncio
import os
import sys
from typing import Any, Dict, List, Optional
from datetime import datetime

# Add project root to path for Django setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scanx.settings')

import django
django.setup()

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool, TextContent, Resource, ListResourcesResult, 
    ListToolsResult, CallToolResult, ReadResourceResult,
    ListResourcesRequest, ListToolsRequest, CallToolRequest,
    ReadResourceRequest, ResourceContents, TextResourceContents
)

from scanner.models import Scan, Program, Report
from scanner.services import get_technology_breakdown

app = Server("scanx-mcp")

# =====================================================================
# Resources - Read-only data access
# =====================================================================

async def handle_list_resources(request: ListResourcesRequest) -> ListResourcesResult:
    """List available ScanX data resources"""
    return ListResourcesResult(resources=[
        Resource(
            uri="scanx://organizations",
            name="All Organizations",
            description="List all authorized organizations with their types",
            mimeType="application/json"
        ),
        Resource(
            uri="scanx://scans/recent",
            name="Recent Scans",
            description="Most recent reconnaissance scans with results",
            mimeType="application/json"
        ),
        Resource(
            uri="scanx://technologies",
            name="Detected Technologies",
            description="All technologies discovered across scans",
            mimeType="application/json"
        ),
    ])

async def handle_read_resource(request: ReadResourceRequest) -> ReadResourceResult:
    """Read a specific resource"""
    uri = str(request.params.uri)
    
    if uri == "scanx://organizations":
        orgs = Program.objects.all().order_by("-created_at")
        data = [{
            "id": str(o.id),
            "name": o.name,
            "type": o.get_organization_type_display(),
            "description": o.description,
            "created": o.created_at.isoformat(),
        } for o in orgs]
        content = json.dumps(data, indent=2)
    
    elif uri == "scanx://scans/recent":
        scans = Scan.objects.select_related("program").order_by("-created_at")[:20]
        data = [{
            "id": str(s.id),
            "domain": s.domain,
            "status": s.get_status_display(),
            "organization": s.program.name if s.program else None,
            "org_type": s.program.get_organization_type_display() if s.program else None,
            "created": s.created_at.isoformat(),
            "started": s.started_at.isoformat() if s.started_at else None,
            "completed": s.completed_at.isoformat() if s.completed_at else None,
            "stats": {
                "subdomains": s.total_subdomains,
                "live": s.live_subdomains,
                "http_ok": s.http_success,
                "http_failed": s.http_failed,
            }
        } for s in scans]
        content = json.dumps(data, indent=2)
    
    elif uri == "scanx://technologies":
        tech_data = get_technology_breakdown(sort_by="count")
        content = json.dumps(tech_data, indent=2)
    
    else:
        raise ValueError(f"Unknown resource: {uri}")
    
    return ReadResourceResult(contents=[
        TextResourceContents(
            uri=uri,
            mimeType="application/json",
            text=content
        )
    ])

# =====================================================================
# Tools - Actions the AI can perform
# =====================================================================

async def handle_list_tools(request: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=[
        Tool(
            name="get_scan_details",
            description="Get detailed results for a specific scan including subdomains, live hosts, and HTTP results",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "UUID of the scan"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="get_organization_scans",
            description="Get all scans for a specific organization",
            inputSchema={
                "type": "object",
                "properties": {
                    "organization_id": {"type": "string", "description": "UUID of the organization"},
                },
                "required": ["organization_id"],
            },
        ),
        Tool(
            name="search_subdomains",
            description="Search subdomains across all scans by pattern",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Subdomain pattern to search (e.g., 'api.*', '*.admin.*')"},
                    "organization_type": {"type": "string", "description": "Filter by organization type (optional)"},
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="analyze_attack_surface",
            description="Analyze attack surface for a domain - finds exposed services, technologies, and potential vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain to analyze"},
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="get_technology_exposure",
            description="Find all subdomains using a specific technology across organizations",
            inputSchema={
                "type": "object",
                "properties": {
                    "technology": {"type": "string", "description": "Technology name (e.g., 'nginx', 'WordPress', 'Apache')"},
                },
                "required": ["technology"],
            },
        ),
        Tool(
            name="create_report",
            description="Create an AI analysis report for a scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "UUID of the scan to analyze"},
                    "report_type": {"type": "string", "enum": ["attack_surface", "vulnerability", "technology_exposure", "attack_vector", "custom"], "description": "Type of analysis report"},
                    "title": {"type": "string", "description": "Report title"},
                    "prompt": {"type": "string", "description": "Analysis prompt/instructions for the AI"},
                },
                "required": ["scan_id", "report_type", "title", "prompt"],
            },
        ),
    ])

async def handle_call_tool(request: CallToolRequest) -> CallToolResult:
    """Execute a tool"""
    name = request.params.name
    arguments = request.params.arguments or {}
    
    if name == "get_scan_details":
        scan_id = arguments["scan_id"]
        try:
            scan = Scan.objects.select_related("program").prefetch_related("httpx_results").get(id=scan_id)
        except Scan.DoesNotExist:
            return CallToolResult(content=[TextContent(type="text", text=f"Scan {scan_id} not found")])
        
        return CallToolResult(content=[TextContent(
            type="text",
            text=json.dumps({
                "scan_id": str(scan.id),
                "domain": scan.domain,
                "status": scan.get_status_display(),
                "organization": scan.program.name if scan.program else None,
                "organization_type": scan.program.get_organization_type_display() if scan.program else None,
                "timing": {
                    "created": scan.created_at.isoformat(),
                    "started": scan.started_at.isoformat() if scan.started_at else None,
                    "completed": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration": scan.duration_display,
                },
                "statistics": {
                    "total_subdomains": scan.total_subdomains,
                    "live_subdomains": scan.live_subdomains,
                    "http_success": scan.http_success,
                    "http_failed": scan.http_failed,
                },
                "httpx_results": scan.httpx_results or [],
            }, indent=2)
        )]
        )
    
    elif name == "get_organization_scans":
        org_id = arguments["organization_id"]
        try:
            program = Program.objects.get(id=org_id)
        except Program.DoesNotExist:
            return CallToolResult(content=[TextContent(type="text", text=f"Organization {org_id} not found")])
        
        scans = program.scans.order_by("-created_at")
        
        data = [{
            "scan_id": str(s.id),
            "domain": s.domain,
            "status": s.get_status_display(),
            "created": s.created_at.isoformat(),
            "completed": s.completed_at.isoformat() if s.completed_at else None,
            "stats": {
                "subdomains": s.total_subdomains,
                "live": s.live_subdomains,
                "http_ok": s.http_success,
                "http_failed": s.http_failed,
            }
        } for s in scans]
        
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(data, indent=2))])
    
    elif name == "search_subdomains":
        pattern = arguments["pattern"]
        org_type = arguments.get("organization_type")
        
        import re
        regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
        
        scans = Scan.objects.filter(status=Scan.Status.COMPLETED).select_related("program")
        if org_type:
            scans = scans.filter(program__organization_type=org_type)
        
        results = []
        for scan in scans:
            for result in scan.httpx_results or []:
                url = result.get("url", "")
                if re.search(regex_pattern, url, re.IGNORECASE):
                    results.append({
                        "scan_id": str(scan.id),
                        "domain": scan.domain,
                        "organization": scan.program.name if scan.program else None,
                        "org_type": scan.program.get_organization_type_display() if scan.program else None,
                        "url": url,
                        "status": result.get("status-code"),
                        "title": result.get("title"),
                        "tech": result.get("tech", []),
                    })
        
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(results[:100], indent=2))])
    
    elif name == "analyze_attack_surface":
        domain = arguments["domain"]
        scans = Scan.objects.filter(
            domain__icontains=domain,
            status=Scan.Status.COMPLETED
        ).select_related("program")
        
        if not scans.exists():
            return CallToolResult(content=[TextContent(type="text", text=f"No completed scans found for {domain}")])
        
        all_subdomains = set()
        all_technologies = {}
        all_ips = set()
        
        for scan in scans:
            for result in scan.httpx_results or []:
                url = result.get("url", "")
                if domain in url:
                    all_subdomains.add(url)
                    for tech in result.get("tech", []):
                        all_technologies[tech] = all_technologies.get(tech, 0) + 1
                    ip = result.get("ip")
                    if ip:
                        all_ips.add(ip)
        
        return CallToolResult(content=[TextContent(type="text", text=json.dumps({
            "target_domain": domain,
            "scans_analyzed": len(scans),
            "organizations": list(set(s.program.name for s in scans if s.program)),
            "subdomains_found": len(all_subdomains),
            "unique_ips": len(all_ips),
            "technologies": dict(sorted(all_technologies.items(), key=lambda x: x[1], reverse=True)[:20]),
        }, indent=2))])
    
    elif name == "get_technology_exposure":
        tech = arguments["technology"]
        
        scans = Scan.objects.filter(
            status=Scan.Status.COMPLETED,
            httpx_results__tech__icontains=tech
        ).select_related("program").distinct()
        
        results = []
        for scan in scans:
            for result in scan.httpx_results or []:
                if tech.lower() in str(result.get("tech", "")).lower():
                    results.append({
                        "scan_id": str(scan.id),
                        "domain": scan.domain,
                        "organization": scan.program.name if scan.program else None,
                        "org_type": scan.program.get_organization_type_display() if scan.program else None,
                        "url": result.get("url"),
                        "status": result.get("status-code"),
                        "title": result.get("title"),
                        "ip": result.get("ip"),
                    })
        
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(results, indent=2))])
    
    elif name == "create_report":
        scan_id = arguments["scan_id"]
        report_type = arguments["report_type"]
        title = arguments["title"]
        prompt = arguments["prompt"]
        
        try:
            scan = Scan.objects.select_related("program").prefetch_related("httpx_results").get(id=scan_id)
        except Scan.DoesNotExist:
            return CallToolResult(content=[TextContent(type="text", text=f"Scan {scan_id} not found")])
        
        if scan.status != Scan.Status.COMPLETED:
            return CallToolResult(content=[TextContent(type="text", text=f"Scan {scan_id} is not completed (status: {scan.get_status_display()})")])
        
        # Create report record
        report = Report.objects.create(
            scan=scan,
            report_type=report_type,
            title=title,
            status=Report.Status.GENERATING,
            generated_by="MCP Agent",
        )
        
        # Build analysis context from scan data
        context = {
            "domain": scan.domain,
            "organization": scan.program.name if scan.program else None,
            "organization_type": scan.program.get_organization_type_display() if scan.program else None,
            "total_subdomains": scan.total_subdomains,
            "live_subdomains": scan.live_subdomains,
            "http_success": scan.http_success,
            "http_failed": scan.http_failed,
            "httpx_results": scan.httpx_results or [],
        }
        
        # Build analysis context from scan data
        findings = {
            "target_domain": scan.domain,
            "organization": context.get("organization"),
            "organization_type": context.get("organization_type"),
            "total_subdomains": context.get("total_subdomains"),
            "live_subdomains": context.get("live_subdomains"),
            "http_success": context.get("http_success"),
            "http_failed": context.get("http_failed"),
            "top_technologies": _get_top_technologies(context.get("httpx_results", [])),
            "subdomains": [r.get("url") for r in context.get("httpx_results", []) if r.get("url")],
        }
        
        # Generate report content based on type
        content = _generate_report_content(report_type, title, prompt, context, findings)
        summary = _generate_summary(report_type, context, findings)
        
        report.mark_completed(content=content, findings=findings)
        
        return CallToolResult(content=[TextContent(
            type="text", 
            text=json.dumps({
                "report_id": str(report.id),
                "title": report.title,
                "status": "completed",
                "url": f"/reports/{report.id}/",
                "download_url": f"/reports/{report.id}/download/",
            }, indent=2)
        )]
        )
    
    raise ValueError(f"Unknown tool: {name}")


def _get_top_technologies(httpx_results: list) -> dict:
    """Extract top technologies from httpx results"""
    tech_counts = {}
    for result in httpx_results:
        for tech in result.get("tech", []):
            tech_counts[tech] = tech_counts.get(tech, 0) + 1
    return dict(sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:20])


def _generate_report_content(report_type: str, title: str, prompt: str, context: dict, findings: dict) -> str:
    """Generate report content based on type and prompt"""
    
    sections = []
    
    # Header
    sections.append(f"# {title}\n")
    sections.append(f"**Report Type:** {report_type.replace('_', ' ').title()}")
    sections.append(f"**Target Domain:** {context.get('domain', 'N/A')}")
    sections.append(f"**Organization:** {context.get('organization', 'N/A')}")
    sections.append(f"**Organization Type:** {context.get('organization_type', 'N/A')}")
    sections.append(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sections.append(f"\n---\n")
    
    # Prompt context
    if prompt:
        sections.append(f"## Analysis Request\n{prompt}\n")
    
    # Summary statistics
    sections.append("## Summary Statistics\n")
    sections.append(f"- **Target Domain:** {context.get('domain', 'N/A')}")
    sections.append(f"- **Organization:** {context.get('organization', 'N/A')} ({context.get('organization_type', 'N/A')})")
    sections.append(f"- **Total Subdomains:** {context.get('total_subdomains', 0)}")
    sections.append(f"- **Live Subdomains:** {context.get('live_subdomains', 0)}")
    sections.append(f"- **HTTP Success:** {context.get('http_success', 0)}")
    sections.append(f"- **HTTP Failed:** {context.get('http_failed', 0)}")
    sections.append("")
    
    # Type-specific content
    if report_type == "attack_surface":
        sections.append("## Attack Surface Analysis\n")
        sections.append(f"Found **{findings.get('subdomains_found', 0)}** subdomains across **{len(findings.get('subdomains', []))}** unique hosts.\n")
        
        if findings.get('top_technologies'):
            sections.append("### Top Technologies Detected\n")
            for tech, count in list(findings.get('top_technologies', {}).items())[:10]:
                sections.append(f"- **{tech}**: {count} hosts")
            sections.append("")
        
        if findings.get('subdomains'):
            sections.append("### Discovered Subdomains\n")
            for sub in findings.get('subdomains', [])[:50]:
                sections.append(f"- {sub}")
            if len(findings.get('subdomains', [])) > 50:
                sections.append(f"- ... and {len(findings['subdomains']) - 50} more")
    
    elif report_type == "vulnerability":
        sections.append("## Vulnerability Assessment\n")
        sections.append("Analyzed HTTP responses for potential vulnerability indicators.\n")
        
    elif report_type == "technology_exposure":
        sections.append("## Technology Exposure Analysis\n")
        if findings.get('top_technologies'):
            sections.append("### Technology Distribution\n")
            for tech, count in findings.get('top_technologies', {}).items():
                sections.append(f"- **{tech}**: {count} hosts")
    
    elif report_type == "attack_vector":
        sections.append("## Attack Vector Analysis\n")
        sections.append("Potential attack vectors identified from reconnaissance data.\n")
        
        sections.append("### Potential Entry Points\n")
        sections.append("- **Web Applications**: HTTP/HTTPS services on subdomains")
        sections.append("- **Technology Stack**: Known vulnerabilities in detected technologies")
        sections.append("- **Exposed Services**: Open ports and services from subdomain enumeration")
    
    sections.append(f"\n---\n*Report generated by ScanX MCP Agent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    
    return "\n".join(sections)


def _generate_summary(report_type: str, context: dict, findings: dict) -> str:
    """Generate a brief summary"""
    domain = context.get('domain', 'Unknown')
    org = context.get('organization', 'Unknown')
    subdomains = findings.get('subdomains_found', 0)
    
    return f"Analysis of {domain} ({org}) - {report_type.replace('_', ' ').title()}. Found {subdomains} subdomains."


async def main():
    # Register handlers
    app.add_request_handler("resources/list", ListResourcesRequest, handle_list_resources)
    app.add_request_handler("resources/read", ReadResourceRequest, handle_read_resource)
    app.add_request_handler("tools/list", ListToolsRequest, handle_list_tools)
    app.add_request_handler("tools/call", CallToolRequest, handle_call_tool)
    
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())