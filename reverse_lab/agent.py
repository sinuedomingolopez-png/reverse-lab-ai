"""Local owner controls and MCP entry point. Never accepts arbitrary shell commands."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .authorizations import Authorizations


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reverse Lab AI private local MCP agent")
    parser.add_argument("--manifest", type=Path, required=True,
                        help="Private local file grants; never commit this file")
    commands = parser.add_subparsers(dest="command", required=True)
    grant = commands.add_parser("authorize", help="Local-only explicit authorization")
    grant.add_argument("file", type=Path)
    grant.add_argument("--root", type=Path, required=True)
    grant.add_argument("--share-content", action="store_true", help="Permit recovered names and pseudocode to MCP clients")
    grant.add_argument("--confirm-sharing", action="store_true", required=True,
                       help="Confirm metadata, hash and optional content may reach the connected client")
    grant.add_argument("--lifetime", type=int, default=3600)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("file_id")
    commands.add_parser("list")
    serve = commands.add_parser("serve")
    serve.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--timeout", type=int, default=180)
    serve.add_argument("--memory-mb", type=int, default=2048)
    serve.add_argument("--ghidra-headless")
    serve.add_argument("--issuer")
    serve.add_argument("--resource-url")
    serve.add_argument("--jwks", type=Path)
    serve.add_argument("--owner-subject")
    args = parser.parse_args(argv)
    grants = Authorizations(args.manifest)
    if args.command == "authorize":
        print(json.dumps(grants.grant(args.file, root=args.root, content=args.share_content,
                                      lifetime=args.lifetime)))
        return
    if args.command == "revoke":
        grants.revoke(args.file_id)
        print('{"status":"revoked"}')
        return
    if args.command == "list":
        print(json.dumps(grants.list_files()))
        return
    if sys.version_info < (3, 11):
        parser.error("MCP SDK 2 requires Python 3.11+; core app still supports Python 3.10")
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    from .analysis_jobs import AnalysisJobs
    from .mcp_server import create_server
    options = {}
    if args.transport == "http":
        if not all((args.issuer, args.resource_url, args.jwks, args.owner_subject)):
            parser.error("HTTP requires --issuer, --resource-url, --jwks and --owner-subject")
        from .mcp_auth import LocalJWKVerifier
        from mcp.server.auth.settings import AuthSettings
        from pydantic import AnyHttpUrl
        verifier = LocalJWKVerifier(args.jwks, issuer=args.issuer,
                                     resource=args.resource_url, subject=args.owner_subject)
        if urlsplit(args.resource_url).path != "/mcp":
            parser.error("resource URL must end in /mcp")
        options = {"token_verifier": verifier,
                   "auth": AuthSettings(issuer_url=AnyHttpUrl(args.issuer),
                                        resource_server_url=AnyHttpUrl(args.resource_url),
                                        required_scopes=["reverse:read"], validate_token_resource=True)}
    jobs = AnalysisJobs(grants, timeout=args.timeout, memory_mb=args.memory_mb,
                        ghidra_headless=args.ghidra_headless)
    try:
        server = create_server(jobs, remote=args.transport == "http", **options)
        if args.transport == "stdio":
            server.run()
        else:
            from mcp.server.transport_security import TransportSecuritySettings
            from mcp.server.auth.routes import create_protected_resource_routes
            import uvicorn
            host = urlsplit(args.resource_url).netloc
            app = server.streamable_http_app(
                       host="127.0.0.1", json_response=True, stateless_http=True, max_request_body_size=16384,
                       transport_security=TransportSecuritySettings(
                           enable_dns_rebinding_protection=True,
                           allowed_hosts=[host, f"127.0.0.1:{args.port}"],
                           allowed_origins=[f"https://{host}"],
                       ))
            # SDK defaults discovery to required_scopes. Advertise optional scopes
            # as well, while allowing read-only tokens and enforcing each operation.
            routes = create_protected_resource_routes(
                AnyHttpUrl(args.resource_url), [AnyHttpUrl(args.issuer)],
                scopes_supported=["reverse:read", "reverse:analyze", "reverse:content", "reverse:cancel"],
                resource_name="Reverse Lab AI")
            paths = {route.path for route in routes}
            app.router.routes = [route for route in app.router.routes if route.path not in paths] + routes
            uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False,
                        log_level="warning", limit_concurrency=16, timeout_keep_alive=5)
    finally:
        jobs.close()


if __name__ == "__main__":
    main()
