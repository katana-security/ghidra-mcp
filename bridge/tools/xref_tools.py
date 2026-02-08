"""Cross-reference tools."""

from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from http_client import error_response, safe_get, simplify_response
from state import get_instance_port


def register_xref_tools(server: FastMCP) -> None:

    @server.tool
    def xrefs_list(
        to_addr: str | None = Field(default=None, description="Filter references to this address (hex)"),
        from_addr: str | None = Field(default=None, description="Filter references from this address (hex)"),
        type: str | None = Field(default=None, description='Filter by reference type (e.g. "CALL", "READ", "WRITE")'),
        offset: int = Field(default=0, description="Pagination offset"),
        limit: int = Field(default=100, description="Maximum items to return"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """List cross-references with filtering and pagination."""
        if not to_addr and not from_addr:
            return error_response("MISSING_PARAMETER", "Either to_addr or from_addr parameter is required")

        port = get_instance_port(port)

        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if to_addr:
            params["to_addr"] = to_addr
        if from_addr:
            params["from_addr"] = from_addr
        if type:
            params["type"] = type

        response = safe_get(port, "xrefs", params)
        simplified = simplify_response(response)

        if isinstance(simplified, dict) and "error" not in simplified:
            simplified.setdefault("size", len(simplified.get("result", [])))
            simplified.setdefault("offset", offset)
            simplified.setdefault("limit", limit)

        return simplified
