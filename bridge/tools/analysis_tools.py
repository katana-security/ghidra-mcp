"""Analysis tools -- run analysis, call graph, data flow."""

from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from http_client import error_response, safe_get, safe_post, simplify_response
from state import get_instance_port


def register_analysis_tools(server: FastMCP) -> None:

    @server.tool
    def analysis_run(
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
        analysis_options: dict[str, Any] | None = Field(
            default=None,
            description='Analysis options dict (e.g. {"functionRecovery": true, "dataRefs": false})',
        ),
    ) -> dict[str, Any]:
        """Run analysis on the current program."""
        port = get_instance_port(port)
        response = safe_post(port, "analysis", analysis_options or {})
        return simplify_response(response)

    @server.tool
    def analysis_get_callgraph(
        name: str | None = Field(default=None, description="Starting function name"),
        address: str | None = Field(default=None, description="Starting function address"),
        max_depth: int = Field(default=3, description="Maximum call depth to analyze"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get function call graph visualization data."""
        port = get_instance_port(port)

        params: dict[str, Any] = {"max_depth": max_depth}
        if address:
            params["address"] = address
        elif name:
            params["name"] = name

        response = safe_get(port, "analysis/callgraph", params)
        return simplify_response(response)

    @server.tool
    def analysis_get_dataflow(
        address: str = Field(description="Starting address in hex format"),
        direction: str = Field(default="forward", description='"forward" or "backward"'),
        max_steps: int = Field(default=50, description="Maximum analysis steps"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Perform data flow analysis from an address."""
        if not address:
            return error_response("MISSING_PARAMETER", "Address parameter is required")

        port = get_instance_port(port)

        params = {"address": address, "direction": direction, "max_steps": max_steps}
        response = safe_get(port, "analysis/dataflow", params)
        return simplify_response(response)
