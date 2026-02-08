"""UI interaction tools -- get current address/function from Ghidra's GUI."""

from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from http_client import safe_get, simplify_response
from state import get_instance_port


def register_ui_tools(server: FastMCP) -> None:

    @server.tool
    def ui_get_current_address(
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get the address currently selected in Ghidra's UI."""
        port = get_instance_port(port)
        response = safe_get(port, "address")
        return simplify_response(response)

    @server.tool
    def ui_get_current_function(
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get the function currently selected in Ghidra's UI."""
        port = get_instance_port(port)
        response = safe_get(port, "function")
        return simplify_response(response)
