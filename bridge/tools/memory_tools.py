"""Memory read/write tools."""

import time
from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from http_client import error_response, safe_get, safe_patch, simplify_response
from state import get_instance_port


def register_memory_tools(server: FastMCP) -> None:

    @server.tool
    def memory_read(
        address: str = Field(description="Memory address in hex format"),
        length: int = Field(default=16, description="Number of bytes to read"),
        format: str = Field(default="hex", description='Output format - "hex", "base64", or "string"'),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Read bytes from memory."""
        if not address:
            return error_response("MISSING_PARAMETER", "Address parameter is required")

        port = get_instance_port(port)

        params = {"address": address, "length": length, "format": format}
        response = safe_get(port, "memory", params)
        simplified = simplify_response(response)

        if "result" in simplified and isinstance(simplified["result"], dict):
            result = simplified["result"]
            memory_info: dict[str, Any] = {
                "success": True,
                "address": result.get("address", address),
                "length": result.get("bytesRead", length),
                "format": format,
                "timestamp": simplified.get("timestamp", int(time.time() * 1000)),
            }
            if "hexBytes" in result:
                memory_info["hexBytes"] = result["hexBytes"]
            if "rawBytes" in result:
                memory_info["rawBytes"] = result["rawBytes"]
            return memory_info

        return simplified

    @server.tool
    def memory_write(
        address: str = Field(description="Memory address in hex format"),
        bytes_data: str = Field(description="Data to write (format depends on 'format' parameter)"),
        format: str = Field(default="hex", description='Input format - "hex", "base64", or "string"'),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Write bytes to memory (use with caution)."""
        if not address:
            return error_response("MISSING_PARAMETER", "Address parameter is required")
        if not bytes_data:
            return error_response("MISSING_PARAMETER", "Bytes parameter is required")

        port = get_instance_port(port)

        payload = {"bytes": bytes_data, "format": format}
        response = safe_patch(port, f"programs/current/memory/{address}", payload)
        return simplify_response(response)
