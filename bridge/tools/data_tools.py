"""Data item tools -- list, create, rename, delete, set type, list strings."""

from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from http_client import error_response, safe_get, safe_post, simplify_response
from state import get_instance_port


def register_data_tools(server: FastMCP) -> None:

    @server.tool
    def data_list(
        offset: int = Field(default=0, description="Pagination offset"),
        limit: int = Field(default=100, description="Maximum items to return"),
        addr: str | None = Field(default=None, description="Filter by address (hex)"),
        name: str | None = Field(default=None, description="Exact name match filter (case-sensitive)"),
        name_contains: str | None = Field(default=None, description="Substring name filter (case-insensitive)"),
        type: str | None = Field(default=None, description='Filter by data type (e.g. "string", "dword")'),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """List defined data items with filtering and pagination."""
        port = get_instance_port(port)

        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if addr:
            params["addr"] = addr
        if name:
            params["name"] = name
        if name_contains:
            params["name_contains"] = name_contains
        if type:
            params["type"] = type

        response = safe_get(port, "data", params)
        simplified = simplify_response(response)

        if isinstance(simplified, dict) and "error" not in simplified:
            simplified.setdefault("size", len(simplified.get("result", [])))
            simplified.setdefault("offset", offset)
            simplified.setdefault("limit", limit)

        return simplified

    @server.tool
    def data_list_strings(
        offset: int = Field(default=0, description="Pagination offset"),
        limit: int = Field(default=2000, description="Maximum strings to return"),
        filter: str | None = Field(default=None, description="Optional string content filter"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """List all defined strings in the binary with their memory addresses."""
        port = get_instance_port(port)

        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter

        response = safe_get(port, "strings", params)
        return simplify_response(response)

    @server.tool
    def data_create(
        address: str = Field(description="Memory address in hex format"),
        data_type: str = Field(description='Data type (e.g. "string", "dword", "byte")'),
        size: int | None = Field(default=None, description="Optional size in bytes"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Define a new data item at the specified address."""
        if not address or not data_type:
            return error_response("MISSING_PARAMETER", "Address and data_type parameters are required")

        port = get_instance_port(port)

        payload: dict[str, Any] = {"address": address, "type": data_type}
        if size is not None:
            payload["size"] = size

        response = safe_post(port, "data", payload)
        return simplify_response(response)

    @server.tool
    def data_rename(
        address: str = Field(description="Memory address in hex format"),
        name: str = Field(description="New name for the data item"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Rename a data item."""
        if not address or not name:
            return error_response("MISSING_PARAMETER", "Address and name parameters are required")

        port = get_instance_port(port)

        payload = {"address": address, "newName": name}
        response = safe_post(port, "data", payload)
        return simplify_response(response)

    @server.tool
    def data_delete(
        address: str = Field(description="Memory address in hex format"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Delete data at the specified address."""
        if not address:
            return error_response("MISSING_PARAMETER", "Address parameter is required")

        port = get_instance_port(port)

        payload = {"address": address, "action": "delete"}
        response = safe_post(port, "data/delete", payload)
        return simplify_response(response)

    @server.tool
    def data_set_type(
        address: str = Field(description="Memory address in hex format"),
        data_type: str = Field(description='Data type name (e.g. "uint32_t", "char[10]")'),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Set the data type of a data item."""
        if not address or not data_type:
            return error_response("MISSING_PARAMETER", "Address and data_type parameters are required")

        port = get_instance_port(port)

        payload = {"address": address, "type": data_type}
        response = safe_post(port, "data/type", payload)
        return simplify_response(response)
