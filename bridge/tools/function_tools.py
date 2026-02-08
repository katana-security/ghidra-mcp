"""Function tools -- list, get, decompile, disassemble, create, rename, set_signature, get_variables, set_comment."""

from typing import Any
from urllib.parse import quote

from fastmcp import FastMCP
from pydantic import Field

from http_client import error_response, safe_get, safe_patch, safe_post, simplify_response
from state import get_instance_port


def register_function_tools(server: FastMCP) -> None:

    @server.tool
    def functions_list(
        offset: int = Field(default=0, description="Pagination offset"),
        limit: int = Field(default=100, description="Maximum items to return"),
        name_contains: str | None = Field(default=None, description="Substring name filter (case-insensitive)"),
        name_matches_regex: str | None = Field(default=None, description="Regex name filter"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """List functions with filtering and pagination."""
        port = get_instance_port(port)

        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if name_contains:
            params["name_contains"] = name_contains
        if name_matches_regex:
            params["name_matches_regex"] = name_matches_regex

        response = safe_get(port, "functions", params)
        simplified = simplify_response(response)

        if isinstance(simplified, dict) and "error" not in simplified:
            simplified.setdefault("size", len(simplified.get("result", [])))
            simplified.setdefault("offset", offset)
            simplified.setdefault("limit", limit)

        return simplified

    @server.tool
    def functions_get(
        name: str | None = Field(default=None, description="Function name"),
        address: str | None = Field(default=None, description="Function address in hex format"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get detailed information about a function."""
        if not name and not address:
            return error_response("MISSING_PARAMETER", "Either name or address parameter is required")

        port = get_instance_port(port)

        if address:
            endpoint = f"functions/{address}"
        else:
            endpoint = f"functions/by-name/{quote(name)}"

        response = safe_get(port, endpoint)
        return simplify_response(response)

    @server.tool
    def functions_decompile(
        name: str | None = Field(default=None, description="Function name"),
        address: str | None = Field(default=None, description="Function address in hex format"),
        syntax_tree: bool = Field(default=False, description="Include syntax tree"),
        style: str = Field(default="normalize", description="Decompiler style"),
        start_line: int | None = Field(default=None, description="Start at this line number (1-indexed)"),
        end_line: int | None = Field(default=None, description="End at this line number (inclusive)"),
        max_lines: int | None = Field(default=None, description="Maximum lines to return (takes precedence over end_line)"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get decompiled code for a function with optional line filtering for context management.

        Examples:
            functions_decompile(name="main", max_lines=20)
            functions_decompile(name="main", start_line=10, end_line=30)
            functions_decompile(name="main", start_line=25, max_lines=15)
        """
        if not name and not address:
            return error_response("MISSING_PARAMETER", "Either name or address parameter is required")

        port = get_instance_port(port)

        params: dict[str, Any] = {
            "syntax_tree": str(syntax_tree).lower(),
            "style": style,
        }
        if start_line is not None:
            params["start_line"] = str(start_line)
        if end_line is not None:
            params["end_line"] = str(end_line)
        if max_lines is not None:
            params["max_lines"] = str(max_lines)

        if address:
            endpoint = f"functions/{address}/decompile"
        else:
            endpoint = f"functions/by-name/{quote(name)}/decompile"

        response = safe_get(port, endpoint, params)
        return simplify_response(response)

    @server.tool
    def functions_disassemble(
        name: str | None = Field(default=None, description="Function name"),
        address: str | None = Field(default=None, description="Function address in hex format"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get disassembly for a function."""
        if not name and not address:
            return error_response("MISSING_PARAMETER", "Either name or address parameter is required")

        port = get_instance_port(port)

        if address:
            endpoint = f"functions/{address}/disassembly"
        else:
            endpoint = f"functions/by-name/{quote(name)}/disassembly"

        response = safe_get(port, endpoint)
        return simplify_response(response)

    @server.tool
    def functions_create(
        address: str = Field(description="Memory address in hex format where function starts"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Create a new function at the specified address."""
        if not address:
            return error_response("MISSING_PARAMETER", "Address parameter is required")

        port = get_instance_port(port)

        payload = {"address": address}
        response = safe_post(port, "functions", payload)
        return simplify_response(response)

    @server.tool
    def functions_rename(
        old_name: str | None = Field(default=None, description="Current function name"),
        address: str | None = Field(default=None, description="Function address in hex format"),
        new_name: str = Field(default="", description="New function name"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Rename a function."""
        if not (old_name or address) or not new_name:
            return error_response(
                "MISSING_PARAMETER",
                "Either old_name or address, and new_name parameters are required",
            )

        port = get_instance_port(port)

        payload = {"name": new_name}
        if address:
            endpoint = f"functions/{address}"
        else:
            endpoint = f"functions/by-name/{quote(old_name)}"

        response = safe_patch(port, endpoint, payload)
        return simplify_response(response)

    @server.tool
    def functions_set_signature(
        name: str | None = Field(default=None, description="Function name"),
        address: str | None = Field(default=None, description="Function address in hex format"),
        signature: str = Field(default="", description='New function signature (e.g. "int func(char *data, int size)")'),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Set function signature/prototype."""
        if not (name or address) or not signature:
            return error_response(
                "MISSING_PARAMETER",
                "Either name or address, and signature parameters are required",
            )

        port = get_instance_port(port)

        payload = {"signature": signature}
        if address:
            endpoint = f"functions/{address}"
        else:
            endpoint = f"functions/by-name/{quote(name)}"

        response = safe_patch(port, endpoint, payload)
        return simplify_response(response)

    @server.tool
    def functions_get_variables(
        name: str | None = Field(default=None, description="Function name"),
        address: str | None = Field(default=None, description="Function address in hex format"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get variables for a function."""
        if not name and not address:
            return error_response("MISSING_PARAMETER", "Either name or address parameter is required")

        port = get_instance_port(port)

        if address:
            endpoint = f"functions/{address}/variables"
        else:
            endpoint = f"functions/by-name/{quote(name)}/variables"

        response = safe_get(port, endpoint)
        return simplify_response(response)
