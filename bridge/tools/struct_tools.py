"""Struct data type tools -- list, get, create, add field, update field, delete."""

from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from http_client import error_response, safe_get, safe_post, simplify_response
from state import get_instance_port


def register_struct_tools(server: FastMCP) -> None:

    @server.tool
    def structs_list(
        offset: int = Field(default=0, description="Pagination offset"),
        limit: int = Field(default=100, description="Maximum items to return"),
        category: str | None = Field(default=None, description='Filter by category path (e.g. "/winapi")'),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """List all struct data types in the program."""
        port = get_instance_port(port)

        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if category:
            params["category"] = category

        response = safe_get(port, "structs", params)
        simplified = simplify_response(response)

        if isinstance(simplified, dict) and "error" not in simplified:
            simplified.setdefault("size", len(simplified.get("result", [])))
            simplified.setdefault("offset", offset)
            simplified.setdefault("limit", limit)

        return simplified

    @server.tool
    def structs_get(
        name: str = Field(description="Struct name"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Get detailed information about a specific struct including all fields."""
        if not name:
            return error_response("MISSING_PARAMETER", "Struct name parameter is required")

        port = get_instance_port(port)

        params = {"name": name}
        response = safe_get(port, "structs", params)
        return simplify_response(response)

    @server.tool
    def structs_create(
        name: str = Field(description="Name for the new struct"),
        category: str | None = Field(default=None, description='Category path (e.g. "/custom")'),
        description: str | None = Field(default=None, description="Optional description"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Create a new struct data type."""
        if not name:
            return error_response("MISSING_PARAMETER", "Struct name parameter is required")

        port = get_instance_port(port)

        payload: dict[str, Any] = {"name": name}
        if category:
            payload["category"] = category
        if description:
            payload["description"] = description

        response = safe_post(port, "structs/create", payload)
        return simplify_response(response)

    @server.tool
    def structs_add_field(
        struct_name: str = Field(description="Name of the struct to modify"),
        field_name: str = Field(description="Name for the new field"),
        field_type: str = Field(description='Data type for the field (e.g. "int", "char", "pointer")'),
        offset: int | None = Field(default=None, description="Specific offset to insert field (appends if not specified)"),
        comment: str | None = Field(default=None, description="Optional comment for the field"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Add a field to an existing struct."""
        if not struct_name or not field_name or not field_type:
            return error_response(
                "MISSING_PARAMETER", "struct_name, field_name, and field_type parameters are required"
            )

        port = get_instance_port(port)

        payload: dict[str, Any] = {
            "struct": struct_name,
            "fieldName": field_name,
            "fieldType": field_type,
        }
        if offset is not None:
            payload["offset"] = offset
        if comment:
            payload["comment"] = comment

        response = safe_post(port, "structs/addfield", payload)
        return simplify_response(response)

    @server.tool
    def structs_update_field(
        struct_name: str = Field(description="Name of the struct to modify"),
        field_name: str | None = Field(default=None, description="Name of the field to update"),
        field_offset: int | None = Field(default=None, description="Offset of the field to update"),
        new_name: str | None = Field(default=None, description="New name for the field"),
        new_type: str | None = Field(default=None, description='New data type (e.g. "int", "pointer")'),
        new_comment: str | None = Field(default=None, description="New comment for the field"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Update an existing field in a struct (change name, type, or comment)."""
        if not struct_name:
            return error_response("MISSING_PARAMETER", "struct_name parameter is required")
        if not field_name and field_offset is None:
            return error_response("MISSING_PARAMETER", "Either field_name or field_offset must be provided")
        if not new_name and not new_type and new_comment is None:
            return error_response(
                "MISSING_PARAMETER", "At least one of new_name, new_type, or new_comment must be provided"
            )

        port = get_instance_port(port)

        payload: dict[str, Any] = {"struct": struct_name}
        if field_name:
            payload["fieldName"] = field_name
        if field_offset is not None:
            payload["fieldOffset"] = field_offset
        if new_name:
            payload["newName"] = new_name
        if new_type:
            payload["newType"] = new_type
        if new_comment is not None:
            payload["newComment"] = new_comment

        response = safe_post(port, "structs/updatefield", payload)
        return simplify_response(response)

    @server.tool
    def structs_delete(
        name: str = Field(description="Name of the struct to delete"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Delete a struct data type."""
        if not name:
            return error_response("MISSING_PARAMETER", "Struct name parameter is required")

        port = get_instance_port(port)

        payload = {"name": name}
        response = safe_post(port, "structs/delete", payload)
        return simplify_response(response)
